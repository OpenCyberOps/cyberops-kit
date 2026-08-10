"""Scoring model behavior, dimension by dimension."""

from __future__ import annotations

import pytest

from cyberops_kit.config import DEFAULT_WEIGHTS
from cyberops_kit.core.models import (
    Category,
    DimensionKey,
    Grade,
    SBOMFormat,
    SBOMSummary,
    Severity,
    SLSAAssessment,
    SLSAEvidence,
)
from cyberops_kit.core.scoring import (
    CAP_EXPLOITED_CRITICAL,
    CAP_NO_SBOM,
    CAP_VERIFIED_SECRET,
    MIN_SCORING_COVERAGE,
    ScoringContext,
    compute_score,
    grade_for,
    has_known_exploit,
)
from tests.conftest import make_finding

ALL_DIMENSIONS = frozenset(DimensionKey)


def context(**overrides) -> ScoringContext:
    """Build a scoring context where every dimension has data by default."""
    base = {
        "scorecard_aggregate": 10.0,
        "sbom": SBOMSummary(generated=True, component_count=10, formats=[SBOMFormat.CYCLONEDX_1_6]),
        "slsa": SLSAAssessment(
            build_level=3,
            evidence=[SLSAEvidence(check="c", passed=True, detail="d", source="s")],
        ),
        "available_dimensions": ALL_DIMENSIONS,
    }
    base.update(overrides)
    return ScoringContext(**base)


# --- Grade bands ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("composite", "expected"),
    [
        (100, Grade.A),
        (90, Grade.A),
        (89, Grade.B),
        (80, Grade.B),
        (79, Grade.C),
        (70, Grade.C),
        (69, Grade.D),
        (60, Grade.D),
        (59, Grade.F),
        (0, Grade.F),
    ],
)
def test_grade_bands(composite, expected):
    assert grade_for(composite) is expected


# --- Perfect and empty runs ----------------------------------------------------


def test_clean_project_scores_100():
    score = compute_score([], DEFAULT_WEIGHTS, context=context())
    assert score.composite == 100
    assert score.grade is Grade.A


def test_no_available_dimensions_is_zero_coverage():
    score = compute_score([], DEFAULT_WEIGHTS, context=ScoringContext())
    assert score.coverage == 0.0
    assert score.sufficient_coverage is False
    assert all(d.excluded for d in score.dimensions.values())


# --- Penalties -----------------------------------------------------------------


def test_four_critical_cves_zero_the_vulnerability_dimension():
    findings = [
        make_finding(rule_id=f"CVE-{i}", severity=Severity.CRITICAL, purl=f"pkg:npm/p{i}@1")
        for i in range(4)
    ]
    score = compute_score(findings, DEFAULT_WEIGHTS, context=context())
    assert score.dimensions[DimensionKey.KNOWN_VULNERABILITIES].value == 0.0


def test_vulnerability_penalties_are_severity_weighted():
    high = compute_score(
        [make_finding(severity=Severity.HIGH, purl="pkg:npm/a@1")],
        DEFAULT_WEIGHTS,
        context=context(),
    )
    medium = compute_score(
        [make_finding(severity=Severity.MEDIUM, purl="pkg:npm/a@1")],
        DEFAULT_WEIGHTS,
        context=context(),
    )
    assert (
        high.dimensions[DimensionKey.KNOWN_VULNERABILITIES].value
        < medium.dimensions[DimensionKey.KNOWN_VULNERABILITIES].value
    )


def test_static_analysis_is_penalized_more_lightly_than_vulnerabilities():
    """Deliberate: SAST has more false positives, and over-penalizing it pushes
    maintainers to disable the scanner."""
    vuln = compute_score(
        [make_finding(severity=Severity.HIGH, category=Category.VULNERABILITY)],
        DEFAULT_WEIGHTS,
        context=context(),
    )
    sast = compute_score(
        [make_finding(severity=Severity.HIGH, category=Category.STATIC_ANALYSIS)],
        DEFAULT_WEIGHTS,
        context=context(),
    )
    assert (
        sast.dimensions[DimensionKey.STATIC_ANALYSIS].value
        > vuln.dimensions[DimensionKey.KNOWN_VULNERABILITIES].value
    )


# --- Secrets -------------------------------------------------------------------


def test_no_secrets_scores_100():
    score = compute_score([], DEFAULT_WEIGHTS, context=context())
    assert score.dimensions[DimensionKey.SECRETS_EXPOSURE].value == 100.0


def test_unverified_secret_scores_50():
    finding = make_finding(category=Category.SECRET, severity=Severity.CRITICAL)
    score = compute_score([finding], DEFAULT_WEIGHTS, context=context())
    assert score.dimensions[DimensionKey.SECRETS_EXPOSURE].value == 50.0


def test_verified_secret_scores_zero_and_caps_the_composite():
    finding = make_finding(category=Category.SECRET, severity=Severity.CRITICAL, verified=True)
    score = compute_score([finding], DEFAULT_WEIGHTS, context=context())

    assert score.dimensions[DimensionKey.SECRETS_EXPOSURE].value == 0.0
    assert score.composite <= CAP_VERIFIED_SECRET
    assert score.grade is Grade.F


# --- Hard caps -----------------------------------------------------------------


def test_all_three_caps_are_always_reported():
    """Including the ones that did not fire, so a reader sees what was considered."""
    score = compute_score([], DEFAULT_WEIGHTS, context=context())
    assert len(score.caps) == 3
    assert all(cap.applied is False for cap in score.caps)


def test_no_sbom_caps_at_79():
    score = compute_score([], DEFAULT_WEIGHTS, context=context(sbom=SBOMSummary(generated=False)))
    assert score.composite <= CAP_NO_SBOM


def test_known_exploit_cap_requires_evidence():
    """Absence of evidence is not evidence of exploitation."""
    plain = make_finding(
        severity=Severity.CRITICAL, category=Category.VULNERABILITY, raw={"id": "CVE-1"}
    )
    score = compute_score([plain], DEFAULT_WEIGHTS, context=context())
    exploit_cap = next(c for c in score.caps if "public exploit" in c.condition)
    assert exploit_cap.applied is False


def test_known_exploit_cap_fires_on_kev_evidence():
    kev = make_finding(
        severity=Severity.CRITICAL,
        category=Category.VULNERABILITY,
        raw={"database_specific": {"cisa_kev": True}},
    )
    score = compute_score([kev], DEFAULT_WEIGHTS, context=context())
    assert score.composite <= CAP_EXPLOITED_CRITICAL


def test_known_exploit_detection_via_reference_url():
    finding = make_finding(
        severity=Severity.CRITICAL,
        references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
    )
    assert has_known_exploit(finding) is True


def test_known_exploit_detection_is_false_by_default():
    assert has_known_exploit(make_finding()) is False


# --- Exclusion and redistribution ----------------------------------------------


def test_excluded_dimension_weight_is_redistributed():
    """A missing scanner must not drag the score down."""
    available = ALL_DIMENSIONS - {DimensionKey.OPENSSF_SCORECARD}
    score = compute_score(
        [],
        DEFAULT_WEIGHTS,
        context=context(available_dimensions=available, scorecard_aggregate=None),
    )

    scorecard = score.dimensions[DimensionKey.OPENSSF_SCORECARD]
    assert scorecard.excluded is True
    assert scorecard.effective_weight == 0.0
    assert scorecard.exclusion_reason

    # The remaining 75 points of weight are scaled up to 100.
    total = sum(d.effective_weight for d in score.dimensions.values())
    assert total == pytest.approx(100.0)
    # A clean project still scores 100 despite the missing scanner.
    assert score.composite == 100


def test_exclusion_never_scores_a_missing_scanner_as_zero():
    available = {DimensionKey.SECRETS_EXPOSURE, DimensionKey.KNOWN_VULNERABILITIES}
    score = compute_score([], DEFAULT_WEIGHTS, context=context(available_dimensions=available))

    for key in ALL_DIMENSIONS - available:
        assert score.dimensions[key].value is None
        assert score.dimensions[key].excluded is True


def test_coverage_is_reported():
    available = {DimensionKey.SECRETS_EXPOSURE}  # weight 10 of 100
    score = compute_score([], DEFAULT_WEIGHTS, context=context(available_dimensions=available))
    assert score.coverage == pytest.approx(0.1)
    assert score.sufficient_coverage is False


def test_sufficient_coverage_threshold():
    available = {
        DimensionKey.OPENSSF_SCORECARD,  # 25
        DimensionKey.KNOWN_VULNERABILITIES,  # 25
        DimensionKey.STATIC_ANALYSIS,  # 15
    }
    score = compute_score([], DEFAULT_WEIGHTS, context=context(available_dimensions=available))
    assert score.coverage == pytest.approx(0.65)
    assert score.coverage >= MIN_SCORING_COVERAGE
    assert score.sufficient_coverage is True


# --- SBOM health ---------------------------------------------------------------


def test_sbom_health_drops_freshness_when_unmeasured():
    """Assuming everything is current would silently inflate the dimension."""
    sbom = SBOMSummary(
        generated=True,
        component_count=10,
        unresolved_count=0,
        license_unknown_count=0,
        outdated_count=None,
    )
    score = compute_score([], DEFAULT_WEIGHTS, context=context(sbom=sbom))
    assert score.dimensions[DimensionKey.SBOM_HEALTH].value == 100.0
    assert any(
        "freshness" in line.lower() for line in score.dimensions[DimensionKey.SBOM_HEALTH].evidence
    )


def test_sbom_health_penalizes_unresolved_and_unlicensed():
    sbom = SBOMSummary(
        generated=True, component_count=10, unresolved_count=5, license_unknown_count=10
    )
    score = compute_score([], DEFAULT_WEIGHTS, context=context(sbom=sbom))
    assert score.dimensions[DimensionKey.SBOM_HEALTH].value < 60


# --- Supply chain --------------------------------------------------------------


def test_supply_chain_reflects_slsa_level():
    low = compute_score(
        [],
        DEFAULT_WEIGHTS,
        context=context(
            slsa=SLSAAssessment(
                build_level=0,
                evidence=[SLSAEvidence(check="c", passed=False, detail="d", source="s")],
            )
        ),
    )
    high = compute_score([], DEFAULT_WEIGHTS, context=context())

    assert (
        low.dimensions[DimensionKey.SUPPLY_CHAIN_INTEGRITY].value
        < high.dimensions[DimensionKey.SUPPLY_CHAIN_INTEGRITY].value
    )


def test_misconfiguration_penalty_is_capped():
    """Misconfigurations must not be able to erase a well-secured pipeline."""
    many = [
        make_finding(
            rule_id=f"AVD-{i}",
            category=Category.MISCONFIGURATION,
            severity=Severity.CRITICAL,
            path=f"file{i}.tf",
        )
        for i in range(20)
    ]
    score = compute_score(many, DEFAULT_WEIGHTS, context=context())
    # Base is 100 at SLSA 3 with all evidence passing; the cap is 25.
    assert score.dimensions[DimensionKey.SUPPLY_CHAIN_INTEGRITY].value == 75.0


# --- Rounding ------------------------------------------------------------------


def test_rounding_is_half_up_not_bankers():
    """Python's round() would send 84.5 to 84. The published model says half-up."""
    from cyberops_kit.core.scoring import _round_half_up

    assert _round_half_up(84.5) == 85
    assert _round_half_up(85.5) == 86
    assert _round_half_up(84.4) == 84


def test_scoring_model_version_is_set():
    from cyberops_kit.core.scoring import SCORING_MODEL_VERSION

    assert SCORING_MODEL_VERSION == "1.0.0"
