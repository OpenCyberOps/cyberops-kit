"""The composite scoring model — pure, deterministic, and versioned.

:func:`compute_score` is a pure function of deterministic scanner findings and the
configured weights (INV-1). It never reads ``Finding.advisory`` (INV-2), never calls
a network service, never consults wall-clock time, and never depends on dict or set
iteration order.

Everything in this module is published verbatim in ``docs/methodology/scoring.md``.
Any change to scoring behavior updates that document in the same commit and bumps
:data:`SCORING_MODEL_VERSION` (INV-7). A security score nobody can audit is
worthless.

Two principles drive the design decisions here:

**A missing scanner is not a failing grade.** A dimension with no data is excluded
and its weight redistributed proportionally, with the exclusion stated in the
report. Silently scoring an absent scanner as zero is dishonest.

**We never assert what we did not observe.** The "known public exploit" hard cap
fires only when a scanner supplied actual exploit evidence, not when we merely
failed to rule one out.
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from cyberops_kit.core.models import (
    AppliedCap,
    Category,
    DimensionKey,
    DimensionScore,
    Finding,
    Grade,
    SBOMSummary,
    Score,
    Severity,
    SLSAAssessment,
    sort_findings,
)

SCORING_MODEL_VERSION: Final = "1.0.0"
"""Bumped by any change to scoring behavior, in the same commit as the doc update."""

MAX_SCORE: Final = 100.0
MIN_SCORE: Final = 0.0

GRADE_BANDS: Final[tuple[tuple[int, Grade], ...]] = (
    (90, Grade.A),
    (80, Grade.B),
    (70, Grade.C),
    (60, Grade.D),
    (0, Grade.F),
)

SCORECARD_MAX: Final = 10.0
"""Scorecard's aggregate is 0-10; the dimension scales it by 10."""

VULNERABILITY_PENALTIES: Final[dict[Severity, float]] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 10.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}
"""Points deducted per known vulnerability. One critical CVE costs a quarter of the
dimension; four sink it entirely."""

STATIC_ANALYSIS_PENALTIES: Final[dict[Severity, float]] = {
    Severity.CRITICAL: 20.0,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 0.5,
    Severity.INFO: 0.0,
}
"""Lighter than vulnerability penalties: SAST findings carry more false positives,
and penalizing them at CVE weight would push maintainers to disable the scanner."""

MISCONFIGURATION_PENALTIES: Final[dict[Severity, float]] = {
    Severity.CRITICAL: 12.0,
    Severity.HIGH: 6.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 0.5,
    Severity.INFO: 0.0,
}

MISCONFIGURATION_PENALTY_CAP: Final = 25.0
"""Misconfigurations reduce supply chain integrity but cannot zero it on their own;
the SLSA level and its evidence carry the dimension."""

SLSA_MAX_LEVEL: Final = 3

SECRETS_NONE: Final = 100.0
SECRETS_UNVERIFIED: Final = 50.0
"""No scanner in the Phase 1 set verifies a credential against its provider, so an
unverified secret is scored as a serious but unconfirmed exposure rather than as a
confirmed breach. See the methodology doc."""

SECRETS_VERIFIED: Final = 0.0

SBOM_RESOLUTION_WEIGHT: Final = 0.4
SBOM_LICENSE_WEIGHT: Final = 0.3
SBOM_STALENESS_WEIGHT: Final = 0.3

MIN_SCORING_COVERAGE: Final = 0.5
"""Below this fraction of configured weight, a composite is not meaningful.

Weight redistribution keeps a partial run honest in *relative* terms, but it cannot
manufacture information. A run where only one dimension had data produces a number
derived entirely from that dimension, and presenting it as a comparable grade would
overstate what was measured. Such a score is flagged, and CI does not fail on it.
"""

CAP_VERIFIED_SECRET: Final = 59
CAP_EXPLOITED_CRITICAL: Final = 69
CAP_NO_SBOM: Final = 79

_KEV_MARKERS: Final[tuple[str, ...]] = (
    "cisa_kev",
    "cisakev",
    "known_exploited",
    "knownexploited",
)
"""Fields a scanner sets when an advisory appears in a known-exploited catalog."""

_EXPLOIT_URL_MARKERS: Final[tuple[str, ...]] = (
    "cisa.gov/known-exploited-vulnerabilities",
    "exploit-db.com",
    "metasploit",
)


class ScoringContext(BaseModel):
    """Deterministic inputs to scoring that are measurements rather than findings.

    Everything here comes from scanner output and is reproducible for a given commit
    and set of tool versions. Nothing here is advisory, and nothing here is derived
    from wall-clock time.
    """

    model_config = ConfigDict(frozen=True)

    scorecard_aggregate: float | None = None
    """Scorecard's 0-10 aggregate. ``None`` when Scorecard did not run."""

    sbom: SBOMSummary = Field(default_factory=SBOMSummary)
    slsa: SLSAAssessment | None = None
    available_dimensions: frozenset[DimensionKey] = frozenset()
    """Dimensions whose scanner produced data. Others are excluded, not zeroed."""

    exclusion_reasons: dict[DimensionKey, str] = Field(default_factory=dict)


def compute_score(
    findings: Sequence[Finding],
    weights: dict[DimensionKey, float],
    *,
    context: ScoringContext | None = None,
) -> Score:
    """Compute the composite score.

    Pure and deterministic. Given the same findings, weights, and context, this
    returns the same result on every machine, in every process, forever.

    Args:
        findings: All normalized findings from the run, in any order.
        weights: Configured dimension weights.
        context: Measurements that are not findings, plus which dimensions have data.
            Defaults to an empty context, in which case only finding-derived
            dimensions are scored.

    Returns:
        The composite score with its full derivation.
    """
    ctx = context or ScoringContext()

    # Sort before any aggregation. Every downstream sum, count, and max then walks
    # the same sequence regardless of the order scanners happened to finish in.
    ordered = sort_findings(list(findings))
    by_category = _group_by_category(ordered)

    dimensions = _score_dimensions(by_category, ctx, weights)
    _redistribute_weights(dimensions)

    weighted_mean = (
        sum(
            dimension.value * dimension.effective_weight
            for dimension in dimensions.values()
            if dimension.value is not None
        )
        / 100.0
    )

    composite = _round_half_up(weighted_mean)
    caps = _evaluate_caps(by_category, ctx)
    for cap in caps:
        if cap.applied:
            composite = min(composite, cap.capped_at)

    coverage = _coverage(dimensions)

    return Score(
        composite=composite,
        grade=grade_for(composite),
        weighted_mean=round(weighted_mean, 4),
        dimensions=dimensions,
        caps=caps,
        excluded_dimensions=[key for key, dimension in dimensions.items() if dimension.excluded],
        coverage=coverage,
        sufficient_coverage=coverage >= MIN_SCORING_COVERAGE,
    )


def _coverage(dimensions: dict[DimensionKey, DimensionScore]) -> float:
    """Compute the fraction of configured weight that had data.

    Args:
        dimensions: The scored dimensions.

    Returns:
        A value from 0.0 to 1.0. Returns 0.0 when no weight was configured at all.
    """
    total = sum(d.configured_weight for d in dimensions.values())
    if total <= 0:
        return 0.0
    scored = sum(d.configured_weight for d in dimensions.values() if not d.excluded)
    return round(scored / total, 4)


def grade_for(composite: int) -> Grade:
    """Map a composite score to its letter grade.

    Args:
        composite: The 0-100 composite score.

    Returns:
        The letter grade.
    """
    for threshold, grade in GRADE_BANDS:
        if composite >= threshold:
            return grade
    return Grade.F  # pragma: no cover - the 0 band is exhaustive


# --- Dimension scoring ---------------------------------------------------------


def _score_dimensions(
    by_category: dict[Category, list[Finding]],
    ctx: ScoringContext,
    weights: dict[DimensionKey, float],
) -> dict[DimensionKey, DimensionScore]:
    """Score every dimension, marking those without data as excluded.

    Args:
        by_category: Findings grouped by category.
        ctx: Deterministic non-finding inputs.
        weights: Configured dimension weights.

    Returns:
        Dimension scores, built in sorted key order so the mapping never depends on
        iteration order (INV-1).
    """
    scorers = {
        DimensionKey.OPENSSF_SCORECARD: lambda: _score_scorecard(ctx),
        DimensionKey.KNOWN_VULNERABILITIES: lambda: _score_vulnerabilities(by_category),
        DimensionKey.SUPPLY_CHAIN_INTEGRITY: lambda: _score_supply_chain(by_category, ctx),
        DimensionKey.STATIC_ANALYSIS: lambda: _score_static_analysis(by_category),
        DimensionKey.SECRETS_EXPOSURE: lambda: _score_secrets(by_category),
        DimensionKey.SBOM_HEALTH: lambda: _score_sbom(ctx),
    }

    dimensions: dict[DimensionKey, DimensionScore] = {}
    for key in sorted(DimensionKey, key=lambda k: k.value):
        configured = float(weights.get(key, 0.0))

        if key not in ctx.available_dimensions:
            dimensions[key] = DimensionScore(
                key=key,
                value=None,
                configured_weight=configured,
                effective_weight=0.0,
                excluded=True,
                exclusion_reason=ctx.exclusion_reasons.get(
                    key, "no scanner produced data for this dimension"
                ),
            )
            continue

        value, evidence = scorers[key]()
        dimensions[key] = DimensionScore(
            key=key,
            value=_clamp(value),
            configured_weight=configured,
            effective_weight=configured,
            excluded=False,
            evidence=evidence,
        )

    return dimensions


def _score_scorecard(ctx: ScoringContext) -> tuple[float, list[str]]:
    """Score the OpenSSF Scorecard dimension.

    Args:
        ctx: Deterministic non-finding inputs.

    Returns:
        The 0-100 value and its evidence lines.
    """
    if ctx.scorecard_aggregate is None:
        return MIN_SCORE, ["Scorecard reported no aggregate."]
    value = ctx.scorecard_aggregate * (MAX_SCORE / SCORECARD_MAX)
    return value, [f"Scorecard aggregate {ctx.scorecard_aggregate:.1f}/10 scaled to {value:.0f}."]


def _score_vulnerabilities(
    by_category: dict[Category, list[Finding]],
) -> tuple[float, list[str]]:
    """Score known vulnerabilities as a severity-weighted penalty.

    Args:
        by_category: Findings grouped by category.

    Returns:
        The 0-100 value and its evidence lines.
    """
    findings = by_category.get(Category.VULNERABILITY, [])
    if not findings:
        return MAX_SCORE, ["No known vulnerabilities were reported."]

    penalty = sum(VULNERABILITY_PENALTIES[f.severity] for f in findings)
    counts = _severity_counts(findings)
    return MAX_SCORE - penalty, [
        f"{len(findings)} known vulnerabilities ({counts}) cost {penalty:.1f} points."
    ]


def _score_static_analysis(
    by_category: dict[Category, list[Finding]],
) -> tuple[float, list[str]]:
    """Score static analysis as a severity-weighted penalty.

    Args:
        by_category: Findings grouped by category.

    Returns:
        The 0-100 value and its evidence lines.
    """
    findings = by_category.get(Category.STATIC_ANALYSIS, [])
    if not findings:
        return MAX_SCORE, ["Static analysis reported no findings."]

    penalty = sum(STATIC_ANALYSIS_PENALTIES[f.severity] for f in findings)
    counts = _severity_counts(findings)
    return MAX_SCORE - penalty, [
        f"{len(findings)} static analysis findings ({counts}) cost {penalty:.1f} points."
    ]


def _score_secrets(by_category: dict[Category, list[Finding]]) -> tuple[float, list[str]]:
    """Score secrets exposure.

    Args:
        by_category: Findings grouped by category.

    Returns:
        The 0-100 value and its evidence lines.
    """
    findings = by_category.get(Category.SECRET, [])
    if not findings:
        return SECRETS_NONE, ["No committed secrets were detected."]

    verified = [f for f in findings if f.verified]
    if verified:
        return SECRETS_VERIFIED, [
            f"{len(verified)} verified secret(s) detected. This dimension scores 0 "
            "and the composite is capped at 59."
        ]

    return SECRETS_UNVERIFIED, [
        f"{len(findings)} unverified secret(s) detected. Scored as a serious but "
        "unconfirmed exposure: no Phase 1 scanner tests a credential against its "
        "provider, so we do not claim these are live."
    ]


def _score_supply_chain(
    by_category: dict[Category, list[Finding]], ctx: ScoringContext
) -> tuple[float, list[str]]:
    """Score supply chain integrity from SLSA level, evidence, and misconfigurations.

    Half the dimension comes from the achieved SLSA build level and half from the
    proportion of supply chain evidence checks that passed. Misconfigurations then
    apply a bounded penalty — they matter, but they should not be able to erase a
    genuinely well-secured build pipeline.

    Args:
        by_category: Findings grouped by category.
        ctx: Deterministic non-finding inputs.

    Returns:
        The 0-100 value and its evidence lines.
    """
    evidence: list[str] = []

    if ctx.slsa is None:
        level_component = MIN_SCORE
        evidence_component = MIN_SCORE
        evidence.append("No SLSA assessment was produced.")
    else:
        level_component = (ctx.slsa.build_level / SLSA_MAX_LEVEL) * MAX_SCORE
        evidence.append(
            f"SLSA build level {ctx.slsa.build_level}/{SLSA_MAX_LEVEL} "
            f"contributes {level_component / 2:.0f} of 50."
        )

        checks = ctx.slsa.evidence
        if checks:
            passed = sum(1 for check in checks if check.passed)
            evidence_component = (passed / len(checks)) * MAX_SCORE
            evidence.append(
                f"{passed} of {len(checks)} supply chain evidence checks passed, "
                f"contributing {evidence_component / 2:.0f} of 50."
            )
        else:
            evidence_component = MIN_SCORE
            evidence.append("No supply chain evidence checks were recorded.")

    base = (level_component + evidence_component) / 2

    misconfigurations = by_category.get(Category.MISCONFIGURATION, [])
    penalty = min(
        sum(MISCONFIGURATION_PENALTIES[f.severity] for f in misconfigurations),
        MISCONFIGURATION_PENALTY_CAP,
    )
    if misconfigurations:
        evidence.append(
            f"{len(misconfigurations)} misconfiguration(s) cost {penalty:.1f} points "
            f"(capped at {MISCONFIGURATION_PENALTY_CAP:.0f})."
        )

    return base - penalty, evidence


def _score_sbom(ctx: ScoringContext) -> tuple[float, list[str]]:
    """Score SBOM health from resolution, license clarity, and staleness.

    Sub-metrics with no data are dropped and the remaining weights renormalized,
    for the same reason absent dimensions are excluded rather than zeroed.

    Args:
        ctx: Deterministic non-finding inputs.

    Returns:
        The 0-100 value and its evidence lines.
    """
    sbom = ctx.sbom
    if not sbom.generated:
        return MIN_SCORE, ["No SBOM could be generated. The composite is capped at 79."]
    if sbom.component_count == 0:
        return MIN_SCORE, ["The SBOM contains no components."]

    total = float(sbom.component_count)
    parts: list[tuple[float, float, str]] = [
        (
            SBOM_RESOLUTION_WEIGHT,
            1.0 - (sbom.unresolved_count / total),
            f"{sbom.unresolved_count} of {sbom.component_count} components unresolved",
        ),
        (
            SBOM_LICENSE_WEIGHT,
            1.0 - (sbom.license_unknown_count / total),
            f"{sbom.license_unknown_count} of {sbom.component_count} components "
            "without a clear license",
        ),
    ]

    # Staleness needs a network lookup against each ecosystem's registry. When it was
    # not measured, drop the sub-metric and renormalize rather than assuming every
    # component is current — that would silently inflate the dimension.
    if sbom.outdated_count is not None:
        parts.append(
            (
                SBOM_STALENESS_WEIGHT,
                1.0 - (sbom.outdated_count / total),
                f"{sbom.outdated_count} of {sbom.component_count} components outdated",
            )
        )

    total_weight = sum(weight for weight, _, _ in parts)
    value = sum(weight * max(0.0, ratio) for weight, ratio, _ in parts) / total_weight
    evidence = [f"{sbom.component_count} components cataloged."]
    evidence.extend(detail for _, _, detail in parts)
    if sbom.outdated_count is None:
        evidence.append("Component freshness was not measured; sub-metric excluded.")

    return value * MAX_SCORE, evidence


# --- Weight redistribution -----------------------------------------------------


def _redistribute_weights(dimensions: dict[DimensionKey, DimensionScore]) -> None:
    """Redistribute excluded dimensions' weights across the included ones.

    A project with no Go toolchain should not be marked down because a Go-specific
    scanner never ran. The remaining dimensions absorb the freed weight in
    proportion to their configured weights, so their relative importance is
    preserved.

    Args:
        dimensions: Dimension scores, mutated in place with effective weights.
    """
    included = [d for d in dimensions.values() if not d.excluded and d.configured_weight > 0]
    included_weight = sum(d.configured_weight for d in included)

    if not included or included_weight <= 0:
        return

    scale = 100.0 / included_weight
    for key, dimension in dimensions.items():
        if dimension.excluded or dimension.configured_weight <= 0:
            dimensions[key] = dimension.model_copy(update={"effective_weight": 0.0})
        else:
            dimensions[key] = dimension.model_copy(
                update={"effective_weight": round(dimension.configured_weight * scale, 6)}
            )


# --- Hard caps -----------------------------------------------------------------


def _evaluate_caps(
    by_category: dict[Category, list[Finding]], ctx: ScoringContext
) -> list[AppliedCap]:
    """Evaluate every hard cap, applied or not.

    All three are always reported so a reader can see which were considered, not
    only which fired.

    Args:
        by_category: Findings grouped by category.
        ctx: Deterministic non-finding inputs.

    Returns:
        The caps, in a fixed order.
    """
    verified = [f for f in by_category.get(Category.SECRET, []) if f.verified]
    exploited = [
        f
        for f in by_category.get(Category.VULNERABILITY, [])
        if f.severity is Severity.CRITICAL and has_known_exploit(f)
    ]

    return [
        AppliedCap(
            condition="Any verified, unrevoked secret in git history",
            capped_at=CAP_VERIFIED_SECRET,
            applied=bool(verified),
            detail=(
                f"{len(verified)} verified secret(s)."
                if verified
                else "No verified secrets were detected."
            ),
        ),
        AppliedCap(
            condition="Any critical vulnerability with a known public exploit",
            capped_at=CAP_EXPLOITED_CRITICAL,
            applied=bool(exploited),
            detail=(
                f"{len(exploited)} critical vulnerability/ies with published exploit evidence."
                if exploited
                else "No critical vulnerability carried exploit evidence from a scanner."
            ),
        ),
        AppliedCap(
            condition="No SBOM could be generated",
            capped_at=CAP_NO_SBOM,
            applied=not ctx.sbom.generated,
            detail=(
                f"SBOM generated with {ctx.sbom.component_count} components."
                if ctx.sbom.generated
                else "No SBOM was produced for this project."
            ),
        ),
    ]


def has_known_exploit(finding: Finding) -> bool:
    """Return whether a scanner supplied evidence of a public exploit.

    Deliberately evidence-based. Absence of evidence is not evidence of exploitation,
    so a vulnerability we simply know nothing about does not trigger the cap. Claiming
    otherwise would make the cap fire on almost every critical CVE and render it
    meaningless.

    Args:
        finding: The finding to inspect.

    Returns:
        True only when the scanner's own output marks it as known-exploited.
    """
    for key, value in finding.raw.items():
        normalized = key.lower().replace("-", "_")
        if any(marker in normalized for marker in _KEV_MARKERS) and value:
            return True

    database = finding.raw.get("database_specific")
    if isinstance(database, dict):
        for key, value in database.items():
            normalized = key.lower().replace("-", "_")
            if any(marker in normalized for marker in _KEV_MARKERS) and value:
                return True

    return any(
        marker in reference.lower()
        for reference in finding.references
        for marker in _EXPLOIT_URL_MARKERS
    )


# --- Helpers -------------------------------------------------------------------


def _group_by_category(findings: Sequence[Finding]) -> dict[Category, list[Finding]]:
    """Group findings by category, preserving canonical order within each group.

    Args:
        findings: Findings already in canonical order.

    Returns:
        Category to findings.
    """
    grouped: dict[Category, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.category, []).append(finding)
    return grouped


def _severity_counts(findings: Sequence[Finding]) -> str:
    """Render a severity breakdown for an evidence line.

    Args:
        findings: Findings to summarize.

    Returns:
        A string like ``"2 critical, 5 high"``, in fixed severity order.
    """
    counts: dict[Severity, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: item[0].rank)
    return ", ".join(f"{count} {severity.value}" for severity, count in ordered)


def _clamp(value: float) -> float:
    """Constrain a dimension value to 0-100.

    Args:
        value: The raw computed value.

    Returns:
        The value clamped into range, rounded to 4 decimal places for stable
        serialization across platforms.
    """
    return round(max(MIN_SCORE, min(MAX_SCORE, value)), 4)


def _round_half_up(value: float) -> int:
    """Round to the nearest integer, halves upward.

    Python's built-in ``round`` uses banker's rounding, which would send 84.5 to 84
    and 85.5 to 86. The published methodology says half-up, so this uses ``Decimal``
    to do exactly that.

    Args:
        value: The weighted mean.

    Returns:
        The rounded composite score.
    """
    return int(Decimal(str(value)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
