"""All six Phase 2 seams exist, are wired, and are dormant in Phase 1.

Skipping a seam is what causes a rewrite later, and a seam that is "present" but not
actually called by the pipeline is worse than no seam at all — it looks done. These
tests assert the seams are load-bearing, not decorative.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from cyberops_kit.config import AISettings, Settings
from cyberops_kit.core import enrichment
from cyberops_kit.core.enrichment import ENRICHERS, Enricher, run_enrichment
from cyberops_kit.core.errors import EnrichmentContractError
from cyberops_kit.core.models import Finding, Severity
from cyberops_kit.report.sarif import render_sarif
from cyberops_kit.report.writer import render
from tests.conftest import make_finding, make_report

# --- SEAM-1: reserved advisory field -------------------------------------------


def test_seam_1_advisory_field_exists_and_defaults_to_none():
    """``Finding.advisory`` exists, is optional, and is None in Phase 1."""
    assert "advisory" in Finding.model_fields
    assert make_finding().advisory is None


def test_seam_1_advisory_survives_a_json_round_trip(advisory):
    """A populated advisory round-trips, so Phase 2 needs no schema change."""
    annotated = make_finding().model_copy(update={"advisory": advisory})
    restored = Finding.model_validate_json(annotated.model_dump_json())
    assert restored.advisory == advisory


# --- SEAM-2: enrich stage -------------------------------------------------------


def test_seam_2_registry_is_empty_in_phase_one():
    """No enrichers are registered in Phase 1."""
    assert ENRICHERS == []


async def test_seam_2_enrichment_is_a_passthrough(sample_findings, run_context):
    """With an empty registry, enrichment returns its input unchanged."""
    result = await run_enrichment(sample_findings, run_context)
    assert result == sample_findings


def test_seam_2_orchestrator_calls_enrichment_between_normalize_and_score():
    """The pipeline actually invokes the stage, in the right place.

    A seam nothing calls is not a seam.
    """
    from cyberops_kit.core import orchestrator

    source = Path(inspect.getfile(orchestrator)).read_text(encoding="utf-8")
    assert "run_enrichment(" in source

    normalize_at = source.index("findings = normalize(")
    enrich_at = source.index("await run_enrichment(")
    score_at = source.index("compute_score(")

    assert normalize_at < enrich_at < score_at


async def test_seam_2_enricher_may_only_populate_advisory(sample_findings, run_context, advisory):
    """An enricher that touches any other field aborts the run."""

    class BadEnricher(Enricher):
        name = "bad"
        version = "1.0.0"

        def applies_to(self, finding: Finding) -> bool:
            return True

        async def enrich(self, findings, ctx):
            return [f.model_copy(update={"severity": Severity.INFO}) for f in findings]

    enrichment.register(BadEnricher())
    try:
        with pytest.raises(EnrichmentContractError, match="modified non-advisory field"):
            await run_enrichment(sample_findings, run_context)
    finally:
        enrichment.clear_registry()


async def test_seam_2_enricher_may_not_drop_findings(sample_findings, run_context):
    """Suppressing a finding is a contract breach."""

    class DroppingEnricher(Enricher):
        name = "dropper"
        version = "1.0.0"

        def applies_to(self, finding: Finding) -> bool:
            return True

        async def enrich(self, findings, ctx):
            return findings[:-1]

    enrichment.register(DroppingEnricher())
    try:
        with pytest.raises(EnrichmentContractError, match="changed the finding count"):
            await run_enrichment(sample_findings, run_context)
    finally:
        enrichment.clear_registry()


async def test_seam_2_a_well_behaved_enricher_is_accepted(sample_findings, run_context, advisory):
    """Populating only ``advisory`` is allowed — this is what Phase 2 will do."""

    class GoodEnricher(Enricher):
        name = "good"
        version = "1.0.0"

        def applies_to(self, finding: Finding) -> bool:
            return True

        async def enrich(self, findings, ctx):
            return [f.model_copy(update={"advisory": advisory}) for f in findings]

    enrichment.register(GoodEnricher())
    try:
        result = await run_enrichment(sample_findings, run_context)
        assert all(f.advisory is not None for f in result)
        assert [f.id for f in result] == [f.id for f in sample_findings]
    finally:
        enrichment.clear_registry()


# --- SEAM-3: reserved ai config block -------------------------------------------


def test_seam_3_ai_block_exists_and_is_disabled_by_default():
    """The ``ai`` block ships in Phase 1, defaulting to disabled."""
    settings = Settings()
    assert settings.ai.enabled is False
    assert settings.ai.provider is None
    assert settings.ai.model is None
    assert settings.ai.max_findings == 25
    assert settings.ai.redact is True


def test_seam_3_ai_block_has_the_specified_shape():
    """No key is missing, so Phase 2 needs no config migration."""
    assert set(AISettings.model_fields) == {
        "enabled",
        "provider",
        "model",
        "max_findings",
        "redact",
    }


# --- SEAM-4: dormant report templates -------------------------------------------


@pytest.mark.parametrize("fmt", ["markdown", "html"])
def test_seam_4_advisory_block_is_absent_when_dormant(fmt, sample_findings):
    """With no advisory data, no advisory *content* is emitted.

    The HTML stylesheet legitimately carries the ``.advisory`` rules in Phase 1 —
    that is the seam. What must be absent is the rendered block itself.
    """
    output = render(make_report(sample_findings), fmt)

    assert "AI advisory — not part of the score" not in output
    assert 'data-generated="ai"' not in output
    assert '<aside class="advisory"' not in output


@pytest.mark.parametrize("fmt", ["markdown", "html"])
def test_seam_4_advisory_block_renders_when_populated(fmt, sample_findings, advisory):
    """The same templates render advisory content the moment data appears."""
    annotated = [f.model_copy(update={"advisory": advisory}) for f in sample_findings]
    output = render(make_report(annotated), fmt)

    assert "AI advisory — not part of the score" in output
    assert advisory.rationale in output
    assert advisory.confidence in output


def test_seam_4_advisory_css_class_ships_in_phase_one():
    """The ``.advisory`` class and its treatment exist before Phase 2."""
    template = Path("src/cyberops_kit/report/templates/report.html.j2").read_text(encoding="utf-8")
    assert ".advisory" in template
    assert ".advisory-label" in template
    assert 'class="advisory"' in template


def test_seam_4_sarif_confines_advisory_to_the_properties_bag(sample_findings, advisory):
    """Advisory content never touches level, ruleId, kind, or rank.

    Those four drive GitHub's Security tab and must stay deterministic.
    """
    baseline = render_sarif(make_report(sample_findings))
    annotated = [f.model_copy(update={"advisory": advisory}) for f in sample_findings]
    with_advisory = render_sarif(make_report(annotated))

    baseline_results = baseline["runs"][0]["results"]
    advisory_results = with_advisory["runs"][0]["results"]

    for before, after in zip(baseline_results, advisory_results, strict=True):
        for field in ("level", "ruleId", "ruleIndex", "kind"):
            assert before[field] == after[field]
        assert "rank" not in after
        assert after["properties"]["advisory"]["rationale"] == advisory.rationale
        assert "not part of the score" in after["properties"]["advisory"]["disclaimer"]


# --- SEAM-5: redaction boundary -------------------------------------------------


def test_seam_5_redact_has_the_specified_signature():
    """``redact(payload, findings)`` exists as specified, ready for Phase 2's client."""
    from cyberops_kit.core.redaction import redact

    parameters = list(inspect.signature(redact).parameters)
    assert parameters == ["payload", "findings"]


# --- SEAM-6: score isolation test -----------------------------------------------


def test_seam_6_isolation_test_exists():
    """The INV-2 enforcement test is present and named as specified."""
    path = Path("tests/invariants/test_score_is_advisory_invariant.py")
    assert path.is_file()
    assert "def test_score_is_advisory_invariant(" in path.read_text(encoding="utf-8")


# --- The Phase 2 acceptance test ------------------------------------------------


def test_advisors_package_is_reserved_and_empty():
    """``advisors/`` exists with a README and no implementation."""
    package = Path("src/cyberops_kit/advisors")
    assert (package / "__init__.py").is_file()
    assert (package / "README.md").is_file()

    modules = [p.name for p in package.glob("*.py") if p.name != "__init__.py"]
    assert modules == [], f"Phase 2 code appeared in advisors/ during Phase 1: {modules}"
