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
    """The Phase 1 SEAM-3 fields are all present. Phase 2 needs no migration for them.

    ``timeout_seconds`` is not in this set: it did not exist when SEAM-3 was
    designed, and adding a new Phase-2-only field to a settings block that has
    always been "reserved for Phase 2" is not the schema migration this seam
    promises to avoid. This test guards the fields Phase 1 fixed; it does not
    freeze the block against every future addition.
    """
    assert {"enabled", "provider", "model", "max_findings", "redact"}.issubset(
        set(AISettings.model_fields)
    )


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


ADVISORS = Path("src/cyberops_kit/advisors")

advisory_layer_present = pytest.mark.skipif(
    not ADVISORS.is_dir(),
    reason="advisory layer not installed; its absence is the Phase 2 acceptance case",
)
"""Skip, never fail, when ``advisors/`` is gone.

Deleting the advisory layer must leave this suite green. A test that asserts
something *about* that layer therefore cannot fail when it is absent — it has
nothing to check. The two tests below this marker are the ones that constrain the
core regardless, and they stay active either way.
"""


@advisory_layer_present
def test_advisors_package_exists_with_its_boundary_documented():
    """``advisors/`` still documents the boundary it must respect.

    Through Phase 1 this test asserted the package was *empty*. That guard did its
    job — it would have caught Phase 2 code landing early — and Phase 2 retires it,
    replacing it with the checks below, which are strictly stronger: an empty
    directory trivially respects the boundary, whereas a populated one has to be
    shown to.
    """
    assert (ADVISORS / "__init__.py").is_file()
    assert (ADVISORS / "README.md").is_file()


@advisory_layer_present
def test_importing_the_advisors_package_registers_nothing():
    """Importing must never arm an outbound path.

    "Off by default" is worth nothing if merely importing ``cyberops_kit.advisors``
    puts an enricher in the registry. Registration is an explicit call that only
    ``cli.py`` makes, and only when the user passed ``--ai-triage``.
    """
    import importlib

    from cyberops_kit.core.enrichment import ENRICHERS, clear_registry

    clear_registry()
    try:
        importlib.import_module("cyberops_kit.advisors")
        importlib.import_module("cyberops_kit.advisors.triage")
        assert ENRICHERS == []
    finally:
        clear_registry()


@advisory_layer_present
def test_the_advisory_layer_never_reaches_scoring():
    """No module under ``advisors/`` may import or call the scoring machinery.

    The AST check in ``test_score_is_advisory_invariant`` guards the other
    direction — that ``scoring.py`` never reads ``.advisory``. This guards this one:
    that no advisor ever calls ``compute_score``. Together they close the loop that
    ADR 0004 describes, from both ends.
    """
    import ast

    offenders: list[str] = []
    for path in Path("src/cyberops_kit/advisors").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "cyberops_kit.core.scoring":
                offenders.append(f"{path}: imports from core.scoring")
            if isinstance(node, ast.Name) and node.id == "compute_score":
                offenders.append(f"{path}: references compute_score")

    assert not offenders, f"the advisory layer reached scoring (INV-2): {offenders}"


def test_deleting_the_advisory_layer_leaves_the_core_importable():
    """The Phase 2 acceptance test, in the form a test can express.

    The full version — `rm -rf advisors/ && make test` — is a CI job, not a unit
    test. What is checkable here is the property that makes it pass: nothing outside
    ``advisors/`` imports it at module scope, so removing the package cannot break
    an import anywhere in the core, the scanners, or the reporters.
    """
    import ast

    offenders: list[str] = []
    source_root = Path("src/cyberops_kit")
    for path in source_root.rglob("*.py"):
        if "advisors" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            if not node.module.startswith("cyberops_kit.advisors"):
                continue
            # A deferred import inside a function is fine: it runs only when the
            # feature is switched on, and `cli.py` guards it behind ai.enabled.
            if node.col_offset == 0:
                offenders.append(f"{path.relative_to(source_root)}:{node.lineno}")

    assert not offenders, f"core code imports the advisory layer at module scope: {offenders}"
