"""INV-2 / SEAM-6 — AI output never influences the score.

The AI advisory layer annotates. It does not grade, re-rank severity, suppress
findings, or feed any value into scoring.

This test is the enforcement mechanism for INV-2. It fails loudly the first time
anyone wires advisory data into scoring. **Extend it, never relax it.**
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cyberops_kit.config import DEFAULT_WEIGHTS
from cyberops_kit.core.models import Advisory, Finding
from cyberops_kit.core.scoring import compute_score

ASSESSMENTS = ("likely_exploitable", "likely_false_positive", "unclear")
CONFIDENCES = ("low", "medium", "high")


def make_fake_advisory(
    assessment: str = "likely_false_positive", confidence: str = "high"
) -> Advisory:
    """Build an advisory for isolation testing."""
    return Advisory(
        enricher="llm-triage",
        enricher_version="1.0.0",
        assessment=assessment,
        rationale="Synthetic rationale used to prove scoring ignores this field.",
        confidence=confidence,
        remediation="Synthetic remediation.",
        evidence_refs=["src/app.py:1"],
        generated_at=datetime(2026, 6, 1, tzinfo=UTC),
        provider="anthropic",
        model_id="claude-opus-5",
        prompt_version="triage.v1",
    )


def test_score_is_advisory_invariant(sample_findings, full_context):
    """The canonical SEAM-6 test: annotating findings cannot move the score."""
    baseline = compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)
    annotated = [f.model_copy(update={"advisory": make_fake_advisory()}) for f in sample_findings]

    assert compute_score(annotated, DEFAULT_WEIGHTS, context=full_context) == baseline


def test_score_bytes_are_identical_with_and_without_advisory(sample_findings, full_context):
    """Byte equality, not just object equality."""
    baseline = compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)
    annotated = [f.model_copy(update={"advisory": make_fake_advisory()}) for f in sample_findings]
    result = compute_score(annotated, DEFAULT_WEIGHTS, context=full_context)

    assert result.model_dump_json() == baseline.model_dump_json()


@pytest.mark.parametrize("assessment", ASSESSMENTS)
@pytest.mark.parametrize("confidence", CONFIDENCES)
def test_every_advisory_combination_is_inert(assessment, confidence, sample_findings, full_context):
    """No combination of assessment and confidence changes anything.

    A "likely_exploitable / high" advisory must not raise the penalty, and a
    "likely_false_positive / high" must not suppress it. Both would be a grading
    decision, which the AI layer is never allowed to make.
    """
    baseline = compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)
    annotated = [
        f.model_copy(update={"advisory": make_fake_advisory(assessment, confidence)})
        for f in sample_findings
    ]

    assert (
        compute_score(annotated, DEFAULT_WEIGHTS, context=full_context).model_dump_json()
        == baseline.model_dump_json()
    )


def test_partial_annotation_is_inert(sample_findings, full_context):
    """Annotating only some findings is equally inert."""
    baseline = compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)
    annotated = [
        f.model_copy(update={"advisory": make_fake_advisory()}) if index % 2 == 0 else f
        for index, f in enumerate(sample_findings)
    ]

    assert (
        compute_score(annotated, DEFAULT_WEIGHTS, context=full_context).model_dump_json()
        == baseline.model_dump_json()
    )


def test_scoring_source_never_references_the_advisory_field():
    """Static guard: scoring.py must never access ``.advisory``.

    A behavioral test can only catch advisory data that *changes* the output. This
    catches the moment someone reads the field at all, which is the actual line INV-2
    draws. The check walks the AST rather than the text, so the invariant can be
    discussed freely in docstrings and comments without tripping it.
    """
    import ast
    from pathlib import Path

    import cyberops_kit.core.scoring as scoring_module

    tree = ast.parse(Path(scoring_module.__file__).read_text(encoding="utf-8"))

    attribute_reads = [
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "advisory"
    ]
    name_reads = [
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "advisory"
    ]

    assert not attribute_reads, "scoring.py accesses Finding.advisory (INV-2)"
    assert not name_reads, "scoring.py binds a name 'advisory' (INV-2)"


def test_advisory_defaults_to_none_in_phase_one():
    """A Phase 1 finding serializes ``advisory`` as null.

    Consumers written against Phase 1 output keep working unchanged in Phase 2 — no
    schema version bump, no migration (SEAM-1).
    """
    from tests.conftest import make_finding

    finding = make_finding()
    assert finding.advisory is None
    assert '"advisory":null' in finding.model_dump_json().replace(" ", "")


def test_advisory_model_is_fully_specified_in_phase_one():
    """The Advisory model exists and is complete before any AI code is written."""
    fields = set(Advisory.model_fields)
    assert fields == {
        "enricher",
        "enricher_version",
        "assessment",
        "rationale",
        "confidence",
        "remediation",
        "evidence_refs",
        "generated_at",
        "provider",
        "model_id",
        "prompt_version",
    }
    assert Advisory.model_config.get("frozen") is True
    assert "advisory" in Finding.model_fields
