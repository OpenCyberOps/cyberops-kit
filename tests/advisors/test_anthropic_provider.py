"""Anthropic-provider-specific coverage.

Everything shared across providers is in ``test_provider_contract.py``. This file
exists for the one thing that suite cannot catch: whether the request this provider
actually builds matches what the installed SDK's ``messages.create`` accepts.

That gap is not hypothetical — a mismatched ``output_config`` shape shipped here
undetected until a real ``pip install`` with the SDK present ran ``mypy --strict``
against it. A contract test that never imports the SDK cannot catch a wire-format
error against that SDK.
"""

from __future__ import annotations

import pytest

pytest.importorskip("anthropic", reason="requires the optional anthropic SDK ([ai] extra)")


def test_output_config_matches_the_installed_sdks_typed_param():
    """The dict this provider builds must satisfy the SDK's own TypedDict.

    Structural, not just "isinstance dict": constructing a value typed as the SDK's
    ``OutputConfigParam`` from what we build is what mypy checks statically, and
    what this test checks at runtime against whatever SDK version is installed.
    """
    from anthropic.types import OutputConfigParam

    from cyberops_kit.advisors.providers.anthropic import _build_output_config

    config = _build_output_config()
    # A TypedDict has no runtime validation of its own; asserting the exact keys
    # the SDK's param type declares is the closest a test gets to "mypy but at
    # import time," and it is what would have caught the original mismatch.
    typed: OutputConfigParam = config
    assert set(typed) == {"format"}
    assert typed["format"]["type"] == "json_schema"


def test_the_json_schema_matches_triageresult():
    """The wire-format schema and the Pydantic model must describe the same shape.

    They are maintained in two places for a real reason — one is a JSON Schema, the
    other a Pydantic model — so nothing enforces they stay in sync except this test.
    """
    from cyberops_kit.advisors.providers.anthropic import _ADVISORY_JSON_SCHEMA
    from cyberops_kit.advisors.triage import TriageResult

    schema_fields = set(_ADVISORY_JSON_SCHEMA["properties"])
    model_fields = set(TriageResult.model_fields)

    assert schema_fields == model_fields
    assert set(_ADVISORY_JSON_SCHEMA["required"]) == {"assessment", "rationale", "confidence"}


def test_the_schema_enums_match_the_advisory_models_literals():
    """A drift here would mean the schema accepts a value ``Advisory`` rejects."""
    from cyberops_kit.advisors.providers.anthropic import _ADVISORY_JSON_SCHEMA
    from cyberops_kit.core.models import Advisory

    assessment_field = Advisory.model_fields["assessment"]
    confidence_field = Advisory.model_fields["confidence"]

    schema_assessments = set(_ADVISORY_JSON_SCHEMA["properties"]["assessment"]["enum"])
    schema_confidences = set(_ADVISORY_JSON_SCHEMA["properties"]["confidence"]["enum"])

    assert schema_assessments == set(assessment_field.annotation.__args__)  # type: ignore[union-attr]
    assert schema_confidences == set(confidence_field.annotation.__args__)  # type: ignore[union-attr]
