"""INV-3 — reproducibility.

The same commit SHA, the same tool versions, and the same config must produce a
byte-identical ``results`` block. Nondeterministic values live only in the separate
``run_metadata`` block. Never mix them.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from cyberops_kit.core.models import Results, RunMetadata
from tests.conftest import make_report

NONDETERMINISTIC_FIELD_MARKERS = (
    "started_at",
    "completed_at",
    "duration",
    "timestamp",
    "hostname",
    "host",
    "run_id",
    "elapsed",
)


def test_results_block_is_byte_identical_across_runs(sample_findings):
    """Two runs over the same input serialize the results block identically."""
    first = make_report(sample_findings)
    second = make_report(sample_findings)

    assert first.results.model_dump_json(indent=2) == second.results.model_dump_json(indent=2)


def test_results_block_excludes_every_nondeterministic_field():
    """No timestamp, duration, hostname, or run ID may appear in ``results``."""
    offending = [
        name
        for name in Results.model_fields
        if any(marker in name.lower() for marker in NONDETERMINISTIC_FIELD_MARKERS)
    ]
    assert not offending, f"nondeterministic fields leaked into Results (INV-3): {offending}"


def test_run_metadata_owns_the_nondeterministic_values():
    """The fields excluded from ``results`` are present in ``run_metadata``."""
    fields = set(RunMetadata.model_fields)
    assert {"started_at", "completed_at", "duration_seconds", "run_id", "host"} <= fields


def test_results_serialization_is_stable_under_input_reordering(sample_findings):
    """Findings arriving in a different order serialize identically."""
    forward = make_report(sample_findings)
    backward = make_report(list(reversed(sample_findings)))

    assert forward.results.model_dump_json() == backward.results.model_dump_json()


def test_findings_are_canonically_ordered_at_the_envelope_boundary(sample_findings):
    """The envelope enforces canonical order regardless of what it was handed."""
    report = make_report(list(reversed(sample_findings)))
    ordered = report.results.findings

    keys = [(f.severity.rank, f.category.value, f.id) for f in ordered]
    assert keys == sorted(keys)


def test_run_metadata_differs_while_results_do_not(sample_findings):
    """Metadata is allowed to differ; results are not."""
    first = make_report(sample_findings)
    second = first.model_copy(
        update={
            "run_metadata": first.run_metadata.model_copy(
                update={
                    "run_id": "different-run",
                    "started_at": datetime(2030, 1, 1, tzinfo=UTC),
                    "duration_seconds": 999.0,
                    "host": "another-machine",
                }
            )
        }
    )

    assert first.results.model_dump_json() == second.results.model_dump_json()
    assert first.run_metadata.model_dump_json() != second.run_metadata.model_dump_json()


def test_full_report_json_separates_the_two_blocks(sample_findings):
    """The serialized envelope has exactly the two top-level blocks."""
    payload = json.loads(make_report(sample_findings).model_dump_json())
    assert set(payload) == {"results", "run_metadata"}
