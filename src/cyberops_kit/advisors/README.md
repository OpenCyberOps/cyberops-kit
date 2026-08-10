# `advisors/` — reserved for Phase 2

This package is **intentionally empty in Phase 1**. It is not dead code and it is
not an oversight. Do not delete it — see [ADR 0004](../../../docs/adr/0004-ai-boundary.md).

## Why it exists now

Phase 2 adds an optional AI advisory layer that explains findings and drafts
remediations. That layer is designed to be **additive**: it creates files here and
registers an enricher, without modifying `core/models.py`, `core/scoring.py`, the
report templates, the config schema, or the CLI surface.

The seams that make that possible are built in Phase 1:

| Seam | Where | Phase 2 action |
|---|---|---|
| SEAM-1 `Advisory` model | `core/models.py` | Populate it. No schema change. |
| SEAM-2 `enrich` stage | `core/enrichment.py` | Register an enricher here. |
| SEAM-3 `ai` config block | `config.py` | Flip defaults on. No migration. |
| SEAM-4 template blocks | `report/templates/` | Nothing — they activate when data appears. |
| SEAM-5 redaction | `core/redaction.py` | Route LLM payloads through `redact()`. |
| SEAM-6 isolation test | `tests/invariants/` | Extend with real advisory fixtures. |

## The boundary this package must respect

**The AI layer annotates. It never grades.**

| The deterministic core does | The AI layer does |
|---|---|
| Detect findings | Explain findings |
| Assign severity | Suggest a fix |
| Compute the score | — |
| Determine pass/fail | — |

Code in this package must never feed a value into `compute_score()`, change
`Finding.severity` or any other core field, add or remove findings, determine CI
exit codes, or become required for any core feature to work.

`tests/invariants/test_score_is_advisory_invariant.py` enforces this today, against
the empty registry. It will keep enforcing it against real advisories.

## The acceptance test for Phase 2

Deleting this directory entirely must leave the test suite green, with the score,
the grade, the SARIF output, and the CI exit code bit-for-bit identical.
