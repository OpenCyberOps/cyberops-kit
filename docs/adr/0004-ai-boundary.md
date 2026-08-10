# ADR 0004 — The AI layer annotates; it never grades

**Status:** Accepted

## Context

Phase 2 adds an optional AI advisory layer for two things: triage (is this finding
genuinely exploitable in this codebase?) and remediation drafting.

Both are genuinely useful. A maintainer facing 200 alerts with no prioritization
signal typically ignores all 200.

Both are also the obvious way to destroy this project's credibility. The moment a
non-deterministic model influences a security score, the score stops being
reproducible, stops being auditable, and stops being defensible to an auditor. "The
AI thought it was fine" is not a security finding.

## Decision

**The AI layer annotates. It never grades.**

| The deterministic core does | The AI layer does |
|---|---|
| Detect findings | Explain findings |
| Assign severity | Suggest a fix |
| Compute the score | — |
| Determine pass/fail | — |

Concretely, the AI layer must never feed a value into `compute_score()`, change
`Finding.severity` or any other core field, add or remove findings, determine CI exit
codes, or be required for any core feature to work.

This boundary is enforced structurally, in Phase 1, before any AI code exists:

- `Advisory` is a separate frozen model on a single reserved field (SEAM-1)
- `Finding` is frozen, so an enricher cannot mutate one in place
- The enrichment stage verifies at runtime that only `advisory` changed (SEAM-2)
- `tests/invariants/test_score_is_advisory_invariant.py` asserts byte-identical
  scores with and without advisory data, across every assessment/confidence
  combination (SEAM-6)
- A static AST check asserts `scoring.py` never even *reads* `.advisory`
- SARIF confines advisory content to the `properties` bag, never `level`, `ruleId`,
  `kind`, or `rank`

The acceptance test is blunt: **deleting `advisors/` entirely must leave the score,
the grade, the SARIF output, and the CI exit code bit-for-bit identical.**

Additional safeguards: off by default, hard-disabled by `--offline`, every outbound
payload through `redact()` with no bypass, labeled distinctly in all five output
formats, and budget-capped.

## Consequences

**Good:**

- The score remains reproducible and auditable no matter what the AI layer does.
- Users who distrust LLMs lose nothing; users who want triage get it.
- Phase 2 adds files rather than modifying the pipeline, because the seams exist.

**Bad, and accepted:**

- The AI layer is strictly less useful than one allowed to suppress false positives.
  Someone will ask for auto-suppression. The answer is no.
- Maintaining the boundary costs test surface and review attention forever.
- Advisory output can be wrong and still be displayed. Mitigated by labeling it as
  advisory everywhere, publishing eval results including weaknesses, and forbidding
  the prompt from asserting a finding is safe to ignore.
