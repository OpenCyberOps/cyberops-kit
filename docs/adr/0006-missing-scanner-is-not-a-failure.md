# ADR 0006 — Exclude dimensions without data; never score them zero

**Status:** Accepted

## Context

Six weighted dimensions produce the composite score. On any given run, some may
have no data: the scanner is not installed, it was skipped under `--offline`, it
timed out, or it does not apply to the detected stack.

The naive implementation scores a missing dimension as 0. It is simple, and it
produces a number every time.

It is also dishonest. It reports a project as insecure when the truth is that we did
not look. It punishes projects for our tooling gaps and for the user's install
choices, and it makes the score depend on the machine it ran on.

## Decision

Three layers:

**1. Exclusion with redistribution.** A dimension with no data is excluded. Its
weight is redistributed proportionally across the dimensions that do have data, so
their relative importance is preserved. The exclusion and its reason appear in every
report.

**2. Coverage reporting.** Every score carries `coverage` — the fraction of
configured weight that had data.

**3. A meaningfulness floor.** Below 50% coverage, the run is marked
`sufficient_coverage: false`. The CLI prints `NOT SCORED` instead of a grade, the
badge reads `not scored` in grey, the reports lead with the coverage warning, and
`--fail-below` does not fail the build. The composite is still computed and recorded
in the JSON — nothing is hidden — it is simply not presented as a grade.

Severity thresholds (`--fail-on-severity`) still apply at any coverage. A finding is
a finding regardless of how much else we managed to measure.

## Consequences

**Good:**

- A `pip install` user with two scanners gets an honest partial assessment instead of
  a fake F.
- The score is comparable across runs, because coverage is visible when it is not.
- Nobody can be misled by a badge produced on a machine with no scanners installed.

**Bad, and accepted:**

- Two runs of the same commit can produce different composites if different scanners
  were available. `coverage` and `run_metadata.tool_versions` make that traceable,
  but it is still a real limitation on comparability.
- The 50% threshold is a judgment call. It is documented in
  `docs/methodology/scoring.md` and versioned with `SCORING_MODEL_VERSION`.
- "Not scored" is a worse product demo than a confident letter grade. We would rather
  show nothing than show something wrong.
