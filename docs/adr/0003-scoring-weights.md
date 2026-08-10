# ADR 0003 — The six dimensions and their weights

**Status:** Accepted

## Context

A composite score needs dimensions and weights. Any choice is arguable, and the
argument recurs constantly ("why is Scorecard worth more than SAST?"). Without a
recorded rationale, the weights drift toward whatever the last complainant wanted.

## Decision

Six dimensions, weighted as follows:

| Dimension | Weight | Why this weight |
|---|---|---|
| `openssf_scorecard` | 25 | Process hygiene predicts future posture better than any point-in-time scan. A project with branch protection and signed releases will be more secure next quarter than one without, regardless of today's CVE count. |
| `known_vulnerabilities` | 25 | The most concrete, least arguable signal. A known CVE in a shipped dependency is a real, exploitable risk today. |
| `supply_chain_integrity` | 20 | Where the industry is heading and where most projects are weakest. High enough to matter, not so high that a project without provenance is unsalvageable. |
| `static_analysis` | 15 | Genuinely useful but noisiest. Weighted below vulnerabilities because SAST false positives are common. |
| `secrets_exposure` | 10 | Low weight because the hard cap does the real work: a verified secret caps the composite at 59 regardless of this dimension. |
| `sbom_health` | 5 | A hygiene signal, not a vulnerability. Low weight, plus a cap at 79 when no SBOM can be generated at all. |

Penalty tables, hard caps, and grade bands are published in full in
`docs/methodology/scoring.md`.

Note the deliberate asymmetry: **static analysis is penalized more lightly than
known vulnerabilities** (8 points per high vs 10, 2 vs 3 for medium). Over-penalizing
SAST pushes maintainers to disable the scanner, which makes a project less secure,
not more. A scoring model that incentivizes turning off tools has failed.

## Consequences

**Good:**

- The weights are defensible in public, with a stated reason for each.
- Hard caps handle the "severe finding masked by a good average" case, so the weights
  do not have to be distorted to compensate.
- Changing them requires an ADR update, a methodology doc update, and a
  `SCORING_MODEL_VERSION` bump in the same commit (INV-7).

**Bad, and accepted:**

- Scorecard dominates for clean repositories. At 25 points on a project with no
  vulnerabilities and no secrets, process hygiene drives most of the composite. This
  is intentional but means a well-run repo with an unpatched CVE can outscore a quiet
  clean one. Documented as a known limitation.
- The weights are not empirically validated against breach outcomes. Nobody's are.
  We do not claim otherwise.
- Users can override weights in `.cyberops.yml`, so cross-project comparison requires
  checking whether defaults were used. Reports state the weights when they are
  non-default.

**Never:** scoring is not rewritten to improve the score of any specific repository,
including our own.
