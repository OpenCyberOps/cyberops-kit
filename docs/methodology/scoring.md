# Scoring methodology

**`SCORING_MODEL_VERSION = 1.0.0`**

This document is the authoritative, public description of how CyberOps Kit computes
a score. It is maintained under INV-7: any change to scoring behavior updates this
document *in the same commit* and bumps `SCORING_MODEL_VERSION`.

A security score nobody can audit is worthless. Everything below is implemented in
[`src/cyberops_kit/core/scoring.py`](../../src/cyberops_kit/core/scoring.py), and
the numbers here are the numbers in the code.

---

## Guarantees

**Deterministic (INV-1).** `compute_score()` is a pure function of deterministic
scanner findings and the configured weights. It does not read the clock, call the
network, consult the environment, use randomness, or depend on dict or set
iteration order. Findings are sorted by `(severity, category, id)` before any
aggregation.

**Never influenced by AI (INV-2).** `compute_score()` never reads
`Finding.advisory`. Computing the score with and without advisory data populated
yields byte-identical output, enforced by
`tests/invariants/test_score_is_advisory_invariant.py`.

**Reproducible (INV-3).** The same commit SHA, the same tool versions, and the same
config produce a byte-identical `results` block. A change in a scanner's version is
a legitimate reason for a score to move, which is why every tool version is recorded
in `run_metadata.tool_versions`.

---

## The formula

Each of six dimensions is normalized to 0–100, then combined as a weighted mean:

```
composite = round_half_up( Σ (dimension_value × effective_weight) / 100 )
```

Then any triggered hard cap is applied:

```
composite = min(composite, *[cap.capped_at for cap in caps if cap.applied])
```

Rounding is **half-up**, not Python's default banker's rounding. `84.5` scores `85`.

### Weights

| Dimension | Default weight |
|---|---|
| `openssf_scorecard` | 25 |
| `known_vulnerabilities` | 25 |
| `supply_chain_integrity` | 20 |
| `static_analysis` | 15 |
| `secrets_exposure` | 10 |
| `sbom_health` | 5 |

Weights are configurable in `.cyberops.yml`. A report generated with non-default
weights states them.

### Grade bands

| Composite | Grade |
|---|---|
| ≥ 90 | A |
| ≥ 80 | B |
| ≥ 70 | C |
| ≥ 60 | D |
| < 60 | F |

---

## Excluded dimensions

**A missing scanner is never scored as zero.** If a scanner did not run — not
installed, skipped under `--offline`, timed out, or not applicable to the detected
stack — its dimension is *excluded*. Its weight is redistributed proportionally
across the dimensions that do have data, and the exclusion is stated explicitly in
every report.

For example, with Scorecard unavailable, its 25 points are redistributed across the
remaining 75 points of weight, each scaled by `100/75`. `known_vulnerabilities`
becomes an effective 33.3 rather than 25.

Scoring an absent scanner as a failure would be dishonest, and would punish projects
for our tooling gaps rather than for their security posture.

### Coverage, and when there is no grade at all

Redistribution keeps a partial run honest in *relative* terms, but it cannot
manufacture information. If only one dimension has data, the composite is derived
entirely from that dimension — and presenting it as a grade comparable to a full run
would overstate what was measured.

Every score therefore reports **coverage**: the fraction of configured weight that
had data.

```
coverage = Σ configured_weight(included) / Σ configured_weight(all)
```

When `coverage < 0.5`, the run is marked `sufficient_coverage: false` and:

- the CLI prints **NOT SCORED** instead of a letter grade
- the Markdown, HTML, and PR comment outputs lead with the coverage warning
- the badge reads `not scored` in grey rather than showing a grade
- `--fail-below` does **not** fail the build, because a score derived from a fraction
  of the model is not a score worth failing on

Severity thresholds (`--fail-on-severity`) still apply at any coverage. A finding is a
finding regardless of how much else we managed to measure.

The composite is still computed and recorded in the JSON output, so nothing is hidden
— it is simply not presented as a grade.

---

## Dimension derivations

### `openssf_scorecard` — weight 25

```
value = scorecard_aggregate × 10
```

Scorecard's 0–10 aggregate, scaled. Excluded when Scorecard did not run (it needs a
remote repository and network access, so local-only and `--offline` runs exclude it).

Individual Scorecard checks scoring below 10 are also emitted as `PRACTICE` findings.
Because Scorecard has no severity concept, this mapping is ours:

| Check score | Severity |
|---|---|
| 0, on `Dangerous-Workflow`, `Binary-Artifacts`, or `Vulnerabilities` | high |
| ≤ 2 | medium |
| ≤ 6 | low |
| 7–9 | info |

A check Scorecard reports as `-1` is *inconclusive*, not failing. It produces no
finding and does not affect the aggregate.

### `known_vulnerabilities` — weight 25

```
value = 100 − Σ penalty(severity)
```

| Severity | Penalty |
|---|---|
| critical | 25 |
| high | 10 |
| medium | 3 |
| low | 1 |
| info | 0 |

Four critical CVEs zero this dimension. Clamped to [0, 100].

Vulnerability data comes from OSV-Scanner. OSV advisories prefixed `MAL-` — malicious
packages — are always treated as critical regardless of what their severity field
says, because a hostile dependency is not a graded defect.

Trivy is configured to scan only misconfigurations, not dependencies, specifically so
one CVE is never counted twice across two dimensions.

### `supply_chain_integrity` — weight 20

```
base  = (slsa_level_component + evidence_component) / 2
value = base − min(misconfiguration_penalty, 25)
```

where

```
slsa_level_component = (slsa_build_level / 3) × 100
evidence_component   = (evidence_checks_passed / evidence_checks_total) × 100
```

| Misconfiguration severity | Penalty |
|---|---|
| critical | 12 |
| high | 6 |
| medium | 2 |
| low | 0.5 |

The misconfiguration penalty is capped at 25 points. Misconfigurations matter, but
they should not be able to erase a genuinely well-secured build pipeline; the SLSA
level and its evidence carry this dimension.

#### SLSA build levels

Conservative, and never asserted without evidence. Each level requires everything the
level below requires.

| Level | Requires |
|---|---|
| 0 | Default. No hosted build platform, or no provenance generator configured. |
| 1 | Hosted build platform **and** a provenance generator in a workflow. |
| 2 | Level 1 **and** Scorecard reports signed releases. |
| 3 | Level 2 **and** all workflow actions SHA-pinned **and** no dangerous workflow patterns. |

Every level is reported with its full evidence list, including the checks that
failed. Phase 1 does not fetch and cryptographically verify a published attestation,
so `provenance_verified` is always `false` — we do not claim verification we did not
perform.

### `static_analysis` — weight 15

```
value = 100 − Σ penalty(severity)
```

| Severity | Penalty |
|---|---|
| critical | 20 |
| high | 8 |
| medium | 2 |
| low | 0.5 |
| info | 0 |

Deliberately lighter than the vulnerability penalties. SAST carries a higher false
positive rate, and penalizing it at CVE weight would push maintainers to disable the
scanner — which makes a project less secure, not more.

Semgrep's `severity` reflects rule confidence more than exploitability, so a rule
declaring `impact: HIGH` in its metadata is promoted one band.

### `secrets_exposure` — weight 10

| Condition | Value |
|---|---|
| No secrets detected | 100 |
| Unverified secrets only | 50 |
| Any verified secret | 0 |

**On the middle row:** the specification defines this dimension as "100 if none; 0 if
any verified secret" and is silent on unverified detections. No scanner in the Phase 1
set tests a discovered credential against its provider, so treating every Gitleaks hit
as verified would zero this dimension — and trigger an F cap — on any repository with
a single false positive. Scoring unverified secrets at 50 records a serious,
unconfirmed exposure without asserting something we did not observe. This is a
documented extension of the specification, not an implementation detail.

Gitleaks findings always report `verified: false` for the same reason.

### `sbom_health` — weight 5

```
value = (0.4 × resolution + 0.3 × license_clarity + 0.3 × freshness) × 100
```

where each sub-metric is `1 − (affected_components / total_components)`:

| Sub-metric | Weight | Measures |
|---|---|---|
| `resolution` | 0.4 | Declared dependencies resolved to a concrete version |
| `license_clarity` | 0.3 | Components with an identifiable license |
| `freshness` | 0.3 | Components not behind their latest release |

Scores 0 when no SBOM was generated, or when the SBOM contains no components.

---

## Hard caps

Some findings are severe enough that a good average should not mask them. Caps are
applied **after** the weighted mean, and all three are disclosed in every report —
including the ones that did not fire, so a reader can see what was considered.

| Condition | Composite capped at | Grade |
|---|---|---|
| Any verified, unrevoked secret in git history | 59 | F |
| Any critical vulnerability with a known public exploit | 69 | D |
| No SBOM could be generated | 79 | C |

### On "known public exploit"

This cap fires only when a scanner supplied **actual exploit evidence** — a CISA KEV
marker in the advisory's `database_specific` block, or a reference URL pointing at a
known-exploited catalog or exploit database.

Absence of evidence is not evidence of exploitation. If we treated every critical CVE
without exploit data as potentially exploited, this cap would fire on nearly every
critical finding and stop meaning anything.

---

## Known limitations

Stated plainly, because a methodology document that lists only strengths is marketing.

- **Scorecard dominates for repositories with few findings.** At 25 points on a
  project with no vulnerabilities and no secrets, process hygiene drives most of the
  composite. That is intentional — hygiene predicts future posture — but it means a
  well-run repository with an unpatched CVE can outscore a quiet one that is clean.
- **Semgrep's `--config=auto` ruleset is not pinned.** Rule updates can move the
  static analysis score between runs on an unchanged commit. This is the one place
  where reproducibility depends on an upstream service; `run_metadata.tool_versions`
  records the Semgrep version but not the ruleset revision.
- **Unverified secrets are a judgment call.** See the `secrets_exposure` section.
- **SLSA level 3 is hard to reach honestly.** It requires every action SHA-pinned and
  no dangerous workflow patterns. Most repositories that generate provenance will
  score level 1 or 2 here, which is accurate rather than harsh.
- **Freshness data is only as good as the SBOM.** Syft reports what it can catalog;
  ecosystems with weak lockfile support yield an incomplete component list, which
  inflates `sbom_health` by shrinking the denominator.
- **A score is not an assessment.** This tool augments professional security review
  and does not replace it.

---

## Changing this model

1. Change `core/scoring.py`.
2. Update this document in the same commit.
3. Bump `SCORING_MODEL_VERSION`.
4. Run `make invariants` — the determinism and advisory-isolation guards must stay green.

Scoring is never rewritten to improve the score of any specific repository, including
our own. See [ADR 0003](../adr/0003-scoring-weights.md).
