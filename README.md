# CyberOps Kit

**Reproducible, auditable security report cards for any software project.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)

CyberOps Kit analyzes a software project, orchestrates the OpenSSF tool ecosystem,
evaluates supply chain posture against SLSA, generates SBOMs, and produces a
security report card you can hand to an auditor.

---

## What this is, and what it is not

This tool **augments professional security review. It does not replace it.** A good
grade means the automated checks we run found little; it does not mean the software
is secure. No automated tool can tell you that.

**We orchestrate, we do not reimplement.** Scanning is delegated to
[Scorecard](https://github.com/ossf/scorecard),
[OSV-Scanner](https://github.com/google/osv-scanner),
[Semgrep](https://semgrep.dev), [Gitleaks](https://github.com/gitleaks/gitleaks),
[Trivy](https://trivy.dev), and [Syft](https://github.com/anchore/syft). Our value
is the detection layer, the normalization layer, the scoring model, and the
reporting layer. There is no CVE matcher or SAST engine in this codebase, and there
never will be.

---

## Design commitments

These are structural, not aspirational. Each is enforced by a test in
`tests/invariants/`.

| | |
|---|---|
| **Deterministic** | The same commit, tool versions, and config produce a byte-identical `results` block. Timestamps and durations live in a separate `run_metadata` block. |
| **Auditable** | The scoring formula, weights, grade bands, and hard caps are [published in full](docs/methodology/scoring.md). A security score nobody can audit is worthless. |
| **Honest about gaps** | A missing scanner is never scored as zero. Its dimension is excluded, its weight redistributed, and the exclusion stated in the report. |
| **No phone-home** | No hosted backend, no telemetry, no analytics. The tool runs entirely in your environment. This is permanent. |
| **Secrets never leak** | Every payload crossing a process boundary passes through `core/redaction.py`. There is no bypass flag. |
| **Untrusted code is sandboxed** | Anything that could execute code from the target tree runs in an ephemeral, network-restricted container. |

---

## Install

```bash
pip install cyberops-kit
```

`pip install` gives you the orchestrator. The external scanners are separate
binaries — install the ones you want, or use the container image, which bundles all
of them:

```bash
docker run --rm -v "$PWD:/workspace" ghcr.io/opencyberops/cyberops-kit scan /workspace
```

Any scanner you do not have installed is reported as **not run**, and the dimension
it feeds is excluded from the score rather than counted as a failure. A scanner that
*ran and broke* — crashed, or exceeded its timeout — is reported separately as
**failed**, because that is a problem to investigate rather than an expected gap.

---

## Use

```bash
# Scan a local checkout
cyberops scan .

# Scan a public repository
cyberops scan https://github.com/owner/repo

# Choose output formats and where they land
cyberops scan . --format json --format markdown --output ./reports

# Fail CI below a threshold
cyberops scan . --fail-below 70 --fail-on-severity high

# No network calls at all, including AI
cyberops scan . --offline

# What would run, and what is missing?
cyberops doctor
```

Outputs: JSON, [SARIF](https://sarifweb.azurewebsites.net/) (for the GitHub Security
tab), Markdown, HTML, and a shields.io-compatible badge endpoint.

---

## The score

Six weighted dimensions, each normalized to 0–100:

| Dimension | Weight | Derived from |
|---|---|---|
| `openssf_scorecard` | 25 | Scorecard aggregate, scaled ×10 |
| `known_vulnerabilities` | 25 | Severity-weighted penalty from OSV |
| `supply_chain_integrity` | 20 | SLSA build level, provenance, action pinning, signed releases |
| `static_analysis` | 15 | Severity-weighted penalty from Semgrep |
| `secrets_exposure` | 10 | 100 if none; 0 if a verified secret |
| `sbom_health` | 5 | Resolution completeness, license clarity, staleness |

Grades: `A ≥ 90` · `B ≥ 80` · `C ≥ 70` · `D ≥ 60` · `F < 60`

Three conditions cap the composite regardless of the weighted mean, because a good
average should not mask a severe finding:

| Condition | Capped at |
|---|---|
| Verified, unrevoked secret in git history | 59 (F) |
| Critical vulnerability with a known public exploit | 69 (D) |
| No SBOM could be generated | 79 (C) |

**[The full methodology is published here.](docs/methodology/scoring.md)** Any change
to scoring behavior updates that document in the same commit and bumps
`SCORING_MODEL_VERSION`.

---

## Configuration

Drop a `.cyberops.yml` at your repository root:

```yaml
version: 1

scanners:
  enabled: [scorecard, osv, semgrep, gitleaks, trivy, syft, slsa]
  timeout_seconds: 600

scoring:
  weights:
    openssf_scorecard: 25
    known_vulnerabilities: 25
    supply_chain_integrity: 20
    static_analysis: 15
    secrets_exposure: 10
    sbom_health: 5

thresholds:
  fail_below_score: 60
  fail_on_severity: critical

ai:
  enabled: false          # Phase 2. Advisory only — never affects the score.
  provider: null
  model: null
  max_findings: 25
  redact: true            # cannot be set to false
```

---

## The AI boundary

An optional AI advisory layer is planned for Phase 2 (v1.1.0+). Its boundary is
fixed now, before any of it is written:

| The deterministic core does | The AI layer will do |
|---|---|
| Detect findings | Explain findings |
| Assign severity | Suggest a fix |
| Compute the score | — |
| Determine pass/fail | — |

**The AI layer annotates. It never grades.** It is off by default, it is disabled
entirely by `--offline`, and removing it must leave the score, the grade, the SARIF
output, and the CI exit code bit-for-bit identical. That last property is enforced by
`tests/invariants/test_score_is_advisory_invariant.py`, which exists today.

---

## Contributing

The most common contribution is a new scanner plugin, and that path is deliberately
short — see [docs/contributing/add-a-scanner.md](docs/contributing/add-a-scanner.md).

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go through
[SECURITY.md](SECURITY.md), not the public issue tracker.

```bash
make install     # editable install + dev extras + pre-commit hooks
make lint        # ruff
make typecheck   # mypy --strict
make test        # pytest
make invariants  # the INV-* guards — run before every commit
make selfscan    # run CyberOps Kit against itself
```

---

## License

Apache-2.0. See [LICENSE](LICENSE).
