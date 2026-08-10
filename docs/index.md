# CyberOps Kit

**Reproducible, auditable security report cards for any software project.**

CyberOps Kit analyzes a software project, orchestrates the OpenSSF tool ecosystem,
evaluates supply chain posture against SLSA, generates SBOMs, and produces a
security report card you can hand to an auditor.

!!! warning "What this is, and what it is not"
    This tool **augments professional security review. It does not replace it.** A
    good grade means the automated checks we run found little; it does not mean the
    software is secure. No automated tool can tell you that.

## Start here

- **[Scoring methodology](methodology/scoring.md)** — the complete formula, weights,
  grade bands, hard caps, and known limitations. Published in full, because a
  security score nobody can audit is worthless.
- **[Add a scanner](contributing/add-a-scanner.md)** — the most common contribution,
  with a working template.
- **[Architecture decisions](adr/README.md)** — why the project is built the way it
  is, including the decisions that are settled permanently.

## Quick start

```bash
pip install cyberops-kit

cyberops doctor        # which scanners are available, and what a missing one costs
cyberops scan .        # scan a local checkout
cyberops scan https://github.com/owner/repo
```

The external scanners are separate binaries. Install the ones you want, or use the
container image, which bundles all of them:

```bash
docker run --rm -v "$PWD:/workspace" ghcr.io/opencyberops/cyberops-kit scan /workspace
```

Any scanner you do not have is reported as **not run**, and the dimension it feeds
is excluded from the score rather than counted as a failure. A scanner that *ran and
broke* is reported separately as **failed** — an expected gap and a bug should never
look the same.

## Design commitments

Each is enforced by a test in `tests/invariants/`, not just documented.

| | |
|---|---|
| **Deterministic** | Same commit, tool versions, and config ⇒ byte-identical `results`. |
| **Auditable** | The scoring formula is published and versioned. |
| **Honest about gaps** | A missing scanner is never scored as zero, and a run that measured too little reports *not scored* rather than a misleading grade. |
| **No phone-home** | No backend, no telemetry. Permanent. |
| **Secrets never leak** | Every outbound payload passes through redaction. No bypass flag. |
| **Untrusted code is sandboxed** | Package managers and build tools cannot run on the host. |

## The AI boundary

An optional AI advisory layer is planned for Phase 2. **The AI layer annotates. It
never grades.** It cannot influence the score, the grade, or the CI exit code, and
removing it entirely leaves all three bit-for-bit identical. See
[ADR 0004](adr/0004-ai-boundary.md).
