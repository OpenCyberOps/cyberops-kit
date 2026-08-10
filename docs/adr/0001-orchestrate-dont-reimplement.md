# ADR 0001 — Orchestrate existing tools; never reimplement scanning

**Status:** Accepted

## Context

The obvious temptation for a security assessment framework is to write its own
scanners. It removes external dependencies, avoids parsing other people's output
formats, and makes the project look more substantial.

The OpenSSF ecosystem already contains mature, well-maintained, widely-audited
tools for every category we care about: Scorecard for process hygiene, OSV-Scanner
for known vulnerabilities, Semgrep for SAST, Gitleaks for secrets, Trivy for
misconfiguration, Syft for SBOMs.

## Decision

We orchestrate. We do not reimplement. **There will never be a CVE matcher or a
SAST engine in this codebase.**

Our value is in four layers the ecosystem does not provide:

1. **Detection** — figuring out what a project is built from, so the right scanners
   run and the wrong ones do not
2. **Normalization** — one canonical `Finding` model across seven wildly different
   output formats
3. **Scoring** — a deterministic, versioned, publicly documented composite
4. **Reporting** — JSON, SARIF, Markdown, HTML, badge, PR comment, trend dashboard

## Consequences

**Good:**

- Vulnerability data quality is OSV's problem, and OSV is better at it than we
  would be. The same applies to every other tool.
- A `pip install` is small; the dependency surface is our own five Python packages.
- New ecosystem coverage often means a new plugin, not new detection logic.

**Bad, and accepted:**

- We inherit our tools' bugs, false positives, and CVEs. The sandbox reduces blast
  radius but cannot eliminate it. This is stated in `SECURITY.md`.
- Users must install binaries separately, or use our container image. `pip install`
  alone gives a degraded experience — which is why `cyberops doctor` exists and why
  missing scanners exclude dimensions rather than failing.
- Upstream output format changes break our parsers. Fixtures under `tests/fixtures/`
  catch this.
- We cannot fix a bad finding at the source. We can only decline to overstate it,
  and never claim a finding is a false positive without evidence.
