# ADR 0002 — No hosted backend, telemetry, or phone-home

**Status:** Accepted. **Permanent** — this is not revisited.

## Context

Usage analytics would tell us which scanners matter, where runs fail, and what to
prioritize. A hosted backend would enable a nicer dashboard, cross-repository
comparison, and a business model. Nearly every tool in this space does one or both.

This is a security tool. It runs against private source code. It reads dependency
manifests, git history, and — by design — discovered credentials.

## Decision

**The tool runs entirely in the user's environment.** No hosted backend, no
telemetry, no analytics, no crash reporting, no phone-home of any kind.

The only outbound network calls are the ones scanners must make to do their job
(the GitHub API for Scorecard, OSV.dev for advisories, the Semgrep registry for
rules), and `--offline` disables all of them absolutely (INV-6).

## Consequences

**Good:**

- A user can read the source, run it air-gapped, and verify that claim. The
  guarantee is auditable rather than a privacy policy.
- We cannot leak what we never collect. A breach of our infrastructure cannot expose
  a user's findings, because our infrastructure never has them.
- `--offline` is a real feature, not a marketing checkbox.

**Bad, and accepted:**

- We are blind. We will not know how many people use this, which scanners fail most,
  or where the friction is, except when someone tells us.
- Prioritization depends on issues, discussions, and asking people directly. Week 2
  of the roadmap explicitly budgets for "ask three people to run it and file the
  friction" because we have no substitute.
- The trend dashboard is a static site built from local history files, which is more
  work than a hosted database and less capable.

We consider being blind an acceptable price for being trustworthy. A security tool
that exfiltrates data about the code it scans has the wrong threat model.
