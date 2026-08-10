# Governance

CyberOps Kit is an open-source project under Apache-2.0. This document describes
how decisions get made, so that contributors know what to expect and users know
the project is not one person's whim.

## Roles

### Contributors

Anyone who opens an issue, files a PR, improves documentation, or reports a bug.
No formal process; just follow [CONTRIBUTING.md](CONTRIBUTING.md).

### Maintainers

Listed in [MAINTAINERS.md](MAINTAINERS.md). Maintainers review and merge PRs, triage
issues, cut releases, and respond to security reports.

A contributor becomes a maintainer by sustained, high-quality contribution and an
invitation from existing maintainers with no objection. There is no quota.

Maintainers step down by saying so, or are moved to emeritus after 12 months of
inactivity. This is not a judgment; people's circumstances change.

## Decisions

**Ordinary changes** — bug fixes, new scanner plugins, documentation, refactors —
need one maintainer approval. Lazy consensus: if nobody objects within a
reasonable window, it merges.

**Significant changes** need an [ADR](docs/adr/) and two maintainer approvals:

- Changes to the scoring model, weights, grade bands, or hard caps
- Changes to the canonical data model in `core/models.py`
- Adding or removing a pipeline stage
- Adding a runtime dependency
- Anything touching an invariant

**Changes to an invariant** need an ADR, unanimous maintainer approval, and a
public discussion period of at least 14 days. The invariants are the reason anyone
should trust this tool; they do not change quietly.

Disagreements are resolved by discussion. If that fails, a simple majority of
maintainers decides. We would rather move slowly than break the trust posture.

## What will not change

Some decisions are settled and are not reopened without extraordinary reason. They
are recorded as ADRs so they do not get re-litigated every six months:

- **No hosted backend, telemetry, or phone-home.** The tool runs entirely in the
  user's environment. Permanent.
- **We orchestrate, we do not reimplement.** No CVE matcher, no SAST engine.
- **The AI layer annotates; it never grades.** Advisory output never touches the
  score, the grade, or the CI exit code.
- **The scoring methodology stays public.** A security score nobody can audit is
  worthless.

## Releases

Semantic versioning. Releases are cut by maintainers, signed, and published with
SLSA build provenance. The changelog is generated from Conventional Commits.

## Security

See [SECURITY.md](SECURITY.md). Security reports are handled privately by
maintainers and are not subject to the public discussion norms above.

## Code of conduct

Enforcement is a maintainer responsibility. See
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
