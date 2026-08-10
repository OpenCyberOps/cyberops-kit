# Maintainers

Maintainers review and merge pull requests, triage issues, cut releases, and
respond to security reports. See [GOVERNANCE.md](GOVERNANCE.md) for how the role
works.

## Current maintainers

| Name | GitHub | Areas |
|---|---|---|
| Ambrish | [@AMBRISH10](https://github.com/AMBRISH10) | Project lead, scoring model, security response |

Reviews are currently routed to individual maintainers via
[`.github/CODEOWNERS`](.github/CODEOWNERS). Once the organization has more than one
maintainer, an `@OpenCyberOps/maintainers` team will replace the individual entries
there — a CODEOWNERS rule naming a team that does not exist silently requests no
review at all, which is why it is not used prematurely.

## Emeritus

None yet.

## Becoming a maintainer

Sustained, high-quality contribution and an invitation from existing maintainers.
There is no quota and no fixed timeline. Reviewing other people's PRs well counts
for as much as writing your own.

## Areas needing an owner

We would particularly welcome maintainers with depth in:

- **Ecosystem coverage** — Ruby, .NET, PHP, Java detection and scanning
- **Container and IaC security** — Trivy policy depth, Kubernetes manifests
- **SLSA and provenance** — attestation verification beyond Phase 1's scope
- **Documentation** — the methodology docs are the project's credibility surface
