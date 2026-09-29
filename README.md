# CyberOps Kit

**Reproducible, auditable security report cards for any software project.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![Security report card](https://img.shields.io/endpoint?url=https%3A%2F%2Fopencyberops.github.io%2Fcyberops-kit%2Freport%2Fbadge.json)](https://opencyberops.github.io/cyberops-kit/report/)
[![Nix flake](https://img.shields.io/badge/nix-flake-5277C3.svg?logo=nixos&logoColor=white)](#nix-and-nixos)

CyberOps Kit analyzes a software project, orchestrates the OpenSSF tool ecosystem,
evaluates supply chain posture against SLSA, generates SBOMs, and produces a
security report card you can hand to an auditor.

**We grade ourselves in public.** Every push to `main` runs CyberOps Kit against this
repository and publishes the [full report card](https://opencyberops.github.io/cyberops-kit/report/)
and its [trend over time](https://opencyberops.github.io/cyberops-kit/report/trend.html),
whatever the result. The security badge above comes from that report.

> **On Nix or NixOS? One command gets you the whole toolchain.**
>
> ```bash
> nix run github:OpenCyberOps/cyberops-kit -- scan .
> ```
>
> That fetches CyberOps Kit together with all seven scanners, each pinned to an
> exact version in `flake.lock`. You don't need pip or Docker, and you don't have to
> assemble a toolchain. [More below](#nix-and-nixos).

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

### Nix and NixOS

This is the quickest way to get the full toolchain. The flake ships `cyberops` with
every scanner it orchestrates already on its `PATH`: Scorecard, OSV-Scanner,
Semgrep, Gitleaks, Trivy, Syft, and slsa-verifier. `flake.lock` pins all of them.

```bash
# Run it once, without installing anything
nix run github:OpenCyberOps/cyberops-kit -- scan .

# Install it into your profile
nix profile install github:OpenCyberOps/cyberops-kit
cyberops doctor        # every scanner reports "available"
```

Why Nix suits this tool:

- **Complete.** Nothing is left for you to install by hand, so no dimension drops
  out of the score just because a binary is missing on this machine.
- **Reproducible.** A given flake revision always resolves to the same scanner
  versions on every machine, and each version is recorded in `run_metadata`. The
  vulnerability databases those scanners download still change as new advisories
  are published, which is what they are supposed to do.
- **Tested as it is built.** Building the package runs the unit tests and every
  `INV-*` invariant guard inside the Nix sandbox. A build that breaks determinism
  or redaction fails.
- **Clean.** Nothing is installed globally, and removing it from your profile
  removes all of it.

**NixOS system configuration.** Add the flake as an input and enable the module:

```nix
{
  inputs.cyberops-kit.url = "github:OpenCyberOps/cyberops-kit";

  outputs = { nixpkgs, cyberops-kit, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        cyberops-kit.nixosModules.default
        { programs.cyberops-kit.enable = true; }
      ];
    };
  };
}
```

The module installs the CLI and does nothing else. It adds no service, no timer,
and no listener.

**home-manager or an overlay.** Both expose it as `pkgs.cyberops-kit`:

```nix
nixpkgs.overlays = [ cyberops-kit.overlays.default ];
home.packages = [ pkgs.cyberops-kit ];
```

**Without flakes.** `default.nix` pins nixpkgs to the same revision as `flake.lock`:

```bash
nix-env -f https://github.com/OpenCyberOps/cyberops-kit/archive/main.tar.gz -i
```

**Variants**

| Output | Contents |
|---|---|
| `#default` | `cyberops` and every scanner |
| `#cyberops-kit-minimal` | `cyberops` only. It uses whatever scanners are already on your `PATH`, the same as `pip install`. |
| `#cyberops-kit-ai` | Everything above, plus the Anthropic and OpenAI SDKs for the optional [AI advisory layer](#the-ai-boundary). On NixOS, set `programs.cyberops-kit.withAI = true;`. |

Supported platforms are `x86_64-linux`, `aarch64-linux`, and `aarch64-darwin`.

Some things still depend on your environment:

- Scorecard still needs a [GitHub token](#scorecard-needs-a-github-token).
- OSV-Scanner, Trivy, and Semgrep fetch vulnerability data or rules at run time
  unless you pass `--offline`.
- Sandboxed stages ([INV-5](#design-commitments)) need a container runtime from
  the system, such as `virtualisation.docker.enable = true;` or
  `virtualisation.podman.enable = true;`.
- If you set `inputs.cyberops-kit.inputs.nixpkgs.follows = "nixpkgs"`, the scanner
  versions come from *your* nixpkgs, not ours. That works, but you lose the pinned
  set that this repository's CI builds and tests.

### pip

```bash
pip install cyberops-kit
```

`pip install` gives you the orchestrator. The external scanners are separate
binaries. Install the ones you want, or use Nix (above) or the container image,
both of which bundle all of them.

### Container

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

### Scorecard needs a GitHub token

```bash
export GITHUB_AUTH_TOKEN=<a token with public repo read access>
```

OpenSSF Scorecard queries the GitHub API heavily. Unauthenticated requests are capped
at 60 per hour — far fewer than its checks need — and it does not fail when it runs
out, it stalls. Without a token CyberOps Kit therefore declines to start it and says
so, rather than spending the whole timeout to report "timed out". With one it takes a
few seconds. In GitHub Actions, `secrets.GITHUB_TOKEN` is sufficient.

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
  timeout_seconds: 600      # default budget for any scanner without its own
  timeouts:                 # per-scanner budgets, so one slow tool does not set them all
    gitleaks: 120
    scorecard: 300
  exclude_paths:            # findings under these paths are dropped, and disclosed
    - tests/fixtures

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

Phase 2 (v1.1.0+) adds an optional AI advisory layer that annotates findings with an
exploitability assessment. Its boundary was fixed before any of it was written, and
the implementation is held to it structurally, not just by policy:

| The deterministic core does | The AI layer does |
|---|---|
| Detect findings | Explain findings |
| Assign severity | Suggest a fix |
| Compute the score | — |
| Determine pass/fail | — |

**The AI layer annotates. It never grades.** It is off by default (`--ai-triage` to
enable), it is disabled entirely by `--offline`, and removing it leaves the score, the
grade, the SARIF output, and the CI exit code bit-for-bit identical. That last property
is enforced by `tests/invariants/test_score_is_advisory_invariant.py`.

**[Read the full explanation — what gets sent, what's redacted, how to turn it on, and
how it's labeled in every output format.](docs/ai-advisory.md)**

Quality is not yet independently measured; see
[the eval methodology](docs/methodology/ai-advisory-evals.md) for what's published so
far and what isn't yet.

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

On Nix, `nix develop` opens a shell with the Python toolchain and every scanner
already present. Skip `make install` and run the other targets directly.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
