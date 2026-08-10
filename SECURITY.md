# Security policy

CyberOps Kit is a security tool. Its credibility is the product. We treat reports
against it with the seriousness we would want from any project we assess.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's [private vulnerability reporting](https://github.com/OpenCyberOps/cyberops-kit/security/advisories/new)
on this repository. It keeps the report private until a fix ships, gives you a
private thread with the maintainers, and produces a CVE and advisory when we publish.

It is the only channel we monitor for security reports. We deliberately do not
publish an email address: an unmonitored inbox on a security policy is worse than no
inbox at all.

### What to include

- What the issue is, and which component it affects
- Steps to reproduce, or a proof of concept
- The version or commit SHA you tested
- Any impact you have already assessed

### Our commitments

These are real numbers we hold ourselves to, not aspirations:

| Stage | Commitment |
|---|---|
| Acknowledgement | Within **3 business days** |
| Initial assessment and severity | Within **7 days** |
| Fix or documented mitigation for critical issues | Within **30 days** |
| Public advisory | Within **7 days** of the fix shipping |

If we are going to miss one of these, we will tell you before it lapses rather
than after.

You will be credited in the advisory unless you ask not to be. We will not take
legal action against good-faith research that follows this policy.

## Supported versions

| Version | Supported |
|---|---|
| `1.x` | ✅ |
| `0.x` | ⚠️ Pre-release; fixes land on `main` only |

## Threat model

Understanding what this tool is exposed to is the point of the design, so it is
stated here rather than assumed.

### What we assume is hostile

**The target repository.** Everything about it: file contents, file names,
dependency manifests, lockfiles, and the packages those manifests resolve to.
Scanning a repository is not a statement of trust in it — the whole point is that
you scan things you do not trust yet.

### The controls that follow from that

| Threat | Control |
|---|---|
| A dependency's install script executes on the host | **INV-5.** Anything that resolves a dependency tree runs in an ephemeral, network-restricted container. `run_host()` structurally refuses to execute `npm`, `pip`, `go`, `make`, and every other tool that runs untrusted lifecycle scripts. |
| A discovered secret is written to a log, report, or artifact | **INV-4.** Every payload crossing a process boundary passes through `core/redaction.py`. There is no bypass flag and the config validator rejects `ai.redact: false`. |
| A malicious repository exfiltrates data through the tool | **No telemetry, no backend, no phone-home.** The tool runs entirely in your environment. This is permanent ([ADR 0002](docs/adr/0002-no-telemetry.md)). |
| A repository forces a misleading score | **INV-1 / INV-7.** Scoring is a pure, deterministic function with a published formula. There is no input a repository controls that is not visible in the report. |
| A hostile path escapes the workspace | Paths are normalized relative to the workspace before use; the target tree is mounted read-only inside the sandbox. |
| A scanner crashes or hangs and takes the run with it | Each scanner has a timeout and a containment boundary. A failed scanner is reported as skipped and its dimension excluded — never silently scored as zero. |

### What is explicitly out of scope

- **We do not sanitize scanner binaries.** If Semgrep or Trivy has an RCE, running
  it on a hostile repository is a risk you inherit from that tool. We reduce blast
  radius via the sandbox; we cannot eliminate it.
- **A good grade is not a security guarantee.** The tool augments professional
  security review and does not replace it. Reports say so.
- **Findings are as good as the underlying scanners.** We normalize and score what
  they report; we do not independently verify their conclusions, and we never
  claim a finding is a false positive without evidence.

## Known limitations

Published in [`docs/methodology/scoring.md`](docs/methodology/scoring.md), including
where the scoring model is weakest. A methodology document that lists only strengths
is marketing.

## Our own posture

We scan ourselves in CI and publish the result, including when it is unflattering.
See the [self-scan workflow](.github/workflows/self-scan.yml) and the current open
item on [action SHA pinning](.github/workflows/README.md) — which our own SLSA
evaluator reports against us.
