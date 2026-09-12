# AI advisory layer

CyberOps Kit can optionally annotate findings with an AI assessment of whether they
look genuinely exploitable in your codebase. This page explains exactly what that
layer does, what it is structurally prevented from doing, and how to decide whether
you want it on.

**It is off by default.** If you never pass `--ai-triage`, nothing on this page
applies to you, and no byte of your code leaves your machine.

---

## The boundary

**The AI layer annotates. It never grades.**

| The deterministic core does | The AI layer does |
|---|---|
| Detect findings | Explain findings |
| Assign severity | Suggest a fix |
| Compute the score | — |
| Determine pass/fail | — |

Concretely, the advisory layer cannot:

- feed any value into the score
- change a finding's severity, category, or any other field
- add or remove findings
- determine your CI exit code
- be required for any core feature to work

This is not a policy we promise to follow. It is enforced by the architecture and by
tests that fail loudly if it is ever broken — see [ADR 0004](adr/0004-ai-boundary.md).

### Why it is built this way

A security score that a non-deterministic model can influence is not reproducible,
not auditable, and not defensible to anyone who asks how it was computed. "The AI
thought it was fine" is not a security finding.

So the score is computed from scanner output alone, and the AI layer is bolted on
beside it. Turning triage on and off changes exactly one field in the output:
`finding.advisory`. Everything else — the findings, the severities, the score, the
grade, the SARIF, the exit code — is byte-for-byte identical either way.

You can verify this yourself:

```bash
cyberops scan .                          # deterministic
cyberops scan . --ai-triage              # same score, plus annotations
```

Both runs produce the same `results` block. Only `run_metadata` and the advisory
fields differ.

---

## What you get

For dependency vulnerabilities and SAST findings at medium severity or above, each
advisory carries:

- **assessment** — `likely_exploitable`, `likely_false_positive`, or `unclear`
- **rationale** — why, citing something concrete from the code it was shown
- **confidence** — `low`, `medium`, or `high`
- **remediation** — a suggested fix, when there is a specific one
- **provenance** — the provider, model ID, and prompt version that produced it

`unclear` is a real answer, not a failure. The prompt explicitly tells the model that
"I cannot tell from this excerpt" is correct and valued. An honest uncertainty is more
useful than a confident guess you then have to verify yourself.

### What it will not tell you

The prompt forbids the model from asserting a finding is safe to ignore,
recommending suppression, inventing CVE identifiers, claiming to have executed or
tested anything, or claiming your code is secure overall. If you want a tool that
closes tickets for you, this is not it — and deliberately so.

---

## Turning it on

```bash
# Local inference — nothing leaves your machine
cyberops scan . --ai-triage

# A hosted provider
cyberops scan . --ai-triage --ai-provider anthropic
cyberops scan . --ai-triage --ai-provider openai --ai-model gpt-4o
```

Or in `.cyberops.yml`:

```yaml
ai:
  enabled: true
  provider: local
  model: llama3.1:8b
  max_findings: 25
```

### The default provider is local

`--ai-triage` with no `--ai-provider` uses local inference via
[Ollama](https://ollama.com), which requires no API key and sends nothing anywhere:

```bash
ollama serve
ollama pull llama3.1:8b
cyberops scan . --ai-triage
```

This default is deliberate. If the default were a hosted provider, a flag typo would
ship your source context to a vendor. Choosing to send code off your machine should
be an explicit act.

Hosted providers need the `ai` extra and a credential:

```bash
pip install 'cyberops-kit[ai]'
export ANTHROPIC_API_KEY=...     # or OPENAI_API_KEY
```

---

## What gets sent

Only when you enable it, only for findings that qualify, and only after redaction.

**Sent per finding:**

- the finding itself — rule, message, severity, CVE identifiers
- roughly 60 lines of source around the reported location
- the package name and version, for dependency findings
- your project profile — languages, package managers, library-vs-application

**Never sent:**

- the whole repository
- `.env` files
- anything from a secret finding — secrets are excluded from triage entirely, by
  category, before any context is assembled
- any payload that has not passed through redaction

### Redaction has no off switch

Every outbound payload goes through the same redactor the reports use. It removes
known credential formats, exact secret values that scanners found, and high-entropy
strings that no scanner flagged.

`ai.redact: false` is rejected by the config validator. There is no bypass flag, and
the check lives inside each provider immediately before the network call — so a code
path that skipped redaction could not transmit even if someone wrote one.

If you see `[REDACTED:aws-key]` in an advisory rationale, that is the system working.

---

## Offline mode

`--offline` disables the AI layer entirely. Combining it with `--ai-triage` is a
configuration error that exits non-zero:

```
error: --offline cannot be combined with --ai-triage
  Offline mode disables every outbound network call (INV-6). Drop one of the two flags.
```

It does not warn and continue, and it does not silently skip. If you asked for two
contradictory things, you get told, not guessed at.

Note that local inference still counts as a network call — it is an HTTP request to
a daemon. If you want triage in an air-gapped environment, use the local provider
*without* `--offline`.

---

## Cost and caching

- **`max_findings`** (default 25) caps how many findings are analyzed, highest
  severity first. Hitting it truncates cleanly and says so.
- **Responses are cached** by a hash of the redacted payload, so re-running on an
  unchanged commit costs nothing.
- **Selection is deterministic.** Which findings get analyzed depends on severity
  and finding ID, never on the order scanners happened to finish.

---

## When it fails

Every failure mode leaves your report intact. A provider outage, a malformed reply,
an unreachable daemon, an exhausted budget, a source file that no longer exists —
each produces findings without advisories, never a failed scan or a corrupted
finding.

Inference failing is not scanning failing. That is what "never required for any core
feature to work" means in practice.

---

## How advisory content is labeled

You will never have to guess whether you are reading a scanner result or a generated
one:

| Format | Treatment |
|---|---|
| HTML | `.advisory` block, labeled "AI advisory — not part of the score" |
| Markdown | Blockquote with the same label, plus model and confidence |
| SARIF | `properties` bag only — never `level`, `ruleId`, `kind`, or `rank` |
| JSON | Nested under `finding.advisory` with full provenance |
| PR comment | Collapsed by default, under a clear heading |

The SARIF rule matters most: GitHub code scanning reads `level` and `ruleId` to
decide what to show and how to gate. Advisory content is confined to `properties`,
so it can never influence that.

---

## Should you turn it on?

**Reasonable to enable** when you have more findings than time, and a prioritization
hint — clearly labeled, never authoritative — would help you decide where to look
first.

**Reasonable to leave off** when you do not want code context leaving your machine
and do not want to run a local model, when you are working to a compliance standard
that rejects AI-assisted analysis, or when you simply do not trust LLM output for
security work. You lose nothing: the score, the findings, and the report card are
identical without it.

We would rather you left it off and trusted the score than turned it on and trusted
it too much.

---

## Measured quality

Advisory output can be wrong and still be displayed. That is why it is labeled
everywhere, why the prompt forbids the model from asserting anything is safe to
ignore, and why we publish eval results — including where the layer performs badly —
in [AI advisory evals](methodology/ai-advisory-evals.md).

An advisory layer nobody has measured is a liability. If those numbers are not
published for a release, treat the feature as unproven for that release.
