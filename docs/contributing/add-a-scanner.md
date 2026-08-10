# Adding a scanner plugin

This is the most common contribution to CyberOps Kit, so the path is deliberately
short. The base class handles availability detection, version capture, execution
mode, timeouts, offline enforcement, temp directories, and error classification.
You implement five things.

**Remember what we are building.** We orchestrate; we do not reimplement. A plugin
maps a tool's native output into the canonical `Finding` model and nothing more.
Never write a CVE matcher or a SAST engine.

## The seven steps

1. Create `src/cyberops_kit/scanners/<tool>.py`
2. Subclass `ScannerPlugin` from `scanners/base.py`
3. Declare `name`, `version_command`, `applies_to()`, `build_command()`, `parse()`
4. Map native output into `Finding`, preserving the original in `Finding.raw`
5. Add a fixture under `tests/fixtures/` with known expected findings
6. Register in `scanners/registry.py`
7. Document it here

## Three rules a plugin never breaks

- A plugin **never computes a score.**
- A plugin **never mutates another plugin's findings.** (Reading them is fine — see
  `slsa.py`.)
- A plugin **never writes outside its own temp directory.** Use the `workdir` handed
  to `build_command()` and `parse()`.

## A working template

```python
"""Example integration for a hypothetical tool called `fooscan`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberops_kit.core.models import (
    Category, Confidence, DimensionKey, Finding, Location,
    RunContext, ProjectProfile, ScannerRef, Severity, normalize_path,
)
from cyberops_kit.core.sandbox import CommandResult
from cyberops_kit.scanners.base import UNKNOWN_VERSION, ExecutionMode, ScannerPlugin


class FooScanPlugin(ScannerPlugin):
    """Runs fooscan over the target's source."""

    name = "fooscan"
    version_command = ("fooscan", "--version")
    categories = frozenset({Category.STATIC_ANALYSIS})
    dimension = DimensionKey.STATIC_ANALYSIS

    # HOST is only for tools that read the tree without executing anything from it.
    # Anything that resolves a dependency graph must be SANDBOX (INV-5).
    execution_mode = ExecutionMode.HOST

    # Declare this or the base class will happily run you under --offline (INV-6).
    requires_network = False

    # Many tools exit non-zero when they find something. That is a result, not a fault.
    ok_returncodes = frozenset({0, 1})

    def applies_to(self, profile: ProjectProfile) -> bool:
        """Return whether this scanner is relevant to the detected project."""
        return "Python" in profile.language_names

    def build_command(self, ctx: RunContext, workdir: Path) -> list[str]:
        """Return the argv to execute."""
        return ["fooscan", "--json", str(ctx.workspace)]

    def parse(self, result: CommandResult, ctx: RunContext, workdir: Path) -> list[Finding]:
        """Map native output into canonical findings."""
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            # A malformed payload is not a crash. Return nothing and let the run
            # continue; the base class records the outcome.
            return []

        scanner = ScannerRef(name=self.name, version=UNKNOWN_VERSION)
        findings: list[Finding] = []

        for item in payload.get("issues") or []:
            findings.append(
                Finding.build(
                    scanner=scanner,
                    rule_id=str(item["rule"]),
                    title=str(item["message"]),
                    description=str(item.get("detail", item["message"])),
                    severity=_severity(item.get("level")),
                    category=Category.STATIC_ANALYSIS,
                    confidence=Confidence.MEDIUM,
                    location=Location(
                        path=normalize_path(item["file"], root=ctx.workspace),
                        start_line=item.get("line"),
                        # Anchor on content, never on the line number alone.
                        snippet_hash=item.get("fingerprint"),
                    ),
                    raw=item,          # preserved verbatim, for auditability
                )
            )

        return findings


def _severity(level: Any) -> Severity:
    """Map fooscan's native levels onto our five."""
    return {
        "critical": Severity.CRITICAL,
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "note": Severity.LOW,
    }.get(str(level).lower(), Severity.MEDIUM)


PLUGIN = FooScanPlugin()
```

Then register it:

```python
# src/cyberops_kit/scanners/registry.py
from cyberops_kit.scanners import fooscan   # add to the import list
...
for module in (scorecard, osv, semgrep, gitleaks, trivy, syft, slsa, fooscan):
    register(module.PLUGIN)
```

## Getting the details right

### Use `Finding.build`, not the constructor

It derives the stable finding ID from the identity fields. Do not compute IDs
yourself — there is exactly one place that logic lives.

### Anchor on content, not line numbers

`Finding.id` is what makes PR deltas, the trend dashboard, and suppression files
survive a refactor. Line numbers shift whenever anything above them changes. Prefer,
in order:

1. A content hash the tool gives you (`snippet_hash`)
2. A hash you compute from the matched text
3. An enclosing symbol name
4. A line number — only when the tool offers nothing better

### Leave the version as `UNKNOWN_VERSION`

The base class stamps the detected version onto your findings after `parse()`. Only
set it yourself if the tool reports its version inside its own output, which is more
accurate (see `scorecard.py`).

### Do not double-count

If another plugin already covers a category, do not also report it. Trivy is
configured for misconfigurations only, precisely so a CVE is never penalized twice
across two scoring dimensions.

### Declining cleanly

Two ways, depending on what the decision depends on:

- `applies_to(profile)` — depends on the detected stack
- `preflight(ctx)` — depends on the run; return a human-readable reason string.
  `scorecard.py` uses this to decline when there is no remote repository URL.

Both produce a `SKIPPED` result with a stated reason, which excludes the dimension
from scoring rather than zeroing it.

### Producing something other than findings

- Scalar measurements → override `extract_metrics()` (see `scorecard.py`)
- Documents such as SBOMs → override `extract_documents()` (see `syft.py`)
- Deriving from another scanner's results → set `depends_on` and override
  `run_with()` (see `slsa.py`)

## Testing

Add a fixture of real tool output and assert the known findings:

```python
def test_fooscan_parses_fixture(run_context):
    findings = fooscan.PLUGIN.parse(
        command_result(load_fixture("fooscan.json")), run_context, Path()
    )
    assert len(findings) == 2
    assert findings[0].severity is Severity.HIGH
    assert findings[0].location.snippet_hash          # content-anchored
    assert "rule" in findings[0].raw                  # raw preserved


def test_fooscan_handles_malformed_output(run_context):
    assert fooscan.PLUGIN.parse(command_result("{"), run_context, Path()) == []
```

`tests/unit/test_scanners.py` has parametrized contract tests that will pick your
plugin up automatically once it is registered.

## Before you open the PR

```bash
make lint typecheck test invariants
```

In the PR description, say which tool you integrated, what it produces, and whether
it needs network access or the sandbox. If you added a dependency, justify it.
