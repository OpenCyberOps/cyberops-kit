"""Semgrep OSS integration.

Produces ``STATIC_ANALYSIS`` findings. Semgrep reports a location with a line range
and the matched source text; the matched text is hashed into
``Location.snippet_hash`` so a finding keeps its identity when unrelated edits shift
its line numbers.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Final

from cyberops_kit.core.models import (
    Category,
    Confidence,
    DimensionKey,
    Finding,
    Location,
    ProjectProfile,
    RunContext,
    ScannerRef,
    Severity,
    normalize_path,
)
from cyberops_kit.core.sandbox import CommandResult
from cyberops_kit.scanners.base import UNKNOWN_VERSION, ExecutionMode, ScannerPlugin

FINDINGS_EXIT: Final = 1
"""Semgrep exits 1 when it has findings."""

RULESET: Final = "p/default"
"""Registry ruleset this integration runs.

Named explicitly rather than using ``--config=auto`` for two reasons.

First, ``auto`` is incompatible with ``--metrics=off``: Semgrep resolves an auto
config by reporting the project to its registry, so it refuses the combination
outright with *"Cannot create auto config when metrics are off"*. Sending telemetry
to obtain a ruleset is not a trade this project makes (ADR 0002), so the ruleset is
the part that gives.

Second, ``auto`` is unpinned. Which rules it selects depends on what the registry
infers about the project at request time, so an unchanged commit could score
differently between runs. A named ruleset is a fixed input recorded in
``run_metadata.tool_versions``.

The registry still serves this ruleset's *contents*, which can change upstream. That
residual limitation is documented in ``docs/methodology/scoring.md`` rather than
papered over.
"""

_SEVERITY_BY_NAME: Final[dict[str, Severity]] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

_CONFIDENCE_BY_NAME: Final[dict[str, Confidence]] = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
}


class SemgrepPlugin(ScannerPlugin):
    """Runs Semgrep OSS over the target's source."""

    name = "semgrep"
    version_command = ("semgrep", "--version")
    categories = frozenset({Category.STATIC_ANALYSIS})
    dimension = DimensionKey.STATIC_ANALYSIS
    execution_mode = ExecutionMode.HOST
    """Semgrep pattern-matches source text; it never executes the code it reads."""

    requires_network = True
    """Ruleset contents are fetched from the Semgrep registry (see ``RULESET``)."""

    ok_returncodes = frozenset({0, FINDINGS_EXIT})

    def applies_to(self, profile: ProjectProfile) -> bool:
        """Return True when the project contains source Semgrep can analyze.

        Args:
            profile: The detected project profile.

        Returns:
            True when at least one language was detected.
        """
        return bool(profile.languages)

    def build_command(self, ctx: RunContext, workdir: Path) -> list[str]:
        """Build the Semgrep invocation.

        Args:
            ctx: The current run context.
            workdir: Unused; Semgrep writes JSON to stdout.

        Returns:
            The command to run.
        """
        del workdir
        return [
            "semgrep",
            "scan",
            f"--config={RULESET}",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--metrics=off",
            str(ctx.workspace),
        ]

    def parse(self, result: CommandResult, ctx: RunContext, workdir: Path) -> list[Finding]:
        """Map Semgrep results into canonical static-analysis findings.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: Unused.

        Returns:
            One finding per Semgrep result.
        """
        del workdir
        payload = _load(result.stdout)
        if payload is None:
            return []

        scanner = ScannerRef(name=self.name, version=UNKNOWN_VERSION)
        findings: list[Finding] = []

        for entry in payload.get("results") or []:
            if not isinstance(entry, dict):
                continue
            extra = entry.get("extra") or {}
            metadata = extra.get("metadata") or {}
            check_id = str(entry.get("check_id", "unknown"))
            message = str(extra.get("message", "")).strip()

            findings.append(
                Finding.build(
                    scanner=scanner,
                    rule_id=check_id,
                    title=message.splitlines()[0] if message else check_id,
                    description=message or f"Semgrep rule {check_id} matched.",
                    severity=_severity_for(extra, metadata),
                    category=Category.STATIC_ANALYSIS,
                    confidence=_CONFIDENCE_BY_NAME.get(
                        str(metadata.get("confidence", "")).upper(), Confidence.MEDIUM
                    ),
                    location=_location(entry, extra, ctx),
                    cwe_ids=_cwe_ids(metadata),
                    references=_references(metadata),
                    raw=entry,
                )
            )

        return findings


def _location(entry: dict[str, Any], extra: dict[str, Any], ctx: RunContext) -> Location | None:
    """Build a location with a content anchor from a Semgrep result.

    Args:
        entry: The Semgrep result object.
        extra: The result's ``extra`` block, holding the matched lines.
        ctx: The current run context, for path normalization.

    Returns:
        The location, or ``None`` when Semgrep reported no path.
    """
    path = str(entry.get("path", "")).strip()
    if not path:
        return None

    start = entry.get("start") or {}
    end = entry.get("end") or {}
    matched = str(extra.get("lines", "")).strip()

    return Location(
        path=normalize_path(path, root=ctx.workspace),
        start_line=_as_int(start.get("line")),
        end_line=_as_int(end.get("line")),
        # The matched text is a far more durable anchor than a line number: it
        # survives every edit that does not touch the match itself.
        snippet_hash=hashlib.sha256(matched.encode("utf-8")).hexdigest()[:16] if matched else None,
    )


def _severity_for(extra: dict[str, Any], metadata: dict[str, Any]) -> Severity:
    """Map Semgrep's severity, refined by rule metadata, to a normalized severity.

    Semgrep's own ``severity`` reflects rule confidence more than exploitability, so
    a rule that declares ``impact: HIGH`` is promoted one band.

    Args:
        extra: The result's ``extra`` block.
        metadata: The rule's metadata block.

    Returns:
        The normalized severity.
    """
    base = _SEVERITY_BY_NAME.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM)
    impact = str(metadata.get("impact", "")).upper()
    if impact == "HIGH" and base is Severity.HIGH:
        return Severity.CRITICAL
    if impact == "HIGH" and base is Severity.MEDIUM:
        return Severity.HIGH
    return base


def _cwe_ids(metadata: dict[str, Any]) -> list[str]:
    """Extract CWE identifiers from Semgrep rule metadata.

    Semgrep writes them as prose, e.g. ``"CWE-79: Cross-site Scripting"``.

    Args:
        metadata: The rule's metadata block.

    Returns:
        Sorted, deduplicated CWE identifiers.
    """
    raw = metadata.get("cwe")
    entries = raw if isinstance(raw, list) else [raw] if raw else []
    ids: set[str] = set()
    for entry in entries:
        text = str(entry)
        if text.upper().startswith("CWE-"):
            ids.add(text.split(":")[0].strip())
    return sorted(ids)


def _references(metadata: dict[str, Any]) -> list[str]:
    """Extract reference URLs from Semgrep rule metadata.

    Args:
        metadata: The rule's metadata block.

    Returns:
        Sorted, deduplicated URLs.
    """
    raw = metadata.get("references") or []
    if isinstance(raw, str):
        raw = [raw]
    return sorted({str(url) for url in raw if url})


def _as_int(value: Any) -> int | None:
    """Coerce a JSON value to an int, tolerating nulls and strings.

    Args:
        value: The raw value.

    Returns:
        The integer, or ``None``.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _load(stdout: str) -> dict[str, Any] | None:
    """Parse Semgrep's JSON output.

    Args:
        stdout: Raw stdout from the tool.

    Returns:
        The parsed payload, or ``None`` when empty or malformed.
    """
    text = stdout.strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


PLUGIN = SemgrepPlugin()
