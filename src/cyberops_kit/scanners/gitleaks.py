"""Gitleaks integration.

Produces ``SECRET`` findings from the working tree and the full git history.

Everything this scanner returns carries the secret material itself in
``Finding.raw``. That is deliberate — it is what lets ``core/redaction.py`` remove
the exact bytes from every other payload — and it is why no finding from this
scanner may reach a report, a log, or a Phase 2 LLM request without passing through
``redact()`` first (INV-4).
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

REPORT_FILENAME: Final = "gitleaks.json"

HIGH_ENTROPY_THRESHOLD: Final = 4.5
"""Gitleaks reports per-match entropy; above this a generic rule is more credible."""


class GitleaksPlugin(ScannerPlugin):
    """Runs Gitleaks over the working tree and git history."""

    name = "gitleaks"
    version_command = ("gitleaks", "version")
    categories = frozenset({Category.SECRET})
    dimension = DimensionKey.SECRETS_EXPOSURE
    execution_mode = ExecutionMode.HOST
    """Gitleaks reads files and git objects; it never executes repository code."""

    requires_network = False

    def applies_to(self, profile: ProjectProfile) -> bool:
        """Return True for any project.

        A committed credential is a risk regardless of language or ecosystem.

        Args:
            profile: The detected project profile.

        Returns:
            Always True.
        """
        del profile
        return True

    def build_command(self, ctx: RunContext, workdir: Path) -> list[str]:
        """Build the Gitleaks invocation.

        Gitleaks writes its report to a file rather than stdout, so it goes into this
        scanner's private temp directory (see docs/contributing/add-a-scanner.md).

        Subcommand choice, which is load-bearing:

        * ``git`` when the target is a git repository. It walks the full commit
          history, which is where the dangerous secrets are — removing a file does
          not revoke a credential, and the hard cap is specifically about secrets in
          history. It is also consistent with the rest of the pipeline, which
          assesses a *pinned commit* rather than whatever is currently on disk.
        * ``dir`` otherwise, so a plain directory still gets scanned.

        Note that ``gitleaks detect --source=`` from v7 no longer exists; v8 replaced
        it with these subcommands and a positional target.

        Args:
            ctx: The current run context.
            workdir: This scanner's private temp directory.

        Returns:
            The command to run.
        """
        subcommand = "git" if (ctx.workspace / ".git").exists() else "dir"
        return [
            "gitleaks",
            subcommand,
            str(ctx.workspace),
            "--report-format=json",
            f"--report-path={workdir / REPORT_FILENAME}",
            # Keep the literal value in the report. It never leaves this temp
            # directory, and core/redaction.py needs the exact bytes to strip the
            # secret precisely from every payload that does leave (INV-4).
            "--redact=0",
            "--no-banner",
            # Report findings via the report file, not the exit code, so a repo with
            # leaks is not misread as a scanner failure.
            "--exit-code=0",
        ]

    def parse(self, result: CommandResult, ctx: RunContext, workdir: Path) -> list[Finding]:
        """Map Gitleaks results into canonical secret findings.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: This scanner's private temp directory.

        Returns:
            One finding per detected secret.
        """
        del result
        report = workdir / REPORT_FILENAME
        entries = _load(report)
        scanner = ScannerRef(name=self.name, version=UNKNOWN_VERSION)
        findings: list[Finding] = []

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            rule_id = str(entry.get("RuleID", "unknown"))
            description = str(entry.get("Description", "")).strip()
            commit = str(entry.get("Commit", "")).strip()

            findings.append(
                Finding.build(
                    scanner=scanner,
                    rule_id=rule_id,
                    title=description or f"Secret detected by rule {rule_id}",
                    description=_describe(entry, description, commit),
                    severity=Severity.CRITICAL,
                    category=Category.SECRET,
                    confidence=_confidence(entry),
                    location=_location(entry, ctx),
                    # Gitleaks detects; it does not call the provider to confirm the
                    # credential is live. Claiming verification we did not perform
                    # would be dishonest, and the hard cap depends on this flag.
                    verified=False,
                    raw=entry,
                )
            )

        return findings


def _describe(entry: dict[str, Any], description: str, commit: str) -> str:
    """Build a finding description, noting git history provenance.

    Args:
        entry: The Gitleaks finding record.
        description: The rule's description.
        commit: The commit the secret was found in, if any.

    Returns:
        A human-readable description. Never includes the secret itself.
    """
    base = description or "A credential-like string was detected."
    if commit:
        author = str(entry.get("Author", "")).strip()
        attribution = f" (commit {commit[:12]}{f', {author}' if author else ''})"
        return (
            f"{base}{attribution}. This secret is present in git history; rotating it "
            "is required — removing the file does not revoke the credential."
        )
    return f"{base} Detected in the working tree."


def _confidence(entry: dict[str, Any]) -> Confidence:
    """Derive confidence from the rule kind and reported entropy.

    Gitleaks' provider-specific rules match a known credential format and are
    high-confidence. Generic entropy rules are not, unless the entropy is high.

    Args:
        entry: The Gitleaks finding record.

    Returns:
        The scanner confidence.
    """
    rule_id = str(entry.get("RuleID", "")).lower()
    entropy = entry.get("Entropy")

    if "generic" not in rule_id:
        return Confidence.HIGH
    if isinstance(entropy, (int, float)) and entropy >= HIGH_ENTROPY_THRESHOLD:
        return Confidence.MEDIUM
    return Confidence.LOW


def _location(entry: dict[str, Any], ctx: RunContext) -> Location | None:
    """Build a location for a Gitleaks finding.

    Gitleaks supplies a ``Fingerprint`` that already encodes file, rule, and commit.
    Where it is absent, the matched text is hashed instead — never the line number
    alone, which shifts constantly.

    Args:
        entry: The Gitleaks finding record.
        ctx: The current run context, for path normalization.

    Returns:
        The location, or ``None`` when no file was reported.
    """
    file_path = str(entry.get("File", "")).strip()
    if not file_path:
        return None

    match = str(entry.get("Match", ""))
    fingerprint = str(entry.get("Fingerprint", "")).strip()
    anchor = (
        hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16]
        if fingerprint
        else hashlib.sha256(match.encode("utf-8")).hexdigest()[:16]
        if match
        else None
    )

    return Location(
        path=normalize_path(file_path, root=ctx.workspace),
        start_line=_as_int(entry.get("StartLine")),
        end_line=_as_int(entry.get("EndLine")),
        snippet_hash=anchor,
    )


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


def _load(report: Path) -> list[Any]:
    """Read Gitleaks' JSON report file.

    Args:
        report: Path to the report inside the scanner's temp directory.

    Returns:
        The list of findings, or empty when the report is missing or malformed.
        Gitleaks writes ``null`` rather than ``[]`` when it finds nothing.
    """
    try:
        text = report.read_text(encoding="utf-8").strip()
    except OSError:
        return []
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    return payload if isinstance(payload, list) else []


PLUGIN = GitleaksPlugin()
