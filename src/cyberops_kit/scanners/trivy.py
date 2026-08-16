"""Trivy integration.

Produces ``MISCONFIGURATION`` findings across IaC, container, and CI workflow
definitions.

Trivy can also scan dependencies for vulnerabilities, but that job belongs to
OSV-Scanner here. Running both would double-count the same CVE across two scoring
dimensions and inflate the penalty for a single underlying problem, so this plugin
requests only the misconfiguration scanner.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from cyberops_kit.core.models import (
    Category,
    Confidence,
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

REPORT_FILENAME: Final = "trivy.json"

_SEVERITY_BY_NAME: Final[dict[str, Severity]] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

FAIL_STATUS: Final = "FAIL"


class TrivyPlugin(ScannerPlugin):
    """Runs Trivy's misconfiguration scanner over the target tree."""

    name = "trivy"
    version_command = ("trivy", "--version")
    categories = frozenset({Category.MISCONFIGURATION})
    dimension = None
    """Misconfigurations inform ``supply_chain_integrity`` but do not own a
    dimension of their own; the SLSA evaluator consumes them."""

    execution_mode = ExecutionMode.HOST
    requires_network = True
    """Trivy downloads and refreshes its policy bundle."""

    def applies_to(self, profile: ProjectProfile) -> bool:
        """Return True when there is IaC, a container definition, or CI config.

        Args:
            profile: The detected project profile.

        Returns:
            True when Trivy has something to check.
        """
        return bool(profile.iac or profile.containerized or profile.ci_workflows)

    def build_command(self, ctx: RunContext, workdir: Path) -> list[str]:
        """Build the Trivy invocation.

        Args:
            ctx: The current run context.
            workdir: This scanner's private temp directory.

        Returns:
            The command to run.
        """
        return [
            "trivy",
            "filesystem",
            "--scanners=misconfig",
            "--format=json",
            f"--output={workdir / REPORT_FILENAME}",
            "--quiet",
            "--exit-code=0",
            *self.exclude_args(ctx.config.scanners.exclude_paths),
            str(ctx.workspace),
        ]

    def exclude_args(self, patterns: Sequence[str]) -> list[str]:
        """Skip excluded paths natively via ``--skip-dirs``.

        Args:
            patterns: Configured exclusion patterns.

        Returns:
            One ``--skip-dirs`` flag per pattern.
        """
        return [f"--skip-dirs={pattern}" for pattern in patterns if pattern.strip()]

    def parse(self, result: CommandResult, ctx: RunContext, workdir: Path) -> list[Finding]:
        """Map Trivy misconfigurations into canonical findings.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: This scanner's private temp directory.

        Returns:
            One finding per failing misconfiguration check.
        """
        del result
        payload = _load(workdir / REPORT_FILENAME)
        if payload is None:
            return []

        scanner = ScannerRef(name=self.name, version=UNKNOWN_VERSION)
        findings: list[Finding] = []

        for entry in payload.get("Results") or []:
            if not isinstance(entry, dict):
                continue
            target = str(entry.get("Target", "")).strip()

            for misconfig in entry.get("Misconfigurations") or []:
                if not isinstance(misconfig, dict):
                    continue
                # Trivy reports PASS records too; only failures are findings.
                if str(misconfig.get("Status", "")).upper() != FAIL_STATUS:
                    continue

                check_id = str(misconfig.get("ID", "unknown"))
                title = str(misconfig.get("Title", "")).strip()
                message = str(misconfig.get("Message", "")).strip()
                resolution = str(misconfig.get("Resolution", "")).strip()

                findings.append(
                    Finding.build(
                        scanner=scanner,
                        rule_id=check_id,
                        title=title or check_id,
                        description=_describe(message, resolution),
                        severity=_SEVERITY_BY_NAME.get(
                            str(misconfig.get("Severity", "")).upper(), Severity.MEDIUM
                        ),
                        category=Category.MISCONFIGURATION,
                        confidence=Confidence.HIGH,
                        location=_location(target, misconfig, ctx),
                        references=_references(misconfig),
                        fix_available=bool(resolution),
                        raw=misconfig,
                    )
                )

        return findings


def _describe(message: str, resolution: str) -> str:
    """Combine Trivy's message and resolution into one description.

    Args:
        message: What is wrong.
        resolution: How to fix it.

    Returns:
        The combined description.
    """
    if message and resolution:
        return f"{message}\n\nResolution: {resolution}"
    return message or resolution or "Trivy reported a failing misconfiguration check."


def _location(target: str, misconfig: dict[str, Any], ctx: RunContext) -> Location | None:
    """Build a location from Trivy's target path and cause metadata.

    Args:
        target: The file Trivy evaluated.
        misconfig: The misconfiguration record.
        ctx: The current run context, for path normalization.

    Returns:
        The location, or ``None`` when no target was reported.
    """
    if not target:
        return None

    cause = misconfig.get("CauseMetadata") or {}
    return Location(
        path=normalize_path(target, root=ctx.workspace),
        start_line=_as_int(cause.get("StartLine")),
        end_line=_as_int(cause.get("EndLine")),
        # Trivy's rule IDs are already file-scoped and stable, so the rule itself is
        # the anchor. Resource names shift less than line numbers do.
        symbol=str(cause.get("Resource", "")).strip() or None,
    )


def _references(misconfig: dict[str, Any]) -> list[str]:
    """Extract reference URLs from a Trivy misconfiguration record.

    Args:
        misconfig: The misconfiguration record.

    Returns:
        Sorted, deduplicated URLs.
    """
    urls: set[str] = set()
    primary = misconfig.get("PrimaryURL")
    if isinstance(primary, str) and primary:
        urls.add(primary)
    for url in misconfig.get("References") or []:
        if isinstance(url, str) and url:
            urls.add(url)
    return sorted(urls)


def _as_int(value: Any) -> int | None:
    """Coerce a JSON value to an int, tolerating nulls and zero sentinels.

    Args:
        value: The raw value.

    Returns:
        The integer, or ``None`` when absent or zero (Trivy's "unknown").
    """
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number or None


def _load(report: Path) -> dict[str, Any] | None:
    """Read Trivy's JSON report file.

    Args:
        report: Path to the report inside the scanner's temp directory.

    Returns:
        The parsed payload, or ``None`` when missing or malformed.
    """
    try:
        text = report.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


PLUGIN = TrivyPlugin()
