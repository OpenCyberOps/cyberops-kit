"""OpenSSF Scorecard integration.

Produces ``PRACTICE`` findings for each check scoring below its maximum, plus the
0-10 aggregate that feeds the ``openssf_scorecard`` scoring dimension.

Scorecard's raw check output is also what the SLSA evaluator layers on top of, which
is why the full check payload is preserved in ``Finding.raw`` rather than summarized
away (see ``slsa.py``).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final

from cyberops_kit.core.models import (
    Category,
    Confidence,
    DimensionKey,
    Finding,
    ProjectProfile,
    RunContext,
    ScannerRef,
    Severity,
)
from cyberops_kit.core.sandbox import CommandResult
from cyberops_kit.scanners.base import ExecutionMode, ScannerPlugin

MAX_CHECK_SCORE: Final = 10
INCONCLUSIVE: Final = -1
"""Scorecard reports -1 when a check could not run. Not a failure — excluded."""

AGGREGATE_METRIC: Final = "aggregate"
"""Metric key the scoring model reads for the 0-10 Scorecard aggregate."""

CRITICAL_CHECKS: Final[frozenset[str]] = frozenset(
    {"Dangerous-Workflow", "Binary-Artifacts", "Vulnerabilities"}
)
"""Checks where a zero score is an active risk rather than a missing practice."""

TOKEN_ENV_VARS: Final[tuple[str, ...]] = ("GITHUB_AUTH_TOKEN", "GITHUB_TOKEN")
"""Environment variables Scorecard reads a GitHub credential from, in its own order."""

UNAUTHENTICATED_RATE_LIMIT: Final = 60
"""GitHub API requests per hour without a token. Scorecard needs far more."""


def _github_token() -> str | None:
    """Return the first non-empty GitHub token in the environment.

    Only presence is checked, never the value, and the value is never logged or
    included in a skip reason (INV-4).

    Returns:
        The variable name that held a token, or ``None`` when none did.
    """
    for name in TOKEN_ENV_VARS:
        if os.environ.get(name, "").strip():
            return name
    return None


class ScorecardPlugin(ScannerPlugin):
    """Runs OpenSSF Scorecard against the target's remote repository."""

    name = "scorecard"
    version_command = ("scorecard", "version")
    """Scorecard has no ``--version`` flag; it exposes a ``version`` subcommand.

    The wrong form did not error visibly — it printed a usage message, the version
    parser found nothing, and Scorecard's version was quietly absent from
    ``run_metadata.tool_versions``. INV-3 requires it: a tool version change is a
    legitimate reason for a score to move and has to be traceable.
    """
    categories = frozenset({Category.PRACTICE})
    dimension = DimensionKey.OPENSSF_SCORECARD
    execution_mode = ExecutionMode.HOST
    requires_network = True
    """Scorecard queries the GitHub API; there is no offline equivalent."""

    env_passthrough = frozenset(TOKEN_ENV_VARS)
    """Without the token forwarded, Scorecard runs unauthenticated and stalls."""

    def applies_to(self, profile: ProjectProfile) -> bool:
        """Return True for any project.

        Scorecard evaluates process hygiene, which is language-independent.

        Args:
            profile: The detected project profile.

        Returns:
            Always True.
        """
        del profile
        return True

    def preflight(self, ctx: RunContext) -> str | None:
        """Decline when there is no remote repository, or no token to reach it with.

        Args:
            ctx: The current run context.

        Returns:
            A skip reason, or ``None`` when Scorecard can run.
        """
        if not ctx.target.origin_url:
            return (
                "no remote repository URL: Scorecard evaluates a hosted repository's "
                "process hygiene and cannot assess a local-only checkout"
            )
        if not _github_token():
            # Measured, not assumed: with a valid token Scorecard finished this
            # repository's 18 checks in ~6s. Without one it does not error — it spins
            # against a 60 request/hour unauthenticated limit until something kills
            # it, consuming the entire timeout budget and reporting only "timed out".
            # An honest skip beats ten minutes spent earning a misleading verdict.
            return (
                "no GitHub token: set GITHUB_AUTH_TOKEN (or GITHUB_TOKEN) so Scorecard "
                f"can query the API. Unauthenticated requests are limited to "
                f"{UNAUTHENTICATED_RATE_LIMIT}/hour, far fewer than its checks need, and "
                "it will hang rather than fail"
            )
        return None

    def build_command(self, ctx: RunContext, workdir: Path) -> list[str]:
        """Build the Scorecard invocation.

        Args:
            ctx: The current run context.
            workdir: Unused; Scorecard writes to stdout.

        Returns:
            The command to run.
        """
        del workdir
        return [
            "scorecard",
            f"--repo={ctx.target.origin_url}",
            "--format=json",
            "--show-details",
        ]

    def parse(self, result: CommandResult, ctx: RunContext, workdir: Path) -> list[Finding]:
        """Map each below-maximum Scorecard check to a ``PRACTICE`` finding.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: Unused.

        Returns:
            One finding per check that scored below 10, excluding inconclusive checks.
        """
        del ctx, workdir
        payload = _load(result.stdout)
        if payload is None:
            return []

        scanner = ScannerRef(name=self.name, version=_tool_version(payload))
        findings: list[Finding] = []

        for check in payload.get("checks") or []:
            if not isinstance(check, dict):
                continue
            score = check.get("score")
            check_name = str(check.get("name", "unknown"))

            if not isinstance(score, int):
                continue
            # An inconclusive check is missing data, not a failed practice. Reporting
            # it as a finding would be dishonest.
            if score == INCONCLUSIVE or score >= MAX_CHECK_SCORE:
                continue

            documentation = check.get("documentation") or {}
            short = str(documentation.get("short", "")).strip()
            url = str(documentation.get("url", "")).strip()
            reason = str(check.get("reason", "")).strip()

            findings.append(
                Finding.build(
                    scanner=scanner,
                    rule_id=check_name,
                    title=f"Scorecard: {check_name} scored {score}/10",
                    description=reason or short or f"{check_name} scored {score}/10.",
                    severity=_severity_for(check_name, score),
                    category=Category.PRACTICE,
                    confidence=Confidence.HIGH,
                    references=[url] if url else [],
                    raw=check,
                )
            )

        return findings

    def extract_metrics(
        self, result: CommandResult, ctx: RunContext, workdir: Path
    ) -> dict[str, float]:
        """Surface the 0-10 aggregate for the scoring model.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: Unused.

        Returns:
            ``{"aggregate": score}``, or empty when Scorecard reported no aggregate.
        """
        del ctx, workdir
        payload = _load(result.stdout)
        if payload is None:
            return {}
        score = payload.get("score")
        if not isinstance(score, (int, float)) or score == INCONCLUSIVE:
            return {}
        return {AGGREGATE_METRIC: float(score)}


def _severity_for(check_name: str, score: int) -> Severity:
    """Map a Scorecard check score to a normalized severity.

    Scorecard's own scale is 0-10 per check with no severity concept, so this
    mapping is ours and is published in ``docs/methodology/scoring.md``.

    Args:
        check_name: The Scorecard check name.
        score: The check's 0-10 score.

    Returns:
        The normalized severity.
    """
    if score == 0 and check_name in CRITICAL_CHECKS:
        return Severity.HIGH
    if score <= 2:
        return Severity.MEDIUM
    if score <= 6:
        return Severity.LOW
    return Severity.INFO


def _load(stdout: str) -> dict[str, Any] | None:
    """Parse Scorecard's JSON output.

    Args:
        stdout: Raw stdout from the tool.

    Returns:
        The parsed payload, or ``None`` when output was empty or malformed.
    """
    text = stdout.strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _tool_version(payload: dict[str, Any]) -> str:
    """Read the Scorecard version from its own output.

    More reliable than parsing ``--version``, because it reports the binary that
    actually produced these results.

    Args:
        payload: Parsed Scorecard output.

    Returns:
        The version string, or ``"unknown"``.
    """
    meta = payload.get("scorecard")
    if isinstance(meta, dict):
        version = meta.get("version")
        if isinstance(version, str) and version:
            return version
    return "unknown"


PLUGIN = ScorecardPlugin()
