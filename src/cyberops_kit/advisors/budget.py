"""Per-run ceilings on how much inference a scan may perform.

Two independent limits, because they fail differently. ``max_findings`` bounds the
work before it starts and is deterministic given a finding set. The token ceiling
bounds cost as it accrues, and can only be checked between calls.

Exceeding either is **clean truncation, not failure**: findings already annotated
keep their advisories, the rest pass through unannotated, and the truncation is
recorded so the report can say so. A budget that aborted the run would make the AI
layer load-bearing, which INV-2 forbids.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from cyberops_kit.core.models import Finding, Severity

logger = structlog.get_logger(__name__)

DEFAULT_MAX_TOKENS: int = 120_000
"""Total tokens across a run. Roughly 25 findings at a generous context each."""

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Budget:
    """Tracks spend against a run's ceilings.

    Attributes:
        max_findings: Most findings that may be sent for analysis.
        max_tokens: Total token ceiling across the run.
        findings_analyzed: How many findings have been sent so far.
        tokens_used: Tokens consumed so far, as reported by the provider.
        truncated: Whether a ceiling stopped enrichment early.
        truncation_reason: Operator-facing explanation, empty when not truncated.
    """

    max_findings: int
    max_tokens: int = DEFAULT_MAX_TOKENS
    findings_analyzed: int = 0
    tokens_used: int = 0
    truncated: bool = False
    truncation_reason: str = field(default="")

    def can_analyze(self) -> bool:
        """Report whether another finding may be sent.

        Returns:
            True while both ceilings have headroom.
        """
        if self.findings_analyzed >= self.max_findings:
            self._truncate(
                f"reached the configured ceiling of {self.max_findings} findings (ai.max_findings)"
            )
            return False
        if self.tokens_used >= self.max_tokens:
            self._truncate(f"reached the token ceiling of {self.max_tokens:,} tokens")
            return False
        return True

    def record(self, *, tokens: int) -> None:
        """Record the cost of one completed call.

        Args:
            tokens: Total tokens the provider reported. Providers that report no
                usage — the local one commonly does not — contribute zero, so the
                finding ceiling remains the effective bound for them.
        """
        self.findings_analyzed += 1
        self.tokens_used += max(0, tokens)

    def _truncate(self, reason: str) -> None:
        """Mark the run truncated, recording the first reason only.

        Args:
            reason: Why enrichment stopped.
        """
        if not self.truncated:
            self.truncated = True
            self.truncation_reason = reason
            logger.info(
                "advisors.budget.truncated",
                reason=reason,
                findings_analyzed=self.findings_analyzed,
                tokens_used=self.tokens_used,
            )


def select_findings(findings: list[Finding], *, limit: int) -> list[Finding]:
    """Choose which findings to analyze, most severe first.

    When the ceiling is lower than the number of candidates, the choice of *which*
    findings get analyzed must not depend on scanner completion order, or the same
    commit would produce different advisories run to run. Sorting by severity and
    then by the stable finding ID makes the selection deterministic even though the
    advisory content itself is not (INV-3 covers ``results``; this keeps the
    selection reproducible regardless).

    Args:
        findings: Candidate findings, already filtered by ``applies_to``.
        limit: Maximum number to return.

    Returns:
        At most ``limit`` findings, severity-descending then ID-ascending.
    """
    ordered = sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, len(_SEVERITY_ORDER)), f.id),
    )
    return ordered[:limit]


__all__ = ["DEFAULT_MAX_TOKENS", "Budget", "select_findings"]
