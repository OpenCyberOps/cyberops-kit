"""Enrichment stage — a passthrough in Phase 1, the Phase 2 seam (SEAM-2).

The orchestrator calls :func:`run_enrichment` between normalize and score from day
one. In Phase 1 the registry is empty and this is a no-op, which is the point: the
pipeline never has to be rewritten to accommodate an advisory layer.

**Do not delete this module because it looks unused.** It is a load-bearing seam
(see ``docs/adr/0004-ai-boundary.md``).

The contract an enricher must honor is enforced here at runtime, not left to code
review. An enricher may only populate ``Finding.advisory``. Adding findings,
removing findings, reordering identity, or touching any other field aborts the run.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import structlog

from cyberops_kit.core.errors import EnrichmentContractError
from cyberops_kit.core.models import Finding, RunContext

logger = structlog.get_logger(__name__)

_ADVISORY_FIELD = "advisory"


class Enricher(ABC):
    """Attaches non-authoritative annotations to findings.

    Implementations live in ``cyberops_kit.advisors`` and are registered in
    :data:`ENRICHERS`. An enricher never grades, never re-ranks severity, never
    suppresses a finding, and never feeds a value into scoring (INV-2).
    """

    name: str
    version: str

    @abstractmethod
    def applies_to(self, finding: Finding) -> bool:
        """Return whether this enricher has anything to say about a finding.

        Args:
            finding: The candidate finding.

        Returns:
            True when the finding should be passed to :meth:`enrich`.
        """

    @abstractmethod
    async def enrich(self, findings: list[Finding], ctx: RunContext) -> list[Finding]:
        """Return the findings with ``advisory`` populated where applicable.

        Args:
            findings: Findings selected by :meth:`applies_to`, plus any others the
                caller passed through unchanged.
            ctx: The current run context, including configuration and offline state.

        Returns:
            The same findings, with advisories attached. No additions, no removals,
            no other field modified.
        """


ENRICHERS: list[Enricher] = []
"""Registered enrichers. Empty in Phase 1; Phase 2 registers here."""


async def run_enrichment(findings: list[Finding], ctx: RunContext) -> list[Finding]:
    """Run every registered enricher in order.

    A no-op passthrough when no enrichers are registered, which is always the case
    in Phase 1.

    Args:
        findings: Normalized findings from the scan stage.
        ctx: The current run context.

    Returns:
        The findings, possibly with advisories attached.

    Raises:
        EnrichmentContractError: An enricher modified anything other than
            ``advisory``, or added or removed a finding.
    """
    if not ENRICHERS:
        return findings

    for enricher in ENRICHERS:
        before = findings
        after = await enricher.enrich(list(before), ctx)
        _assert_contract(before, after, enricher=enricher.name)
        findings = after
        logger.debug(
            "enrichment.applied",
            enricher=enricher.name,
            version=enricher.version,
            annotated=sum(1 for f in after if f.advisory is not None),
        )

    return findings


def _assert_contract(before: list[Finding], after: list[Finding], *, enricher: str) -> None:
    """Verify an enricher touched only the ``advisory`` field.

    Args:
        before: Findings as they were handed to the enricher.
        after: Findings the enricher returned.
        enricher: Enricher name, for the error message.

    Raises:
        EnrichmentContractError: The enricher breached the SEAM-2 contract.
    """
    if len(before) != len(after):
        raise EnrichmentContractError(
            f"enricher {enricher!r} changed the finding count "
            f"({len(before)} -> {len(after)}); enrichers annotate, they never add or remove"
        )

    original = {finding.id: finding for finding in before}
    if len(original) != len(before):
        raise EnrichmentContractError(
            f"duplicate finding IDs were passed to enricher {enricher!r}; "
            "finding IDs must be unique before enrichment"
        )

    for finding in after:
        source = original.get(finding.id)
        if source is None:
            raise EnrichmentContractError(
                f"enricher {enricher!r} returned unknown finding id {finding.id!r}; "
                "enrichers may not create findings"
            )
        changed = _changed_fields(source, finding)
        if changed:
            raise EnrichmentContractError(
                f"enricher {enricher!r} modified non-advisory field(s) "
                f"{sorted(changed)} on finding {finding.id!r}; "
                "only 'advisory' may be populated (INV-2)"
            )


def _changed_fields(before: Finding, after: Finding) -> set[str]:
    """Return the names of fields that differ, ignoring ``advisory``.

    Args:
        before: The original finding.
        after: The returned finding.

    Returns:
        Names of every field that changed other than ``advisory``.
    """
    original: dict[str, Any] = before.model_dump(exclude={_ADVISORY_FIELD})
    updated: dict[str, Any] = after.model_dump(exclude={_ADVISORY_FIELD})
    return {key for key, value in original.items() if updated.get(key) != value}


def register(enricher: Enricher) -> None:
    """Register an enricher.

    Phase 2 calls this at import time. Phase 1 never does.

    Args:
        enricher: The enricher to append to the registry.
    """
    ENRICHERS.append(enricher)


def clear_registry() -> None:
    """Remove all registered enrichers.

    Used by tests to restore the empty Phase 1 state after registering a fake.
    """
    ENRICHERS.clear()
