"""Normalization — merge per-scanner findings into one canonical, ordered set.

Each scanner plugin already maps its own native output into ``Finding``; that is
where format-specific knowledge belongs. This stage is what happens *after*: merging
results from every scanner, removing exact duplicates, and imposing the canonical
order that scoring and reporting both depend on.

Cross-scanner deduplication — recognizing that OSV's `GHSA-xxxx` and Trivy's
`CVE-yyyy` describe the same defect in the same package — is deliberately **not**
done here. Trivy is configured to scan misconfigurations only, so the Phase 1
scanner set produces no meaningful overlap, and a merge heuristic that silently drops
a real finding is worse than a duplicate a human can see.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

import structlog

from cyberops_kit.core.models import Finding, sort_findings
from cyberops_kit.scanners.base import ScanResult

logger = structlog.get_logger(__name__)


def normalize(results: Iterable[ScanResult]) -> list[Finding]:
    """Merge scanner results into one canonically-ordered finding set.

    Args:
        results: Results from every scanner that ran.

    Returns:
        Deduplicated findings in canonical order.
    """
    collected: list[Finding] = []
    for result in results:
        collected.extend(result.findings)
    return sort_findings(deduplicate(collected))


def deduplicate(findings: Sequence[Finding]) -> list[Finding]:
    """Remove findings that share an ID.

    A repeated ID means the same scanner reported the same rule at the same anchor
    twice — a lockfile listing a package in two dependency groups, for instance. The
    first occurrence wins, which is stable because the caller sorted first.

    Args:
        findings: Findings from all scanners.

    Returns:
        Findings with duplicate IDs removed, in input order.
    """
    seen: set[str] = set()
    unique: list[Finding] = []

    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        unique.append(finding)

    dropped = len(findings) - len(unique)
    if dropped:
        logger.debug("normalize.deduplicated", dropped=dropped, kept=len(unique))

    return unique


def assert_unique_ids(findings: Sequence[Finding]) -> None:
    """Verify no two findings share an ID.

    Stable IDs are what make PR deltas, the trend dashboard, and suppression files
    work. A collision would silently corrupt all three, so it is checked rather than
    assumed.

    Args:
        findings: Findings to verify.

    Raises:
        ValueError: Two findings share an ID.
    """
    seen: dict[str, Finding] = {}
    for finding in findings:
        existing = seen.get(finding.id)
        if existing is not None:
            msg = (
                f"finding ID collision on {finding.id!r}: "
                f"{existing.scanner.name}/{existing.rule_id} and "
                f"{finding.scanner.name}/{finding.rule_id}"
            )
            raise ValueError(msg)
        seen[finding.id] = finding
