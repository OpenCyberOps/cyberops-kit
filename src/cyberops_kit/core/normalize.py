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
from fnmatch import fnmatchcase

import structlog

from cyberops_kit.core.models import Finding, PathExclusions, sort_findings
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


def path_is_excluded(path: str, patterns: Sequence[str]) -> bool:
    """Return whether a repo-relative path matches any exclusion pattern.

    Three shapes are accepted, because all three are what people actually write:

    * an exact path — ``tests/fixtures/creds.json``
    * a directory — ``tests/fixtures``, which excludes everything beneath it
    * a glob — ``**/*.min.js``, matched with :func:`fnmatch.fnmatchcase`

    Matching is case-sensitive and anchored at the repository root, so ``tests``
    excludes ``tests/a.py`` but never ``src/tests/a.py``. Erring toward matching
    less is deliberate: an over-broad pattern hides real findings, which is the
    failure mode that matters in a security tool.

    Args:
        path: Repo-relative POSIX path, as produced by ``normalize_path``.
        patterns: Configured exclusion patterns.

    Returns:
        True when the path should be excluded.
    """
    subject = path.strip("/")
    for raw in patterns:
        pattern = raw.strip().lstrip("./").rstrip("/")
        if not pattern:
            continue
        if subject == pattern or subject.startswith(f"{pattern}/"):
            return True
        if fnmatchcase(subject, pattern):
            return True
    return False


def apply_path_exclusions(
    findings: Sequence[Finding], patterns: Sequence[str]
) -> tuple[list[Finding], PathExclusions]:
    """Drop findings located under a configured excluded path.

    This is the authoritative implementation of ``scanners.exclude_paths``. It runs
    centrally, after normalization, rather than being delegated to each tool's own
    exclusion flag, because tool support is neither universal nor trustworthy:
    Gitleaks has no path flag at all, and OSV-Scanner's ``--experimental-exclude``
    was measured either ignoring the pattern entirely or excluding every package
    source in the tree, depending on the syntax used. Plugins may *additionally*
    pass a native flag to avoid scanning what will be discarded (see
    ``ScannerPlugin.exclude_args``), but correctness does not depend on it.

    Findings with no location are never excluded. A path pattern cannot speak to a
    finding about the repository as a whole.

    Args:
        findings: Canonically-ordered findings.
        patterns: Configured exclusion patterns.

    Returns:
        The surviving findings, and a disclosure record of what was removed.
    """
    kept = [
        finding
        for finding in findings
        if finding.location is None or not path_is_excluded(finding.location.path, patterns)
    ]
    suppressed = len(findings) - len(kept)

    if suppressed:
        logger.info(
            "normalize.path_excluded",
            suppressed=suppressed,
            kept=len(kept),
            patterns=list(patterns),
        )

    return kept, PathExclusions(patterns=list(patterns), suppressed_findings=suppressed)


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
