"""Historical results, stored on the local filesystem and keyed by commit SHA.

Two consumers: the PR comment, which needs a delta against the base branch, and the
trend dashboard, which needs a time series. Both are only possible because finding
IDs are stable content hashes rather than line numbers — the whole reason
``compute_finding_id`` exists.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cyberops_kit.core.errors import StorageError
from cyberops_kit.core.models import Finding, Grade, Report

logger = structlog.get_logger(__name__)

HISTORY_DIRNAME: Final = "history"
INDEX_FILENAME: Final = "index.json"
MAX_HISTORY_ENTRIES: Final = 500


class HistoryEntry(BaseModel):
    """One recorded run, summarized for the trend series."""

    model_config = ConfigDict(frozen=True)

    commit_sha: str
    repository: str
    composite: int
    grade: Grade
    finding_count: int
    critical: int = 0
    high: int = 0
    recorded_at: str
    scoring_model_version: str
    ref: str | None = None


class Delta(BaseModel):
    """Difference between two runs, for the PR comment."""

    model_config = ConfigDict(frozen=True)

    new: list[Finding] = Field(default_factory=list)
    fixed: list[Finding] = Field(default_factory=list)
    unchanged: int = 0
    score_change: int | None = None


class History:
    """Reads and writes run history under an output directory."""

    def __init__(self, root: Path) -> None:
        """Initialize storage.

        Args:
            root: The output directory; history lives in a subdirectory of it.
        """
        self.root = root / HISTORY_DIRNAME

    @property
    def index_path(self) -> Path:
        """Return the path to the trend index."""
        return self.root / INDEX_FILENAME

    def record(self, report: Report) -> Path:
        """Store a run and update the trend index.

        Args:
            report: The completed report. Redact it before calling this — the stored
                artifact is a file on disk like any other (INV-4).

        Returns:
            Path to the stored run.

        Raises:
            StorageError: The run could not be written.
        """
        commit = report.results.target.commit_sha
        destination = self.root / f"{commit}.json"

        try:
            self.root.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            raise StorageError(f"could not record run to {destination}: {exc}") from exc

        self._update_index(report)
        logger.debug("storage.recorded", commit=commit[:12], path=str(destination))
        return destination

    def load(self, commit_sha: str) -> Report | None:
        """Load a previously recorded run.

        Args:
            commit_sha: The commit to look up.

        Returns:
            The report, or ``None`` when it was never recorded or is unreadable.
        """
        path = self.root / f"{commit_sha}.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

        try:
            return Report.model_validate(payload)
        except ValidationError:
            # A report written by an incompatible schema version. Not fatal: the
            # delta is simply unavailable, and the current run still succeeds.
            logger.warning("storage.incompatible_record", commit=commit_sha[:12])
            return None

    def entries(self) -> list[HistoryEntry]:
        """Return the trend series, oldest first.

        Returns:
            Recorded entries, or an empty list when no history exists.
        """
        try:
            payload = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []

        if not isinstance(payload, list):
            return []

        entries: list[HistoryEntry] = []
        for item in payload:
            try:
                entries.append(HistoryEntry.model_validate(item))
            except ValidationError:
                continue
        return entries

    def _update_index(self, report: Report) -> None:
        """Append this run to the trend index, replacing any run for the same commit.

        Args:
            report: The completed report.

        Raises:
            StorageError: The index could not be written.
        """
        findings = report.results.findings
        entry = HistoryEntry(
            commit_sha=report.results.target.commit_sha,
            repository=report.results.target.repository,
            composite=report.results.score.composite,
            grade=report.results.score.grade,
            finding_count=len(findings),
            critical=sum(1 for f in findings if f.severity.value == "critical"),
            high=sum(1 for f in findings if f.severity.value == "high"),
            recorded_at=report.run_metadata.completed_at.isoformat(),
            scoring_model_version=report.results.scoring_model_version,
            ref=report.results.target.ref,
        )

        entries = [e for e in self.entries() if e.commit_sha != entry.commit_sha]
        entries.append(entry)
        trimmed = entries[-MAX_HISTORY_ENTRIES:]

        try:
            self.index_path.write_text(
                json.dumps(
                    [e.model_dump(mode="json") for e in trimmed], indent=2, ensure_ascii=False
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            raise StorageError(f"could not update history index: {exc}") from exc


def compare(current: Report, baseline: Report | None) -> Delta:
    """Compute the finding delta between two runs.

    Matching is by ``Finding.id``, the stable content hash. That is what makes
    "3 new, 5 fixed since main" survive a refactor that moved every line.

    Args:
        current: The run being reported.
        baseline: The run to compare against, or ``None`` when there is no baseline.

    Returns:
        The delta. With no baseline, every finding counts as unchanged rather than
        new — reporting an entire backlog as "new" on the first run would be noise.
    """
    if baseline is None:
        return Delta(unchanged=len(current.results.findings))

    current_by_id = {f.id: f for f in current.results.findings}
    baseline_ids = {f.id for f in baseline.results.findings}

    new = [f for finding_id, f in current_by_id.items() if finding_id not in baseline_ids]
    fixed = [f for f in baseline.results.findings if f.id not in current_by_id]

    return Delta(
        new=sorted(new, key=lambda f: (f.severity.rank, f.id)),
        fixed=sorted(fixed, key=lambda f: (f.severity.rank, f.id)),
        unchanged=len(current_by_id) - len(new),
        score_change=current.results.score.composite - baseline.results.score.composite,
    )


def delta_context(delta: Delta) -> dict[str, Any]:
    """Convert a delta into a template context mapping.

    Args:
        delta: The computed delta.

    Returns:
        The mapping consumed by ``pr_comment.md.j2``.
    """
    return {
        "new": delta.new,
        "fixed": delta.fixed,
        "unchanged": delta.unchanged,
        "score_change": delta.score_change,
    }
