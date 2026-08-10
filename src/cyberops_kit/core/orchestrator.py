"""Pipeline orchestration.

Executes the fixed pipeline, in this order and only this order:

``ingest → detect → scan → normalize → enrich → score → report``

``report`` is the caller's job — this module returns a ``Report`` and writes nothing.

Two details worth knowing:

**The enrich stage is called unconditionally**, from day one, even though the Phase 1
registry is empty. That is the point of SEAM-2: Phase 2 registers an enricher and the
pipeline does not change.

**Scanners run concurrently in dependency waves.** Most run in one wave; the SLSA
evaluator declares ``depends_on = {"scorecard"}`` and runs in a second wave with the
first wave's results handed to it.
"""

from __future__ import annotations

import asyncio
import socket
import uuid
from datetime import UTC, datetime
from pathlib import Path

import structlog

from cyberops_kit import __version__
from cyberops_kit.config import Settings
from cyberops_kit.core.detector import detect_project
from cyberops_kit.core.enrichment import run_enrichment
from cyberops_kit.core.ingest import git_version
from cyberops_kit.core.models import (
    DimensionKey,
    ExcludedScanner,
    ExclusionOutcome,
    Finding,
    ProjectProfile,
    Report,
    Results,
    RunContext,
    RunMetadata,
    SBOMSummary,
    SLSAAssessment,
    Target,
)
from cyberops_kit.core.normalize import normalize
from cyberops_kit.core.scoring import SCORING_MODEL_VERSION, ScoringContext, compute_score
from cyberops_kit.sbom.analyze import analyze_sbom
from cyberops_kit.scanners import registry
from cyberops_kit.scanners.base import ScannerPlugin, ScanOutcome, ScanResult
from cyberops_kit.scanners.scorecard import AGGREGATE_METRIC
from cyberops_kit.scanners.syft import COMPONENT_COUNT_METRIC

logger = structlog.get_logger(__name__)

MAX_WAVES = 4
"""Guard against a dependency cycle in the plugin registry."""


class Pipeline:
    """Runs the full assessment pipeline for one target."""

    def __init__(self, settings: Settings) -> None:
        """Initialize the pipeline.

        Args:
            settings: Resolved configuration for this run.
        """
        self.settings = settings

    async def run(self, workspace: Path, target: Target) -> Report:
        """Execute the pipeline and return the complete report envelope.

        Args:
            workspace: The ingested tree to analyze.
            target: The resolved, commit-pinned target.

        Returns:
            The report, with deterministic ``results`` and nondeterministic
            ``run_metadata`` kept strictly separate (INV-3).
        """
        run_id = uuid.uuid4().hex
        started_at = datetime.now(UTC)

        profile = detect_project(
            workspace, exclude_paths=tuple(self.settings.scanners.exclude_paths)
        )
        logger.info(
            "pipeline.detected",
            languages=profile.language_names[:5],
            package_managers=[m.value for m in profile.package_managers],
        )

        ctx = RunContext(
            run_id=run_id,
            target=target,
            workspace=workspace,
            offline=self.settings.offline,
            config=self.settings,
            profile=profile,
        )

        scan_results = await self._scan(ctx, profile)
        findings = normalize(scan_results.values())

        # SEAM-2: always called, no-op in Phase 1. Do not make this conditional.
        findings = await run_enrichment(findings, ctx)

        sbom = self._analyze_sbom(scan_results)
        slsa = self._slsa_assessment(scan_results)
        scoring_context = self._scoring_context(scan_results, sbom, slsa)

        score = compute_score(findings, self.settings.scoring.weights, context=scoring_context)

        completed_at = datetime.now(UTC)
        return Report(
            results=Results(
                target=target,
                profile=profile,
                findings=findings,
                sbom=sbom,
                slsa=slsa,
                score=score,
                scoring_model_version=SCORING_MODEL_VERSION,
                excluded_scanners=self._excluded(scan_results),
            ),
            run_metadata=RunMetadata(
                run_id=run_id,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=round((completed_at - started_at).total_seconds(), 3),
                tool_versions=await self._tool_versions(scan_results),
                cyberops_version=__version__,
                offline=self.settings.offline,
                host=socket.gethostname(),
            ),
        )

    async def _scan(self, ctx: RunContext, profile: ProjectProfile) -> dict[str, ScanResult]:
        """Run every applicable scanner, in dependency waves.

        Args:
            ctx: The current run context.
            profile: The detected project profile.

        Returns:
            Scan results keyed by scanner name.
        """
        selected = registry.select(self.settings, profile)
        if not selected:
            logger.warning("pipeline.no_scanners_selected")
            return {}

        results: dict[str, ScanResult] = {}
        pending = list(selected)

        for _wave in range(MAX_WAVES):
            if not pending:
                break

            ready = [p for p in pending if p.depends_on.issubset(results.keys())]
            if not ready:
                # Dependencies that never became satisfiable — a missing scanner the
                # dependent needs. Run them anyway with what we have; a derived
                # evaluator reports reduced evidence rather than nothing.
                ready = list(pending)

            logger.info("pipeline.scan_wave", scanners=[p.name for p in ready])
            completed = await asyncio.gather(
                *(self._run_plugin(plugin, ctx, results) for plugin in ready)
            )
            for plugin, result in zip(ready, completed, strict=True):
                results[plugin.name] = result

            pending = [p for p in pending if p.name not in results]

        return results

    @staticmethod
    async def _run_plugin(
        plugin: ScannerPlugin, ctx: RunContext, prior: dict[str, ScanResult]
    ) -> ScanResult:
        """Run one plugin, converting any escaped exception into a failed result.

        The base class already handles expected failures. This is the last line of
        defense so a single misbehaving plugin cannot abort an otherwise good run.

        Args:
            plugin: The plugin to run.
            ctx: The current run context.
            prior: Results from earlier waves.

        Returns:
            The scan result.
        """
        try:
            return await plugin.run_with(ctx, dict(prior))
        except Exception as exc:
            logger.exception("pipeline.plugin_crashed", scanner=plugin.name)
            return ScanResult(
                scanner=plugin.name,
                outcome=ScanOutcome.FAILED,
                reason="plugin_crashed",
                detail=f"{type(exc).__name__}: {exc}",
                dimension=plugin.dimension,
            )

    @staticmethod
    def _analyze_sbom(results: dict[str, ScanResult]) -> SBOMSummary:
        """Derive the SBOM summary from Syft's documents.

        Args:
            results: All scan results.

        Returns:
            The SBOM summary, or an ungenerated summary when Syft did not run.
        """
        syft = results.get("syft")
        if syft is None or syft.outcome is not ScanOutcome.COMPLETED:
            return SBOMSummary(generated=False)
        reported = syft.metrics.get(COMPONENT_COUNT_METRIC)
        return analyze_sbom(
            syft.documents, component_count=int(reported) if reported is not None else None
        )

    @staticmethod
    def _slsa_assessment(results: dict[str, ScanResult]) -> SLSAAssessment:
        """Extract the SLSA assessment from the evaluator's result.

        Args:
            results: All scan results.

        Returns:
            The assessment, or a level-0 assessment with no evidence when the
            evaluator did not run.
        """
        slsa = results.get("slsa")
        if slsa is None or slsa.slsa is None:
            return SLSAAssessment()
        return slsa.slsa

    @staticmethod
    def _scoring_context(
        results: dict[str, ScanResult], sbom: SBOMSummary, slsa: SLSAAssessment
    ) -> ScoringContext:
        """Build the deterministic non-finding inputs to scoring.

        A dimension is available only when the scanner that feeds it actually
        completed. Everything else is excluded with a stated reason, rather than
        scored as zero (Phase 1 spec §4).

        Args:
            results: All scan results.
            sbom: The derived SBOM summary.
            slsa: The derived SLSA assessment.

        Returns:
            The scoring context.
        """
        available: set[DimensionKey] = set()
        reasons: dict[DimensionKey, str] = {}

        for result in results.values():
            if result.dimension is None:
                continue
            if result.produced_data:
                available.add(result.dimension)
            else:
                reasons[result.dimension] = (
                    f"{result.scanner} did not produce data ({result.reason}): "
                    f"{result.detail or 'no detail'}"
                )

        # SBOM health is fed by Syft, which owns no dimension of its own because it
        # produces an inventory rather than findings.
        syft = results.get("syft")
        if syft is not None and syft.produced_data and sbom.generated:
            available.add(DimensionKey.SBOM_HEALTH)
        elif DimensionKey.SBOM_HEALTH not in reasons:
            reasons[DimensionKey.SBOM_HEALTH] = (
                "no SBOM was generated, so SBOM health could not be measured"
            )

        for key in DimensionKey:
            if key not in available and key not in reasons:
                reasons[key] = "no scanner for this dimension ran"

        scorecard = results.get("scorecard")
        aggregate = (
            scorecard.metrics.get(AGGREGATE_METRIC)
            if scorecard is not None and scorecard.produced_data
            else None
        )
        if aggregate is None:
            available.discard(DimensionKey.OPENSSF_SCORECARD)
            reasons.setdefault(
                DimensionKey.OPENSSF_SCORECARD,
                "Scorecard did not report an aggregate score",
            )

        return ScoringContext(
            scorecard_aggregate=aggregate,
            sbom=sbom,
            slsa=slsa,
            available_dimensions=frozenset(available),
            exclusion_reasons=reasons,
        )

    @staticmethod
    def _excluded(results: dict[str, ScanResult]) -> list[ExcludedScanner]:
        """List every scanner that produced no data, with why.

        The mapping below is the point: a scanner that was never installed and a
        scanner that crashed both cost the run a dimension, but only one of them is a
        problem. Reports and the CLI present them differently on the strength of this
        field.

        Args:
            results: All scan results.

        Returns:
            Excluded scanners, sorted by name for deterministic output.
        """
        outcomes = {
            ScanOutcome.SKIPPED: ExclusionOutcome.NOT_RUN,
            ScanOutcome.FAILED: ExclusionOutcome.FAILED,
            ScanOutcome.TIMED_OUT: ExclusionOutcome.TIMED_OUT,
        }
        return [
            ExcludedScanner(
                name=result.scanner,
                outcome=outcomes[result.outcome],
                reason=result.reason or result.outcome.value,
                detail=result.detail,
            )
            for result in sorted(results.values(), key=lambda r: r.scanner)
            if result.outcome is not ScanOutcome.COMPLETED
        ]

    @staticmethod
    async def _tool_versions(results: dict[str, ScanResult]) -> dict[str, str]:
        """Collect external tool versions for ``run_metadata``.

        A tool version change is a legitimate reason for a score to move, and must be
        traceable (Phase 1 spec §4).

        Args:
            results: All scan results.

        Returns:
            Tool name to version, in sorted key order.
        """
        versions = {
            result.scanner: result.version
            for result in results.values()
            if result.version and result.version != "unknown"
        }
        if (git := await git_version()) is not None:
            versions["git"] = git
        return {name: versions[name] for name in sorted(versions)}


def unresolved_findings_count(findings: list[Finding]) -> int:
    """Count findings that block a passing threshold.

    Args:
        findings: All findings from the run.

    Returns:
        The number of findings at an actionable severity.
    """
    return sum(1 for finding in findings if finding.severity.is_actionable)
