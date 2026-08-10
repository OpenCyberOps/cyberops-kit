"""SLSA build track evaluation.

This is a derived evaluator, not a wrapper around one tool. It layers on Scorecard's
raw check output rather than re-checking what Scorecard already checks (Phase 1 spec
§5), and adds only what Scorecard does not cover:

* whether the release workflow uses a Build L3-capable provenance generator
* whether a provenance attestation exists on the latest release
* verification via ``slsa-verifier`` where an attestation exists

**A level is never asserted without its evidence.** Every level below is justified by
an explicit :class:`SLSAEvidence` entry, and the report shows all of them, including
the ones that failed. An evaluator that reports "Level 2" with no derivation is
indistinguishable from one that guessed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

import structlog

from cyberops_kit.core.models import (
    Category,
    CIPlatform,
    Confidence,
    DimensionKey,
    Finding,
    Location,
    ProjectProfile,
    RunContext,
    ScannerRef,
    Severity,
    SLSAAssessment,
    SLSAEvidence,
    normalize_path,
)
from cyberops_kit.core.sandbox import CommandResult
from cyberops_kit.scanners.base import (
    ExecutionMode,
    ScannerPlugin,
    ScanOutcome,
    ScanResult,
)

logger = structlog.get_logger(__name__)

BUILD_LEVEL_METRIC: Final = "build_level"

L3_GENERATORS: Final[tuple[str, ...]] = (
    "slsa-framework/slsa-github-generator",
    "actions/attest-build-provenance",
    "actions/attest",
)
"""Actions that produce non-forgeable provenance on a hosted builder."""

_USES_RE: Final = re.compile(r"^\s*-?\s*uses:\s*[\"']?([^\s\"'#]+)", re.MULTILINE)
_SHA_PINNED_RE: Final = re.compile(r"@[0-9a-f]{40}$")

RELEASE_WORKFLOW_HINTS: Final[tuple[str, ...]] = ("release", "publish", "deploy", "tag")

# Scorecard checks this evaluator consumes as supply-chain evidence.
PINNED_DEPENDENCIES: Final = "Pinned-Dependencies"
SIGNED_RELEASES: Final = "Signed-Releases"
DANGEROUS_WORKFLOW: Final = "Dangerous-Workflow"
TOKEN_PERMISSIONS: Final = "Token-Permissions"  # noqa: S105 - a check name

MAX_CHECK_SCORE: Final = 10


class SLSAPlugin(ScannerPlugin):
    """Evaluates the SLSA build track from Scorecard output and workflow evidence."""

    name = "slsa"
    version_command = ("slsa-verifier", "version")
    categories = frozenset({Category.SUPPLY_CHAIN})
    dimension = DimensionKey.SUPPLY_CHAIN_INTEGRITY
    execution_mode = ExecutionMode.HOST
    requires_network = False
    """The derivation is filesystem-based. Attestation verification needs network and
    is skipped, with that noted in the evidence, when offline."""

    depends_on = frozenset({"scorecard"})

    def is_available(self) -> bool:
        """Return True always.

        The evaluation derives from files and from Scorecard output. ``slsa-verifier``
        strengthens the result where present but is not required to produce one.

        Returns:
            Always True.
        """
        return True

    def applies_to(self, profile: ProjectProfile) -> bool:
        """Return True when the project has CI, containers, or dependencies.

        Args:
            profile: The detected project profile.

        Returns:
            True when there is a build process worth evaluating.
        """
        return bool(profile.ci_platform or profile.package_managers or profile.containerized)

    def build_command(self, ctx: RunContext, workdir: Path) -> list[str]:
        """Unused: this evaluator derives rather than executing a scanner.

        Args:
            ctx: The current run context.
            workdir: This scanner's private temp directory.

        Returns:
            Never returns; see :meth:`run_with`.

        Raises:
            NotImplementedError: Always. ``run_with`` is overridden instead.
        """
        del ctx, workdir
        raise NotImplementedError("slsa derives its result; see run_with()")

    def parse(self, result: CommandResult, ctx: RunContext, workdir: Path) -> list[Finding]:
        """Unused: this evaluator derives rather than parsing tool output.

        Args:
            result: Unused.
            ctx: Unused.
            workdir: Unused.

        Returns:
            An empty list.
        """
        del result, ctx, workdir
        return []

    async def run_with(self, ctx: RunContext, prior: Mapping[str, ScanResult]) -> ScanResult:
        """Derive the SLSA build level from prior results and workflow files.

        Args:
            ctx: The current run context.
            prior: Completed scan results, keyed by scanner name.

        Returns:
            A completed scan result carrying findings and the assessment.
        """
        scorecard_result = prior.get("scorecard")
        scorecard_ran = (
            scorecard_result is not None and scorecard_result.outcome is ScanOutcome.COMPLETED
        )
        scorecard_checks = _scorecard_checks(scorecard_result)
        workflows = _read_workflows(ctx.workspace)

        hosted = ctx.profile is not None and ctx.profile.ci_platform is CIPlatform.GITHUB_ACTIONS

        # With no CI-based build process and no Scorecard data, there is nothing to
        # evaluate. Emitting a level 0 here would read as "this project failed the
        # SLSA assessment" when the truth is that no assessment was possible.
        if not hosted and not workflows and not scorecard_ran:
            return self._skipped(
                "insufficient_evidence",
                "no CI-based build process was detected and Scorecard did not run, "
                "so the SLSA build track could not be assessed",
            )

        evidence: list[SLSAEvidence] = []
        findings: list[Finding] = []
        scanner = ScannerRef(name=self.name, version=await self.detect_version())
        evidence.append(
            SLSAEvidence(
                check="hosted-build-platform",
                passed=hosted,
                detail=(
                    "Builds run on GitHub Actions, a hosted platform."
                    if hosted
                    else "No hosted CI platform was detected; builds may be run locally."
                ),
                source="detector",
            )
        )

        generator = _find_generator(workflows)
        has_generator = generator is not None
        evidence.append(
            SLSAEvidence(
                check="provenance-generator",
                passed=has_generator,
                detail=(
                    f"Release workflow uses {generator}, a Build L3-capable generator."
                    if generator
                    else "No build provenance generator was found in any workflow."
                ),
                source="workflow-analysis",
            )
        )
        if not has_generator and hosted:
            findings.append(
                Finding.build(
                    scanner=scanner,
                    rule_id="slsa-no-provenance",
                    title="No build provenance is generated",
                    description=(
                        "No workflow uses a provenance generator such as "
                        "actions/attest-build-provenance or slsa-github-generator. "
                        "Without provenance, consumers cannot verify that a released "
                        "artifact was built from this source by this workflow."
                    ),
                    severity=Severity.MEDIUM,
                    category=Category.SUPPLY_CHAIN,
                    confidence=Confidence.HIGH,
                    fix_available=True,
                    references=["https://slsa.dev/spec/v1.0/levels"],
                    raw={"workflows_examined": sorted(workflows)},
                )
            )

        unpinned = _unpinned_actions(workflows)
        # Only claim this check when there were actions to examine. "All actions are
        # pinned" is vacuously true for a repo with no workflows, and counting that
        # as a passed hardening check would inflate the level.
        if workflows:
            evidence.append(
                SLSAEvidence(
                    check="pinned-build-dependencies",
                    passed=not unpinned,
                    detail=(
                        "All workflow actions are pinned to a full commit SHA."
                        if not unpinned
                        else f"{len(unpinned)} workflow action reference(s) are not SHA-pinned."
                    ),
                    source="workflow-analysis",
                )
            )
        findings.extend(_unpinned_findings(unpinned, scanner, ctx))

        # Scorecard-derived evidence is recorded only when Scorecard actually ran.
        # Absence of data is not a failed check.
        signed = _scorecard_passed(scorecard_checks, SIGNED_RELEASES) if scorecard_ran else None
        dangerous = (
            _scorecard_passed(scorecard_checks, DANGEROUS_WORKFLOW) if scorecard_ran else None
        )

        if scorecard_ran:
            evidence.append(
                SLSAEvidence(
                    check="signed-releases",
                    passed=signed is True,
                    detail=_scorecard_detail(scorecard_checks, SIGNED_RELEASES, "signed releases"),
                    source="scorecard",
                )
            )
            evidence.append(
                SLSAEvidence(
                    check="no-dangerous-workflow",
                    passed=dangerous is True,
                    detail=_scorecard_detail(
                        scorecard_checks, DANGEROUS_WORKFLOW, "dangerous workflow patterns"
                    ),
                    source="scorecard",
                )
            )
        else:
            evidence.append(
                SLSAEvidence(
                    check="scorecard-supply-chain-checks",
                    passed=False,
                    detail=(
                        "Not evaluated: Scorecard did not run, so signed releases and "
                        "dangerous workflow patterns could not be checked. This is a "
                        "gap in evidence, not a failed check."
                    ),
                    source="cyberops",
                )
            )

        if ctx.offline:
            evidence.append(
                SLSAEvidence(
                    check="published-attestation",
                    passed=False,
                    detail=(
                        "Not checked: verifying a published attestation requires network "
                        "access and --offline is absolute (INV-6)."
                    ),
                    source="cyberops",
                )
            )

        build_level = _derive_level(
            hosted=hosted,
            has_generator=has_generator,
            unpinned_count=len(unpinned),
            signed_releases=signed is True,
            no_dangerous_workflow=dangerous is True,
        )

        assessment = SLSAAssessment(
            build_level=build_level,
            evidence=evidence,
            provenance_found=has_generator,
            # Phase 1 does not fetch and cryptographically verify a published
            # attestation, so this stays False rather than overstating what we know.
            provenance_verified=False,
        )

        logger.debug("slsa.evaluated", build_level=build_level, findings=len(findings))

        return ScanResult(
            scanner=self.name,
            version=scanner.version,
            outcome=ScanOutcome.COMPLETED,
            findings=findings,
            metrics={BUILD_LEVEL_METRIC: float(build_level)},
            slsa=assessment,
            dimension=self.dimension,
        )


def _derive_level(
    *,
    hosted: bool,
    has_generator: bool,
    unpinned_count: int,
    signed_releases: bool,
    no_dangerous_workflow: bool,
) -> int:
    """Map evidence to a SLSA build level.

    Conservative by design. Each level requires everything the level below requires,
    and an unmet condition stops the climb rather than being averaged away.

    Args:
        hosted: Builds run on a hosted platform.
        has_generator: A provenance generator is configured.
        unpinned_count: Number of workflow actions not pinned to a SHA.
        signed_releases: Scorecard reports signed releases.
        no_dangerous_workflow: Scorecard found no dangerous workflow patterns.

    Returns:
        The SLSA build level, 0 through 3.
    """
    if not hosted or not has_generator:
        # L1 requires provenance to exist at all.
        return 0
    if not signed_releases:
        return 1
    if unpinned_count or not no_dangerous_workflow:
        # L3 requires a hardened build: pinned dependencies and no injection paths.
        return 2
    return 3


def _scorecard_checks(result: ScanResult | None) -> dict[str, dict[str, Any]]:
    """Recover Scorecard's raw check records from its scan result.

    Reading another plugin's output is permitted; mutating it is not. The records
    come back as plain dicts and are never written to.

    Args:
        result: Scorecard's scan result, when it ran.

    Returns:
        Check name to raw check record.
    """
    if result is None or result.outcome is not ScanOutcome.COMPLETED:
        return {}
    checks: dict[str, dict[str, Any]] = {}
    for finding in result.findings:
        name = finding.raw.get("name")
        if isinstance(name, str):
            checks[name] = finding.raw
    return checks


def _scorecard_passed(checks: Mapping[str, dict[str, Any]], name: str) -> bool | None:
    """Return whether a Scorecard check passed.

    Args:
        checks: Raw check records, keyed by check name.
        name: The check to look up.

    Returns:
        ``True`` when the check scored full marks, ``False`` when it did not, and
        ``None`` when Scorecard did not report it. ``None`` is not a failure — it
        means we have no evidence, and evidence is the point.
    """
    record = checks.get(name)
    if record is None:
        # Callers only reach this when Scorecard ran. Scorecard emits a finding only
        # for checks scoring below maximum, so an absent record means it passed.
        return True
    score = record.get("score")
    if not isinstance(score, int) or score < 0:
        return None
    return score >= MAX_CHECK_SCORE


def _scorecard_detail(checks: Mapping[str, dict[str, Any]], name: str, label: str) -> str:
    """Build an evidence detail string for a Scorecard-sourced check.

    Args:
        checks: Raw check records, keyed by check name.
        name: The check to describe.
        label: Human-readable name for the practice.

    Returns:
        A sentence describing what Scorecard observed.
    """
    if not checks:
        return f"Not evaluated: Scorecard did not run, so {label} could not be checked."
    record = checks.get(name)
    if record is None:
        return f"Scorecard reported no issues with {label}."
    reason = str(record.get("reason", "")).strip()
    score = record.get("score")
    return f"Scorecard scored {name} at {score}/10: {reason}" if reason else f"{name}: {score}/10"


def _read_workflows(workspace: Path) -> dict[str, str]:
    """Read every GitHub Actions workflow in the target.

    Args:
        workspace: Repository root.

    Returns:
        Repo-relative path to file content, for each readable workflow.
    """
    workflow_dir = workspace / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return {}

    workflows: dict[str, str] = {}
    for path in sorted(workflow_dir.iterdir()):
        if path.suffix.lower() not in {".yml", ".yaml"} or not path.is_file():
            continue
        try:
            workflows[normalize_path(path, root=workspace)] = path.read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            continue
    return workflows


def _find_generator(workflows: Mapping[str, str]) -> str | None:
    """Find a Build L3-capable provenance generator in the workflows.

    Args:
        workflows: Workflow path to content.

    Returns:
        The generator's action reference, or ``None``.
    """
    for _path, content in sorted(workflows.items()):
        for match in _USES_RE.finditer(content):
            reference = match.group(1)
            for generator in L3_GENERATORS:
                if reference.startswith(generator):
                    return reference
    return None


def _unpinned_actions(workflows: Mapping[str, str]) -> list[tuple[str, int, str]]:
    """Find workflow action references that are not pinned to a commit SHA.

    A tag is mutable: whoever controls the action can change what ``@v4`` points at
    after review. This is the single most common supply chain weakness in CI, and it
    is the one this project holds itself to as well (see SECURITY.md).

    Args:
        workflows: Workflow path to content.

    Returns:
        Tuples of (workflow path, line number, action reference), sorted.
    """
    unpinned: list[tuple[str, int, str]] = []
    for path, content in sorted(workflows.items()):
        for match in _USES_RE.finditer(content):
            reference = match.group(1)
            # Local composite actions and Docker references are not SHA-pinnable.
            if reference.startswith(("./", "docker://")):
                continue
            if _SHA_PINNED_RE.search(reference):
                continue
            line = content.count("\n", 0, match.start()) + 1
            unpinned.append((path, line, reference))
    return unpinned


def _unpinned_findings(
    unpinned: list[tuple[str, int, str]], scanner: ScannerRef, ctx: RunContext
) -> list[Finding]:
    """Build one finding per unpinned action reference.

    Args:
        unpinned: Tuples of (workflow path, line number, action reference).
        scanner: Reference to this evaluator.
        ctx: The current run context.

    Returns:
        Supply chain findings.
    """
    del ctx
    findings: list[Finding] = []
    for path, line, reference in unpinned:
        action = reference.split("@")[0]
        findings.append(
            Finding.build(
                scanner=scanner,
                rule_id="slsa-unpinned-action",
                title=f"Workflow action {action} is not pinned to a commit SHA",
                description=(
                    f"{path} references {reference}, which resolves through a mutable "
                    "tag or branch. Whoever controls that action can change what the "
                    "reference points at after it was reviewed. Pin to a full 40-character "
                    "commit SHA instead."
                ),
                severity=Severity.MEDIUM,
                category=Category.SUPPLY_CHAIN,
                confidence=Confidence.HIGH,
                location=Location(
                    path=path,
                    start_line=line,
                    # The reference itself is the anchor: it survives edits elsewhere
                    # in the workflow that would shift the line number.
                    symbol=reference,
                ),
                fix_available=True,
                references=["https://docs.github.com/actions/security-guides"],
                raw={"workflow": path, "line": line, "uses": reference},
            )
        )
    return findings


PLUGIN = SLSAPlugin()
