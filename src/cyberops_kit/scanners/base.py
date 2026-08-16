"""Scanner plugin interface.

Adding a scanner is the most common contribution to this project, so the surface a
contributor has to implement is deliberately small: declare a ``name``, a
``version_command``, an ``applies_to``, a ``build_command``, and a ``parse``. The
base class handles availability detection, version capture, execution mode,
timeouts, offline enforcement, and error classification.

Three rules a plugin must never break (see docs/contributing/add-a-scanner.md):

* A plugin never computes a score.
* A plugin never mutates another plugin's findings.
* A plugin never writes outside its own temp directory.

The first two are structural here — ``parse`` receives only its own process output
and returns only ``Finding`` objects, and ``Finding`` is frozen.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Final

import structlog
from pydantic import BaseModel, ConfigDict, Field

from cyberops_kit.core.errors import (
    SandboxError,
    SandboxTimeoutError,
    SandboxUnavailableError,
    ScannerError,
)
from cyberops_kit.core.models import (
    Category,
    DimensionKey,
    Finding,
    ProjectProfile,
    RunContext,
    ScannerRef,
    SLSAAssessment,
)
from cyberops_kit.core.sandbox import (
    CommandResult,
    Sandbox,
    SandboxSpec,
    run_host,
)

logger = structlog.get_logger(__name__)

# The lookbehind, rather than \b, is what makes a "v" prefix work: in "v5.0.0" there
# is no word boundary between "v" and "5", so \b would skip ahead and capture "0.0".
_VERSION_RE: Final = re.compile(r"(?<![\d.])(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?)")
UNKNOWN_VERSION: Final = "unknown"


class ExecutionMode(StrEnum):
    """Where a scanner is allowed to run.

    ``HOST`` is reserved for trusted analyzers that read the target tree without
    executing anything from it. ``SANDBOX`` is required for anything that resolves
    a dependency graph or invokes a build tool (INV-5).
    """

    HOST = "host"
    SANDBOX = "sandbox"


class ScanOutcome(StrEnum):
    """How a scanner run ended."""

    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class ScanResult(BaseModel):
    """What one scanner produced, including why it produced nothing.

    A skipped scanner is a first-class outcome, not an error. Its dimension is
    excluded from scoring rather than counted as a failure, and the exclusion is
    stated in the report (Phase 1 spec §4).
    """

    model_config = ConfigDict(frozen=True)

    scanner: str
    version: str = UNKNOWN_VERSION
    outcome: ScanOutcome
    findings: list[Finding] = Field(default_factory=list)
    metrics: dict[str, float] = Field(default_factory=dict)
    """Scalar measurements a dimension needs but that are not findings, such as
    Scorecard's 0-10 aggregate. Deterministic, and therefore safe for scoring."""

    slsa: SLSAAssessment | None = None
    """Set only by the SLSA evaluator. Flows into the ``Results`` envelope."""

    documents: dict[str, str] = Field(default_factory=dict)
    """Serialized artifacts produced by the scanner, such as Syft's SBOMs, keyed by
    format name. Held in memory because a plugin's temp directory is destroyed when
    it finishes; the orchestrator decides where these are written."""

    reason: str | None = None
    detail: str | None = None
    duration_seconds: float = 0.0
    dimension: DimensionKey | None = None

    @property
    def produced_data(self) -> bool:
        """Return whether this run yielded usable data for scoring.

        A completed run with zero findings is still data — it means the scanner
        looked and found nothing, which is a genuine 100 for that dimension.
        """
        return self.outcome is ScanOutcome.COMPLETED


class ScannerPlugin(ABC):
    """Base class for every external tool integration."""

    name: str
    """Plugin identifier. Matches the module name and the config entry."""

    version_command: Sequence[str]
    """Argv that prints the tool's version, e.g. ``("osv-scanner", "--version")``."""

    categories: frozenset[Category] = frozenset()
    """Finding categories this scanner can produce. Documentation, not enforcement."""

    dimension: DimensionKey | None = None
    """Scoring dimension this scanner feeds. ``None`` when it feeds none directly."""

    execution_mode: ExecutionMode = ExecutionMode.HOST
    requires_network: bool = False
    """When true, the scanner is skipped under ``--offline`` (INV-6)."""

    ok_returncodes: frozenset[int] = frozenset({0})
    """Exit codes treated as success. Many scanners exit non-zero when they find
    something, which is not a failure of the scanner."""

    depends_on: frozenset[str] = frozenset()
    """Scanners whose results this one derives from. The orchestrator schedules
    dependents in a later wave and hands them the earlier results."""

    env_passthrough: frozenset[str] = frozenset()
    """Environment variables this scanner needs forwarded from the host.

    ``run_host`` deliberately starts from a minimal environment — ``PATH``, ``HOME``,
    ``LANG`` — so that a scanner subprocess cannot read whatever happens to be in the
    operator's shell. That default is right, but it is silent: a variable a tool
    genuinely requires is dropped with no warning, and the tool misbehaves in a way
    that looks like the tool's fault.

    That is exactly what happened to Scorecard. ``GITHUB_AUTH_TOKEN`` was set in CI
    and stripped here, so Scorecard ran unauthenticated, stalled against the API rate
    limit, and was reported as a timeout on every run.

    Declaring a variable here forwards it, and only it. Naming the variables keeps the
    allowlist auditable — the alternative, passing the whole environment through, would
    hand every scanner every secret in the shell.
    """

    @abstractmethod
    def applies_to(self, profile: ProjectProfile) -> bool:
        """Return whether this scanner is relevant to the detected project.

        Args:
            profile: The detected project profile.

        Returns:
            True when the scanner should run.
        """

    @abstractmethod
    def build_command(self, ctx: RunContext, workdir: Path) -> list[str]:
        """Return the argv to execute.

        Args:
            ctx: The current run context.
            workdir: A private temp directory this scanner may write to.

        Returns:
            The command to run.
        """

    @abstractmethod
    def parse(self, result: CommandResult, ctx: RunContext, workdir: Path) -> list[Finding]:
        """Map native tool output into canonical findings.

        Implementations preserve the tool's original record in ``Finding.raw`` and
        build IDs with ``Finding.build`` so ID computation stays in one place.

        Args:
            result: The completed command, with stdout and stderr.
            ctx: The current run context.
            workdir: The scanner's private temp directory.

        Returns:
            Canonical findings. May be empty.
        """

    def preflight(self, ctx: RunContext) -> str | None:
        """Return a skip reason when the run cannot proceed, or ``None`` to run.

        Lets a scanner decline cleanly for a reason that depends on the run rather
        than the profile — Scorecard needs a remote repository URL, for instance, and
        a local-only checkout has none. Declining here yields a ``SKIPPED`` result
        with an honest explanation instead of a confusing tool error.

        Args:
            ctx: The current run context.

        Returns:
            A human-readable skip reason, or ``None``.
        """
        del ctx
        return None

    def exclude_args(self, patterns: Sequence[str]) -> list[str]:
        """Return native argv flags that skip ``patterns``, when the tool has them.

        This is an **optimization, not a correctness mechanism**. ``exclude_paths`` is
        enforced centrally in ``core/normalize.py`` after every scanner has run, so a
        plugin that returns nothing here is still fully compliant — it just spends
        time scanning files whose findings are discarded.

        Only wire this up for flags that are stable and precisely scoped. OSV-Scanner
        deliberately does not implement it: its ``--experimental-exclude`` was
        measured either ignoring the pattern or excluding every package source in the
        tree depending on syntax, and a flag that can silently blank a whole dimension
        is worse than no flag.

        Args:
            patterns: Configured exclusion patterns.

        Returns:
            Extra argv entries. Empty by default.
        """
        del patterns
        return []

    def extract_documents(
        self, result: CommandResult, ctx: RunContext, workdir: Path
    ) -> dict[str, str]:
        """Return serialized artifacts this scanner produced.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: The scanner's private temp directory.

        Returns:
            Format name to serialized content. Empty by default.
        """
        del result, ctx, workdir
        return {}

    def extract_metrics(
        self, result: CommandResult, ctx: RunContext, workdir: Path
    ) -> dict[str, float]:
        """Return scalar measurements this scanner contributes to scoring.

        Most scanners contribute only findings and need not override this. Scorecard
        overrides it to surface its 0-10 aggregate, which is a measurement rather
        than a finding.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: The scanner's private temp directory.

        Returns:
            Metric name to value. Empty by default.
        """
        del result, ctx, workdir
        return {}

    # --- Provided by the base class --------------------------------------------

    @property
    def executable(self) -> str:
        """Return the binary name, taken from ``version_command``."""
        return self.version_command[0]

    def is_available(self) -> bool:
        """Return whether the tool's binary can be found on PATH.

        Sandboxed scanners rely on the container image instead, so availability is
        reported by the sandbox rather than by PATH.
        """
        if self.execution_mode is ExecutionMode.SANDBOX:
            return True
        return shutil.which(self.executable) is not None

    async def detect_version(self) -> str:
        """Return the installed tool version.

        Recorded in ``run_metadata.tool_versions``: a tool version change is a
        legitimate reason for a score to move and must be traceable (INV-3).

        Returns:
            The parsed version, or ``"unknown"`` when it cannot be determined.
        """
        try:
            result = await run_host(self.version_command, timeout_seconds=30)
        except (SandboxError, OSError):
            return UNKNOWN_VERSION
        return self.parse_version(f"{result.stdout}\n{result.stderr}")

    @staticmethod
    def parse_version(output: str) -> str:
        """Extract a version string from a tool's ``--version`` output.

        Args:
            output: Combined stdout and stderr from the version command.

        Returns:
            The first semver-looking token, or ``"unknown"``.
        """
        match = _VERSION_RE.search(output)
        return match.group(1) if match else UNKNOWN_VERSION

    async def run(self, ctx: RunContext) -> ScanResult:
        """Execute the scanner and normalize its output.

        Never raises for an expected condition. A missing binary, an offline
        conflict, a timeout, or a crash all come back as a ``ScanResult`` with the
        reason recorded, so one broken tool cannot abort an otherwise good run.

        Args:
            ctx: The current run context.

        Returns:
            The scan result, whatever the outcome.
        """
        if self.requires_network and ctx.offline:
            return self._skipped(
                "offline",
                f"{self.name} requires network access and --offline is absolute (INV-6)",
            )

        if not self.is_available():
            return self._skipped(
                "not_installed",
                f"{self.executable!r} was not found on PATH",
            )

        if (reason := self.preflight(ctx)) is not None:
            return self._skipped("preflight", reason)

        version = await self.detect_version()

        try:
            with self.workdir() as workdir:
                command = self.build_command(ctx, workdir)
                result = await self._execute(command, ctx)

                if result.returncode not in self.ok_returncodes:
                    return ScanResult(
                        scanner=self.name,
                        version=version,
                        outcome=ScanOutcome.FAILED,
                        reason="nonzero_exit",
                        detail=_tail(result.stderr or result.stdout),
                        duration_seconds=result.duration_seconds,
                        dimension=self.dimension,
                    )

                findings = _stamp_version(self.parse(result, ctx, workdir), version)
                metrics = self.extract_metrics(result, ctx, workdir)
                documents = self.extract_documents(result, ctx, workdir)

            return ScanResult(
                scanner=self.name,
                version=version,
                outcome=ScanOutcome.COMPLETED,
                findings=findings,
                metrics=metrics,
                documents=documents,
                duration_seconds=result.duration_seconds,
                dimension=self.dimension,
            )

        except SandboxTimeoutError as exc:
            return ScanResult(
                scanner=self.name,
                version=version,
                outcome=ScanOutcome.TIMED_OUT,
                reason="timeout",
                detail=exc.message,
                dimension=self.dimension,
            )
        except SandboxUnavailableError as exc:
            return self._skipped("sandbox_unavailable", exc.message, version=version)
        except (ScannerError, SandboxError) as exc:
            return ScanResult(
                scanner=self.name,
                version=version,
                outcome=ScanOutcome.FAILED,
                reason="scanner_error",
                detail=exc.message,
                dimension=self.dimension,
            )
        except (OSError, ValueError) as exc:
            # A malformed payload from one tool must not take down the whole run.
            logger.warning("scanner.unexpected_error", scanner=self.name, error=str(exc))
            return ScanResult(
                scanner=self.name,
                version=version,
                outcome=ScanOutcome.FAILED,
                reason="unexpected_error",
                detail=str(exc),
                dimension=self.dimension,
            )

    async def run_with(self, ctx: RunContext, prior: Mapping[str, ScanResult]) -> ScanResult:
        """Execute the scanner, given the results of the scanners it depends on.

        Plugins with no dependencies ignore ``prior`` entirely; the orchestrator
        calls this uniformly so it does not need to special-case derived scanners.

        Args:
            ctx: The current run context.
            prior: Results of already-completed scanners, keyed by name.

        Returns:
            The scan result.
        """
        del prior
        return await self.run(ctx)

    async def _execute(self, command: list[str], ctx: RunContext) -> CommandResult:
        """Run the built command through the appropriate execution path.

        Args:
            command: Argv to execute.
            ctx: The current run context.

        Returns:
            The command result.
        """
        timeout = ctx.config.scanners.timeout_for(self.name)

        if self.execution_mode is ExecutionMode.SANDBOX:
            # Sandboxed scanners get no host environment at all. Forwarding a
            # credential into a container that runs untrusted code is the one place
            # this allowlist must not reach (INV-5).
            sandbox = Sandbox(
                SandboxSpec(
                    image=ctx.config.sandbox.image,
                    workspace=ctx.workspace,
                    network="none" if ctx.offline else ctx.config.sandbox.network,
                    memory_limit=ctx.config.sandbox.memory_limit,
                    cpu_limit=ctx.config.sandbox.cpu_limit,
                    read_only_root=ctx.config.sandbox.read_only_root,
                ),
                runtime=ctx.config.sandbox.runtime,
            )
            return await sandbox.run(command, timeout_seconds=timeout)

        return await run_host(
            command,
            cwd=ctx.workspace,
            timeout_seconds=timeout,
            env=self.host_env(),
        )

    def host_env(self) -> dict[str, str]:
        """Return the host environment variables this scanner declared it needs.

        Variables that are unset or empty are omitted rather than forwarded as an
        empty string, because some tools treat an empty credential as a present one
        and fail in a more confusing way than they would with nothing at all.

        Returns:
            The forwarded subset of the environment. Empty for most scanners.
        """
        return {
            name: value
            for name in sorted(self.env_passthrough)
            if (value := os.environ.get(name, "").strip())
        }

    @contextmanager
    def workdir(self) -> Iterator[Path]:
        """Yield a private temp directory, removed when the scan finishes.

        A plugin never writes outside this directory (see docs/contributing/add-a-scanner.md).

        Yields:
            Path to a fresh temp directory.
        """
        with tempfile.TemporaryDirectory(prefix=f"cyberops-{self.name}-") as tmp:
            yield Path(tmp)

    def _skipped(self, reason: str, detail: str, *, version: str = UNKNOWN_VERSION) -> ScanResult:
        """Build a skipped result.

        Args:
            reason: Machine-readable skip reason.
            detail: Human-readable explanation shown in the report.
            version: Tool version, when it was determined before the skip.

        Returns:
            A skipped scan result.
        """
        logger.info("scanner.skipped", scanner=self.name, reason=reason, detail=detail)
        return ScanResult(
            scanner=self.name,
            version=version,
            outcome=ScanOutcome.SKIPPED,
            reason=reason,
            detail=detail,
            dimension=self.dimension,
        )


def _stamp_version(findings: list[Finding], version: str) -> list[Finding]:
    """Record the detected tool version on findings that did not set one.

    Plugins that can read their version out of the tool's own output — Scorecard,
    for instance — keep what they parsed, since that reflects the binary that
    actually produced the results. Everyone else gets the detected version.

    Finding IDs are derived from the scanner *name*, never the version, so a tool
    upgrade does not renumber every finding and break delta comparison.

    Args:
        findings: Findings returned by ``parse``.
        version: Version detected by ``detect_version``.

    Returns:
        Findings with a populated scanner version.
    """
    if version == UNKNOWN_VERSION:
        return findings
    return [
        finding
        if finding.scanner.version != UNKNOWN_VERSION
        else finding.model_copy(
            update={"scanner": ScannerRef(name=finding.scanner.name, version=version)}
        )
        for finding in findings
    ]


def _tail(text: str, limit: int = 500) -> str:
    """Return the last ``limit`` characters of tool output for an error detail.

    Args:
        text: Raw tool output.
        limit: Maximum characters to keep.

    Returns:
        The trailing slice, stripped.
    """
    cleaned = text.strip()
    return cleaned[-limit:] if len(cleaned) > limit else cleaned
