"""Sandboxed command execution — the enforcement point for INV-5.

Analyzing a target repository sometimes requires resolving a real dependency tree,
which executes lifecycle scripts written by whoever published those packages. That
work never runs on the host.

Two execution paths, and the distinction between them is the whole design:

:meth:`Sandbox.run` — ephemeral container, no network by default, read-only root,
all capabilities dropped, non-root user. Anything that could execute code from the
target tree goes here.

:func:`run_host` — a trusted analyzer binary reading files it never executes.
Gitleaks reading git history and Semgrep pattern-matching source are in this class.
To keep that distinction from eroding into "whatever is convenient", ``run_host``
refuses to launch any program on :data:`FORBIDDEN_HOST_PROGRAMS` — the package
managers and build tools that run untrusted code by design. That check is what makes
INV-5 structural instead of a rule people remember.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

import structlog
from pydantic import BaseModel, ConfigDict, Field

from cyberops_kit.core.errors import SandboxTimeoutError, SandboxUnavailableError

logger = structlog.get_logger(__name__)

WORKSPACE_MOUNT: Final = "/workspace"
"""Where the target tree appears inside the container."""

SUPPORTED_RUNTIMES: Final[tuple[str, ...]] = ("docker", "podman")

FORBIDDEN_HOST_PROGRAMS: Final[frozenset[str]] = frozenset(
    {
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "pip",
        "pip3",
        "pipenv",
        "poetry",
        "uv",
        "go",
        "cargo",
        "mvn",
        "gradle",
        "gradlew",
        "bundle",
        "bundler",
        "gem",
        "composer",
        "dotnet",
        "nuget",
        "make",
        "cmake",
        "ninja",
        "sbt",
        "ant",
        "bazel",
        "setup.py",
    }
)
"""Programs that execute untrusted code by design. Never runnable on the host."""


class CommandResult(BaseModel):
    """Outcome of a command, whether sandboxed or host-run."""

    model_config = ConfigDict(frozen=True)

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    sandboxed: bool
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """Return whether the command exited cleanly."""
        return self.returncode == 0 and not self.timed_out


class SandboxSpec(BaseModel):
    """Isolation parameters for one sandboxed command."""

    model_config = ConfigDict(frozen=True)

    image: str
    workspace: Path
    network: str = "none"
    memory_limit: str = "2g"
    cpu_limit: str = "2"
    read_only_root: bool = True
    env: dict[str, str] = Field(default_factory=dict)
    writable_paths: list[str] = Field(default_factory=list)
    """Container paths mounted as tmpfs when the root filesystem is read-only."""


def detect_runtime(preferred: str = "docker") -> str | None:
    """Find an available container runtime.

    Args:
        preferred: Runtime to try first, from configuration.

    Returns:
        The runtime executable name, or ``None`` when none is installed.
    """
    ordered = (preferred, *(r for r in SUPPORTED_RUNTIMES if r != preferred))
    for runtime in ordered:
        if shutil.which(runtime):
            return runtime
    return None


class Sandbox:
    """Runs commands inside ephemeral, network-restricted containers."""

    def __init__(self, spec: SandboxSpec, *, runtime: str = "docker") -> None:
        """Initialize the sandbox.

        Args:
            spec: Isolation parameters.
            runtime: Preferred container runtime.

        Raises:
            SandboxUnavailableError: No container runtime is installed. There is no
                host fallback — that would defeat INV-5.
        """
        resolved = detect_runtime(runtime)
        if resolved is None:
            raise SandboxUnavailableError(
                f"no container runtime found (tried: {', '.join(SUPPORTED_RUNTIMES)})",
                remediation=(
                    "Install Docker or Podman, or use the published container image "
                    "which bundles every scanner. Untrusted dependency resolution is "
                    "never run on the host (INV-5)."
                ),
            )
        self.runtime = resolved
        self.spec = spec

    async def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int = 600,
        workdir: str = WORKSPACE_MOUNT,
    ) -> CommandResult:
        """Run a command inside a fresh container.

        The container is removed on exit, gets no network unless the spec grants it,
        drops all capabilities, and cannot gain privileges.

        Args:
            argv: Command and arguments to run inside the container.
            timeout_seconds: Wall-clock budget before the container is killed.
            workdir: Working directory inside the container.

        Returns:
            The command result.

        Raises:
            SandboxTimeoutError: The command exceeded its budget and was killed.
        """
        container_name = f"cyberops-{uuid.uuid4().hex[:12]}"
        command = self._build_command(argv, container_name=container_name, workdir=workdir)

        logger.debug(
            "sandbox.run",
            runtime=self.runtime,
            image=self.spec.image,
            network=self.spec.network,
            argv=list(argv),
        )

        started = time.monotonic()
        try:
            result = await _execute(command, timeout_seconds=timeout_seconds, sandboxed=True)
        except TimeoutError as exc:
            await self._force_remove(container_name)
            raise SandboxTimeoutError(
                f"sandboxed command exceeded {timeout_seconds}s and was killed: {' '.join(argv)}",
                remediation="Raise scanners.timeout_seconds, or narrow the target.",
            ) from exc

        logger.debug(
            "sandbox.complete",
            returncode=result.returncode,
            duration=round(time.monotonic() - started, 3),
        )
        return result

    def _build_command(
        self, argv: Sequence[str], *, container_name: str, workdir: str
    ) -> list[str]:
        """Assemble the full container invocation.

        Args:
            argv: The command to run inside the container.
            container_name: Name used so a timeout can kill the right container.
            workdir: Working directory inside the container.

        Returns:
            The complete argv for the container runtime.
        """
        command = [
            self.runtime,
            "run",
            "--rm",
            "--name",
            container_name,
            f"--network={self.spec.network}",
            f"--memory={self.spec.memory_limit}",
            f"--cpus={self.spec.cpu_limit}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=512",
            # The target tree is mounted read-only: a scanner has no business
            # modifying the code it is analyzing.
            "-v",
            f"{self.spec.workspace.resolve()}:{WORKSPACE_MOUNT}:ro",
            "-w",
            workdir,
        ]

        if self.spec.read_only_root:
            command.append("--read-only")
            # Container-internal paths, mounted noexec/nosuid. Not host temp files.
            for writable in ("/tmp", *self.spec.writable_paths):  # noqa: S108
                command.extend(["--tmpfs", f"{writable}:rw,noexec,nosuid,size=512m"])

        for key, value in sorted(self.spec.env.items()):
            command.extend(["-e", f"{key}={value}"])

        command.append(self.spec.image)
        command.extend(argv)
        return command

    async def _force_remove(self, container_name: str) -> None:
        """Kill a container left behind by a timeout.

        Killing the runtime client does not stop the container, so this is required
        to keep a timed-out scan from leaking a running container.

        Args:
            container_name: Name of the container to kill.
        """
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            process = await asyncio.create_subprocess_exec(
                self.runtime,
                "kill",
                container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(process.wait(), timeout=30)


async def run_host(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout_seconds: int = 600,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run a trusted analyzer binary directly on the host.

    Only for tools that *read* the target tree without executing anything from it.
    Any program that resolves or installs dependencies is rejected here and must go
    through :class:`Sandbox` instead (INV-5).

    Args:
        argv: Command and arguments.
        cwd: Working directory.
        timeout_seconds: Wall-clock budget.
        env: Environment overrides layered onto a minimal base environment.

    Returns:
        The command result.

    Raises:
        SandboxUnavailableError: The program is one that executes untrusted code.
        SandboxTimeoutError: The command exceeded its budget.
    """
    if not argv:
        raise SandboxUnavailableError("refusing to run an empty command")

    program = Path(argv[0]).name.lower()
    if program in FORBIDDEN_HOST_PROGRAMS:
        raise SandboxUnavailableError(
            f"refusing to run {program!r} on the host: package managers and build "
            "tools execute untrusted lifecycle scripts",
            remediation="Route this command through core.sandbox.Sandbox (INV-5).",
        )

    base_env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),  # noqa: S108 - fallback only
        "LANG": "C.UTF-8",
    }
    if env:
        base_env.update(env)

    try:
        return await _execute(
            list(argv),
            timeout_seconds=timeout_seconds,
            sandboxed=False,
            cwd=cwd,
            env=base_env,
        )
    except TimeoutError as exc:
        raise SandboxTimeoutError(
            f"command exceeded {timeout_seconds}s and was killed: {' '.join(argv)}",
            remediation="Raise scanners.timeout_seconds, or narrow the target.",
        ) from exc


async def _execute(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    sandboxed: bool,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Spawn a subprocess and collect its output under a timeout.

    Args:
        argv: Full command to execute.
        timeout_seconds: Wall-clock budget.
        sandboxed: Recorded on the result for auditability.
        cwd: Working directory.
        env: Full environment for the child process.

    Returns:
        The command result.

    Raises:
        TimeoutError: The budget elapsed; the child has been killed.
        SandboxUnavailableError: The executable does not exist.
    """
    started = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env else None,
        )
    except FileNotFoundError as exc:
        raise SandboxUnavailableError(f"executable not found: {argv[0]}") from exc

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except TimeoutError:
        process.kill()
        with contextlib.suppress(ProcessLookupError):
            await process.wait()
        raise TimeoutError(f"command timed out after {timeout_seconds}s") from None

    return CommandResult(
        argv=list(argv),
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
        duration_seconds=round(time.monotonic() - started, 3),
        sandboxed=sandboxed,
    )
