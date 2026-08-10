"""Ingest — resolve a target to a readable tree pinned at an exact commit.

Accepts a local path or a GitHub URL. A remote target is shallow-cloned into a temp
directory; a local target is used in place and never modified.

Cloning is the one network operation in this stage, and it is refused under
``--offline`` rather than silently degraded (INV-6). Note that ``git clone`` does not
execute hooks or lifecycle scripts from the remote, so it does not require the
sandbox — resolving the *dependency tree* does, and that happens inside scanners.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

import structlog

from cyberops_kit.core.errors import IngestError, OfflineViolationError
from cyberops_kit.core.models import Target
from cyberops_kit.core.sandbox import run_host

logger = structlog.get_logger(__name__)

UNKNOWN_SHA: Final = "unknown"

_GITHUB_URL_RE: Final = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+?)(?:\.git)?/?$"
)
_SSH_URL_RE: Final = re.compile(
    r"^git@github\.com:(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+?)(?:\.git)?$"
)

CLONE_TIMEOUT_SECONDS: Final = 300


def is_remote(target: str) -> bool:
    """Return whether a target string refers to a remote repository.

    Args:
        target: The user-supplied target.

    Returns:
        True when the target is a URL rather than a local path.
    """
    return bool(_GITHUB_URL_RE.match(target) or _SSH_URL_RE.match(target))


def parse_github_url(target: str) -> tuple[str, str] | None:
    """Extract owner and repository name from a GitHub URL.

    Args:
        target: The user-supplied target.

    Returns:
        ``(owner, repo)``, or ``None`` when the target is not a GitHub URL.
    """
    match = _GITHUB_URL_RE.match(target) or _SSH_URL_RE.match(target)
    if match is None:
        return None
    return match.group("owner"), match.group("repo")


@contextmanager
def ingest(target: str, *, offline: bool = False) -> Iterator[tuple[Path, Target]]:
    """Resolve a target to a workspace directory and a pinned ``Target``.

    Args:
        target: A local path or a GitHub URL.
        offline: When true, remote targets are refused.

    Yields:
        The workspace path and the resolved target metadata. A cloned workspace is
        removed on exit; a local one is left untouched.

    Raises:
        IngestError: The target could not be resolved.
        OfflineViolationError: A remote target was requested in offline mode.
    """
    if is_remote(target):
        if offline:
            raise OfflineViolationError(
                f"cannot clone {target} in offline mode",
                remediation="Clone the repository yourself and scan the local path.",
            )
        with _clone(target) as (workspace, resolved):
            yield workspace, resolved
    else:
        workspace = _resolve_local(target)
        yield workspace, _describe_local(workspace)


def _resolve_local(target: str) -> Path:
    """Validate and resolve a local target path.

    Args:
        target: A filesystem path.

    Returns:
        The resolved absolute path.

    Raises:
        IngestError: The path does not exist or is not a directory.
    """
    path = Path(target).expanduser()
    if not path.exists():
        raise IngestError(f"target path does not exist: {target}")
    if not path.is_dir():
        raise IngestError(f"target path is not a directory: {target}")
    return path.resolve()


@contextmanager
def _clone(url: str) -> Iterator[tuple[Path, Target]]:
    """Shallow-clone a remote repository into a temp directory.

    Args:
        url: The repository URL.

    Yields:
        The clone path and the resolved target metadata.

    Raises:
        IngestError: The clone failed.
    """
    parsed = parse_github_url(url)
    if parsed is None:  # pragma: no cover - guarded by is_remote
        raise IngestError(f"unsupported remote target: {url}")
    owner, repo = parsed
    clone_url = f"https://github.com/{owner}/{repo}.git"

    temp_root = Path(tempfile.mkdtemp(prefix="cyberops-clone-"))
    workspace = temp_root / repo

    try:
        logger.info("ingest.clone", repository=f"{owner}/{repo}")
        result = _run_git_sync(
            ["git", "clone", "--depth=1", "--quiet", clone_url, str(workspace)],
            cwd=temp_root,
        )
        if result is None:
            raise IngestError(
                f"failed to clone {clone_url}",
                remediation="Check the URL, your network, and your credentials.",
            )

        commit_sha = _git_output(workspace, ["rev-parse", "HEAD"]) or UNKNOWN_SHA
        ref = _git_output(workspace, ["rev-parse", "--abbrev-ref", "HEAD"])

        yield (
            workspace,
            Target(
                repository=f"{owner}/{repo}",
                commit_sha=commit_sha,
                source="github",
                ref=ref,
                origin_url=f"https://github.com/{owner}/{repo}",
                dirty=False,
            ),
        )
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def _describe_local(workspace: Path) -> Target:
    """Build target metadata for a local checkout.

    Args:
        workspace: The resolved local path.

    Returns:
        The target, with ``commit_sha`` set to ``"unknown"`` when the directory is
        not a git repository. A scan of a non-git tree is still useful; it just is
        not reproducible, and the report says so.
    """
    commit_sha = _git_output(workspace, ["rev-parse", "HEAD"])
    origin = _git_output(workspace, ["remote", "get-url", "origin"])
    ref = _git_output(workspace, ["rev-parse", "--abbrev-ref", "HEAD"])
    status = _git_output(workspace, ["status", "--porcelain"])

    repository = workspace.name
    normalized_origin: str | None = None
    if origin:
        parsed = parse_github_url(origin)
        if parsed:
            owner, repo = parsed
            repository = f"{owner}/{repo}"
            normalized_origin = f"https://github.com/{owner}/{repo}"

    if commit_sha is None:
        logger.warning("ingest.not_a_git_repo", path=str(workspace))

    return Target(
        repository=repository,
        commit_sha=commit_sha or UNKNOWN_SHA,
        source="local",
        ref=ref,
        origin_url=normalized_origin,
        dirty=bool(status),
    )


def _git_output(workspace: Path, args: list[str]) -> str | None:
    """Run a read-only git command and return its trimmed stdout.

    Args:
        workspace: Directory to run in.
        args: Git arguments, without the leading ``git``.

    Returns:
        The output, or ``None`` when git failed or is unavailable.
    """
    result = _run_git_sync(["git", *args], cwd=workspace)
    if result is None:
        return None
    return result or None


def _run_git_sync(argv: list[str], *, cwd: Path) -> str | None:
    """Run git synchronously and return stdout, or ``None`` on failure.

    Ingest runs before the event loop starts, so this stays synchronous rather than
    forcing the CLI to bootstrap asyncio just to read a commit SHA.

    Args:
        argv: The full command.
        cwd: Working directory.

    Returns:
        Trimmed stdout on success, ``None`` on any failure.
    """
    import subprocess

    if shutil.which("git") is None:
        return None

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, never shell
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


async def git_version() -> str | None:
    """Return the installed git version, for ``run_metadata.tool_versions``.

    Returns:
        The version string, or ``None`` when git is unavailable.
    """
    if shutil.which("git") is None:
        return None
    try:
        result = await run_host(["git", "--version"], timeout_seconds=15)
    except OSError:  # pragma: no cover - defensive
        return None
    match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
    return match.group(1) if match else None
