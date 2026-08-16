"""Syft integration — SBOM generation in CycloneDX and SPDX.

Produces no findings. Syft emits two SBOM documents and a component count; the
``sbom`` package analyzes them and the ``sbom_health`` dimension scores them.

Both documents are returned in ``ScanResult.documents`` rather than written
directly, because a plugin never writes outside its own temp directory (see
``docs/contributing/add-a-scanner.md``) and that directory is destroyed when the
scan finishes. The orchestrator decides where artifacts land.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from cyberops_kit.core.models import (
    Finding,
    ProjectProfile,
    RunContext,
    SBOMFormat,
)
from cyberops_kit.core.sandbox import CommandResult
from cyberops_kit.scanners.base import ExecutionMode, ScannerPlugin

CYCLONEDX_FILENAME: Final = "sbom.cdx.json"
SPDX_FILENAME: Final = "sbom.spdx.json"

COMPONENT_COUNT_METRIC: Final = "component_count"


class SyftPlugin(ScannerPlugin):
    """Generates SBOMs with Syft."""

    name = "syft"
    version_command = ("syft", "version")
    categories = frozenset()
    dimension = None
    """Feeds ``sbom_health`` through the SBOM analyzer rather than through findings."""

    execution_mode = ExecutionMode.HOST
    """Syft catalogs files and manifests statically; it resolves nothing and runs no
    lifecycle scripts, which is what keeps it out of the sandbox."""

    requires_network = False

    def applies_to(self, profile: ProjectProfile) -> bool:
        """Return True for any project with detectable content.

        Args:
            profile: The detected project profile.

        Returns:
            True when the tree has files to catalog.
        """
        return profile.file_count > 0

    def build_command(self, ctx: RunContext, workdir: Path) -> list[str]:
        """Build the Syft invocation, emitting both required formats at once.

        Args:
            ctx: The current run context.
            workdir: This scanner's private temp directory.

        Returns:
            The command to run.
        """
        return [
            "syft",
            "scan",
            f"dir:{ctx.workspace}",
            "--output",
            f"cyclonedx-json={workdir / CYCLONEDX_FILENAME}",
            "--output",
            f"spdx-json={workdir / SPDX_FILENAME}",
            "--quiet",
            *self.exclude_args(ctx.config.scanners.exclude_paths),
        ]

    def exclude_args(self, patterns: Sequence[str]) -> list[str]:
        """Skip excluded paths natively via ``--exclude``.

        Syft is the one scanner where this is more than an optimization. It produces
        an inventory rather than findings, so the central finding filter cannot reach
        it — components catalogued from an excluded path would otherwise still count
        toward ``sbom_health`` and the published component total.

        Args:
            patterns: Configured exclusion patterns.

        Returns:
            One ``--exclude`` flag per pattern, as a Syft glob.
        """
        return [
            f"--exclude=./{pattern.strip().lstrip('./').rstrip('/')}/**"
            for pattern in patterns
            if pattern.strip()
        ]

    def parse(self, result: CommandResult, ctx: RunContext, workdir: Path) -> list[Finding]:
        """Return no findings.

        An SBOM is an inventory, not a set of problems. Vulnerabilities against these
        components are OSV-Scanner's job.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: This scanner's private temp directory.

        Returns:
            An empty list, always.
        """
        del result, ctx, workdir
        return []

    def extract_documents(
        self, result: CommandResult, ctx: RunContext, workdir: Path
    ) -> dict[str, str]:
        """Return both SBOM documents as serialized text.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: This scanner's private temp directory.

        Returns:
            Format name to document content, omitting any format Syft did not write.
        """
        del result, ctx
        documents: dict[str, str] = {}
        for fmt, filename in (
            (SBOMFormat.CYCLONEDX_1_6, CYCLONEDX_FILENAME),
            (SBOMFormat.SPDX_3_0, SPDX_FILENAME),
        ):
            try:
                content = (workdir / filename).read_text(encoding="utf-8")
            except OSError:
                continue
            if content.strip():
                documents[fmt.value] = content
        return documents

    def extract_metrics(
        self, result: CommandResult, ctx: RunContext, workdir: Path
    ) -> dict[str, float]:
        """Report how many components Syft cataloged.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: This scanner's private temp directory.

        Returns:
            ``{"component_count": n}``, or empty when the SBOM is unreadable.
        """
        del result, ctx
        payload = _load(workdir / CYCLONEDX_FILENAME)
        if payload is None:
            return {}
        components = payload.get("components")
        if not isinstance(components, list):
            return {}
        return {COMPONENT_COUNT_METRIC: float(len(components))}


def _load(path: Path) -> dict[str, Any] | None:
    """Read a JSON document written by Syft.

    Args:
        path: Path to the document.

    Returns:
        The parsed payload, or ``None`` when missing or malformed.
    """
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


PLUGIN = SyftPlugin()
