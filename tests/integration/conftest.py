"""Fixtures for integration tests."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from cyberops_kit.config import Settings
from cyberops_kit.core.detector import detect_project
from cyberops_kit.core.models import RunContext, Target


@pytest.fixture
def run_context_factory() -> Callable[..., RunContext]:
    """Build a real run context for a workspace on disk.

    Unlike the unit-test fixture, this runs actual detection so a plugin's
    ``applies_to`` and ``preflight`` see the real tree.
    """

    def build(
        workspace: Path, *, offline: bool = True, origin_url: str | None = None
    ) -> RunContext:
        settings = Settings(offline=offline)
        return RunContext(
            run_id="integration",
            target=Target(
                repository="local/test",
                commit_sha="c" * 40,
                source="local",
                origin_url=origin_url,
            ),
            workspace=workspace,
            offline=offline,
            config=settings,
            profile=detect_project(workspace),
        )

    return build
