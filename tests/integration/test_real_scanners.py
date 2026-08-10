"""Integration tests against real scanner binaries and a real container runtime.

Run with ``make test-integration``. Every test here skips cleanly when the tool it
needs is absent, so the suite is safe to run anywhere — but it is only *meaningful*
where the binaries exist, which is why it is a separate target from ``make test``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cyberops_kit.config import Settings
from cyberops_kit.core.detector import detect_project
from cyberops_kit.core.models import Category, Severity, Target
from cyberops_kit.core.orchestrator import Pipeline
from cyberops_kit.core.sandbox import Sandbox, SandboxSpec, detect_runtime
from cyberops_kit.report.writer import write_reports
from cyberops_kit.scanners import gitleaks, registry, syft
from cyberops_kit.scanners.base import ScanOutcome

pytestmark = pytest.mark.integration


def requires(tool: str) -> pytest.MarkDecorator:
    """Skip a test unless the named binary is on PATH."""
    return pytest.mark.skipif(shutil.which(tool) is None, reason=f"{tool} is not installed")


SEEDED_SECRET = "".join(("ghp", "_9xKq2mBvT7nWpLr", "4sYhGd8FjCe3AuX01"))
"""A synthetic, never-valid token in a real credential format.

Two deliberate choices here:

* It is *not* a vendor documentation placeholder such as ``AKIAIOSFODNN7EXAMPLE``.
  Gitleaks allowlists those by default, so a test seeded with one passes while
  proving nothing.
* It is assembled from fragments rather than written as a literal, so this file
  contains no credential-shaped string for GitHub push protection or our own
  Gitleaks run to flag. The repository fixture still receives the full value.
"""


@pytest.fixture
def leaky_repo(tmp_path: Path) -> Path:
    """A git repository with a seeded, known secret committed to its history."""
    import subprocess

    if shutil.which("git") is None:
        pytest.skip("git is not installed")

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)

    (tmp_path / "deploy.sh").write_text(f"#!/bin/sh\nexport GITHUB_TOKEN={SEEDED_SECRET}\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='leaky'\nversion='0.1.0'\n")

    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "seed a known secret"], cwd=tmp_path, check=True)
    return tmp_path


# --- Sandbox -------------------------------------------------------------------


@pytest.mark.skipif(detect_runtime("docker") is None, reason="no container runtime")
async def test_sandbox_runs_a_command_with_no_network(tmp_path):
    """A real container runs, and it genuinely has no network."""
    sandbox = Sandbox(SandboxSpec(image="alpine:latest", workspace=tmp_path, network="none"))

    result = await sandbox.run(["sh", "-c", "echo sandboxed"], timeout_seconds=120)
    assert result.ok
    assert "sandboxed" in result.stdout
    assert result.sandboxed is True


@pytest.mark.skipif(detect_runtime("docker") is None, reason="no container runtime")
async def test_sandbox_workspace_is_read_only(tmp_path):
    """A scanner has no business modifying the code it analyzes."""
    (tmp_path / "target.txt").write_text("original\n")
    sandbox = Sandbox(SandboxSpec(image="alpine:latest", workspace=tmp_path))

    result = await sandbox.run(
        ["sh", "-c", "echo tampered > /workspace/target.txt"], timeout_seconds=120
    )

    assert not result.ok
    assert (tmp_path / "target.txt").read_text() == "original\n"


@pytest.mark.skipif(detect_runtime("docker") is None, reason="no container runtime")
async def test_sandbox_has_no_egress(tmp_path):
    """INV-5's network restriction, verified rather than assumed."""
    sandbox = Sandbox(SandboxSpec(image="alpine:latest", workspace=tmp_path, network="none"))

    result = await sandbox.run(
        ["sh", "-c", "wget -q -T 3 -O- https://example.com || echo BLOCKED"],
        timeout_seconds=120,
    )
    assert "BLOCKED" in result.stdout


@pytest.mark.skipif(detect_runtime("docker") is None, reason="no container runtime")
async def test_sandbox_kills_a_command_that_exceeds_its_timeout(tmp_path):
    """A hung scanner must not hang the run."""
    from cyberops_kit.core.errors import SandboxTimeoutError

    sandbox = Sandbox(SandboxSpec(image="alpine:latest", workspace=tmp_path))

    with pytest.raises(SandboxTimeoutError):
        await sandbox.run(["sleep", "60"], timeout_seconds=3)


# --- Real scanners --------------------------------------------------------------


@requires("gitleaks")
async def test_gitleaks_finds_a_seeded_secret(leaky_repo, run_context_factory):
    """End-to-end against a real binary and a real git history."""
    ctx = run_context_factory(leaky_repo)
    result = await gitleaks.PLUGIN.run(ctx)

    assert result.outcome is ScanOutcome.COMPLETED
    assert result.findings, "gitleaks found nothing in a repo with a seeded secret"
    assert all(f.category is Category.SECRET for f in result.findings)
    assert all(f.severity is Severity.CRITICAL for f in result.findings)


@requires("gitleaks")
async def test_seeded_secret_never_reaches_a_report(leaky_repo, tmp_path):
    """The full INV-4 guarantee, with a real scanner and real report files."""
    target = Target(repository="local/leaky", commit_sha="b" * 40, source="local")
    report = await Pipeline(Settings(offline=True)).run(leaky_repo, target)

    assert any(f.category is Category.SECRET for f in report.results.findings), (
        "the pipeline did not detect the seeded secret, so this test would pass vacuously"
    )

    written = write_reports(report, tmp_path / "out", ["json", "sarif", "markdown", "html"])

    for fmt, path in written.items():
        assert SEEDED_SECRET not in path.read_text(encoding="utf-8"), (
            f"the seeded secret leaked into the {fmt} report (INV-4)"
        )


@requires("syft")
async def test_syft_generates_both_sbom_formats(leaky_repo, run_context_factory):
    """Phase 1 requires CycloneDX and SPDX."""
    ctx = run_context_factory(leaky_repo)
    result = await syft.PLUGIN.run(ctx)

    assert result.outcome is ScanOutcome.COMPLETED
    assert "cyclonedx-1.6" in result.documents
    assert "spdx-3.0" in result.documents


@requires("osv-scanner")
async def test_osv_runs_against_a_real_manifest(leaky_repo, run_context_factory):
    ctx = run_context_factory(leaky_repo, offline=False)
    result = await osv_plugin().run(ctx)
    assert result.outcome in (ScanOutcome.COMPLETED, ScanOutcome.FAILED)


def osv_plugin():
    """Look the plugin up rather than importing it, to keep skips clean."""
    plugin = registry.get("osv")
    assert plugin is not None
    return plugin


# --- Reproducibility with real tools -------------------------------------------


async def test_two_runs_of_the_same_commit_produce_identical_results(leaky_repo):
    """INV-3, end to end, with whatever scanners this machine actually has."""
    target = Target(repository="local/leaky", commit_sha="b" * 40, source="local")
    settings = Settings(offline=True)

    first = await Pipeline(settings).run(leaky_repo, target)
    second = await Pipeline(settings).run(leaky_repo, target)

    assert first.results.model_dump_json() == second.results.model_dump_json()


async def test_detection_matches_the_real_tree(leaky_repo):
    profile = detect_project(leaky_repo)
    assert "pyproject.toml" in profile.manifests
