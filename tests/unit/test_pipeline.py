"""End-to-end pipeline and CLI behavior, with scanners stubbed out.

These exercise the wiring — stage order, exclusion accounting, threshold-to-exit-code
mapping — without requiring any external scanner binary to be installed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cyberops_kit.cli import app
from cyberops_kit.config import Settings
from cyberops_kit.core.errors import ExitCode
from cyberops_kit.core.ingest import ingest, is_remote, parse_github_url
from cyberops_kit.core.models import ExclusionOutcome, Severity, Target
from cyberops_kit.core.orchestrator import Pipeline
from cyberops_kit.scanners import registry
from cyberops_kit.scanners.base import ScanOutcome, ScanResult
from tests.conftest import make_finding

runner = CliRunner()


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A small Python project on disk."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hello')\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n")
    return tmp_path


def stub_all_scanners(monkeypatch, handler) -> None:
    """Replace every registered plugin's ``run_with`` with ``handler``.

    Patched per instance rather than on ``ScannerPlugin``, because the SLSA
    evaluator overrides ``run_with`` and a base-class patch would silently miss it.

    Args:
        monkeypatch: The pytest monkeypatch fixture.
        handler: ``async (plugin, ctx, prior) -> ScanResult``.
    """
    for plugin in registry.all_plugins():

        def bound(ctx, prior, _plugin=plugin):
            return handler(_plugin, ctx, prior)

        monkeypatch.setattr(plugin, "run_with", bound, raising=False)


# --- Ingest --------------------------------------------------------------------


def test_is_remote_recognizes_github_urls():
    assert is_remote("https://github.com/owner/repo")
    assert is_remote("github.com/owner/repo")
    assert is_remote("git@github.com:owner/repo.git")
    assert not is_remote(".")
    assert not is_remote("/tmp/project")


def test_parse_github_url():
    assert parse_github_url("https://github.com/owner/repo.git") == ("owner", "repo")
    assert parse_github_url("/tmp/x") is None


def test_ingest_local_path(project):
    with ingest(str(project)) as (workspace, target):
        assert workspace == project.resolve()
        assert target.source == "local"


def test_ingest_rejects_a_missing_path():
    from cyberops_kit.core.errors import IngestError

    with pytest.raises(IngestError), ingest("/nonexistent/path/xyz"):
        pass


# --- Pipeline ------------------------------------------------------------------


async def test_pipeline_produces_a_full_report(project, monkeypatch):
    """A complete run with every scanner stubbed to succeed."""

    async def fake_run_with(self, ctx, prior):
        findings = []
        metrics = {}
        documents = {}
        slsa = None

        if self.name == "osv":
            findings = [make_finding(rule_id="CVE-1", severity=Severity.HIGH)]
        elif self.name == "scorecard":
            metrics = {"aggregate": 8.0}
        elif self.name == "syft":
            documents = {
                "cyclonedx-1.6": json.dumps(
                    {
                        "components": [
                            {"name": "a", "version": "1", "licenses": [{"license": {"id": "MIT"}}]}
                        ]
                    }
                )
            }
            metrics = {"component_count": 1.0}
        elif self.name == "slsa":
            from cyberops_kit.core.models import SLSAAssessment, SLSAEvidence

            slsa = SLSAAssessment(
                build_level=2,
                evidence=[SLSAEvidence(check="c", passed=True, detail="d", source="s")],
            )

        return ScanResult(
            scanner=self.name,
            version="1.0.0",
            outcome=ScanOutcome.COMPLETED,
            findings=findings,
            metrics=metrics,
            documents=documents,
            slsa=slsa,
            dimension=self.dimension,
        )

    stub_all_scanners(monkeypatch, fake_run_with)

    target = Target(repository="owner/repo", commit_sha="a" * 40, source="local")
    report = await Pipeline(Settings()).run(project, target)

    assert report.results.score.composite > 0
    assert report.results.sbom.generated is True
    assert report.results.slsa.build_level == 2
    assert report.results.scoring_model_version == "1.0.0"
    assert report.run_metadata.duration_seconds >= 0
    assert any(f.rule_id == "CVE-1" for f in report.results.findings)


async def test_pipeline_excludes_dimensions_for_scanners_that_did_not_run(project, monkeypatch):
    """A scanner that never ran excludes its dimension rather than zeroing it."""

    async def all_skipped(self, ctx, prior):
        return ScanResult(
            scanner=self.name,
            outcome=ScanOutcome.SKIPPED,
            reason="not_installed",
            detail="stubbed",
            dimension=self.dimension,
        )

    stub_all_scanners(monkeypatch, all_skipped)

    target = Target(repository="owner/repo", commit_sha="a" * 40, source="local")
    report = await Pipeline(Settings()).run(project, target)

    assert report.results.excluded_scanners
    # Not installed is benign: these must be classified NOT_RUN, never as failures.
    assert report.results.not_run_scanners
    assert report.results.failed_scanners == []
    assert all(s.outcome is ExclusionOutcome.NOT_RUN for s in report.results.excluded_scanners)
    assert report.results.score.sufficient_coverage is False
    assert all(d.excluded for d in report.results.score.dimensions.values())
    for dimension in report.results.score.dimensions.values():
        assert dimension.exclusion_reason


async def test_pipeline_survives_a_crashing_plugin(project, monkeypatch):
    """One broken plugin must not abort an otherwise good run."""

    async def crash(self, ctx, prior):
        msg = "simulated plugin crash"
        raise RuntimeError(msg)

    stub_all_scanners(monkeypatch, crash)

    target = Target(repository="owner/repo", commit_sha="a" * 40, source="local")
    report = await Pipeline(Settings()).run(project, target)

    # A crash is a failure, not a skip. Reporting it as "skipped" would hide a bug
    # behind language that reads as expected and benign.
    assert report.results.failed_scanners
    assert report.results.not_run_scanners == []
    assert any(s.reason == "plugin_crashed" for s in report.results.failed_scanners)
    assert all(s.outcome is ExclusionOutcome.FAILED for s in report.results.failed_scanners)


async def test_pipeline_runs_slsa_after_scorecard(project, monkeypatch):
    """Dependency waves: the derived evaluator sees the earlier results."""
    seen: dict[str, set[str]] = {}

    async def record(self, ctx, prior):
        seen[self.name] = set(prior)
        return ScanResult(
            scanner=self.name, outcome=ScanOutcome.COMPLETED, dimension=self.dimension
        )

    stub_all_scanners(monkeypatch, record)

    target = Target(repository="owner/repo", commit_sha="a" * 40, source="local")
    await Pipeline(Settings()).run(project, target)

    assert "scorecard" in seen.get("slsa", set())
    assert seen.get("scorecard") == set()


def test_registry_selects_only_applicable_scanners(project):
    from cyberops_kit.core.detector import detect_project

    profile = detect_project(project)
    selected = {p.name for p in registry.select(Settings(), profile)}

    # A Python project with no IaC, containers, or CI: Trivy has nothing to check.
    assert "trivy" not in selected
    assert "osv" in selected
    assert "gitleaks" in selected


def test_registry_respects_the_enabled_list(project):
    from cyberops_kit.core.detector import detect_project

    settings = Settings(scanners={"enabled": ["gitleaks"]})
    selected = {p.name for p in registry.select(settings, detect_project(project))}
    assert selected == {"gitleaks"}


# --- CLI -----------------------------------------------------------------------


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "cyberops-kit" in result.stdout
    assert "scoring model" in result.stdout


def test_cli_doctor_reports_availability():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    for name in ("scorecard", "osv", "semgrep", "gitleaks", "trivy", "syft", "slsa"):
        assert name in result.stdout


def test_cli_doctor_explains_the_cost_of_missing_scanners():
    result = runner.invoke(app, ["doctor"])
    assert "excluded" in result.stdout or "All scanners are available" in result.stdout


def test_cli_scan_writes_reports(project, tmp_path):
    out = tmp_path / "reports"
    result = runner.invoke(app, ["scan", str(project), "--offline", "--output", str(out), "-q"])

    assert result.exit_code in (ExitCode.OK, ExitCode.THRESHOLD_FAILED)
    assert (out / "report.json").is_file()
    assert (out / "report.sarif").is_file()
    assert (out / "report.md").is_file()
    assert (out / "report.html").is_file()
    assert (out / "badge.json").is_file()


def test_cli_scan_records_history(project, tmp_path):
    out = tmp_path / "reports"
    runner.invoke(app, ["scan", str(project), "--offline", "--output", str(out), "-q"])
    assert (out / "history" / "index.json").is_file()


def test_cli_offline_with_remote_target_fails_cleanly(tmp_path):
    result = runner.invoke(
        app, ["scan", "https://github.com/owner/repo", "--offline", "-o", str(tmp_path)]
    )
    assert result.exit_code == ExitCode.USAGE
    assert "offline" in result.output.lower()


def test_cli_bad_config_is_a_usage_error(project, tmp_path):
    config = tmp_path / "bad.yml"
    config.write_text("version: 99\n")
    result = runner.invoke(
        app, ["scan", str(project), "--config", str(config), "--offline", "-o", str(tmp_path)]
    )
    assert result.exit_code == ExitCode.USAGE


def test_cli_does_not_fail_the_build_on_an_unscoreable_run(project, tmp_path):
    """With almost nothing measured, --fail-below must not fail the build."""
    result = runner.invoke(
        app,
        [
            "scan",
            str(project),
            "--offline",
            "-o",
            str(tmp_path / "r"),
            "--fail-below",
            "100",
            "-q",
        ],
    )
    assert result.exit_code == ExitCode.OK


def test_cli_scan_emits_a_pr_comment_when_asked(project, tmp_path):
    out = tmp_path / "reports"
    runner.invoke(app, ["scan", str(project), "--offline", "-o", str(out), "--pr-comment", "-q"])
    assert (out / "pr-comment.md").is_file()
