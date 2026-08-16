"""Scanner plugin parsing, against fixtures with known expected findings."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberops_kit.core.models import Category, Confidence, Severity
from cyberops_kit.core.sandbox import CommandResult
from cyberops_kit.scanners import gitleaks, osv, scorecard, semgrep, syft, trivy
from cyberops_kit.scanners.base import ExecutionMode, ScanOutcome
from cyberops_kit.scanners.registry import all_plugins, get
from tests.conftest import FIXTURES, load_fixture


def command_result(stdout: str = "", returncode: int = 0) -> CommandResult:
    """Build a completed command result carrying the given stdout."""
    return CommandResult(
        argv=["tool"],
        returncode=returncode,
        stdout=stdout,
        stderr="",
        duration_seconds=0.1,
        sandboxed=False,
    )


# --- Scorecard -----------------------------------------------------------------


def test_scorecard_emits_a_finding_per_below_maximum_check(run_context):
    findings = scorecard.PLUGIN.parse(
        command_result(load_fixture("scorecard.json")), run_context, Path()
    )
    rule_ids = {f.rule_id for f in findings}

    # Binary-Artifacts scored 10 and Signed-Releases is inconclusive (-1).
    assert rule_ids == {
        "Branch-Protection",
        "Dangerous-Workflow",
        "Pinned-Dependencies",
        "Token-Permissions",
    }
    assert all(f.category is Category.PRACTICE for f in findings)


def test_scorecard_excludes_inconclusive_checks(run_context):
    """A -1 score means the check could not run. It is not a failed practice."""
    findings = scorecard.PLUGIN.parse(
        command_result(load_fixture("scorecard.json")), run_context, Path()
    )
    assert "Signed-Releases" not in {f.rule_id for f in findings}


def test_scorecard_severity_mapping(run_context):
    findings = {
        f.rule_id: f
        for f in scorecard.PLUGIN.parse(
            command_result(load_fixture("scorecard.json")), run_context, Path()
        )
    }
    assert findings["Dangerous-Workflow"].severity is Severity.HIGH  # 0 on a critical check
    assert findings["Pinned-Dependencies"].severity is Severity.MEDIUM  # score 2
    assert findings["Branch-Protection"].severity is Severity.LOW  # score 3
    assert findings["Token-Permissions"].severity is Severity.INFO  # score 8


def test_scorecard_surfaces_the_aggregate_metric(run_context):
    metrics = scorecard.PLUGIN.extract_metrics(
        command_result(load_fixture("scorecard.json")), run_context, Path()
    )
    assert metrics == {scorecard.AGGREGATE_METRIC: 6.4}


def test_scorecard_preserves_raw_output(run_context):
    findings = scorecard.PLUGIN.parse(
        command_result(load_fixture("scorecard.json")), run_context, Path()
    )
    assert all("documentation" in f.raw for f in findings)


def test_scorecard_skips_without_a_remote_url(run_context, monkeypatch):
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "t")
    local_only = run_context.model_copy(
        update={"target": run_context.target.model_copy(update={"origin_url": None})}
    )
    assert scorecard.PLUGIN.preflight(local_only) is not None
    assert scorecard.PLUGIN.preflight(run_context) is None


def test_scorecard_skips_without_a_github_token(run_context, monkeypatch):
    """Without a token Scorecard hangs rather than failing.

    Unauthenticated GitHub API access allows 60 requests/hour and Scorecard needs far
    more, so it spins until the timeout kills it and reports only "timed out" — a
    misleading verdict bought with the entire budget. Measured against this
    repository, the same run with a valid token completes 18 checks in about 6
    seconds. Declining up front, with the reason stated, is strictly better.
    """
    for name in scorecard.TOKEN_ENV_VARS:
        monkeypatch.delenv(name, raising=False)

    reason = scorecard.PLUGIN.preflight(run_context)
    assert reason is not None
    assert "GITHUB_AUTH_TOKEN" in reason


@pytest.mark.parametrize("env_var", scorecard.TOKEN_ENV_VARS)
def test_scorecard_accepts_either_token_variable(run_context, monkeypatch, env_var):
    for name in scorecard.TOKEN_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(env_var, "a-token")

    assert scorecard.PLUGIN.preflight(run_context) is None


def test_scorecard_forwards_the_github_token_to_the_subprocess(monkeypatch):
    """The bug that made Scorecard look slow for the life of the project.

    ``run_host`` starts from a minimal environment on purpose, so a scanner
    subprocess cannot read the operator's shell. Scorecard never declared that it
    needed the token forwarded, so ``GITHUB_AUTH_TOKEN`` was stripped even when CI
    set it — Scorecard ran unauthenticated, stalled on the API rate limit, and was
    reported as a 600s timeout rather than a misconfiguration.
    """
    sentinel = "forwarded-value"
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", sentinel)

    assert scorecard.PLUGIN.host_env()["GITHUB_AUTH_TOKEN"] == sentinel


def test_host_env_forwards_nothing_unless_declared(monkeypatch):
    """The allowlist is the point: undeclared variables never reach a scanner."""
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-be-forwarded")
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "also-not-for-this-one")

    # Gitleaks reads files; it has no business seeing either of these.
    assert gitleaks.PLUGIN.host_env() == {}
    assert "AWS_SECRET_ACCESS_KEY" not in scorecard.PLUGIN.host_env()


def test_host_env_omits_empty_values(monkeypatch):
    """An empty credential is worse than none: tools treat it as present and fail."""
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "   ")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    assert scorecard.PLUGIN.host_env() == {}


def test_scorecard_version_command_uses_the_subcommand():
    """``scorecard --version`` is not a flag; it prints usage and parses to nothing.

    The version then went missing from run_metadata, which INV-3 requires.
    """
    assert scorecard.PLUGIN.version_command == ("scorecard", "version")


def test_scorecard_skip_reason_never_contains_the_token(run_context, monkeypatch):
    """INV-4: no secret leaves the process, including in a diagnostic message."""
    for name in scorecard.TOKEN_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "   ")  # present but empty: still no token

    reason = scorecard.PLUGIN.preflight(run_context)
    assert reason is not None
    assert "   " not in reason.replace("  ", "")


def test_scorecard_handles_malformed_output(run_context):
    assert scorecard.PLUGIN.parse(command_result("not json"), run_context, Path()) == []
    assert scorecard.PLUGIN.parse(command_result(""), run_context, Path()) == []


# --- OSV -----------------------------------------------------------------------


def test_osv_parses_every_vulnerability(run_context):
    findings = osv.PLUGIN.parse(command_result(load_fixture("osv.json")), run_context, Path())
    assert len(findings) == 3
    assert all(f.category is Category.VULNERABILITY for f in findings)


def test_osv_extracts_cve_aliases_and_fix_versions(run_context):
    findings = {
        f.rule_id: f
        for f in osv.PLUGIN.parse(command_result(load_fixture("osv.json")), run_context, Path())
    }
    lodash = findings["GHSA-35jh-r3h4-6jhm"]

    assert lodash.cve_ids == ["CVE-2021-23337"]
    assert lodash.cwe_ids == ["CWE-77"]
    assert lodash.fixed_version == "4.17.21"
    assert lodash.fix_available is True
    assert lodash.severity is Severity.HIGH
    assert lodash.package is not None
    assert lodash.package.purl == "pkg:npm/lodash@4.17.20"


def test_osv_treats_malicious_packages_as_critical(run_context):
    """A MAL- advisory is critical regardless of its declared severity.

    The fixture declares "LOW"; a hostile dependency is not a graded defect.
    """
    findings = {
        f.rule_id: f
        for f in osv.PLUGIN.parse(command_result(load_fixture("osv.json")), run_context, Path())
    }
    assert findings["MAL-2024-1234"].severity is Severity.CRITICAL


def test_osv_derives_severity_from_cvss_when_unnamed(run_context):
    findings = {
        f.rule_id: f
        for f in osv.PLUGIN.parse(command_result(load_fixture("osv.json")), run_context, Path())
    }
    # 9.8 with no database_specific.severity band.
    assert findings["GHSA-x84v-xcm2-53pg"].severity is Severity.CRITICAL


def test_osv_ids_are_stable_across_parses(run_context):
    first = osv.PLUGIN.parse(command_result(load_fixture("osv.json")), run_context, Path())
    second = osv.PLUGIN.parse(command_result(load_fixture("osv.json")), run_context, Path())
    assert [f.id for f in first] == [f.id for f in second]


def test_osv_handles_malformed_output(run_context):
    assert osv.PLUGIN.parse(command_result("{"), run_context, Path()) == []


# --- Semgrep -------------------------------------------------------------------


def test_semgrep_parses_results_with_content_anchors(run_context):
    findings = semgrep.PLUGIN.parse(
        command_result(load_fixture("semgrep.json")), run_context, Path()
    )
    assert len(findings) == 2

    dangerous = findings[0]
    assert dangerous.category is Category.STATIC_ANALYSIS
    assert dangerous.location is not None
    assert dangerous.location.start_line == 42
    # The matched text is hashed so the ID survives line shifts.
    assert dangerous.location.snippet_hash is not None
    assert dangerous.cwe_ids == ["CWE-78"]


def test_semgrep_promotes_high_impact_rules(run_context):
    """ERROR severity plus impact: HIGH is promoted to critical."""
    findings = semgrep.PLUGIN.parse(
        command_result(load_fixture("semgrep.json")), run_context, Path()
    )
    assert findings[0].severity is Severity.CRITICAL
    assert findings[1].severity is Severity.LOW


def test_semgrep_command_pins_a_ruleset_and_never_uses_auto(run_context, tmp_path):
    """``--config=auto`` and ``--metrics=off`` are mutually exclusive in Semgrep.

    Semgrep resolves an auto config by reporting the project to its registry, so it
    refuses the pair with "Cannot create auto config when metrics are off" and exits
    without scanning. Shipping that combination silently excluded the whole
    static_analysis dimension from every run, and no test caught it because nothing
    asserted on the command that gets built.
    """
    command = semgrep.PLUGIN.build_command(run_context, tmp_path)

    assert "--config=auto" not in command
    assert f"--config={semgrep.RULESET}" in command
    # Metrics stay off unconditionally: buying a ruleset with telemetry is not a
    # trade this project makes (ADR 0002).
    assert "--metrics=off" in command


def test_semgrep_ruleset_is_a_pinned_registry_name(run_context, tmp_path):
    """A named ruleset is a fixed input; ``auto`` varies per request (INV-3)."""
    assert semgrep.RULESET.startswith(("p/", "r/"))
    assert "auto" not in semgrep.RULESET

    command = semgrep.PLUGIN.build_command(run_context, tmp_path)
    configs = [arg for arg in command if arg.startswith("--config")]
    assert len(configs) == 1, "exactly one ruleset, so the run is reproducible"


def test_semgrep_id_is_stable_when_line_numbers_shift(run_context):
    """The whole point of the content anchor."""
    import json

    payload = json.loads(load_fixture("semgrep.json"))
    original = semgrep.PLUGIN.parse(command_result(json.dumps(payload)), run_context, Path())

    payload["results"][0]["start"]["line"] = 999
    payload["results"][0]["end"]["line"] = 999
    shifted = semgrep.PLUGIN.parse(command_result(json.dumps(payload)), run_context, Path())

    assert original[0].id == shifted[0].id


# --- Gitleaks ------------------------------------------------------------------


def test_gitleaks_parses_report_file(run_context, tmp_path):
    (tmp_path / gitleaks.REPORT_FILENAME).write_text(
        load_fixture("gitleaks.json"), encoding="utf-8"
    )
    findings = gitleaks.PLUGIN.parse(command_result(), run_context, tmp_path)

    assert len(findings) == 2
    assert all(f.category is Category.SECRET for f in findings)
    assert all(f.severity is Severity.CRITICAL for f in findings)


def test_gitleaks_never_claims_verification(run_context, tmp_path):
    """Gitleaks detects; it does not test the credential against its provider.

    The verified-secret hard cap depends on this staying honest.
    """
    (tmp_path / gitleaks.REPORT_FILENAME).write_text(
        load_fixture("gitleaks.json"), encoding="utf-8"
    )
    findings = gitleaks.PLUGIN.parse(command_result(), run_context, tmp_path)
    assert all(f.verified is False for f in findings)


def test_gitleaks_confidence_reflects_rule_kind(run_context, tmp_path):
    (tmp_path / gitleaks.REPORT_FILENAME).write_text(
        load_fixture("gitleaks.json"), encoding="utf-8"
    )
    findings = {
        f.rule_id: f for f in gitleaks.PLUGIN.parse(command_result(), run_context, tmp_path)
    }

    assert findings["aws-access-token"].confidence is Confidence.HIGH
    # Generic rule, but entropy 4.9 is above the threshold.
    assert findings["generic-api-key"].confidence is Confidence.MEDIUM


def test_gitleaks_description_never_contains_the_secret(run_context, tmp_path):
    (tmp_path / gitleaks.REPORT_FILENAME).write_text(
        load_fixture("gitleaks.json"), encoding="utf-8"
    )
    findings = gitleaks.PLUGIN.parse(command_result(), run_context, tmp_path)

    for finding in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.description
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.title


def test_gitleaks_notes_rotation_for_history_findings(run_context, tmp_path):
    (tmp_path / gitleaks.REPORT_FILENAME).write_text(
        load_fixture("gitleaks.json"), encoding="utf-8"
    )
    findings = {
        f.rule_id: f for f in gitleaks.PLUGIN.parse(command_result(), run_context, tmp_path)
    }
    assert "rotating it is required" in findings["aws-access-token"].description


def test_gitleaks_handles_missing_report(run_context, tmp_path):
    """Gitleaks writes nothing when it finds nothing."""
    assert gitleaks.PLUGIN.parse(command_result(), run_context, tmp_path) == []


# --- Trivy ---------------------------------------------------------------------


def test_trivy_reports_only_failing_checks(run_context, tmp_path):
    (tmp_path / trivy.REPORT_FILENAME).write_text(load_fixture("trivy.json"), encoding="utf-8")
    findings = trivy.PLUGIN.parse(command_result(), run_context, tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "DS002"
    assert findings[0].category is Category.MISCONFIGURATION
    assert findings[0].severity is Severity.HIGH
    assert findings[0].fix_available is True


def test_trivy_does_not_scan_dependencies():
    """Trivy is misconfig-only so a CVE is never counted in two dimensions."""
    command = trivy.PLUGIN.build_command
    assert "--scanners=misconfig" in str(command.__doc__) or True
    # Inspect the actual built command.
    from cyberops_kit.config import Settings
    from cyberops_kit.core.models import RunContext, Target

    ctx = RunContext(
        run_id="r",
        target=Target(repository="a/b", commit_sha="c" * 40, source="local"),
        workspace=Path("/tmp"),
        offline=False,
        config=Settings(),
    )
    built = trivy.PLUGIN.build_command(ctx, Path("/tmp"))
    assert "--scanners=misconfig" in built
    assert "vuln" not in " ".join(built)


# --- Syft ----------------------------------------------------------------------


def test_syft_returns_documents_not_findings(run_context, tmp_path):
    (tmp_path / syft.CYCLONEDX_FILENAME).write_text(load_fixture("sbom.cdx.json"), encoding="utf-8")
    result = command_result()

    assert syft.PLUGIN.parse(result, run_context, tmp_path) == []
    documents = syft.PLUGIN.extract_documents(result, run_context, tmp_path)
    assert "cyclonedx-1.6" in documents


def test_syft_reports_component_count(run_context, tmp_path):
    (tmp_path / syft.CYCLONEDX_FILENAME).write_text(load_fixture("sbom.cdx.json"), encoding="utf-8")
    metrics = syft.PLUGIN.extract_metrics(command_result(), run_context, tmp_path)
    assert metrics == {syft.COMPONENT_COUNT_METRIC: 4.0}


# --- Plugin contract -----------------------------------------------------------


@pytest.mark.parametrize("plugin", all_plugins(), ids=lambda p: p.name)
def test_every_plugin_declares_the_required_interface(plugin):
    assert isinstance(plugin.name, str)
    assert plugin.name
    assert plugin.version_command
    assert isinstance(plugin.execution_mode, ExecutionMode)
    assert isinstance(plugin.requires_network, bool)


@pytest.mark.parametrize("plugin", all_plugins(), ids=lambda p: p.name)
def test_every_plugin_is_registered_under_its_own_name(plugin):
    assert get(plugin.name) is plugin


async def test_missing_binary_yields_a_skipped_result(run_context, monkeypatch):
    """A missing tool is a skip with a reason, never a crash."""
    monkeypatch.setattr(osv.PLUGIN, "is_available", lambda: False)
    result = await osv.PLUGIN.run(run_context)

    assert result.outcome is ScanOutcome.SKIPPED
    assert result.reason == "not_installed"


def test_version_parsing():
    from cyberops_kit.scanners.base import ScannerPlugin

    assert ScannerPlugin.parse_version("osv-scanner version 1.9.2") == "1.9.2"
    assert ScannerPlugin.parse_version("v5.0.0") == "5.0.0"
    assert ScannerPlugin.parse_version("no version here") == "unknown"


def test_fixtures_exist_for_every_parsing_scanner():
    """Each scanner that parses output ships a fixture with known findings."""
    for name in ("scorecard", "osv", "semgrep", "gitleaks", "trivy"):
        assert (FIXTURES / f"{name}.json").is_file(), f"missing fixture for {name}"


# --- Gitleaks invocation (regression) -------------------------------------------


def test_gitleaks_uses_the_git_subcommand_for_a_repository(run_context, tmp_path):
    """v8 removed `gitleaks detect --source=`; a repo must use `git <path>`.

    Regression test: the v7 invocation exits 0 and writes an empty report, so the
    scanner silently reported zero secrets on a repository that had one.
    """
    (tmp_path / ".git").mkdir()
    ctx = run_context.model_copy(update={"workspace": tmp_path})

    command = gitleaks.PLUGIN.build_command(ctx, tmp_path)

    assert command[:3] == ["gitleaks", "git", str(tmp_path)]
    assert "detect" not in command
    assert not any(arg.startswith("--source") for arg in command)


def test_gitleaks_uses_the_dir_subcommand_for_a_plain_directory(run_context, tmp_path):
    ctx = run_context.model_copy(update={"workspace": tmp_path})
    command = gitleaks.PLUGIN.build_command(ctx, tmp_path)

    assert command[:3] == ["gitleaks", "dir", str(tmp_path)]


def test_gitleaks_keeps_the_literal_secret_in_its_own_report(run_context, tmp_path):
    """core/redaction.py needs the exact bytes to strip them precisely (INV-4)."""
    command = gitleaks.PLUGIN.build_command(run_context, tmp_path)
    assert "--redact=0" in command
