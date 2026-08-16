"""Unit tests for detection, config, models, normalization, SBOM, and storage."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberops_kit.config import Settings, find_config_file, load_settings
from cyberops_kit.core.detector import detect_project
from cyberops_kit.core.errors import ConfigError, DetectionError
from cyberops_kit.core.models import (
    Category,
    CIPlatform,
    IaCKind,
    PackageManager,
    Severity,
    compute_finding_id,
    normalize_path,
    sort_findings,
)
from cyberops_kit.core.normalize import (
    apply_path_exclusions,
    assert_unique_ids,
    deduplicate,
    normalize,
    path_is_excluded,
)
from cyberops_kit.core.redaction import Redactor, shannon_entropy
from cyberops_kit.sbom.analyze import analyze_sbom, parse_cyclonedx
from cyberops_kit.scanners.base import ScanOutcome, ScanResult
from cyberops_kit.storage.history import History, compare
from tests.conftest import load_fixture, make_finding, make_report

# --- Detector ------------------------------------------------------------------


@pytest.fixture
def sample_tree(tmp_path: Path) -> Path:
    """A polyglot project with IaC, containers, and CI."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hi')\n")
    (tmp_path / "src" / "util.py").write_text("x = 1\n")
    (tmp_path / "src" / "index.ts").write_text("export const a = 1;\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')

    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
    )

    k8s = tmp_path / "deploy.yaml"
    k8s.write_text("apiVersion: apps/v1\nkind: Deployment\n")

    vendored = tmp_path / "node_modules" / "junk"
    vendored.mkdir(parents=True)
    (vendored / "big.js").write_text("x" * 100)

    return tmp_path


def test_detector_identifies_languages(sample_tree):
    profile = detect_project(sample_tree)
    assert "Python" in profile.language_names
    assert "TypeScript" in profile.language_names
    # Python has 2 files vs TypeScript's 1, so it sorts first.
    assert profile.language_names[0] == "Python"


def test_detector_prunes_vendored_directories(sample_tree):
    """node_modules skews language stats and must not be walked."""
    profile = detect_project(sample_tree)
    assert not any("node_modules" in m for m in profile.manifests)


def test_detector_identifies_package_managers(sample_tree):
    profile = detect_project(sample_tree)
    assert PackageManager.PIP in profile.package_managers
    assert PackageManager.NPM in profile.package_managers


def test_detector_identifies_containers_iac_and_ci(sample_tree):
    profile = detect_project(sample_tree)
    assert profile.containerized is True
    assert IaCKind.TERRAFORM in profile.iac
    assert IaCKind.KUBERNETES in profile.iac
    assert profile.ci_platform is CIPlatform.GITHUB_ACTIONS
    assert ".github/workflows/ci.yml" in profile.ci_workflows


def test_detector_output_is_deterministic(sample_tree):
    """Two walks of the same tree produce identical profiles (INV-3)."""
    first = detect_project(sample_tree)
    second = detect_project(sample_tree)
    assert first.model_dump_json() == second.model_dump_json()


def test_detector_sorts_every_list(sample_tree):
    profile = detect_project(sample_tree)
    assert profile.manifests == sorted(profile.manifests)
    assert profile.lockfiles == sorted(profile.lockfiles)
    assert [m.value for m in profile.package_managers] == sorted(
        m.value for m in profile.package_managers
    )


def test_detector_rejects_a_missing_directory(tmp_path):
    with pytest.raises(DetectionError):
        detect_project(tmp_path / "nope")


def test_detector_classifies_distribution(sample_tree, tmp_path):
    assert detect_project(sample_tree).distribution == "application"  # has Dockerfile

    library = tmp_path / "lib"
    library.mkdir()
    (library / "pyproject.toml").write_text("[project]\n")
    assert detect_project(library).distribution == "library"


# --- Config --------------------------------------------------------------------


def test_config_defaults_match_the_spec():
    settings = Settings()
    weights = {k.value: v for k, v in settings.scoring.weights.items()}
    assert weights == {
        "openssf_scorecard": 25.0,
        "known_vulnerabilities": 25.0,
        "supply_chain_integrity": 20.0,
        "static_analysis": 15.0,
        "secrets_exposure": 10.0,
        "sbom_health": 5.0,
    }
    assert settings.scanners.timeout_seconds == 600
    assert settings.thresholds.fail_below_score == 60
    assert settings.thresholds.fail_on_severity is Severity.CRITICAL


def test_config_loads_from_yaml(tmp_path):
    (tmp_path / ".cyberops.yml").write_text(
        "version: 1\nscanners:\n  timeout_seconds: 120\nthresholds:\n  fail_below_score: 80\n"
    )
    settings = load_settings(search_from=tmp_path)
    assert settings.scanners.timeout_seconds == 120
    assert settings.thresholds.fail_below_score == 80


def test_timeout_for_falls_back_to_the_global_budget():
    settings = Settings()
    assert settings.scanners.timeout_for("scorecard") == settings.scanners.timeout_seconds


def test_timeout_for_prefers_a_per_scanner_budget(tmp_path):
    """One global budget has to be sized for the slowest tool.

    A fast scanner that hangs then holds the run open for as long as the slowest one
    legitimately needs, which is how a Scorecard hang cost a full 600s.
    """
    (tmp_path / ".cyberops.yml").write_text(
        "version: 1\nscanners:\n  timeout_seconds: 600\n  timeouts:\n"
        "    gitleaks: 120\n    SCORECARD: 300\n"
    )
    scanners = load_settings(search_from=tmp_path).scanners

    assert scanners.timeout_for("gitleaks") == 120
    # Names are normalized, so casing in a config file cannot silently miss.
    assert scanners.timeout_for("scorecard") == 300
    assert scanners.timeout_for("semgrep") == 600


def test_timeouts_are_sorted_so_yaml_key_order_cannot_leak_in(tmp_path):
    (tmp_path / ".cyberops.yml").write_text(
        "version: 1\nscanners:\n  timeouts:\n    trivy: 30\n    gitleaks: 20\n    osv: 10\n"
    )
    scanners = load_settings(search_from=tmp_path).scanners
    assert list(scanners.timeouts) == sorted(scanners.timeouts)


@pytest.mark.parametrize("seconds", [0, -1, 86_401])
def test_timeouts_reject_nonsensical_budgets(tmp_path, seconds):
    (tmp_path / ".cyberops.yml").write_text(
        f"version: 1\nscanners:\n  timeouts:\n    gitleaks: {seconds}\n"
    )
    with pytest.raises(ConfigError):
        load_settings(search_from=tmp_path)


def test_config_rejects_unknown_keys(tmp_path):
    (tmp_path / ".cyberops.yml").write_text("version: 1\nnonsense: true\n")
    with pytest.raises(ConfigError):
        load_settings(search_from=tmp_path)


def test_config_rejects_a_future_version(tmp_path):
    (tmp_path / ".cyberops.yml").write_text("version: 99\n")
    with pytest.raises(ConfigError, match="unsupported config version"):
        load_settings(search_from=tmp_path)


def test_config_rejects_negative_weights():
    with pytest.raises(ValueError, match="must be >= 0"):
        Settings(scoring={"weights": {"openssf_scorecard": -1}})


def test_config_rejects_all_zero_weights():
    with pytest.raises(ValueError, match="at least one positive"):
        Settings(scoring={"weights": {"openssf_scorecard": 0, "sbom_health": 0}})


def test_config_missing_explicit_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_settings(config_path=tmp_path / "absent.yml")


def test_config_discovery_walks_upward(tmp_path):
    (tmp_path / ".cyberops.yml").write_text("version: 1\n")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_config_file(nested) == tmp_path / ".cyberops.yml"


def test_weights_are_stored_in_sorted_key_order():
    settings = Settings(scoring={"weights": {"secrets_exposure": 10, "openssf_scorecard": 25}})
    keys = [k.value for k in settings.scoring.weights]
    assert keys == sorted(keys)


# --- Models --------------------------------------------------------------------


def test_finding_ids_are_16_hex_chars():
    finding = make_finding()
    assert len(finding.id) == 16
    int(finding.id, 16)


def test_finding_id_changes_with_identity_but_not_with_metadata():
    base = compute_finding_id(scanner="osv", rule_id="CVE-1", path="a.py", anchor="s:f")
    assert base == compute_finding_id(scanner="osv", rule_id="CVE-1", path="a.py", anchor="s:f")
    assert base != compute_finding_id(scanner="osv", rule_id="CVE-2", path="a.py", anchor="s:f")
    assert base != compute_finding_id(scanner="trivy", rule_id="CVE-1", path="a.py", anchor="s:f")


def test_normalize_path_is_platform_independent(tmp_path):
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "app.py"
    target.write_text("")
    assert normalize_path(target, root=tmp_path) == "src/app.py"
    assert normalize_path("./src/app.py") == "src/app.py"


def test_location_anchor_prefers_content_over_line():
    from cyberops_kit.core.models import Location

    assert Location(path="a.py", start_line=5, snippet_hash="deadbeef").anchor == "h:deadbeef"
    assert Location(path="a.py", start_line=5, symbol="fn").anchor == "s:fn"
    assert Location(path="a.py", start_line=5).anchor == "l:5"


def test_findings_are_frozen():
    finding = make_finding()
    with pytest.raises(ValueError, match="frozen"):
        finding.severity = Severity.LOW


def test_sort_findings_is_total_and_severity_first():
    findings = [
        make_finding(rule_id="a", severity=Severity.LOW),
        make_finding(rule_id="b", severity=Severity.CRITICAL),
        make_finding(rule_id="c", severity=Severity.MEDIUM),
    ]
    ordered = sort_findings(findings)
    assert [f.severity for f in ordered] == [
        Severity.CRITICAL,
        Severity.MEDIUM,
        Severity.LOW,
    ]


# --- Normalize -----------------------------------------------------------------


def test_deduplicate_removes_repeated_ids():
    finding = make_finding()
    assert len(deduplicate([finding, finding, finding])) == 1


def test_normalize_merges_and_orders_scanner_results():
    results = [
        ScanResult(
            scanner="osv",
            outcome=ScanOutcome.COMPLETED,
            findings=[make_finding(rule_id="CVE-1", severity=Severity.LOW)],
        ),
        ScanResult(
            scanner="semgrep",
            outcome=ScanOutcome.COMPLETED,
            findings=[
                make_finding(
                    scanner="semgrep",
                    rule_id="rule-1",
                    severity=Severity.CRITICAL,
                    category=Category.STATIC_ANALYSIS,
                )
            ],
        ),
    ]
    findings = normalize(results)
    assert len(findings) == 2
    assert findings[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # The regression: `lstrip("./")` strips every leading "." and "/" character,
        # not the "./" prefix, so it ate the dot off every dotfile. The mangled path
        # is what SARIF hands to the GitHub Security tab, so annotations pointed at
        # files that do not exist.
        (".github/workflows/ci.yml", ".github/workflows/ci.yml"),
        (".cyberops.yml", ".cyberops.yml"),
        (".env.example", ".env.example"),
        # The prefix it is actually meant to remove.
        ("./src/app.py", "src/app.py"),
        ("././src/app.py", "src/app.py"),
        # Untouched cases.
        ("src/app.py", "src/app.py"),
        ("src/.hidden/x.py", "src/.hidden/x.py"),
    ],
)
def test_normalize_path_keeps_the_dot_on_dotfiles(raw, expected):
    assert normalize_path(raw) == expected


def test_dotted_directories_can_be_named_as_exclusion_patterns():
    """A pattern of `.github` must mean `.github`, not `github`."""
    assert path_is_excluded(".github/workflows/ci.yml", [".github"]) is True
    assert path_is_excluded("github/ci.yml", [".github"]) is False


@pytest.mark.parametrize(
    ("path", "patterns", "excluded"),
    [
        # A bare directory excludes everything beneath it — the common case.
        ("tests/fixtures/sbom.cdx.json", ["tests/fixtures"], True),
        ("tests/fixtures/deep/nested.json", ["tests/fixtures"], True),
        ("tests/fixtures", ["tests/fixtures"], True),
        # Anchored at the repo root, so a bare name never matches mid-path.
        ("src/tests/fixtures/a.json", ["tests"], False),
        # A prefix that is not a path segment must not match.
        ("tests/fixtures_extra/a.json", ["tests/fixtures"], False),
        # Globs work, and are the way to match across directories.
        ("vendor/lib/jquery.min.js", ["**/*.min.js"], True),
        ("src/app.py", ["**/*.min.js"], False),
        # Cosmetic variations users actually type.
        ("tests/fixtures/a.json", ["./tests/fixtures/"], True),
        ("tests/fixtures/a.json", ["  tests/fixtures  "], True),
        # Empty and whitespace-only patterns exclude nothing, rather than everything.
        ("src/app.py", [""], False),
        ("src/app.py", ["   "], False),
        ("src/app.py", [], False),
    ],
)
def test_path_is_excluded_matches_intuitively(path, patterns, excluded):
    assert path_is_excluded(path, patterns) is excluded


def test_apply_path_exclusions_drops_matching_findings_and_discloses_the_count():
    findings = [
        make_finding(rule_id="CVE-1", path="tests/fixtures/sbom.cdx.json"),
        make_finding(rule_id="CVE-2", path="tests/fixtures/creds.json"),
        make_finding(rule_id="CVE-3", path="src/app.py"),
    ]
    kept, disclosure = apply_path_exclusions(findings, ["tests/fixtures"])

    assert [f.rule_id for f in kept] == ["CVE-3"]
    assert disclosure.suppressed_findings == 2
    assert disclosure.patterns == ["tests/fixtures"]
    assert disclosure.active is True


def test_apply_path_exclusions_never_drops_a_finding_with_no_location():
    """A path pattern cannot speak to a finding about the repository as a whole.

    Scorecard's process checks and the SLSA assessment carry no location. Excluding
    them on a path pattern would silently drop whole scoring dimensions.
    """
    findings = [
        make_finding(scanner="scorecard", rule_id="Branch-Protection", path=None),
        make_finding(rule_id="CVE-1", path="tests/fixtures/a.json"),
    ]
    kept, disclosure = apply_path_exclusions(findings, ["tests/fixtures", "**"])

    assert [f.rule_id for f in kept] == ["Branch-Protection"]
    assert disclosure.suppressed_findings == 1


def test_apply_path_exclusions_is_a_no_op_without_patterns():
    findings = [make_finding(rule_id=f"CVE-{n}") for n in range(3)]
    kept, disclosure = apply_path_exclusions(findings, [])

    assert kept == findings
    assert disclosure.suppressed_findings == 0
    assert disclosure.active is False


def test_assert_unique_ids_detects_collisions():
    finding = make_finding()
    assert_unique_ids([finding])
    with pytest.raises(ValueError, match="collision"):
        assert_unique_ids([finding, finding])


# --- Redaction internals -------------------------------------------------------


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0


def test_entropy_layer_ignores_hex():
    """Hex maxes at 4.0 bits/char, below the 4.5 threshold — by design."""
    redactor = Redactor()
    assert redactor._is_high_entropy("a" * 40) is False
    assert redactor._is_high_entropy("3f786850e387550fdab836ed7e6dc881de23001b") is False


def test_pattern_redaction_preserves_context():
    """`password=[REDACTED:...]` is more useful in a report than an erased line."""
    result = Redactor().redact_text('password = "hunter2hunter2"')
    assert "hunter2hunter2" not in result
    assert "password" in result


# --- SBOM ----------------------------------------------------------------------


def test_parse_cyclonedx_extracts_components():
    components = parse_cyclonedx(load_fixture("sbom.cdx.json"))
    assert len(components) == 4
    names = {c.name for c in components}
    assert names == {"lodash", "requests", "mystery-lib", "unversioned-lib"}


def test_sbom_analysis_counts_health_signals():
    summary = analyze_sbom({"cyclonedx-1.6": load_fixture("sbom.cdx.json")})

    assert summary.generated is True
    assert summary.component_count == 4
    assert summary.unresolved_count == 1  # unversioned-lib
    assert summary.license_unknown_count == 2  # mystery-lib and the NOASSERTION entry
    assert summary.outdated_count is None  # never guessed


def test_sbom_analysis_of_nothing():
    assert analyze_sbom({}).generated is False


def test_sbom_parse_of_garbage_is_safe():
    assert parse_cyclonedx("not json") == []


def test_sbom_components_are_sorted_deterministically():
    first = parse_cyclonedx(load_fixture("sbom.cdx.json"))
    second = parse_cyclonedx(load_fixture("sbom.cdx.json"))
    assert [c.purl for c in first] == [c.purl for c in second]


# --- Storage -------------------------------------------------------------------


def test_history_records_and_loads(tmp_path, sample_findings):
    history = History(tmp_path)
    report = make_report(sample_findings)

    history.record(report)
    loaded = history.load(report.results.target.commit_sha)

    assert loaded is not None
    assert loaded.results.score.composite == report.results.score.composite


def test_history_index_is_a_trend_series(tmp_path, sample_findings):
    history = History(tmp_path)
    history.record(make_report(sample_findings))

    entries = history.entries()
    assert len(entries) == 1
    assert entries[0].composite == make_report(sample_findings).results.score.composite


def test_history_replaces_an_entry_for_the_same_commit(tmp_path, sample_findings):
    history = History(tmp_path)
    history.record(make_report(sample_findings))
    history.record(make_report(sample_findings))
    assert len(history.entries()) == 1


def test_history_load_of_unknown_commit_returns_none(tmp_path):
    assert History(tmp_path).load("f" * 40) is None


def test_compare_identifies_new_and_fixed(sample_findings):
    baseline = make_report(sample_findings)
    current = make_report([*sample_findings[:-1], make_finding(rule_id="CVE-NEW")])

    delta = compare(current, baseline)

    assert len(delta.new) == 1
    assert delta.new[0].rule_id == "CVE-NEW"
    assert len(delta.fixed) == 1


def test_compare_without_a_baseline_reports_nothing_as_new(sample_findings):
    """Reporting an entire backlog as "new" on the first run would be noise."""
    delta = compare(make_report(sample_findings), None)
    assert delta.new == []
    assert delta.unchanged == len(sample_findings)


def test_delta_survives_a_line_shift():
    """Stable IDs are what make this work across a refactor."""
    from cyberops_kit.core.models import Location

    original = make_finding(rule_id="rule-1")
    moved = original.model_copy(
        update={"location": Location(path="src/app.py", start_line=500, symbol="handler")}
    )
    # Same scanner, rule, path, and symbol anchor -> same ID despite the new line.
    assert original.id == moved.id
