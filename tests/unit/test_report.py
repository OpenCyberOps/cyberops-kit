"""Report rendering: JSON, SARIF, Markdown, HTML, badge, and the PR comment."""

from __future__ import annotations

import json

import pytest

from cyberops_kit.core.errors import ReportError
from cyberops_kit.core.models import (
    DimensionKey,
    SBOMSummary,
    SLSAAssessment,
    SLSAEvidence,
)
from cyberops_kit.core.scoring import ScoringContext
from cyberops_kit.report.sarif import render_sarif
from cyberops_kit.report.writer import (
    FORMATS,
    render,
    render_badge,
    render_pr_comment,
    write_reports,
)
from cyberops_kit.storage.history import compare, delta_context
from tests.conftest import make_finding, make_report


def test_all_four_required_formats_render(sample_findings):
    """Phase 1 definition of done: JSON, SARIF, Markdown, and HTML output."""
    report = make_report(sample_findings)
    for fmt in ("json", "sarif", "markdown", "html"):
        output = render(report, fmt)
        assert output.strip()


def test_json_output_is_the_two_block_envelope(sample_findings):
    payload = json.loads(render(make_report(sample_findings), "json"))
    assert set(payload) == {"results", "run_metadata"}
    assert "score" in payload["results"]
    assert "scoring_model_version" in payload["results"]


def test_json_output_is_byte_stable(sample_findings):
    report = make_report(sample_findings)
    assert render(report, "json") == render(report, "json")


def test_sarif_is_valid_2_1_0(sample_findings):
    sarif = render_sarif(make_report(sample_findings))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "CyberOps Kit"
    assert driver["rules"]


def test_sarif_results_reference_valid_rule_indices(sample_findings):
    sarif = render_sarif(make_report(sample_findings))
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]

    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_sarif_severity_maps_to_github_levels(sample_findings):
    sarif = render_sarif(make_report(sample_findings))
    levels = {r["level"] for r in sarif["runs"][0]["results"]}
    assert levels <= {"error", "warning", "note"}


def test_sarif_carries_stable_fingerprints(sample_findings):
    """GitHub uses these to track a finding across runs."""
    sarif = render_sarif(make_report(sample_findings))
    for result in sarif["runs"][0]["results"]:
        assert len(result["partialFingerprints"]["cyberopsFindingId"]) == 16


def test_badge_reflects_the_grade():
    clean = make_report(
        [],
        context=ScoringContext(
            available_dimensions=frozenset(DimensionKey),
            sbom=SBOMSummary(generated=True, component_count=5),
            scorecard_aggregate=10.0,
            slsa=SLSAAssessment(
                build_level=3,
                evidence=[SLSAEvidence(check="c", passed=True, detail="d", source="s")],
            ),
        ),
    )
    badge = render_badge(clean)
    assert badge["schemaVersion"] == 1
    assert badge["label"] == "security"
    assert "A" in badge["message"]


def test_badge_says_not_scored_on_low_coverage():
    """A badge is the most decontextualized surface; it must not imply a verdict."""
    thin = make_report([], context=ScoringContext(available_dimensions=frozenset()))
    badge = render_badge(thin)
    assert badge["message"] == "not scored"
    assert badge["color"] == "lightgrey"


def test_markdown_states_the_disclaimer(sample_findings):
    output = render(make_report(sample_findings), "markdown")
    assert "augments professional security review" in output
    assert "does not replace it" in output.lower()


def test_html_is_self_contained(sample_findings):
    """No external CSS, fonts, or scripts."""
    output = render(make_report(sample_findings), "html")
    assert "<style>" in output
    assert "http://" not in output.replace("http://www.w3.org", "")
    assert "<script" not in output


def test_markdown_reports_excluded_dimensions():
    report = make_report(
        [],
        context=ScoringContext(
            available_dimensions=frozenset({DimensionKey.SECRETS_EXPOSURE}),
            sbom=SBOMSummary(generated=True, component_count=1),
        ),
    )
    output = render(report, "markdown")
    assert "excluded" in output


def test_reports_disclose_every_hard_cap(sample_findings):
    """Including the ones that did not fire."""
    output = render(make_report(sample_findings), "markdown")
    assert "verified, unrevoked secret" in output
    assert "known public exploit" in output
    assert "No SBOM could be generated" in output


def test_write_reports_creates_every_file(tmp_path, sample_findings):
    written = write_reports(
        make_report(sample_findings), tmp_path, ["json", "sarif", "markdown", "html"]
    )
    assert set(written) == {"json", "sarif", "markdown", "html", "badge"}
    for path in written.values():
        assert path.is_file()
        assert path.stat().st_size > 0


def test_write_reports_rejects_an_unknown_format(tmp_path, sample_findings):
    with pytest.raises(ReportError, match="unsupported"):
        write_reports(make_report(sample_findings), tmp_path, ["yaml"])


def test_render_rejects_an_unknown_format(sample_findings):
    with pytest.raises(ReportError):
        render(make_report(sample_findings), "yaml")


def test_pr_comment_renders_a_delta(sample_findings):
    baseline = make_report(sample_findings)
    current = make_report([*sample_findings[:-1], make_finding(rule_id="CVE-NEW")])
    delta = compare(current, baseline)

    comment = render_pr_comment(current, delta=delta_context(delta))

    assert "1 new" in comment
    assert "1 fixed" in comment
    assert "Score breakdown" in comment


def test_pr_comment_without_a_delta(sample_findings):
    comment = render_pr_comment(make_report(sample_findings))
    assert "Top findings" in comment


def test_pr_comment_notes_low_coverage():
    thin = make_report([], context=ScoringContext(available_dimensions=frozenset()))
    assert "not scored" in render_pr_comment(thin)


def test_formats_constant_matches_what_render_accepts(sample_findings):
    report = make_report(sample_findings)
    for fmt in FORMATS:
        assert render(report, fmt)
