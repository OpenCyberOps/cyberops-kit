"""Shared test fixtures."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from cyberops_kit.config import Settings
from cyberops_kit.core.models import (
    Advisory,
    Category,
    Confidence,
    DimensionKey,
    Finding,
    Grade,
    Location,
    PackageRef,
    ProjectProfile,
    Report,
    Results,
    RunContext,
    RunMetadata,
    ScannerRef,
    Severity,
    SLSAAssessment,
    SLSAEvidence,
    Target,
)
from cyberops_kit.core.scoring import SCORING_MODEL_VERSION, ScoringContext, compute_score

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    """Read a scanner output fixture as text.

    Args:
        name: Filename under ``tests/fixtures``.

    Returns:
        The file's contents.
    """
    return (FIXTURES / name).read_text(encoding="utf-8")


def make_finding(
    *,
    scanner: str = "osv",
    rule_id: str = "CVE-2021-0001",
    severity: Severity = Severity.HIGH,
    category: Category = Category.VULNERABILITY,
    path: str | None = "src/app.py",
    purl: str | None = None,
    verified: bool = False,
    raw: dict[str, Any] | None = None,
    **extra: Any,
) -> Finding:
    """Build a finding with sensible defaults for tests."""
    return Finding.build(
        scanner=ScannerRef(name=scanner, version="1.0.0"),
        rule_id=rule_id,
        title=f"{rule_id} title",
        description=f"{rule_id} description",
        severity=severity,
        category=category,
        confidence=Confidence.HIGH,
        location=Location(path=path, start_line=10, symbol="handler") if path else None,
        package=PackageRef(name="lodash", version="4.17.20", purl=purl) if purl else None,
        verified=verified,
        raw=raw if raw is not None else {"source": rule_id},
        **extra,
    )


@pytest.fixture
def sample_findings() -> list[Finding]:
    """A mixed set of findings spanning every category and severity."""
    return [
        make_finding(rule_id="CVE-2021-1", severity=Severity.CRITICAL, purl="pkg:npm/a@1.0.0"),
        make_finding(rule_id="CVE-2021-2", severity=Severity.HIGH, purl="pkg:npm/b@1.0.0"),
        make_finding(rule_id="CVE-2021-3", severity=Severity.MEDIUM, purl="pkg:npm/c@1.0.0"),
        make_finding(
            scanner="semgrep",
            rule_id="python.lang.security.audit",
            severity=Severity.HIGH,
            category=Category.STATIC_ANALYSIS,
            path="src/handler.py",
        ),
        make_finding(
            scanner="semgrep",
            rule_id="python.lang.security.other",
            severity=Severity.LOW,
            category=Category.STATIC_ANALYSIS,
            path="src/other.py",
        ),
        make_finding(
            scanner="gitleaks",
            rule_id="generic-api-key",
            severity=Severity.CRITICAL,
            category=Category.SECRET,
            path="config/settings.py",
        ),
        make_finding(
            scanner="scorecard",
            rule_id="Branch-Protection",
            severity=Severity.MEDIUM,
            category=Category.PRACTICE,
            path=None,
        ),
        make_finding(
            scanner="trivy",
            rule_id="AVD-DS-0002",
            severity=Severity.MEDIUM,
            category=Category.MISCONFIGURATION,
            path="Dockerfile",
        ),
        make_finding(
            scanner="slsa",
            rule_id="slsa-unpinned-action",
            severity=Severity.MEDIUM,
            category=Category.SUPPLY_CHAIN,
            path=".github/workflows/ci.yml",
        ),
    ]


@pytest.fixture
def advisory() -> Advisory:
    """A fully-populated advisory, as Phase 2 would produce."""
    return Advisory(
        enricher="llm-triage",
        enricher_version="1.0.0",
        assessment="likely_false_positive",
        rationale="The vulnerable code path is unreachable from any exported entrypoint.",
        confidence="medium",
        remediation="Upgrade to 4.17.21 when convenient.",
        evidence_refs=["src/app.py:10"],
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        provider="anthropic",
        model_id="claude-opus-5",
        prompt_version="triage.v1",
    )


@pytest.fixture
def settings() -> Settings:
    """Default settings."""
    return Settings()


@pytest.fixture
def profile() -> ProjectProfile:
    """A minimal Python project profile."""
    return ProjectProfile(
        languages=[],
        package_managers=[],
        manifests=["pyproject.toml"],
        file_count=10,
    )


@pytest.fixture
def target() -> Target:
    """A pinned local target."""
    return Target(
        repository="owner/repo",
        commit_sha="a" * 40,
        source="local",
        ref="main",
        origin_url="https://github.com/owner/repo",
    )


@pytest.fixture
def run_context(settings: Settings, target: Target, profile: ProjectProfile, tmp_path: Path):
    """A run context pointing at a temp workspace."""
    return RunContext(
        run_id="test-run",
        target=target,
        workspace=tmp_path,
        offline=settings.offline,
        config=settings,
        profile=profile,
    )


@pytest.fixture
def full_context() -> ScoringContext:
    """A scoring context where every dimension has data."""
    return ScoringContext(
        scorecard_aggregate=7.5,
        sbom=_sbom(),
        slsa=SLSAAssessment(
            build_level=2,
            evidence=[
                SLSAEvidence(check="hosted", passed=True, detail="d", source="detector"),
                SLSAEvidence(check="gen", passed=True, detail="d", source="workflow-analysis"),
                SLSAEvidence(check="pinned", passed=False, detail="d", source="workflow-analysis"),
            ],
        ),
        available_dimensions=frozenset(DimensionKey),
    )


def _sbom():
    """Build an SBOM summary with realistic health numbers."""
    from cyberops_kit.core.models import SBOMFormat, SBOMSummary

    return SBOMSummary(
        generated=True,
        component_count=100,
        formats=[SBOMFormat.CYCLONEDX_1_6, SBOMFormat.SPDX_3_0],
        unresolved_count=5,
        license_unknown_count=10,
    )


def make_report(
    findings: list[Finding],
    *,
    context: ScoringContext | None = None,
    settings: Settings | None = None,
    target: Target | None = None,
) -> Report:
    """Assemble a full report envelope around a set of findings."""
    resolved_settings = settings or Settings()
    resolved_context = context or ScoringContext(
        available_dimensions=frozenset(DimensionKey), sbom=_sbom()
    )
    score = compute_score(findings, resolved_settings.scoring.weights, context=resolved_context)
    now = datetime(2026, 1, 1, tzinfo=UTC)

    return Report(
        results=Results(
            target=target or Target(repository="owner/repo", commit_sha="a" * 40, source="local"),
            profile=ProjectProfile(file_count=1),
            findings=findings,
            sbom=resolved_context.sbom,
            slsa=resolved_context.slsa or SLSAAssessment(),
            score=score,
            scoring_model_version=SCORING_MODEL_VERSION,
        ),
        run_metadata=RunMetadata(
            run_id="run-1",
            started_at=now,
            completed_at=now,
            duration_seconds=1.0,
            cyberops_version="0.1.0",
        ),
    )


def write_json(path: Path, payload: Any) -> Path:
    """Write a JSON payload to a path and return it."""
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


__all__ = [
    "FIXTURES",
    "Grade",
    "load_fixture",
    "make_finding",
    "make_report",
    "write_json",
]
