"""Canonical data model — the contract every other module depends on.

Nothing in this package invents its own shape for a finding, a profile, or a score.
Scanners parse native output *into* these types; reporters render *from* them.

Two structural rules are enforced here rather than by convention:

* Models are frozen. An enricher physically cannot mutate a ``Finding`` in place
  (SEAM-2), and a reporter cannot rewrite a score.
* ``Results`` contains no wall-clock, host, or duration values. Everything
  nondeterministic lives in ``RunMetadata`` (INV-3).
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:  # pragma: no cover - resolved by config.py at import time
    # Deliberately deferred: config.py imports models.py, so importing Settings at
    # runtime here would be circular. config.py calls RunContext.model_rebuild() to
    # resolve this forward reference.
    from cyberops_kit.config import Settings  # noqa: TC004

SCHEMA_VERSION: Final = "1.0.0"
"""Version of the output envelope. Bumped only on a breaking schema change."""


# --- Enumerations --------------------------------------------------------------


class Severity(StrEnum):
    """Normalized severity. Every scanner's native scale maps onto these five."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Return sort rank, most severe first. Used for deterministic ordering."""
        return _SEVERITY_RANK[self]

    @property
    def is_actionable(self) -> bool:
        """Return whether this severity counts toward failure thresholds."""
        return self in _ACTIONABLE_SEVERITIES


_SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_ACTIONABLE_SEVERITIES: Final[frozenset[Severity]] = frozenset(
    {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}
)


class Category(StrEnum):
    """What kind of problem a finding describes."""

    VULNERABILITY = "vulnerability"
    """Known CVE in a dependency."""

    SECRET = "secret"  # noqa: S105 - a finding category, not a credential
    """Committed credential."""

    STATIC_ANALYSIS = "static_analysis"
    """SAST result."""

    MISCONFIGURATION = "misconfiguration"
    """IaC, container, or workflow misconfiguration."""

    SUPPLY_CHAIN = "supply_chain"
    """Provenance, pinning, or signing weakness."""

    PRACTICE = "practice"
    """Process hygiene, as reported by Scorecard."""


class Confidence(StrEnum):
    """How certain the *scanner* is. Distinct from advisory confidence."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PackageManager(StrEnum):
    """Package managers the detector recognizes."""

    NPM = "npm"
    YARN = "yarn"
    PNPM = "pnpm"
    PIP = "pip"
    POETRY = "poetry"
    UV = "uv"
    GO_MODULES = "go_modules"
    CARGO = "cargo"
    MAVEN = "maven"
    GRADLE = "gradle"
    NUGET = "nuget"
    BUNDLER = "bundler"
    COMPOSER = "composer"


class IaCKind(StrEnum):
    """Infrastructure-as-code technologies the detector recognizes."""

    TERRAFORM = "terraform"
    KUBERNETES = "kubernetes"
    HELM = "helm"
    CLOUDFORMATION = "cloudformation"
    ANSIBLE = "ansible"
    DOCKER_COMPOSE = "docker_compose"


class CIPlatform(StrEnum):
    """CI platforms the detector recognizes."""

    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    CIRCLECI = "circleci"
    JENKINS = "jenkins"
    AZURE_PIPELINES = "azure_pipelines"
    TRAVIS = "travis"


class Grade(StrEnum):
    """Letter grade derived from the composite score."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class DimensionKey(StrEnum):
    """The six scoring dimensions. Weight keys in config must match these."""

    OPENSSF_SCORECARD = "openssf_scorecard"
    KNOWN_VULNERABILITIES = "known_vulnerabilities"
    SUPPLY_CHAIN_INTEGRITY = "supply_chain_integrity"
    STATIC_ANALYSIS = "static_analysis"
    SECRETS_EXPOSURE = "secrets_exposure"
    SBOM_HEALTH = "sbom_health"


class SBOMFormat(StrEnum):
    """SBOM serialization formats emitted by the ``sbom`` package."""

    CYCLONEDX_1_6 = "cyclonedx-1.6"
    SPDX_3_0 = "spdx-3.0"


# --- Path and identity helpers -------------------------------------------------


def normalize_path(path: str | Path, *, root: Path | None = None) -> str:
    """Normalize a filesystem path into a stable, repo-relative POSIX string.

    Finding IDs must survive a checkout at a different absolute path, on a different
    operating system. This strips the workspace prefix, collapses separators, and
    removes ``./`` prefixes so the same file yields the same anchor everywhere.

    Args:
        path: Absolute or relative path reported by a scanner.
        root: Repository root to make the path relative to, when known.

    Returns:
        A POSIX-style path relative to ``root`` where possible, else normalized
        as given.
    """
    candidate = Path(path)
    if root is not None:
        try:
            candidate = candidate.resolve().relative_to(root.resolve())
        except (ValueError, OSError):
            # Outside the workspace, or unresolvable: fall through to as-given.
            candidate = Path(path)
    text = candidate.as_posix().lstrip("./")
    return text.strip("/")


def compute_finding_id(
    *,
    scanner: str,
    rule_id: str,
    path: str | None = None,
    purl: str | None = None,
    anchor: str | None = None,
) -> str:
    """Compute the stable content hash that identifies a finding.

    ``sha256(scanner | rule_id | normalized_path | package_purl | line_anchor)[:16]``

    Stability across runs is what makes PR deltas, the trend dashboard, and a
    suppression file that survives refactors possible. The anchor deliberately
    prefers a symbol name or content hash over a line number, because line numbers
    shift whenever anything above them changes.

    Args:
        scanner: Scanner plugin name.
        rule_id: Scanner-native rule identifier.
        path: Normalized, repo-relative path, when the finding is file-scoped.
        purl: Package URL, when the finding is dependency-scoped.
        anchor: Symbol name or content hash locating the finding within the file.

    Returns:
        A 16-character lowercase hex digest.
    """
    material = "|".join([scanner, rule_id, path or "", purl or "", anchor or ""])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


# --- Leaf models ---------------------------------------------------------------


class Location(BaseModel):
    """Where in the tree a finding lives."""

    model_config = ConfigDict(frozen=True)

    path: str
    """Repo-relative POSIX path. Always produced via :func:`normalize_path`."""

    start_line: int | None = None
    end_line: int | None = None

    symbol: str | None = None
    """Enclosing function or class, when the scanner reports one."""

    snippet_hash: str | None = None
    """Hash of the matched source text. The preferred stable anchor."""

    @property
    def anchor(self) -> str:
        """Return the most stable available anchor for ID computation.

        Prefers a content hash, then a symbol name, and only falls back to a line
        number when the scanner provides nothing better.
        """
        if self.snippet_hash:
            return f"h:{self.snippet_hash}"
        if self.symbol:
            return f"s:{self.symbol}"
        if self.start_line is not None:
            return f"l:{self.start_line}"
        return ""


class PackageRef(BaseModel):
    """A dependency a finding is attributed to."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    """Package URL, e.g. ``pkg:npm/lodash@4.17.20``."""


class ScannerRef(BaseModel):
    """Which tool produced a finding, at which version.

    The version belongs in ``results`` because it is part of the run's *input*
    identity: the same tool at the same version yields the same output (INV-3).
    """

    model_config = ConfigDict(frozen=True)

    name: str
    version: str


class Advisory(BaseModel):
    """Non-authoritative annotation attached by an enricher.

    Populated only in Phase 2. Never read by scoring (see INV-2).

    This model is fully specified in Phase 1 so that Phase 2 requires no schema
    change and no consumer migration (SEAM-1). A Phase 1 ``Finding`` serializes
    this field as ``null``.
    """

    model_config = ConfigDict(frozen=True)

    enricher: str
    """Enricher name, e.g. ``llm-triage``."""

    enricher_version: str
    assessment: Literal["likely_exploitable", "likely_false_positive", "unclear"]
    rationale: str
    confidence: Literal["low", "medium", "high"]
    remediation: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    generated_at: datetime
    provider: str | None = None
    """Inference provider, e.g. ``anthropic``."""

    model_id: str | None = None
    prompt_version: str | None = None


class Finding(BaseModel):
    """A single normalized security finding.

    Frozen by design: the enrichment stage must not be able to alter a finding in
    place, and reporters must not be able to rewrite one. Phase 2 attaches an
    advisory with ``model_copy(update=...)``, which the enrichment stage then
    verifies touched nothing else (SEAM-2).
    """

    model_config = ConfigDict(frozen=True)

    id: str
    """Stable content hash. See :func:`compute_finding_id`."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    confidence: Confidence = Confidence.MEDIUM
    location: Location | None = None
    package: PackageRef | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    fix_available: bool = False
    fixed_version: str | None = None
    verified: bool = False
    """Scanner-verified, e.g. a Gitleaks secret confirmed live. Drives hard caps."""

    scanner: ScannerRef
    raw: dict[str, Any] = Field(default_factory=dict)
    """The scanner's original record, preserved verbatim for auditability."""

    advisory: Advisory | None = None
    """SEAM-1. Always ``None`` in Phase 1. Never read by scoring (INV-2)."""

    @classmethod
    def build(
        cls,
        *,
        scanner: ScannerRef,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        category: Category,
        raw: dict[str, Any],
        location: Location | None = None,
        package: PackageRef | None = None,
        **extra: Any,
    ) -> Finding:
        """Construct a finding, deriving its stable ID from its identity fields.

        Scanner plugins use this rather than the constructor so that ID computation
        happens in exactly one place.

        Args:
            scanner: The producing tool and its version.
            rule_id: Scanner-native rule identifier.
            title: Short human-readable summary.
            description: Full description of the issue.
            severity: Normalized severity.
            category: Normalized category.
            raw: The scanner's original record, preserved verbatim.
            location: File location, when file-scoped.
            package: Dependency reference, when dependency-scoped.
            **extra: Any other ``Finding`` field.

        Returns:
            A fully-populated, frozen ``Finding``.
        """
        finding_id = compute_finding_id(
            scanner=scanner.name,
            rule_id=rule_id,
            path=location.path if location else None,
            purl=package.purl if package else None,
            anchor=location.anchor if location else None,
        )
        return cls(
            id=finding_id,
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            location=location,
            package=package,
            scanner=scanner,
            raw=raw,
            **extra,
        )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings in canonical order.

    Sorting by ``id`` alone would be deterministic but unreadable; sorting by
    severity first puts the important entries at the top of every report. The
    trailing ``id`` term guarantees a total order regardless of input order, which
    is what INV-1 and INV-3 require before any aggregation.

    Args:
        findings: Findings in arbitrary order.

    Returns:
        A new list in canonical order.
    """
    return sorted(findings, key=lambda f: (f.severity.rank, f.category.value, f.id))


# --- Project profile -----------------------------------------------------------


class LanguageStat(BaseModel):
    """Detected language and how much of the tree it accounts for."""

    model_config = ConfigDict(frozen=True)

    name: str
    file_count: int


class ProjectProfile(BaseModel):
    """What the target project is built from. Drives scanner selection.

    Every list is stored sorted so that two runs over the same tree produce a
    byte-identical profile regardless of filesystem walk order (INV-3).
    """

    model_config = ConfigDict(frozen=True)

    languages: list[LanguageStat] = Field(default_factory=list)
    package_managers: list[PackageManager] = Field(default_factory=list)
    manifests: list[str] = Field(default_factory=list)
    lockfiles: list[str] = Field(default_factory=list)
    containerized: bool = False
    container_files: list[str] = Field(default_factory=list)
    iac: list[IaCKind] = Field(default_factory=list)
    ci_platform: CIPlatform | None = None
    ci_workflows: list[str] = Field(default_factory=list)
    distribution: Literal["library", "application", "unknown"] = "unknown"
    """Best-effort classification. ``unknown`` when the evidence is ambiguous."""

    file_count: int = 0
    total_bytes: int = 0

    @property
    def language_names(self) -> list[str]:
        """Return detected language names, most files first."""
        return [lang.name for lang in self.languages]


# --- Target and run context ----------------------------------------------------


class Target(BaseModel):
    """The thing being scanned, pinned to an exact commit."""

    model_config = ConfigDict(frozen=True)

    repository: str
    """``owner/name`` for a GitHub target, or the directory name for a local one."""

    commit_sha: str
    """Full 40-character SHA, or ``"unknown"`` when the tree is not a git repo."""

    source: Literal["github", "local"]
    ref: str | None = None
    origin_url: str | None = None
    dirty: bool = False
    """True when the working tree has uncommitted changes. Breaks reproducibility."""


class RunContext(BaseModel):
    """Everything a pipeline stage needs to know about the current run.

    Passed to enrichers in Phase 2 (SEAM-2) so they can read configuration and
    honor ``offline`` without reaching for globals.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    run_id: str
    target: Target
    workspace: Path
    offline: bool
    config: Settings
    profile: ProjectProfile | None = None
    tool_versions: dict[str, str] = Field(default_factory=dict)


# --- SBOM and SLSA -------------------------------------------------------------


class SBOMComponent(BaseModel):
    """One component in the generated SBOM."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str | None = None
    purl: str | None = None
    licenses: list[str] = Field(default_factory=list)
    direct: bool | None = None


class SBOMSummary(BaseModel):
    """Aggregate SBOM health, and the formats emitted."""

    model_config = ConfigDict(frozen=True)

    generated: bool = False
    component_count: int = 0
    formats: list[SBOMFormat] = Field(default_factory=list)
    unresolved_count: int = 0
    """Declared dependencies that could not be resolved to a concrete version."""

    license_unknown_count: int = 0

    outdated_count: int | None = None
    """``None`` means staleness was not measured — determining whether a component
    is behind its latest release requires a network lookup. Scoring drops the
    freshness sub-metric rather than assuming everything is current."""

    files: dict[str, str] = Field(default_factory=dict)
    """Format name to written artifact path, relative to the output directory."""


class SLSAEvidence(BaseModel):
    """A single observation supporting or refuting a SLSA build level.

    A level is never asserted without its evidence list (Phase 1 spec §5).
    """

    model_config = ConfigDict(frozen=True)

    check: str
    passed: bool
    detail: str
    source: str
    """Where the observation came from, e.g. ``scorecard`` or ``slsa-verifier``."""


class SLSAAssessment(BaseModel):
    """Evaluated SLSA build track level with its supporting evidence."""

    model_config = ConfigDict(frozen=True)

    build_level: int = 0
    evidence: list[SLSAEvidence] = Field(default_factory=list)
    provenance_found: bool = False
    provenance_verified: bool = False


# --- Scoring -------------------------------------------------------------------


class DimensionScore(BaseModel):
    """One scoring dimension's normalized value and its weight."""

    model_config = ConfigDict(frozen=True)

    key: DimensionKey
    value: float | None = None
    """0-100, or ``None`` when excluded for lack of data."""

    configured_weight: float = 0.0
    effective_weight: float = 0.0
    """Weight after redistributing the weights of excluded dimensions."""

    excluded: bool = False
    exclusion_reason: str | None = None
    evidence: list[str] = Field(default_factory=list)


class AppliedCap(BaseModel):
    """A hard cap and whether this run triggered it."""

    model_config = ConfigDict(frozen=True)

    condition: str
    capped_at: int
    applied: bool
    detail: str | None = None


class Score(BaseModel):
    """The composite score and the full derivation behind it.

    The derivation is part of the output on purpose: a security score nobody can
    audit is worthless (INV-7).
    """

    model_config = ConfigDict(frozen=True)

    composite: int
    grade: Grade
    weighted_mean: float
    dimensions: dict[DimensionKey, DimensionScore] = Field(default_factory=dict)
    """Always built in sorted key order — never rely on dict iteration order."""

    caps: list[AppliedCap] = Field(default_factory=list)
    excluded_dimensions: list[DimensionKey] = Field(default_factory=list)

    coverage: float = 1.0
    """Fraction of configured weight that had data, 0.0-1.0. A composite derived
    from a small slice of the model is not comparable to a full one, so the number
    is reported rather than buried."""

    sufficient_coverage: bool = True
    """False when too little of the model could be evaluated for the grade to mean
    anything. Reports say so prominently and CI does not fail on the score."""


# --- Output envelope -----------------------------------------------------------


class ExclusionOutcome(StrEnum):
    """Why a scanner contributed no data to the run.

    The distinction is the whole point of this enum, so it is worth stating plainly:

    ``NOT_RUN`` is benign and expected. The tool is not installed, ``--offline``
    forbade it, or it did not apply to this project. Nothing is wrong.

    ``FAILED`` and ``TIMED_OUT`` mean the scanner *ran and something went wrong*.
    That is a problem somebody should act on.

    Collapsing these into one word — as an earlier version of this model did, calling
    everything "skipped" — hides real failures behind reassuring language. A scanner
    that crashed and a scanner that was never installed both remove a dimension from
    the score, but only one of them is a bug.
    """

    NOT_RUN = "not_run"
    FAILED = "failed"
    TIMED_OUT = "timed_out"

    @property
    def is_failure(self) -> bool:
        """Return whether this outcome represents something that went wrong."""
        return self is not ExclusionOutcome.NOT_RUN


class ExcludedScanner(BaseModel):
    """A scanner that produced no data, and why. Always surfaced in the report."""

    model_config = ConfigDict(frozen=True)

    name: str
    outcome: ExclusionOutcome
    reason: str
    """Machine-readable cause, e.g. ``not_installed``, ``offline``, ``timeout``."""

    detail: str | None = None


class PathExclusions(BaseModel):
    """What ``scanners.exclude_paths`` removed from this run.

    Scoping a scan and hiding a result are different acts, and the difference is
    only visible if the scope is stated. Every report renders this block, so a
    reader can always tell that a lower finding count reflects a narrower scan
    rather than a cleaner tree.

    Only *file-scoped* findings can be excluded. A finding with no location —
    Scorecard's process checks, the SLSA supply-chain assessment — describes the
    repository as a whole and is never suppressed by a path pattern.
    """

    model_config = ConfigDict(frozen=True)

    patterns: list[str] = Field(default_factory=list)
    """Configured glob patterns, verbatim."""

    suppressed_findings: int = 0
    """How many findings these patterns removed. Zero when nothing matched."""

    @property
    def active(self) -> bool:
        """Return whether any exclusion pattern was configured for this run."""
        return bool(self.patterns)


class Results(BaseModel):
    """The deterministic half of the output envelope.

    Byte-identical across runs of the same commit, tool versions, and config.
    Contains no timestamps, durations, hostnames, or run IDs (INV-3).
    """

    model_config = ConfigDict(frozen=True)

    schema_version: str = SCHEMA_VERSION
    target: Target
    profile: ProjectProfile
    findings: list[Finding] = Field(default_factory=list)
    sbom: SBOMSummary = Field(default_factory=SBOMSummary)
    slsa: SLSAAssessment = Field(default_factory=SLSAAssessment)
    score: Score
    scoring_model_version: str
    excluded_scanners: list[ExcludedScanner] = Field(default_factory=list)
    path_exclusions: PathExclusions = Field(default_factory=PathExclusions)

    @field_validator("findings")
    @classmethod
    def _canonically_ordered(cls, value: list[Finding]) -> list[Finding]:
        """Enforce canonical finding order at the envelope boundary (INV-3)."""
        return sort_findings(value)

    @property
    def failed_scanners(self) -> list[ExcludedScanner]:
        """Return scanners that ran and broke, as opposed to never running."""
        return [s for s in self.excluded_scanners if s.outcome.is_failure]

    @property
    def not_run_scanners(self) -> list[ExcludedScanner]:
        """Return scanners that were never invoked, for a benign, expected reason."""
        return [s for s in self.excluded_scanners if not s.outcome.is_failure]


class RunMetadata(BaseModel):
    """The nondeterministic half of the output envelope.

    Excluded from reproducibility checks by definition. Never merge these fields
    into ``Results`` (INV-3).
    """

    model_config = ConfigDict(frozen=True)

    run_id: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    tool_versions: dict[str, str] = Field(default_factory=dict)
    cyberops_version: str
    offline: bool = False
    host: str | None = None


class Report(BaseModel):
    """The complete output envelope: deterministic results plus run metadata."""

    model_config = ConfigDict(frozen=True)

    results: Results
    run_metadata: RunMetadata
