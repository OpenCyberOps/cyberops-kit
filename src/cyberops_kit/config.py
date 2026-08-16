"""Settings schema and loader for ``.cyberops.yml``.

The schema includes the ``ai`` block in Phase 1 (SEAM-3), validated and defaulting
to disabled. Phase 2 flips defaults on; it adds no keys and needs no migration.
Users can read their own config file and see where the project is going.

Precedence, lowest to highest: built-in defaults, config file, CLI flags.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from cyberops_kit.core.errors import ConfigError
from cyberops_kit.core.models import DimensionKey, RunContext, Severity

CONFIG_FILENAMES: Final[tuple[str, ...]] = (".cyberops.yml", ".cyberops.yaml")
CONFIG_SCHEMA_VERSION: Final = 1

DEFAULT_SCANNERS: Final[tuple[str, ...]] = (
    "scorecard",
    "osv",
    "semgrep",
    "gitleaks",
    "trivy",
    "syft",
    "slsa",
)

DEFAULT_WEIGHTS: Final[dict[DimensionKey, float]] = {
    DimensionKey.OPENSSF_SCORECARD: 25.0,
    DimensionKey.KNOWN_VULNERABILITIES: 25.0,
    DimensionKey.SUPPLY_CHAIN_INTEGRITY: 20.0,
    DimensionKey.STATIC_ANALYSIS: 15.0,
    DimensionKey.SECRETS_EXPOSURE: 10.0,
    DimensionKey.SBOM_HEALTH: 5.0,
}
"""Published weights (Phase 1 spec §4). Changing these requires an INV-7 doc update."""


class ScannerSettings(BaseModel):
    """Which scanners run, and their execution budget."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: list[str] = Field(default_factory=lambda: list(DEFAULT_SCANNERS))
    timeout_seconds: int = Field(default=600, gt=0, le=86_400)
    """Default execution budget for any scanner without its own entry in ``timeouts``."""

    timeouts: dict[str, int] = Field(default_factory=dict)
    """Per-scanner budgets, overriding ``timeout_seconds``.

    One global budget has to be sized for the slowest tool, which means a fast tool
    that hangs holds the whole run open for as long as the slowest one legitimately
    needs. Naming a budget per scanner lets a hang be caught in proportion to what
    the tool actually costs.

    A timeout is a backstop, not a diagnosis. A scanner that reliably needs more time
    than it is given is usually misconfigured rather than slow.
    """
    exclude_paths: list[str] = Field(default_factory=list)
    """Paths excluded from detection and from file-scoped findings.

    Accepts an exact path, a directory (which excludes everything beneath it), or a
    glob. Enforcement is central: findings located under these paths are dropped in
    ``core/normalize.py`` after every scanner has run, so the setting holds even for
    tools with no exclusion flag of their own. Scanners that *do* have a reliable one
    also receive it, to avoid scanning what would be discarded.

    Every report discloses the configured patterns and how many findings they
    removed. Narrowing a scan and hiding a result differ only in whether the scope is
    stated, so it always is.

    Findings with no location are never excluded — a path pattern cannot speak to
    Scorecard's process checks or the SLSA assessment.
    """

    @field_validator("enabled")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        """Normalize scanner names and drop duplicates, preserving order."""
        seen: dict[str, None] = {}
        for name in value:
            seen.setdefault(name.strip().lower(), None)
        return list(seen)

    @field_validator("timeouts")
    @classmethod
    def _validate_timeouts(cls, value: dict[str, int]) -> dict[str, int]:
        """Normalize scanner names and reject nonsensical budgets."""
        normalized: dict[str, int] = {}
        for name, seconds in value.items():
            if not 0 < seconds <= 86_400:
                msg = f"scanners.timeouts.{name} must be between 1 and 86400, got {seconds}"
                raise ValueError(msg)
            normalized[name.strip().lower()] = seconds
        # Sorted so the resolved configuration does not depend on YAML key order.
        return {name: normalized[name] for name in sorted(normalized)}

    def timeout_for(self, name: str) -> int:
        """Return the execution budget for one scanner, in seconds.

        Args:
            name: Scanner plugin name.

        Returns:
            The scanner's own budget when configured, else the global default.
        """
        return self.timeouts.get(name.lower(), self.timeout_seconds)


class ScoringSettings(BaseModel):
    """Dimension weights. Documented publicly in ``docs/methodology/scoring.md``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    weights: dict[DimensionKey, float] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    @field_validator("weights")
    @classmethod
    def _validate_weights(cls, value: dict[DimensionKey, float]) -> dict[DimensionKey, float]:
        """Reject negative weights and all-zero weight sets."""
        for key, weight in value.items():
            if weight < 0:
                msg = f"scoring.weights.{key.value} must be >= 0, got {weight}"
                raise ValueError(msg)
        if sum(value.values()) <= 0:
            msg = "scoring.weights must contain at least one positive weight"
            raise ValueError(msg)
        # Sorted for determinism: the score derivation must not depend on the order
        # keys happened to appear in a YAML file (INV-1).
        return {key: value[key] for key in sorted(value, key=lambda k: k.value)}


class ThresholdSettings(BaseModel):
    """Conditions under which a run exits non-zero."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    fail_below_score: int | None = Field(default=60, ge=0, le=100)
    fail_on_severity: Severity | None = Severity.CRITICAL
    """Fail when any finding at or above this severity is present."""


class SandboxSettings(BaseModel):
    """Isolation settings for untrusted execution (INV-5)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    runtime: str = "docker"
    image: str = "ghcr.io/opencyberops/cyberops-kit-sandbox:latest"
    network: str = "none"
    """Container network mode. ``none`` unless a scanner declares it needs egress."""

    memory_limit: str = "2g"
    cpu_limit: str = "2"
    read_only_root: bool = True

    @field_validator("network")
    @classmethod
    def _validate_network(cls, value: str) -> str:
        """Restrict to the network modes the sandbox knows how to reason about."""
        allowed = {"none", "bridge"}
        if value not in allowed:
            msg = f"sandbox.network must be one of {sorted(allowed)}, got {value!r}"
            raise ValueError(msg)
        return value


class OutputSettings(BaseModel):
    """Where reports are written and in which formats."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    directory: Path = Path(".cyberops")
    formats: list[str] = Field(default_factory=lambda: ["json", "sarif", "markdown", "html"])
    badge: bool = True


class AISettings(BaseModel):
    """Reserved Phase 2 advisory settings (SEAM-3).

    Present, validated, and disabled in Phase 1. The enricher registry is empty, so
    enabling this changes nothing until Phase 2 registers an enricher.

    ``redact`` cannot be set to ``false``. INV-4 has no bypass flag, so the config
    validator refuses to construct a configuration that would imply one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = False
    provider: str | None = None
    model: str | None = None
    max_findings: int = Field(default=25, gt=0, le=1000)
    redact: bool = True

    @field_validator("redact")
    @classmethod
    def _redaction_is_mandatory(cls, value: bool) -> bool:
        """Reject ``ai.redact: false``. There is no bypass (INV-4)."""
        if not value:
            msg = (
                "ai.redact cannot be set to false. Redaction is a structural "
                "guarantee (INV-4), not a preference."
            )
            raise ValueError(msg)
        return value


class Settings(BaseModel):
    """Fully-resolved configuration for a run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int = CONFIG_SCHEMA_VERSION
    scanners: ScannerSettings = Field(default_factory=ScannerSettings)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    thresholds: ThresholdSettings = Field(default_factory=ThresholdSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    ai: AISettings = Field(default_factory=AISettings)

    offline: bool = False
    """Set from ``--offline``. Disables every outbound network call (INV-6)."""

    source_path: Path | None = None
    """Config file this was loaded from, for diagnostics. ``None`` when defaults."""

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: int) -> int:
        """Reject config files written for a schema version we do not understand."""
        if value != CONFIG_SCHEMA_VERSION:
            msg = f"unsupported config version {value}; this build expects {CONFIG_SCHEMA_VERSION}"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _validate_offline_ai(self) -> Settings:
        """Reject ``offline`` combined with AI enabled.

        INV-6 is absolute: offline does not warn and continue, and does not silently
        skip. A configuration that asks for both is a usage error.
        """
        if self.offline and self.ai.enabled:
            msg = (
                "--offline cannot be combined with ai.enabled: the AI layer requires "
                "network access and offline mode is absolute (INV-6)."
            )
            raise ValueError(msg)
        return self

    def scanner_enabled(self, name: str) -> bool:
        """Return whether the named scanner is enabled in this configuration.

        Args:
            name: Scanner plugin name.

        Returns:
            True when the scanner should be run.
        """
        return name.lower() in set(self.scanners.enabled)


def find_config_file(start: Path) -> Path | None:
    """Locate the nearest config file at or above ``start``.

    Args:
        start: Directory to begin searching from.

    Returns:
        Path to the config file, or ``None`` when no config file exists.
    """
    start = start.resolve()
    for directory in (start, *start.parents):
        for filename in CONFIG_FILENAMES:
            candidate = directory / filename
            if candidate.is_file():
                return candidate
    return None


def load_settings(
    *,
    config_path: Path | None = None,
    search_from: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> Settings:
    """Load, merge, and validate configuration.

    Args:
        config_path: Explicit config file. When given and missing, this is an error
            rather than a silent fallback to defaults.
        search_from: Directory to auto-discover a config file from.
        overrides: CLI-level overrides applied last, as a nested mapping.

    Returns:
        A validated, frozen ``Settings``.

    Raises:
        ConfigError: The file is missing, unparseable, or fails validation.
    """
    data: dict[str, Any] = {}
    resolved: Path | None = None

    if config_path is not None:
        if not config_path.is_file():
            raise ConfigError(
                f"config file not found: {config_path}",
                remediation="Check the --config path, or omit it to use defaults.",
            )
        resolved = config_path
    elif search_from is not None:
        resolved = find_config_file(search_from)

    if resolved is not None:
        data = _read_yaml(resolved)
        data["source_path"] = resolved

    if overrides:
        data = _deep_merge(data, _strip_none(overrides))

    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        location = f" in {resolved}" if resolved else ""
        raise ConfigError(
            f"invalid configuration{location}:\n{_format_validation_error(exc)}",
            remediation="See docs/reference/configuration.md for the full schema.",
        ) from exc


def _read_yaml(path: Path) -> dict[str, Any]:
    """Parse a YAML config file into a mapping.

    Args:
        path: File to read.

    Returns:
        The parsed mapping, or an empty mapping for an empty file.

    Raises:
        ConfigError: The file is unreadable or is not a YAML mapping.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"could not read config file {path}: {exc}") from exc

    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"config file {path} must contain a YAML mapping at the top level")
    return raw


def _deep_merge(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``updates`` into ``base`` without mutating either.

    Args:
        base: Lower-precedence mapping.
        updates: Higher-precedence mapping.

    Returns:
        A new merged mapping.
    """
    merged = dict(base)
    for key, value in updates.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(existing, value)
        else:
            merged[key] = value
    return merged


def _strip_none(data: dict[str, Any]) -> dict[str, Any]:
    """Drop ``None`` values so unset CLI flags do not override file settings.

    Args:
        data: Mapping that may contain ``None`` placeholders.

    Returns:
        A new mapping without ``None`` values, applied recursively.
    """
    cleaned: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            nested = _strip_none(value)
            if nested:
                cleaned[key] = nested
        elif value is not None:
            cleaned[key] = value
    return cleaned


def _format_validation_error(exc: ValidationError) -> str:
    """Render a pydantic validation error as operator-readable lines.

    Args:
        exc: The validation error raised while building ``Settings``.

    Returns:
        One ``key: message`` line per problem.
    """
    lines = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<root>"
        lines.append(f"  {location}: {error['msg']}")
    return "\n".join(lines)


# ``RunContext.config`` is annotated as ``Settings`` under TYPE_CHECKING to keep
# models.py free of a config import. Resolve the forward reference now that the real
# class exists; importing this module is enough to make RunContext constructible.
RunContext.model_rebuild()
