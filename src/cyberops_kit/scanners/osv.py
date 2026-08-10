"""OSV-Scanner integration.

Produces ``VULNERABILITY`` findings from lockfiles and manifests, including the
malicious-package signals OSV publishes (``MAL-`` advisories), which are treated as
critical regardless of what the advisory's own severity field claims.

We never match CVEs ourselves. OSV owns that; we normalize what it reports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from cyberops_kit.core.models import (
    Category,
    Confidence,
    DimensionKey,
    Finding,
    Location,
    PackageRef,
    ProjectProfile,
    RunContext,
    ScannerRef,
    Severity,
    normalize_path,
)
from cyberops_kit.core.sandbox import CommandResult
from cyberops_kit.scanners.base import UNKNOWN_VERSION, ExecutionMode, ScannerPlugin

VULNS_FOUND_EXIT: Final = 1
"""OSV-Scanner exits 1 when it finds vulnerabilities. That is a result, not a fault."""

MALICIOUS_PREFIX: Final = "MAL-"

_SEVERITY_BY_NAME: Final[dict[str, Severity]] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# CVSS v3 qualitative bands, per FIRST's published specification.
_CVSS_BANDS: Final[tuple[tuple[float, Severity], ...]] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)


class OSVPlugin(ScannerPlugin):
    """Runs OSV-Scanner over the target's manifests and lockfiles."""

    name = "osv"
    version_command = ("osv-scanner", "--version")
    categories = frozenset({Category.VULNERABILITY})
    dimension = DimensionKey.KNOWN_VULNERABILITIES
    execution_mode = ExecutionMode.HOST
    requires_network = True
    """Queries the OSV.dev API for advisory data."""

    ok_returncodes = frozenset({0, VULNS_FOUND_EXIT})

    def applies_to(self, profile: ProjectProfile) -> bool:
        """Return True when there is a dependency manifest or lockfile to read.

        Args:
            profile: The detected project profile.

        Returns:
            True when the project declares dependencies.
        """
        return bool(profile.package_managers or profile.manifests or profile.lockfiles)

    def build_command(self, ctx: RunContext, workdir: Path) -> list[str]:
        """Build the OSV-Scanner invocation.

        Args:
            ctx: The current run context.
            workdir: Unused; OSV-Scanner writes to stdout.

        Returns:
            The command to run.
        """
        del workdir
        return [
            "osv-scanner",
            "--format=json",
            "--recursive",
            str(ctx.workspace),
        ]

    def parse(self, result: CommandResult, ctx: RunContext, workdir: Path) -> list[Finding]:
        """Map OSV results into canonical vulnerability findings.

        Args:
            result: The completed command.
            ctx: The current run context.
            workdir: Unused.

        Returns:
            One finding per vulnerability per affected package.
        """
        del workdir
        payload = _load(result.stdout)
        if payload is None:
            return []

        # Left as "unknown"; the base class stamps the detected version after parse.
        scanner = ScannerRef(name=self.name, version=UNKNOWN_VERSION)
        findings: list[Finding] = []

        for source_result in payload.get("results") or []:
            if not isinstance(source_result, dict):
                continue
            source_path = str((source_result.get("source") or {}).get("path", ""))
            location = (
                Location(path=normalize_path(source_path, root=ctx.workspace))
                if source_path
                else None
            )

            for package_entry in source_result.get("packages") or []:
                if not isinstance(package_entry, dict):
                    continue
                package = _package_ref(package_entry.get("package") or {})

                for vulnerability in package_entry.get("vulnerabilities") or []:
                    if not isinstance(vulnerability, dict):
                        continue
                    findings.append(
                        _build_finding(
                            scanner=scanner,
                            vulnerability=vulnerability,
                            package=package,
                            location=location,
                        )
                    )

        return findings


def _build_finding(
    *,
    scanner: ScannerRef,
    vulnerability: dict[str, Any],
    package: PackageRef | None,
    location: Location | None,
) -> Finding:
    """Convert one OSV vulnerability record into a ``Finding``.

    Args:
        scanner: Reference to this scanner and its version.
        vulnerability: The OSV vulnerability object.
        package: The affected package.
        location: The manifest or lockfile the package was declared in.

    Returns:
        The canonical finding.
    """
    osv_id = str(vulnerability.get("id", "unknown"))
    aliases = [str(a) for a in vulnerability.get("aliases") or []]
    cve_ids = sorted({a for a in [osv_id, *aliases] if a.startswith("CVE-")})
    fixed_version = _fixed_version(vulnerability, package)

    summary = str(vulnerability.get("summary", "")).strip()
    details = str(vulnerability.get("details", "")).strip()
    package_label = package.name if package else "dependency"

    return Finding.build(
        scanner=scanner,
        rule_id=osv_id,
        title=summary or f"{osv_id} affects {package_label}",
        description=details or summary or f"{osv_id} affects {package_label}.",
        severity=_severity_for(vulnerability, osv_id),
        category=Category.VULNERABILITY,
        confidence=Confidence.HIGH,
        location=location,
        package=package,
        cve_ids=cve_ids,
        cwe_ids=_cwe_ids(vulnerability),
        references=_references(vulnerability),
        fix_available=fixed_version is not None,
        fixed_version=fixed_version,
        raw=vulnerability,
    )


def _package_ref(package: dict[str, Any]) -> PackageRef | None:
    """Build a ``PackageRef`` from OSV's package object.

    Args:
        package: OSV package object.

    Returns:
        The package reference, or ``None`` when unnamed.
    """
    name = str(package.get("name", "")).strip()
    if not name:
        return None
    version = str(package.get("version", "")).strip() or None
    ecosystem = str(package.get("ecosystem", "")).strip() or None
    return PackageRef(
        name=name,
        version=version,
        ecosystem=ecosystem,
        purl=_purl(name, version, ecosystem),
    )


def _purl(name: str, version: str | None, ecosystem: str | None) -> str | None:
    """Construct a package URL from OSV's ecosystem naming.

    Args:
        name: Package name.
        version: Package version.
        ecosystem: OSV ecosystem name.

    Returns:
        A ``pkg:`` URL, or ``None`` when the ecosystem is unrecognized.
    """
    if not ecosystem:
        return None
    mapping = {
        "npm": "npm",
        "pypi": "pypi",
        "go": "golang",
        "maven": "maven",
        "nuget": "nuget",
        "rubygems": "gem",
        "packagist": "composer",
        "crates.io": "cargo",
        "hex": "hex",
        "pub": "pub",
    }
    kind = mapping.get(ecosystem.lower())
    if kind is None:
        return None
    suffix = f"@{version}" if version else ""
    return f"pkg:{kind}/{name}{suffix}"


def _severity_for(vulnerability: dict[str, Any], osv_id: str) -> Severity:
    """Determine normalized severity for an OSV record.

    Args:
        vulnerability: The OSV vulnerability object.
        osv_id: The advisory identifier.

    Returns:
        The normalized severity.
    """
    # A malicious package is not a graded vulnerability — the dependency itself is
    # hostile. OSV's severity field is frequently absent on MAL- advisories.
    if osv_id.startswith(MALICIOUS_PREFIX):
        return Severity.CRITICAL

    database = vulnerability.get("database_specific")
    if isinstance(database, dict):
        named = str(database.get("severity", "")).upper()
        if named in _SEVERITY_BY_NAME:
            return _SEVERITY_BY_NAME[named]

    for entry in vulnerability.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        score = _cvss_base_score(str(entry.get("score", "")))
        if score is not None:
            for threshold, severity in _CVSS_BANDS:
                if score >= threshold:
                    return severity

    return Severity.MEDIUM


def _cvss_base_score(score: str) -> float | None:
    """Extract a numeric base score from an OSV severity entry.

    OSV reports either a bare number or a full CVSS vector string. A vector needs a
    real CVSS implementation to score, which is out of scope — we do not reimplement
    what a dedicated library owns — so only the numeric form is used.

    Args:
        score: The raw score field.

    Returns:
        The numeric base score, or ``None`` when it is a vector string.
    """
    try:
        return float(score)
    except (TypeError, ValueError):
        return None


def _fixed_version(vulnerability: dict[str, Any], package: PackageRef | None) -> str | None:
    """Find the first fixed version OSV reports for the affected package.

    Args:
        vulnerability: The OSV vulnerability object.
        package: The affected package.

    Returns:
        The fixed version, or ``None`` when no fix is published.
    """
    for affected in vulnerability.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        if package is not None:
            affected_name = str((affected.get("package") or {}).get("name", ""))
            if affected_name and affected_name != package.name:
                continue
        for entry in affected.get("ranges") or []:
            if not isinstance(entry, dict):
                continue
            for event in entry.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    return str(event["fixed"])
    return None


def _cwe_ids(vulnerability: dict[str, Any]) -> list[str]:
    """Extract CWE identifiers from OSV's database-specific block.

    Args:
        vulnerability: The OSV vulnerability object.

    Returns:
        Sorted, deduplicated CWE identifiers.
    """
    database = vulnerability.get("database_specific")
    if not isinstance(database, dict):
        return []
    raw = database.get("cwe_ids") or database.get("cwes") or []
    ids: set[str] = set()
    for entry in raw:
        if isinstance(entry, str):
            ids.add(entry)
        elif isinstance(entry, dict) and entry.get("cweId"):
            ids.add(str(entry["cweId"]))
    return sorted(ids)


def _references(vulnerability: dict[str, Any]) -> list[str]:
    """Extract reference URLs.

    Args:
        vulnerability: The OSV vulnerability object.

    Returns:
        Sorted, deduplicated URLs.
    """
    urls: set[str] = set()
    for reference in vulnerability.get("references") or []:
        if isinstance(reference, dict) and reference.get("url"):
            urls.add(str(reference["url"]))
    return sorted(urls)


def _load(stdout: str) -> dict[str, Any] | None:
    """Parse OSV-Scanner's JSON output.

    Args:
        stdout: Raw stdout from the tool.

    Returns:
        The parsed payload, or ``None`` when empty or malformed.
    """
    text = stdout.strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


PLUGIN = OSVPlugin()
