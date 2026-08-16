"""SARIF 2.1.0 rendering, for the GitHub Security tab.

One rule per distinct ``rule_id``, one result per finding.

**Advisory content goes in the result's ``properties`` bag and nowhere else.** It
must never touch ``level``, ``ruleId``, ``kind``, or ``rank``, because those fields
drive GitHub's Security tab and have to stay deterministic (SEAM-4). The code below
enforces that by constructing those four fields before advisory data is even in
scope.
"""

from __future__ import annotations

from typing import Any, Final

from cyberops_kit.core.models import Finding, Report, Severity

SARIF_VERSION: Final = "2.1.0"
SARIF_SCHEMA: Final = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME: Final = "CyberOps Kit"
TOOL_URI: Final = "https://github.com/OpenCyberOps/cyberops-kit"

_LEVEL_BY_SEVERITY: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

REPOSITORY_ROOT_URI: Final = "."
"""Anchor for findings that describe the repository rather than a file.

GitHub Code Scanning rejects an entire SARIF submission when any result carries no
location::

    locationFromSarifResult: expected at least one location

Scorecard's process checks and the SLSA assessment are genuinely repository-scoped
and have no file to point at, so they are anchored at the repository root. Omitting
the location is not an option — one such result discards every other result in the
upload, including the file-scoped ones that would have annotated correctly.
"""

_SECURITY_SEVERITY: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
"""GitHub reads ``security-severity`` to sort and filter the Security tab."""


def render_sarif(report: Report) -> dict[str, Any]:
    """Render a report as a SARIF 2.1.0 log.

    Args:
        report: The completed report, with findings already redacted.

    Returns:
        The SARIF document as a mapping.
    """
    findings = report.results.findings
    rules = _rules(findings)
    rule_index = {rule["id"]: position for position, rule in enumerate(rules)}

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": report.run_metadata.cyberops_version,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": [_result(f, rule_index) for f in findings],
                "properties": {
                    "commit_sha": report.results.target.commit_sha,
                    "composite_score": report.results.score.composite,
                    "grade": report.results.score.grade.value,
                    "scoring_model_version": report.results.scoring_model_version,
                },
            }
        ],
    }


def _rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build the rule descriptors, one per distinct rule ID.

    Args:
        findings: All findings in the report.

    Returns:
        Rule descriptors, sorted by ID for deterministic output.
    """
    rules: dict[str, dict[str, Any]] = {}

    for finding in findings:
        if finding.rule_id in rules:
            continue
        descriptor: dict[str, Any] = {
            "id": finding.rule_id,
            "name": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "defaultConfiguration": {"level": _LEVEL_BY_SEVERITY[finding.severity]},
            "properties": {
                "category": finding.category.value,
                "scanner": finding.scanner.name,
                "security-severity": _SECURITY_SEVERITY[finding.severity],
                "tags": sorted({finding.category.value, *finding.cwe_ids}),
            },
        }
        if finding.references:
            descriptor["helpUri"] = finding.references[0]
        rules[finding.rule_id] = descriptor

    return [rules[rule_id] for rule_id in sorted(rules)]


def _location(finding: Finding) -> dict[str, Any]:
    """Build the SARIF location for a finding, which is never omitted.

    Args:
        finding: The finding to locate.

    Returns:
        A physical location, anchored at the repository root when the finding has no
        file of its own.
    """
    if finding.location is None:
        return {"physicalLocation": {"artifactLocation": {"uri": REPOSITORY_ROOT_URI}}}

    region: dict[str, Any] = {}
    if finding.location.start_line is not None:
        region["startLine"] = finding.location.start_line
    if finding.location.end_line is not None:
        region["endLine"] = finding.location.end_line

    return {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.location.path},
            **({"region": region} if region else {}),
        }
    }


def _result(finding: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    """Build one SARIF result.

    Args:
        finding: The finding to render.
        rule_index: Rule ID to its index in the driver's rule array.

    Returns:
        The SARIF result object.
    """
    # These four fields are computed first and never touched again. GitHub's Security
    # tab depends on them, so they stay a pure function of deterministic scanner data.
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index[finding.rule_id],
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "kind": "fail",
        "message": {"text": finding.description or finding.title},
        "partialFingerprints": {"cyberopsFindingId": finding.id},
    }

    result["locations"] = [_location(finding)]

    properties: dict[str, Any] = {
        "findingId": finding.id,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "scanner": finding.scanner.name,
        "scannerVersion": finding.scanner.version,
        "fixAvailable": finding.fix_available,
    }
    if finding.cve_ids:
        properties["cveIds"] = finding.cve_ids
    if finding.cwe_ids:
        properties["cweIds"] = finding.cwe_ids
    if finding.fixed_version:
        properties["fixedVersion"] = finding.fixed_version
    if finding.package is not None:
        properties["package"] = finding.package.model_dump(exclude_none=True)

    # SEAM-4: advisory data is confined to the properties bag. Dormant in Phase 1.
    if finding.advisory is not None:
        properties["advisory"] = {
            **finding.advisory.model_dump(mode="json", exclude_none=True),
            "disclaimer": "AI advisory — not part of the score",
        }

    result["properties"] = properties
    return result
