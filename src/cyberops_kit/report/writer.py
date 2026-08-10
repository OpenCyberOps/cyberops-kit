"""Report rendering and writing.

One entry point, :func:`write_reports`, which applies redaction **once** at the top
and then renders every requested format from the sanitized report. Redaction is done
here rather than in each renderer so there is exactly one place where a payload
crosses the process boundary, and no renderer can be added later that forgets to
call it (INV-4).
"""

from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path
from typing import Any, Final

import structlog
from jinja2 import Environment, PackageLoader, StrictUndefined

from cyberops_kit.core.errors import ReportError
from cyberops_kit.core.models import Finding, Grade, Report, Severity
from cyberops_kit.core.redaction import redact_findings
from cyberops_kit.report.sarif import render_sarif

logger = structlog.get_logger(__name__)

FORMATS: Final[tuple[str, ...]] = ("json", "sarif", "markdown", "html", "badge")

FILENAMES: Final[dict[str, str]] = {
    "json": "report.json",
    "sarif": "report.sarif",
    "markdown": "report.md",
    "html": "report.html",
    "badge": "badge.json",
}

_BADGE_COLORS: Final[dict[Grade, str]] = {
    Grade.A: "brightgreen",
    Grade.B: "green",
    Grade.C: "yellow",
    Grade.D: "orange",
    Grade.F: "red",
}

TOP_FINDINGS_LIMIT: Final = 5


def _environment() -> Environment:
    """Build the Jinja environment.

    ``StrictUndefined`` makes a typo in a template an error rather than a silently
    blank cell in a security report.

    Returns:
        The configured environment.
    """
    return Environment(
        loader=PackageLoader("cyberops_kit.report", "templates"),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def redacted(report: Report) -> Report:
    """Return a copy of the report with every finding sanitized.

    Args:
        report: The raw report from the pipeline.

    Returns:
        A report safe to write, log, or transmit.
    """
    return report.model_copy(
        update={
            "results": report.results.model_copy(
                update={"findings": redact_findings(report.results.findings)}
            )
        }
    )


def render(report: Report, fmt: str) -> str:
    """Render a report in one format.

    Args:
        report: The report to render. Redact it first with :func:`redacted` unless
            it is already sanitized.
        fmt: One of :data:`FORMATS`.

    Returns:
        The rendered document.

    Raises:
        ReportError: The format is not supported.
    """
    if fmt == "json":
        return _render_json(report)
    if fmt == "sarif":
        return json.dumps(render_sarif(report), indent=2, ensure_ascii=False) + "\n"
    if fmt == "badge":
        return json.dumps(render_badge(report), indent=2, ensure_ascii=False) + "\n"
    if fmt in {"markdown", "html"}:
        template = "report.md.j2" if fmt == "markdown" else "report.html.j2"
        return _environment().get_template(template).render(**_context(report))

    raise ReportError(
        f"unsupported report format: {fmt!r}",
        remediation=f"Supported formats: {', '.join(FORMATS)}.",
    )


def render_pr_comment(report: Report, *, delta: dict[str, Any] | None = None) -> str:
    """Render the pull request comment.

    Args:
        report: The sanitized report.
        delta: Optional comparison against the base branch, with ``new``, ``fixed``,
            ``unchanged``, and ``score_change`` keys.

    Returns:
        The rendered Markdown comment.
    """
    context = _context(report)
    context["delta"] = delta
    context["emoji"] = _grade_emoji(report.results.score.grade)
    context["top_findings"] = report.results.findings[:TOP_FINDINGS_LIMIT]
    return _environment().get_template("pr_comment.md.j2").render(**context)


def render_badge(report: Report) -> dict[str, Any]:
    """Render a shields.io-compatible endpoint payload.

    Args:
        report: The report to summarize.

    Returns:
        The badge endpoint mapping.
    """
    score = report.results.score
    if not score.sufficient_coverage:
        # A badge is the most decontextualized surface this project has. Showing a
        # letter grade derived from a fraction of the model would be read as a
        # verdict by everyone who sees it and by nobody who checks the report.
        return {
            "schemaVersion": 1,
            "label": "security",
            "message": "not scored",
            "color": "lightgrey",
        }
    return {
        "schemaVersion": 1,
        "label": "security",
        "message": f"{score.grade.value} ({score.composite})",
        "color": _BADGE_COLORS[score.grade],
    }


def write_reports(
    report: Report,
    output_dir: Path,
    formats: list[str],
    *,
    include_badge: bool = True,
) -> dict[str, Path]:
    """Redact, render, and write every requested format.

    Args:
        report: The raw report from the pipeline.
        output_dir: Directory to write into. Created if absent.
        formats: Formats to render.
        include_badge: Also write the shields.io badge endpoint.

    Returns:
        Format name to the path written.

    Raises:
        ReportError: A format is unsupported or a file could not be written.
    """
    requested = list(dict.fromkeys(formats))
    if include_badge and "badge" not in requested:
        requested.append("badge")

    unsupported = [fmt for fmt in requested if fmt not in FORMATS]
    if unsupported:
        raise ReportError(
            f"unsupported report format(s): {', '.join(sorted(unsupported))}",
            remediation=f"Supported formats: {', '.join(FORMATS)}.",
        )

    # Redact once, here. Every renderer below reads only from `safe`.
    safe = redacted(report)

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReportError(f"could not create output directory {output_dir}: {exc}") from exc

    written: dict[str, Path] = {}
    for fmt in requested:
        path = output_dir / FILENAMES[fmt]
        try:
            path.write_text(render(safe, fmt), encoding="utf-8")
        except OSError as exc:
            raise ReportError(f"could not write {path}: {exc}") from exc
        written[fmt] = path
        logger.debug("report.written", format=fmt, path=str(path))

    return written


def _render_json(report: Report) -> str:
    """Serialize the full report envelope as JSON.

    Field order follows the model definitions, which is fixed, so two runs over the
    same input produce byte-identical bytes (INV-3).

    Args:
        report: The sanitized report.

    Returns:
        The serialized JSON document.
    """
    payload = report.model_dump(mode="json")
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _context(report: Report) -> dict[str, Any]:
    """Build the shared template context.

    Args:
        report: The sanitized report.

    Returns:
        The context mapping passed to every template.
    """
    return {
        "results": report.results,
        "run_metadata": report.run_metadata,
        "findings_by_severity": _group_by_severity(report.results.findings),
    }


def _group_by_severity(findings: list[Finding]) -> OrderedDict[str, list[Finding]]:
    """Group findings by severity, most severe first.

    Args:
        findings: Findings in canonical order.

    Returns:
        Severity value to its findings, omitting empty severities.
    """
    grouped: OrderedDict[str, list[Finding]] = OrderedDict()
    for severity in sorted(Severity, key=lambda s: s.rank):
        matching = [f for f in findings if f.severity is severity]
        if matching:
            grouped[severity.value] = matching
    return grouped


def _grade_emoji(grade: Grade) -> str:
    """Return a status emoji for a grade, for the PR comment heading.

    Args:
        grade: The letter grade.

    Returns:
        An emoji.
    """
    return {
        Grade.A: "✅",
        Grade.B: "✅",
        Grade.C: "⚠️",
        Grade.D: "⚠️",
        Grade.F: "❌",
    }[grade]
