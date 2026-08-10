"""Typer CLI — the only module permitted to print.

See CONTRIBUTING.md, "Code conventions".

Commands:

``cyberops scan <target>``    run the pipeline and write reports
``cyberops doctor``           report which scanners are installed and what that costs
``cyberops version``          print version and scoring model version

Exit codes are a public interface that CI depends on; they are defined in
``core/errors.ExitCode``.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Annotated, Final

import structlog
import typer

from cyberops_kit import __version__
from cyberops_kit.config import load_settings
from cyberops_kit.core.errors import CyberOpsError, ExitCode
from cyberops_kit.core.ingest import ingest
from cyberops_kit.core.models import Report, Severity
from cyberops_kit.core.orchestrator import Pipeline
from cyberops_kit.core.redaction import structlog_processor
from cyberops_kit.core.scoring import SCORING_MODEL_VERSION
from cyberops_kit.report.writer import redacted, render_pr_comment, write_reports
from cyberops_kit.scanners import registry
from cyberops_kit.storage.history import History, compare, delta_context

app = typer.Typer(
    name="cyberops",
    help="Reproducible, auditable security report cards for any software project.",
    add_completion=False,
    no_args_is_help=True,
)

PR_COMMENT_FILENAME: Final = "pr-comment.md"


def _configure_logging(verbose: bool, quiet: bool) -> None:
    """Configure structlog, with redaction wired into the pipeline.

    Every log event passes through ``redaction.structlog_processor`` so INV-4 holds
    for logs without each call site having to remember.

    Args:
        verbose: Emit debug-level events.
        quiet: Emit errors only.
    """
    level = logging.DEBUG if verbose else logging.ERROR if quiet else logging.INFO
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog_processor,
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(sys.stderr),
        cache_logger_on_first_use=True,
    )


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Local path or GitHub URL to assess.")] = ".",
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to .cyberops.yml.")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Directory for reports.")
    ] = None,
    formats: Annotated[
        list[str] | None,
        typer.Option("--format", "-f", help="Report format; repeatable."),
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Disable every outbound network call.")
    ] = False,
    fail_below: Annotated[
        int | None, typer.Option("--fail-below", help="Exit non-zero below this score.")
    ] = None,
    fail_on_severity: Annotated[
        Severity | None,
        typer.Option("--fail-on-severity", help="Exit non-zero at or above this severity."),
    ] = None,
    scanners: Annotated[
        list[str] | None,
        typer.Option("--scanner", help="Restrict to these scanners; repeatable."),
    ] = None,
    timeout: Annotated[
        int | None, typer.Option("--timeout", help="Per-scanner timeout in seconds.")
    ] = None,
    baseline: Annotated[
        str | None,
        typer.Option("--baseline", help="Commit SHA to compute a finding delta against."),
    ] = None,
    pr_comment: Annotated[
        bool, typer.Option("--pr-comment", help="Also write a PR comment markdown file.")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Errors only.")] = False,
) -> None:
    """Scan a repository and produce a security report card."""
    _configure_logging(verbose, quiet)

    overrides: dict[str, object] = {"offline": offline or None}
    if formats or output:
        overrides["output"] = {
            "formats": list(formats) if formats else None,
            "directory": output,
        }
    if scanners or timeout:
        overrides["scanners"] = {
            "enabled": list(scanners) if scanners else None,
            "timeout_seconds": timeout,
        }
    if fail_below is not None or fail_on_severity is not None:
        overrides["thresholds"] = {
            "fail_below_score": fail_below,
            "fail_on_severity": fail_on_severity,
        }

    try:
        settings = load_settings(
            config_path=config,
            search_from=Path(target) if Path(target).is_dir() else Path.cwd(),
            overrides=overrides,
        )

        with ingest(target, offline=settings.offline) as (workspace, resolved_target):
            if resolved_target.dirty:
                typer.secho(
                    "warning: working tree has uncommitted changes; "
                    "this run is not reproducible from the recorded commit SHA",
                    fg=typer.colors.YELLOW,
                    err=True,
                )

            report = asyncio.run(Pipeline(settings).run(workspace, resolved_target))

            output_dir = settings.output.directory
            written = write_reports(
                report,
                output_dir,
                settings.output.formats,
                include_badge=settings.output.badge,
            )

            history = History(output_dir)
            safe = redacted(report)
            history.record(safe)

            if pr_comment:
                delta = compare(safe, history.load(baseline) if baseline else None)
                comment_path = output_dir / PR_COMMENT_FILENAME
                comment_path.write_text(
                    render_pr_comment(safe, delta=delta_context(delta)), encoding="utf-8"
                )
                written["pr-comment"] = comment_path

    except CyberOpsError as exc:
        _fail(exc)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        typer.secho("interrupted", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=ExitCode.USAGE) from None

    _print_summary(report, written, quiet=quiet)
    raise typer.Exit(code=_exit_code(report, settings))


@app.command()
def doctor(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging.")] = False,
) -> None:
    """Report which scanners are available and what a missing one costs.

    Run this before wiring the tool into CI. It tells you exactly which dimensions
    would be excluded on this machine, rather than letting you discover it from a
    surprising score.
    """
    _configure_logging(verbose, quiet=False)

    typer.echo(f"CyberOps Kit {__version__} · scoring model {SCORING_MODEL_VERSION}\n")

    missing: list[str] = []
    for plugin in registry.all_plugins():
        available = plugin.is_available()
        if not available:
            missing.append(plugin.name)
        status = (
            typer.style("available", fg=typer.colors.GREEN)
            if available
            else typer.style("not installed", fg=typer.colors.YELLOW)
        )
        dimension = plugin.dimension.value if plugin.dimension else "—"
        network = " (needs network)" if plugin.requires_network else ""
        typer.echo(f"  {plugin.name:<12} {status:<28} dimension: {dimension}{network}")

    if not missing:
        typer.echo("\nAll scanners are available.")
        return

    typer.echo(
        f"\n{len(missing)} scanner(s) not installed: {', '.join(missing)}.\n"
        "Dimensions fed by these scanners will be excluded from the score and their\n"
        "weight redistributed — they are never scored as zero. The published container\n"
        "image bundles every scanner."
    )


@app.command()
def version() -> None:
    """Print version information."""
    typer.echo(f"cyberops-kit {__version__}")
    typer.echo(f"scoring model {SCORING_MODEL_VERSION}")


def _exit_code(report: Report, settings: object) -> int:
    """Determine the process exit code from configured thresholds.

    Args:
        report: The completed report.
        settings: Resolved configuration.

    Returns:
        ``ExitCode.OK`` or ``ExitCode.THRESHOLD_FAILED``.
    """
    from cyberops_kit.config import Settings

    assert isinstance(settings, Settings)  # noqa: S101 - internal invariant
    thresholds = settings.thresholds

    # A score derived from a fraction of the model is not a score to fail a build on.
    # Severity thresholds still apply: a finding is a finding regardless of coverage.
    if (
        thresholds.fail_below_score is not None
        and report.results.score.sufficient_coverage
        and report.results.score.composite < thresholds.fail_below_score
    ):
        return ExitCode.THRESHOLD_FAILED

    if thresholds.fail_on_severity is not None:
        limit = thresholds.fail_on_severity.rank
        if any(f.severity.rank <= limit for f in report.results.findings):
            return ExitCode.THRESHOLD_FAILED

    return ExitCode.OK


def _print_summary(report: Report, written: dict[str, Path], *, quiet: bool) -> None:
    """Print the human-readable run summary.

    Args:
        report: The completed report.
        written: Format name to written path.
        quiet: Suppress everything but the grade line.
    """
    score = report.results.score
    color = {
        "A": typer.colors.GREEN,
        "B": typer.colors.GREEN,
        "C": typer.colors.YELLOW,
        "D": typer.colors.YELLOW,
        "F": typer.colors.RED,
    }[score.grade.value]

    typer.echo("")

    if score.sufficient_coverage:
        typer.secho(f"  {score.grade.value}  {score.composite}/100", fg=color, bold=True, nl=False)
        typer.echo(f"   {len(report.results.findings)} findings")
    else:
        # Leading with a letter grade here would be the single most misleading thing
        # this tool could print: it reads as a verdict when almost nothing was measured.
        typer.secho("  NOT SCORED", fg=typer.colors.YELLOW, bold=True, nl=False)
        typer.echo(f"   {len(report.results.findings)} findings")
        typer.secho(
            f"\n  Only {score.coverage:.0%} of the scoring model could be evaluated on this\n"
            "  machine, which is too little for a composite score to mean anything. The\n"
            "  score is recorded in the report but is not comparable to a full run, and\n"
            "  it does not fail the --fail-below check.\n"
            "  Run 'cyberops doctor' to see which scanners are missing.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    if quiet:
        return

    for cap in score.caps:
        if cap.applied:
            typer.secho(
                f"  capped at {cap.capped_at}: {cap.condition}",
                fg=typer.colors.RED,
                err=True,
            )

    # A scanner that was never installed and a scanner that crashed both cost the run
    # a dimension, but only one of them is a problem. Printing one word for both is
    # how a real failure gets mistaken for an expected gap.
    failed = report.results.failed_scanners
    not_run = report.results.not_run_scanners

    if failed:
        typer.secho(
            f"\n  {len(failed)} scanner(s) FAILED — these ran and broke:",
            fg=typer.colors.RED,
            bold=True,
            err=True,
        )
        for scanner in failed:
            typer.secho(
                f"    {scanner.name} ({scanner.reason}): {_trim(scanner.detail)}",
                fg=typer.colors.RED,
                err=True,
            )

    if not_run:
        names = ", ".join(f"{s.name} ({s.reason})" for s in not_run)
        typer.echo(f"\n  scanners not run: {names}")

    if failed or not_run:
        typer.echo("  their dimensions were excluded from the score, not scored as zero")

    typer.echo("")
    for fmt, path in written.items():
        typer.echo(f"  {fmt:<10} {path}")
    typer.echo("")


def _trim(detail: str | None, limit: int = 140) -> str:
    """Condense a scanner failure detail to one readable line.

    Args:
        detail: The scanner's error text, possibly multi-line.
        limit: Maximum characters to show.

    Returns:
        A single-line summary, truncated with an ellipsis.
    """
    if not detail:
        return "no detail reported"
    flat = " ".join(detail.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _fail(exc: CyberOpsError) -> None:
    """Print an error and exit with its mapped code.

    Args:
        exc: The error that ended the run.

    Raises:
        typer.Exit: Always.
    """
    typer.secho(f"error: {exc.message}", fg=typer.colors.RED, err=True)
    if exc.remediation:
        typer.secho(f"  {exc.remediation}", fg=typer.colors.YELLOW, err=True)
    raise typer.Exit(code=exc.exit_code)


if __name__ == "__main__":  # pragma: no cover
    app()
