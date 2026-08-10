"""Exception hierarchy for CyberOps Kit.

Every error raised inside this package derives from :class:`CyberOpsError`. Bare
``Exception`` is never raised (see CONTRIBUTING.md, "Code conventions").

Each error carries an ``exit_code`` so that ``cli.py`` can translate a failure into
a stable, documented process exit status without a chain of ``isinstance`` checks.
"""

from __future__ import annotations

from typing import Final


class ExitCode:
    """Process exit codes. These are a public interface — CI depends on them."""

    OK: Final = 0
    """Run completed and all configured thresholds were met."""

    THRESHOLD_FAILED: Final = 1
    """Run completed successfully but the score or severity threshold failed."""

    USAGE: Final = 2
    """Invalid arguments or invalid configuration."""

    TARGET: Final = 3
    """The target could not be ingested or was not a readable project."""

    TOOLING: Final = 4
    """A required external tool or sandbox runtime was unavailable."""

    SCAN: Final = 5
    """A scanner failed in a way that invalidates the run."""

    INTERNAL: Final = 70
    """An unexpected internal error. Always a bug; please report it."""


class CyberOpsError(Exception):
    """Base class for every error raised by CyberOps Kit.

    Attributes:
        exit_code: Process exit status the CLI uses when this error escapes.
        remediation: Optional operator-facing hint on how to resolve the failure.
    """

    exit_code: int = ExitCode.INTERNAL

    def __init__(self, message: str, *, remediation: str | None = None) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            remediation: Optional actionable hint printed alongside the message.
        """
        super().__init__(message)
        self.message = message
        self.remediation = remediation


# --- Configuration -------------------------------------------------------------


class ConfigError(CyberOpsError):
    """The configuration file or CLI flag combination is invalid."""

    exit_code = ExitCode.USAGE


class OfflineViolationError(CyberOpsError):
    """A code path attempted a network call while ``--offline`` was active.

    Enforces INV-6. Offline mode fails loudly; it never degrades silently.
    """

    exit_code = ExitCode.USAGE


# --- Ingest and detection ------------------------------------------------------


class IngestError(CyberOpsError):
    """The target could not be resolved to a readable tree at a pinned commit."""

    exit_code = ExitCode.TARGET


class DetectionError(CyberOpsError):
    """The project profile could not be built from the target tree."""

    exit_code = ExitCode.TARGET


# --- Sandbox -------------------------------------------------------------------


class SandboxError(CyberOpsError):
    """Base class for sandboxed-execution failures (INV-5)."""

    exit_code = ExitCode.TOOLING


class SandboxUnavailableError(SandboxError):
    """No container runtime is available to isolate untrusted execution.

    Raised instead of falling back to host execution. There is no fallback: running
    untrusted lifecycle scripts on the host would violate INV-5.
    """


class SandboxTimeoutError(SandboxError):
    """A sandboxed command exceeded its wall-clock budget."""

    exit_code = ExitCode.SCAN


# --- Scanners ------------------------------------------------------------------


class ScannerError(CyberOpsError):
    """Base class for scanner plugin failures.

    Attributes:
        scanner: Name of the scanner plugin that failed.
    """

    exit_code = ExitCode.SCAN

    def __init__(self, scanner: str, message: str, *, remediation: str | None = None) -> None:
        """Initialize the error.

        Args:
            scanner: Name of the scanner plugin that failed.
            message: Human-readable description of the failure.
            remediation: Optional actionable hint.
        """
        super().__init__(f"[{scanner}] {message}", remediation=remediation)
        self.scanner = scanner


class ScannerNotAvailableError(ScannerError):
    """The scanner's binary is not installed or not executable.

    This is not fatal to a run. The orchestrator records the scanner as skipped and
    the affected scoring dimension is excluded rather than scored as zero
    (Phase 1 spec §4, "Missing scanner ≠ score of 0").
    """

    exit_code = ExitCode.TOOLING


class ScannerTimeoutError(ScannerError):
    """The scanner exceeded its configured timeout."""


class ScannerExecutionError(ScannerError):
    """The scanner ran but exited with an unexpected status."""


class NormalizationError(CyberOpsError):
    """Scanner output could not be mapped into the canonical ``Finding`` model."""

    exit_code = ExitCode.SCAN


# --- Pipeline stages -----------------------------------------------------------


class EnrichmentContractError(CyberOpsError):
    """An enricher violated the SEAM-2 contract.

    Enrichers may only populate ``Finding.advisory``. Adding findings, removing
    findings, or mutating any other field is a contract breach and aborts the run
    rather than silently corrupting results.
    """

    exit_code = ExitCode.INTERNAL


class ScoringError(CyberOpsError):
    """The composite score could not be computed."""

    exit_code = ExitCode.INTERNAL


class ReportError(CyberOpsError):
    """A report could not be rendered or written."""

    exit_code = ExitCode.INTERNAL


class StorageError(CyberOpsError):
    """Historical results could not be read or written."""

    exit_code = ExitCode.INTERNAL


class RedactionError(CyberOpsError):
    """A payload could not be redacted and therefore must not cross a boundary.

    Enforces INV-4. Callers never proceed with the unredacted payload.
    """

    exit_code = ExitCode.INTERNAL
