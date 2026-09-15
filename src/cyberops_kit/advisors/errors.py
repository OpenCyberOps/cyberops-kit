"""Advisory-layer exceptions.

These live here rather than in ``core/errors.py`` deliberately. Deleting
``advisors/`` must leave the test suite green, which it cannot do if the core error
hierarchy names types that only the AI layer raises.

They still derive from :class:`CyberOpsError`, so ``cli.py`` translates them into a
documented exit code without knowing this package exists.
"""

from __future__ import annotations

from cyberops_kit.core.errors import CyberOpsError, ExitCode


class AdvisorError(CyberOpsError):
    """Base class for every failure in the advisory layer."""

    exit_code = ExitCode.USAGE


class ProviderError(AdvisorError):
    """An inference provider could not serve a request.

    Never fatal to a run. Triage failing must leave the deterministic report intact,
    so the enricher catches this and returns findings unannotated (INV-2: the AI
    layer is never required for a core feature to work).
    """

    exit_code = ExitCode.TOOLING

    def __init__(self, provider: str, message: str, *, remediation: str | None = None) -> None:
        """Initialize the error.

        Args:
            provider: Name of the provider that failed.
            message: Human-readable description. Must never contain a credential.
            remediation: Optional actionable hint.
        """
        super().__init__(f"[{provider}] {message}", remediation=remediation)
        self.provider = provider


class ProviderNotAvailableError(ProviderError):
    """The provider is not configured or its backend is unreachable.

    Raised at startup rather than mid-run, so a missing key or a stopped Ollama
    daemon fails before any finding has been processed.
    """


class UnredactedPayloadError(AdvisorError):
    """A request reached a provider without passing through ``redact()``.

    This is an internal guard, not a user error. If it is ever raised, INV-4 was
    about to be violated and the run must stop rather than continue.
    """

    exit_code = ExitCode.INTERNAL


class BudgetExceededError(AdvisorError):
    """The run's token or finding ceiling was reached.

    Signals clean truncation, not failure. The enricher stops enriching and records
    the truncation; findings already annotated keep their advisories.
    """

    exit_code = ExitCode.OK
