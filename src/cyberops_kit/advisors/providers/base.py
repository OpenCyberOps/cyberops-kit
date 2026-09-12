"""The provider protocol — the one place a vendor SDK is allowed to be named.

Everything above this module speaks :class:`CompletionRequest` and
:class:`CompletionResponse`. No vendor type, no vendor exception, and no
vendor-specific parameter may appear in ``triage.py``, ``base.py``, or anywhere in
``core/``. That is what makes the local provider a first-class citizen rather than a
degraded fallback: the layer above cannot tell which provider it is talking to.

Providers are responsible for transport and for coercing a model's reply into JSON
text. They are *not* responsible for redaction (the caller has already applied it,
and :class:`CompletionRequest` refuses to be built otherwise), for budgeting, or for
interpreting the result as an advisory.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_TIMEOUT_SECONDS: float = 60.0


class CompletionRequest(BaseModel):
    """One inference request, already redacted.

    The ``redacted`` flag is not decoration. :meth:`LLMAdvisor.complete` sets it only
    after routing the payload through ``core.redaction.redact``, and every provider
    asserts it before opening a socket. A request that was never redacted therefore
    cannot reach a network call even if a caller constructs one by hand (INV-4).
    """

    model_config = ConfigDict(frozen=True)

    system: str
    """System prompt, loaded from a versioned file under ``prompts/``."""

    user: str
    """The redacted finding context."""

    model_id: str
    max_output_tokens: int = Field(default=1024, gt=0, le=32_000)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    """Zero by default. Advisory text should not vary run to run without cause."""

    timeout_seconds: float = Field(default=DEFAULT_TIMEOUT_SECONDS, gt=0)
    redacted: bool = False
    """Set by the advisor after redaction. Providers refuse a request without it."""


class CompletionResponse(BaseModel):
    """A provider's reply, normalized across vendors."""

    model_config = ConfigDict(frozen=True)

    text: str
    """Raw reply text. Expected to be JSON, but never trusted to be."""

    model_id: str
    """The model that actually served the request, as reported by the provider."""

    input_tokens: int = 0
    output_tokens: int = 0
    """Zero when a provider does not report usage — the local one often does not."""

    @property
    def total_tokens(self) -> int:
        """Return the combined token count for budget accounting."""
        return self.input_tokens + self.output_tokens


def assert_redacted(request: CompletionRequest, *, provider: str) -> None:
    """Refuse to transmit a request that has not been redacted.

    Called by every provider immediately before it opens a socket. Enforcing INV-4
    at the last possible moment — inside the provider, not at the call site — means
    a future provider author cannot forget it and a caller cannot route around it.
    There is no bypass argument, by design.

    Args:
        request: The request about to be sent.
        provider: Provider name, for the error message.

    Raises:
        UnredactedPayloadError: ``request.redacted`` is not set.
    """
    if not request.redacted:
        from cyberops_kit.advisors.errors import UnredactedPayloadError

        raise UnredactedPayloadError(
            f"provider {provider!r} received a request that did not pass through "
            "core.redaction.redact(); refusing to transmit (INV-4)"
        )


@runtime_checkable
class Provider(Protocol):
    """What every inference backend must implement.

    Deliberately three members. A protocol that grows vendor-shaped options is how
    vendor coupling gets reintroduced after the abstraction is in place.
    """

    name: str
    """Stable identifier used in config and recorded on every ``Advisory``."""

    def available(self) -> tuple[bool, str]:
        """Report whether this provider can serve a request right now.

        Checked before a run begins so a missing API key or an unreachable local
        daemon is a clear startup error rather than a mid-run failure.

        Returns:
            ``(True, "")`` when usable, else ``(False, reason)`` where the reason is
            operator-facing and never contains the credential itself.
        """
        ...

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Perform one inference call.

        Args:
            request: A redacted request.

        Returns:
            The normalized reply.

        Raises:
            ProviderError: Transport failed, the credential was rejected, or the
                request was not redacted.
        """
        ...
