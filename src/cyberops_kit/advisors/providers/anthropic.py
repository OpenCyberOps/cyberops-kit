"""Anthropic provider, via the official ``anthropic`` SDK.

Optional dependency. The import is deferred into :meth:`AnthropicProvider.complete`
and :meth:`available` so that ``pip install cyberops-kit`` without the ``[ai]``
extra never imports it, and so that a missing SDK is a clear operator message rather
than an ImportError traceback.

Structured output is obtained through ``output_config.format`` with a JSON schema,
which constrains the reply to the advisory shape rather than asking for JSON in
prose and hoping. The reply is still validated against the Pydantic model by the
caller: a constrained decode is not a guarantee we are willing to skip a check for.
"""

from __future__ import annotations

import os
from typing import Any, Final

import structlog

from cyberops_kit.advisors.errors import ProviderError, ProviderNotAvailableError
from cyberops_kit.advisors.providers.base import (
    CompletionRequest,
    CompletionResponse,
    assert_redacted,
)

logger = structlog.get_logger(__name__)

DEFAULT_MODEL: Final = "claude-opus-5"
_API_KEY_ENV: Final = "ANTHROPIC_API_KEY"


class AnthropicProvider:
    """Talks to the Anthropic Messages API.

    Attributes:
        name: Stable provider identifier recorded on every ``Advisory``.
    """

    name = "anthropic"

    def __init__(self, *, api_key: str | None = None, default_model: str = DEFAULT_MODEL) -> None:
        """Initialize the provider.

        Args:
            api_key: API key. Read from ``ANTHROPIC_API_KEY`` when omitted. Never
                logged, and never included in an error message.
            default_model: Model used when the request names none.
        """
        self._api_key = api_key or os.environ.get(_API_KEY_ENV)
        self._default_model = default_model

    def available(self) -> tuple[bool, str]:
        """Report whether the SDK is installed and a credential is present.

        Returns:
            ``(True, "")`` when usable, else ``(False, reason)``. The reason names
            the missing environment variable, never its value.
        """
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, (
                "the 'anthropic' package is not installed. "
                "Install it with: pip install 'cyberops-kit[ai]'"
            )
        if not self._api_key:
            return False, f"{_API_KEY_ENV} is not set"
        return True, ""

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Perform one inference call.

        Args:
            request: A redacted request.

        Returns:
            The normalized reply.

        Raises:
            UnredactedPayloadError: The request never passed through ``redact()``.
            ProviderNotAvailableError: The SDK is missing or no key is configured.
            ProviderError: The API rejected the request or returned no text.
        """
        assert_redacted(request, provider=self.name)

        usable, reason = self.available()
        if not usable:
            raise ProviderNotAvailableError(self.name, reason)

        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self._api_key, timeout=request.timeout_seconds)

        try:
            message = await client.messages.create(
                model=request.model_id or self._default_model,
                max_tokens=request.max_output_tokens,
                system=request.system,
                messages=[{"role": "user", "content": request.user}],
                output_config={"format": _ADVISORY_SCHEMA},
            )
        except anthropic.AuthenticationError as exc:
            raise ProviderNotAvailableError(
                self.name,
                "the configured API key was rejected",
                remediation=f"Check {_API_KEY_ENV}.",
            ) from exc
        except anthropic.APIError as exc:
            # The SDK's message can echo request content; state the class of failure
            # instead so a redacted payload is not re-surfaced through an exception.
            raise ProviderError(self.name, f"{type(exc).__name__} from the Messages API") from exc

        text = "".join(block.text for block in message.content if block.type == "text")
        if not text.strip():
            raise ProviderError(self.name, "response contained no text content")

        return CompletionResponse(
            text=text,
            model_id=message.model,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
        )


_ADVISORY_SCHEMA: Final[dict[str, Any]] = {
    "type": "json_schema",
    "schema": {
        "type": "object",
        "properties": {
            "assessment": {
                "type": "string",
                "enum": ["likely_exploitable", "likely_false_positive", "unclear"],
            },
            "rationale": {"type": "string"},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "remediation": {"type": ["string", "null"]},
            "evidence_refs": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["assessment", "rationale", "confidence"],
        "additionalProperties": False,
    },
}
"""Constrains the decode to the advisory shape. Mirrors ``TriageResult``.

Kept beside the provider rather than in ``core/`` because it is a wire-format
detail. The authoritative shape is the Pydantic model in ``triage.py``, which
validates every reply regardless of what the provider claims to have constrained.
"""

__all__ = ["DEFAULT_MODEL", "AnthropicProvider"]
