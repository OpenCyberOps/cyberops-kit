"""OpenAI provider, via the official ``openai`` SDK.

Optional dependency, imported lazily for the same reasons as the Anthropic
provider. Uses JSON mode for structured output; the reply is validated against the
Pydantic model by the caller regardless.

Also serves any OpenAI-compatible endpoint through ``base_url`` — vLLM, LM Studio,
and several self-hosted gateways speak this wire format. That is a convenience, not
a second local provider: the supported air-gapped path is ``LocalProvider``.
"""

from __future__ import annotations

import os
from typing import Final

import structlog

from cyberops_kit.advisors.errors import ProviderError, ProviderNotAvailableError
from cyberops_kit.advisors.providers.base import (
    CompletionRequest,
    CompletionResponse,
    assert_redacted,
)

logger = structlog.get_logger(__name__)

DEFAULT_MODEL: Final = "gpt-4o"
_API_KEY_ENV: Final = "OPENAI_API_KEY"


class OpenAIProvider:
    """Talks to the OpenAI Chat Completions API.

    Attributes:
        name: Stable provider identifier recorded on every ``Advisory``.
    """

    name = "openai"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        default_model: str = DEFAULT_MODEL,
        base_url: str | None = None,
    ) -> None:
        """Initialize the provider.

        Args:
            api_key: API key. Read from ``OPENAI_API_KEY`` when omitted. Never
                logged, and never included in an error message.
            default_model: Model used when the request names none.
            base_url: Override for an OpenAI-compatible endpoint.
        """
        self._api_key = api_key or os.environ.get(_API_KEY_ENV)
        self._default_model = default_model
        self._base_url = base_url

    def available(self) -> tuple[bool, str]:
        """Report whether the SDK is installed and a credential is present.

        Returns:
            ``(True, "")`` when usable, else ``(False, reason)``. The reason names
            the missing environment variable, never its value.
        """
        try:
            import openai  # noqa: F401
        except ImportError:
            return False, (
                "the 'openai' package is not installed. "
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

        import openai

        client = openai.AsyncOpenAI(
            api_key=self._api_key,
            base_url=self._base_url,
            timeout=request.timeout_seconds,
        )

        try:
            completion = await client.chat.completions.create(
                model=request.model_id or self._default_model,
                max_tokens=request.max_output_tokens,
                temperature=request.temperature,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": request.system},
                    {"role": "user", "content": request.user},
                ],
            )
        except openai.AuthenticationError as exc:
            raise ProviderNotAvailableError(
                self.name,
                "the configured API key was rejected",
                remediation=f"Check {_API_KEY_ENV}.",
            ) from exc
        except openai.OpenAIError as exc:
            # Deliberately not interpolating the SDK message: it can echo request
            # content, which would re-surface a payload we just redacted.
            raise ProviderError(
                self.name, f"{type(exc).__name__} from the completions API"
            ) from exc

        if not completion.choices:
            raise ProviderError(self.name, "response contained no choices")

        text = completion.choices[0].message.content or ""
        if not text.strip():
            raise ProviderError(self.name, "response contained no text content")

        usage = completion.usage
        return CompletionResponse(
            text=text,
            model_id=completion.model,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )


__all__ = ["DEFAULT_MODEL", "OpenAIProvider"]
