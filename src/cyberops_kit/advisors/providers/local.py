"""Local inference via an Ollama-compatible HTTP endpoint.

This provider exists so that air-gapped and privacy-sensitive users get triage
without sending a byte to a third party. It is not a degraded fallback — it
implements the same protocol as every other provider and passes the same contract
suite.

Implemented against ``urllib`` from the standard library rather than an HTTP client
dependency. The endpoint is one POST with a JSON body; pulling in a transitive
dependency tree for that would be supply chain surface we could not justify in a
tool that audits supply chain surface.

Weakest structured-output guarantees of the three providers: a local model asked for
JSON will sometimes wrap it in prose or a code fence. That is handled in
``advisors/base.py`` by the shared extraction path, and a reply that still will not
parse drops the advisory rather than degrading the finding.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from typing import Any, Final

import structlog

from cyberops_kit.advisors.errors import ProviderError, ProviderNotAvailableError
from cyberops_kit.advisors.providers.base import (
    CompletionRequest,
    CompletionResponse,
    assert_redacted,
)

logger = structlog.get_logger(__name__)

DEFAULT_HOST: Final = "http://localhost:11434"
DEFAULT_MODEL: Final = "llama3.1:8b"
_HEALTH_TIMEOUT_SECONDS: Final = 2.0


class LocalProvider:
    """Talks to an Ollama-compatible ``/api/chat`` endpoint.

    Attributes:
        name: Stable provider identifier recorded on every ``Advisory``.
    """

    name = "local"

    def __init__(self, *, host: str = DEFAULT_HOST, default_model: str = DEFAULT_MODEL) -> None:
        """Initialize the provider.

        Args:
            host: Base URL of the Ollama daemon. No credential is involved, which is
                the point of this provider.
            default_model: Model used when the request names none.
        """
        self._host = host.rstrip("/")
        self._default_model = default_model

    def available(self) -> tuple[bool, str]:
        """Report whether the local daemon is reachable.

        Returns:
            ``(True, "")`` when the daemon answers, else ``(False, reason)``.
        """
        try:
            with urllib.request.urlopen(  # noqa: S310 - fixed http scheme, operator-supplied host
                f"{self._host}/api/tags", timeout=_HEALTH_TIMEOUT_SECONDS
            ) as response:
                if response.status == 200:
                    return True, ""
                return False, f"daemon at {self._host} returned HTTP {response.status}"
        except (urllib.error.URLError, OSError) as exc:
            return False, (
                f"no Ollama daemon reachable at {self._host} ({exc}). Start it with `ollama serve`."
            )

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Perform one local inference call.

        Args:
            request: A redacted request.

        Returns:
            The normalized reply.

        Raises:
            UnredactedPayloadError: The request never passed through ``redact()``.
            ProviderError: The daemon was unreachable or returned an unusable body.
        """
        assert_redacted(request, provider=self.name)

        body = json.dumps(
            {
                "model": request.model_id or self._default_model,
                "messages": [
                    {"role": "system", "content": request.system},
                    {"role": "user", "content": request.user},
                ],
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": request.temperature,
                    "num_predict": request.max_output_tokens,
                },
            }
        ).encode("utf-8")

        payload = await _post_json(
            f"{self._host}/api/chat",
            body,
            timeout=request.timeout_seconds,
            provider=self.name,
        )

        message = payload.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise ProviderError(
                self.name,
                "response contained no message content",
                remediation="Check that the requested model is pulled: `ollama list`.",
            )

        return CompletionResponse(
            text=message["content"],
            model_id=str(payload.get("model", request.model_id)),
            input_tokens=int(payload.get("prompt_eval_count", 0) or 0),
            output_tokens=int(payload.get("eval_count", 0) or 0),
        )


async def _post_json(url: str, body: bytes, *, timeout: float, provider: str) -> dict[str, Any]:
    """POST a JSON body and decode the JSON reply, off the event loop.

    ``urllib`` is blocking, so it runs in a worker thread to avoid stalling the
    other findings being enriched concurrently.

    Args:
        url: Endpoint to call.
        body: Encoded JSON request body.
        timeout: Socket timeout in seconds.
        provider: Provider name, for error messages.

    Returns:
        The decoded response mapping.

    Raises:
        ProviderNotAvailableError: The endpoint was unreachable.
        ProviderError: The endpoint returned a non-JSON or non-mapping body.
    """

    def _send() -> bytes:
        request = urllib.request.Request(  # noqa: S310 - fixed http scheme
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw: bytes = response.read()
            return raw

    try:
        raw = await asyncio.to_thread(_send)
    except urllib.error.HTTPError as exc:
        raise ProviderError(provider, f"HTTP {exc.code} from {url}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderNotAvailableError(
            provider,
            f"could not reach {url}: {exc}",
            remediation="Start the daemon with `ollama serve`.",
        ) from exc

    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderError(provider, f"response body was not valid JSON: {exc}") from exc

    if not isinstance(decoded, dict):
        raise ProviderError(provider, "response body was not a JSON object")
    return decoded


__all__ = ["DEFAULT_HOST", "DEFAULT_MODEL", "LocalProvider"]
