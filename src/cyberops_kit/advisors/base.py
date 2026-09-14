"""The shared advisor client — redaction, caching, retry, and cost accounting.

Every inference call in the project goes through :meth:`LLMAdvisor.complete`. That
is what makes INV-4 structural: redaction happens here, once, and the ``redacted``
flag it sets is checked inside every provider immediately before the socket opens.
A caller cannot reach a provider without passing through this method, and a
provider will not transmit a request that did not.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Final

import structlog

from cyberops_kit.advisors.budget import Budget
from cyberops_kit.advisors.cache import ResponseCache, cache_key
from cyberops_kit.advisors.errors import ProviderError
from cyberops_kit.advisors.providers import CompletionRequest, Provider
from cyberops_kit.core.models import Finding
from cyberops_kit.core.redaction import redact

logger = structlog.get_logger(__name__)

PROMPTS_DIR: Final = Path(__file__).parent / "prompts"
_MAX_ATTEMPTS: Final = 3
_BACKOFF_SECONDS: Final = (0.0, 1.0, 3.0)
_FENCE_RE: Final = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def load_prompt(name: str) -> tuple[str, str]:
    """Load a versioned prompt file.

    Prompts are files, never inline strings, so that ``prompt_version`` on an
    ``Advisory`` traces back to an exact reviewable artifact.

    Args:
        name: Prompt filename stem, e.g. ``triage.v1``.

    Returns:
        A ``(text, version)`` pair, where version is the stem's version suffix.

    Raises:
        FileNotFoundError: The prompt file does not exist.
    """
    path = PROMPTS_DIR / f"{name}.md"
    text = path.read_text(encoding="utf-8")
    version = name.rsplit(".", 1)[-1] if "." in name else "v1"
    return text, version


class LLMAdvisor:
    """Wraps a provider with the guarantees every advisory call must carry.

    Attributes:
        provider: The underlying inference backend.
        model_id: Model to request.
        budget: Per-run ceilings, updated as calls complete.
        cache: Content-addressed response cache.
        timeout_seconds: Per-call timeout. Public — the enricher logs it up front so
            a slow local run reads as expected behavior, not as a hang.
    """

    def __init__(
        self,
        *,
        provider: Provider,
        model_id: str,
        budget: Budget,
        cache: ResponseCache,
        timeout_seconds: float = 60.0,
    ) -> None:
        """Initialize the advisor.

        Args:
            provider: The inference backend.
            model_id: Model to request. May be empty to use the provider default.
            budget: Ceilings for this run.
            cache: Response cache.
            timeout_seconds: Per-call timeout.
        """
        self.provider = provider
        self.model_id = model_id
        self.budget = budget
        self.cache = cache
        self.timeout_seconds = timeout_seconds

    async def complete(
        self,
        *,
        system: str,
        user: str,
        findings: list[Finding],
        prompt_version: str,
        enricher_version: str,
    ) -> dict[str, Any] | None:
        """Redact, cache-check, call the provider, and parse the reply as JSON.

        Args:
            system: System prompt text, from a versioned file.
            user: The assembled finding context, **not yet redacted**.
            findings: Every finding in the run, supplying literal secret values to
                the redactor. Passing the full set matters: a secret detected in one
                file must be scrubbed from another finding's context too.
            prompt_version: Version recorded on the resulting advisory.
            enricher_version: Version of the calling enricher, for cache keying.

        Returns:
            The parsed JSON object, or ``None`` when the call failed, the budget was
            exhausted, or the reply could not be parsed. Never raises for an
            inference failure — a finding without an advisory is the correct
            degraded state (INV-2).
        """
        # INV-4: the single redaction point. Everything below this line operates on
        # redacted text, and `redacted=True` is what every provider checks.
        redacted_user = redact(user, findings)
        if not isinstance(redacted_user, str):  # pragma: no cover - redact is type-stable
            raise TypeError("redact() returned a non-string for a string payload")

        key = cache_key(
            payload=redacted_user,
            provider=self.provider.name,
            model_id=self.model_id,
            prompt_version=prompt_version,
            enricher_version=enricher_version,
        )

        cached = self.cache.get(key)
        if cached is not None:
            logger.debug("advisors.cache.hit", provider=self.provider.name)
            return _parse_json(cached)

        if not self.budget.can_analyze():
            return None

        request = CompletionRequest(
            system=system,
            user=redacted_user,
            model_id=self.model_id,
            timeout_seconds=self.timeout_seconds,
            redacted=True,
        )

        response = await self._call_with_retry(request)
        if response is None:
            return None

        self.budget.record(tokens=response.total_tokens)
        self.cache.put(key, response.text)
        return _parse_json(response.text)

    async def _call_with_retry(self, request: CompletionRequest) -> Any:
        """Call the provider, retrying transient failures.

        Args:
            request: The redacted request.

        Returns:
            A ``CompletionResponse``, or ``None`` when every attempt failed.
        """
        for attempt in range(_MAX_ATTEMPTS):
            try:
                return await self.provider.complete(request)
            except ProviderError as exc:
                if attempt == _MAX_ATTEMPTS - 1:
                    logger.warning(
                        "advisors.provider.failed",
                        provider=self.provider.name,
                        attempts=_MAX_ATTEMPTS,
                        error=exc.message,
                    )
                    return None
                await asyncio.sleep(_BACKOFF_SECONDS[attempt + 1])
        return None  # pragma: no cover - loop always returns


def _parse_json(text: str) -> dict[str, Any] | None:
    """Parse a model reply as a JSON object, tolerating a code fence.

    Constrained decoding is requested from every provider, but the local one offers
    the weakest guarantee and will sometimes wrap its reply in ```json fences or add
    a sentence before it. Recovering from that here keeps the local provider a
    first-class citizen rather than one that silently produces fewer advisories.

    Args:
        text: Raw reply text.

    Returns:
        The parsed object, or ``None`` when the reply is not a JSON object.
    """
    candidate = text.strip()

    fenced = _FENCE_RE.search(candidate)
    if fenced:
        candidate = fenced.group(1).strip()
    elif not candidate.startswith("{"):
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end <= start:
            logger.debug("advisors.parse.no_json_object")
            return None
        candidate = candidate[start : end + 1]

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        logger.debug("advisors.parse.invalid_json")
        return None

    if not isinstance(parsed, dict):
        logger.debug("advisors.parse.not_an_object")
        return None
    return parsed


__all__ = ["PROMPTS_DIR", "LLMAdvisor", "load_prompt"]
