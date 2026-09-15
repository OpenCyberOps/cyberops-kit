"""Inference providers and the registry that resolves one by name.

Mirrors the structure of ``scanners/registry.py``: a name-keyed factory table, so
adding a provider is one entry plus one module, and no caller needs to change.

Construction is lazy. Naming a provider in config must not import an SDK that is
not installed, and must not read a credential from the environment until the
provider is actually selected for a run.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from cyberops_kit.advisors.errors import ProviderNotAvailableError
from cyberops_kit.advisors.providers.base import (
    CompletionRequest,
    CompletionResponse,
    Provider,
    assert_redacted,
)


def _anthropic() -> Provider:
    """Construct the Anthropic provider."""
    from cyberops_kit.advisors.providers.anthropic import AnthropicProvider

    return AnthropicProvider()


def _openai() -> Provider:
    """Construct the OpenAI provider."""
    from cyberops_kit.advisors.providers.openai import OpenAIProvider

    return OpenAIProvider()


def _local() -> Provider:
    """Construct the local (Ollama) provider."""
    from cyberops_kit.advisors.providers.local import LocalProvider

    return LocalProvider()


PROVIDERS: Final[dict[str, Callable[[], Provider]]] = {
    "anthropic": _anthropic,
    "openai": _openai,
    "local": _local,
}
"""Provider factories by name. ``local`` requires no credential and no network."""

DEFAULT_PROVIDER: Final = "local"
"""The privacy-preserving default.

A user who enables triage without naming a provider gets local inference rather than
an outbound request to a vendor. Defaulting the other way would mean a flag typo
could ship source context off the machine.
"""


def get_provider(name: str | None) -> Provider:
    """Resolve a provider by name.

    Args:
        name: Provider name from config, or ``None`` for the default.

    Returns:
        A constructed provider.

    Raises:
        ProviderNotAvailableError: No provider is registered under that name.
    """
    resolved = (name or DEFAULT_PROVIDER).strip().lower()
    factory = PROVIDERS.get(resolved)
    if factory is None:
        raise ProviderNotAvailableError(
            resolved,
            f"unknown provider {resolved!r}",
            remediation=f"Available providers: {', '.join(sorted(PROVIDERS))}.",
        )
    return factory()


__all__ = [
    "DEFAULT_PROVIDER",
    "PROVIDERS",
    "CompletionRequest",
    "CompletionResponse",
    "Provider",
    "assert_redacted",
    "get_provider",
]
