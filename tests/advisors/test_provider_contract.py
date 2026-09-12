"""The contract every provider must satisfy, applied uniformly to all three.

Parameterized over the shipped providers rather than written once per vendor. A new
provider is added to ``PROVIDERS`` in the registry and is immediately held to the
same standard, which is the property that keeps the local provider first-class
rather than a second-tier fallback.

These tests never perform real inference. They assert the shape of the contract:
construction, availability reporting, the redaction gate, and error typing.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cyberops_kit.advisors.errors import ProviderNotAvailableError, UnredactedPayloadError
from cyberops_kit.advisors.providers import (
    DEFAULT_PROVIDER,
    PROVIDERS,
    CompletionRequest,
    CompletionResponse,
    Provider,
    get_provider,
)
from cyberops_kit.advisors.providers.local import LocalProvider

ALL_PROVIDERS = sorted(PROVIDERS)


@pytest.fixture(params=ALL_PROVIDERS)
def provider(request) -> Provider:
    """Construct each registered provider in turn."""
    return get_provider(request.param)


# --- Registry --------------------------------------------------------------------


def test_at_least_three_providers_ship():
    """Phase 2 definition of done: three providers, one fully local."""
    assert len(PROVIDERS) >= 3
    assert "local" in PROVIDERS


def test_the_default_provider_is_the_local_one():
    """A flag typo must not ship source context to a vendor.

    Defaulting to a hosted provider would mean ``--ai-triage`` with no
    ``--ai-provider`` sends code off the machine. The privacy-preserving default is
    a deliberate design choice, not an accident of dict ordering.
    """
    assert DEFAULT_PROVIDER == "local"


def test_an_unknown_provider_names_the_available_ones():
    """A typo produces an actionable error, not a KeyError."""
    with pytest.raises(ProviderNotAvailableError) as exc:
        get_provider("antropic")
    assert "anthropic" in (exc.value.remediation or "")


def test_provider_names_are_normalized():
    """Config is case- and whitespace-insensitive."""
    assert get_provider("  LOCAL  ").name == "local"


def test_none_resolves_to_the_default():
    """An unset provider is the default, not an error."""
    assert get_provider(None).name == DEFAULT_PROVIDER


# --- Protocol conformance --------------------------------------------------------


def test_provider_satisfies_the_protocol(provider):
    """Every registered provider structurally implements ``Provider``."""
    assert isinstance(provider, Provider)


def test_provider_declares_a_stable_name(provider):
    """The name is recorded on every advisory, so it must be a non-empty string."""
    assert isinstance(provider.name, str)
    assert provider.name == provider.name.strip().lower()
    assert provider.name


def test_availability_returns_a_reason_when_unusable(provider):
    """``available()`` reports why, so ``doctor`` can tell the user what to fix."""
    usable, reason = provider.available()
    assert isinstance(usable, bool)
    assert isinstance(reason, str)
    if not usable:
        assert reason, "an unavailable provider must explain itself"


def test_an_unavailable_provider_never_leaks_a_credential(provider, monkeypatch):
    """The reason names the missing variable, never its value."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-never-be-echoed")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-never-be-echoed")

    _, reason = get_provider(provider.name).available()
    assert "should-never-be-echoed" not in reason


# --- The redaction gate ----------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_refuses_an_unredacted_request(provider):
    """INV-4, enforced inside every provider independently.

    This is the single most important row of the contract. It runs before any
    availability check in each provider, so it holds even where no SDK is installed
    and no credential is configured.
    """
    request = CompletionRequest(system="s", user="secret-bearing text", model_id="m")
    with pytest.raises(UnredactedPayloadError):
        await provider.complete(request)


# --- Request and response models -------------------------------------------------


def test_request_rejects_a_nonsensical_token_ceiling():
    """Bounds are enforced by the model, not left to each provider."""
    with pytest.raises(ValidationError, match="max_output_tokens"):
        CompletionRequest(system="s", user="u", model_id="m", max_output_tokens=0)


def test_request_defaults_to_deterministic_sampling():
    """Temperature zero by default; advisory text should not drift without cause."""
    assert CompletionRequest(system="s", user="u", model_id="m").temperature == 0.0


def test_response_totals_tokens():
    """Budget accounting depends on this sum."""
    response = CompletionResponse(text="{}", model_id="m", input_tokens=10, output_tokens=5)
    assert response.total_tokens == 15


def test_response_tolerates_providers_that_report_no_usage():
    """The local provider often reports nothing; that must not break accounting."""
    assert CompletionResponse(text="{}", model_id="m").total_tokens == 0


# --- Local provider specifics ----------------------------------------------------


def test_local_provider_needs_no_credential():
    """The air-gapped path must not depend on an environment variable.

    Its availability is a question about a daemon, never about a key — that is what
    makes it usable where the other two cannot be.
    """
    _, reason = LocalProvider(host="http://127.0.0.1:1").available()
    assert "API_KEY" not in reason
    assert "ollama serve" in reason.lower() or "reachable" in reason.lower()


@pytest.mark.asyncio
async def test_local_provider_reports_an_unreachable_daemon_clearly():
    """An unreachable daemon is a typed, actionable error."""
    provider = LocalProvider(host="http://127.0.0.1:1")
    request = CompletionRequest(system="s", user="u", model_id="m", redacted=True)

    with pytest.raises(ProviderNotAvailableError) as exc:
        await provider.complete(request)
    assert "ollama serve" in (exc.value.remediation or "").lower()
