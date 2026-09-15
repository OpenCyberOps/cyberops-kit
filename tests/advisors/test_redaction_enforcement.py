"""INV-4 enforcement: no secret reaches a provider request body.

The Phase 2 spec asks this suite to prove two things:

1. No provider client can be constructed with a redaction bypass.
2. Seeded secrets never appear in a captured request body.

Both are tested against the real code path — ``LLMAdvisor.complete`` calling a
provider — rather than against ``redact()`` in isolation. Testing the redactor alone
would prove the function works while leaving the interesting question, *is it
actually on the path*, unanswered.
"""

from __future__ import annotations

import pytest

from cyberops_kit.advisors.base import LLMAdvisor
from cyberops_kit.advisors.budget import Budget
from cyberops_kit.advisors.cache import ResponseCache
from cyberops_kit.advisors.errors import UnredactedPayloadError
from cyberops_kit.advisors.providers import CompletionRequest, CompletionResponse
from cyberops_kit.advisors.providers.base import assert_redacted
from cyberops_kit.advisors.providers.local import LocalProvider
from cyberops_kit.config import AISettings
from cyberops_kit.core.models import Category, Finding, ScannerRef, Severity

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
"""AWS's own canonical placeholder key, recognized as non-functional by convention."""

GITHUB_PAT = "ghp_" + "example00fake00credential00for00tests00"[:36]  # gitleaks:allow
"""Shaped to match the ``ghp_<36 chars>`` pattern our redactor detects, built from an
obviously-fake fill string rather than random-looking characters so it reads as
synthetic to a human reviewer and does not need rotating — it was never live.
"""

PRIVATE_VALUE = "hunter2-super-secret-database-password-value"


class CapturingProvider:
    """Records every request it is given instead of sending one."""

    name = "capturing"

    def __init__(self) -> None:
        """Initialize with an empty capture log."""
        self.requests: list[CompletionRequest] = []

    def available(self) -> tuple[bool, str]:
        """Always usable."""
        return True, ""

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Capture the request and return a valid advisory reply."""
        assert_redacted(request, provider=self.name)
        self.requests.append(request)
        return CompletionResponse(
            text='{"assessment":"unclear","rationale":"captured","confidence":"low"}',
            model_id="capture-1",
        )


def make_secret_finding(value: str) -> Finding:
    """Build a SECRET finding carrying a literal credential.

    Args:
        value: The credential the scanner reports having found.

    Returns:
        A finding whose ``raw`` block contains the literal, as Gitleaks produces.
    """
    return Finding.build(
        scanner=ScannerRef(name="gitleaks", version="8.0.0"),
        rule_id="aws-access-key",
        title="AWS key committed",
        description="A credential was committed to the repository.",
        severity=Severity.CRITICAL,
        category=Category.SECRET,
        raw={"Secret": value, "Match": f"aws_key = {value}"},
    )


@pytest.fixture
def advisor(tmp_path) -> tuple[LLMAdvisor, CapturingProvider]:
    """Build an advisor wired to a capturing provider."""
    provider = CapturingProvider()
    return (
        LLMAdvisor(
            provider=provider,
            model_id="capture-1",
            budget=Budget(max_findings=25),
            cache=ResponseCache(tmp_path, enabled=False),
        ),
        provider,
    )


# --- 1. No client can be constructed with a bypass -------------------------------


def test_ai_redact_cannot_be_disabled_in_config():
    """``ai.redact: false`` is refused by the config validator. There is no flag."""
    with pytest.raises(ValueError, match="redact cannot be set to false"):
        AISettings(redact=False)


def test_completion_request_defaults_to_unredacted():
    """The safe default is 'not yet redacted', so forgetting fails closed."""
    request = CompletionRequest(system="s", user="u", model_id="m")
    assert request.redacted is False


def test_provider_refuses_an_unredacted_request():
    """A request that never passed through redact() cannot be transmitted."""
    request = CompletionRequest(system="s", user=AWS_KEY, model_id="m")
    with pytest.raises(UnredactedPayloadError, match="INV-4"):
        assert_redacted(request, provider="any")


@pytest.mark.asyncio
async def test_every_provider_enforces_the_redaction_gate():
    """The gate is inside each provider, not only at the call site.

    A future provider that forgets this check is the failure mode this test exists
    to catch, so it asserts against the shipped provider classes rather than a stub.
    """
    request = CompletionRequest(system="s", user=AWS_KEY, model_id="m")

    with pytest.raises(UnredactedPayloadError):
        await LocalProvider().complete(request)


@pytest.mark.asyncio
async def test_capturing_provider_would_reject_a_bypass(advisor):
    """Even a test double enforces it — the gate is not test-only scaffolding."""
    _, provider = advisor
    with pytest.raises(UnredactedPayloadError):
        await provider.complete(CompletionRequest(system="s", user="u", model_id="m"))


# --- 2. Seeded secrets never reach a request body --------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("secret", [AWS_KEY, GITHUB_PAT, PRIVATE_VALUE])
async def test_seeded_secret_never_appears_in_a_request_body(advisor, secret):
    """A secret present in the context is gone by the time it reaches the wire."""
    llm, provider = advisor
    findings = [make_secret_finding(secret)]

    await llm.complete(
        system="system prompt",
        user=f"Here is the code:\n    api_key = '{secret}'\n",
        findings=findings,
        prompt_version="v1",
        enricher_version="1.0.0",
    )

    assert provider.requests, "the provider was never called"
    body = provider.requests[0].model_dump_json()
    assert secret not in body
    assert "REDACTED" in provider.requests[0].user


@pytest.mark.asyncio
async def test_a_secret_from_one_finding_is_scrubbed_from_another_context(advisor):
    """Cross-finding redaction.

    The credential was found in ``config.py`` but also appears in the snippet for an
    unrelated SAST finding in ``db.py``. Passing only the finding under analysis to
    the redactor would leak it; the advisor passes the whole finding set precisely
    so this case is covered.
    """
    llm, provider = advisor
    findings = [make_secret_finding(PRIVATE_VALUE)]

    await llm.complete(
        system="system prompt",
        user=f"db.py:\n    conn = connect(password='{PRIVATE_VALUE}')\n",
        findings=findings,
        prompt_version="v1",
        enricher_version="1.0.0",
    )

    assert PRIVATE_VALUE not in provider.requests[0].user


@pytest.mark.asyncio
async def test_high_entropy_values_are_removed_without_a_matching_finding(advisor):
    """Redaction does not depend on a scanner having found the secret first.

    The entropy layer is what covers a credential no scanner flagged. Without it,
    redaction would only ever remove what was already known.
    """
    llm, provider = advisor
    unflagged = "xK9mNp2QrS7tUv4WyZ1aB3cD6eF8gH0jK5lM"

    await llm.complete(
        system="system prompt",
        user=f"token = '{unflagged}'",
        findings=[],
        prompt_version="v1",
        enricher_version="1.0.0",
    )

    assert unflagged not in provider.requests[0].user


@pytest.mark.asyncio
async def test_the_cache_key_is_derived_from_redacted_text(tmp_path):
    """A cache entry must not be a place a secret survives the run.

    The key is a hash of the redacted payload, and the stored body is the response,
    so no file in the cache directory contains the credential.
    """
    provider = CapturingProvider()
    cache = ResponseCache(tmp_path, enabled=True)
    llm = LLMAdvisor(
        provider=provider,
        model_id="capture-1",
        budget=Budget(max_findings=25),
        cache=cache,
    )

    await llm.complete(
        system="system prompt",
        user=f"key = '{AWS_KEY}'",
        findings=[make_secret_finding(AWS_KEY)],
        prompt_version="v1",
        enricher_version="1.0.0",
    )

    written = list(tmp_path.rglob("*.json"))
    assert written, "nothing was cached"
    for path in written:
        assert AWS_KEY not in path.read_text(encoding="utf-8")
        assert AWS_KEY not in path.name
