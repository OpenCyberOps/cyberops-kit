"""The triage enricher: selection, context assembly, and soft failure.

The theme running through this file is that **every failure mode leaves the
deterministic report intact**. A provider outage, a malformed reply, a fourth
assessment value, an exhausted budget, a deleted source file — each produces a
finding without an advisory, never a corrupted or missing finding.
"""

from __future__ import annotations

import pytest

from cyberops_kit.advisors.base import LLMAdvisor
from cyberops_kit.advisors.budget import Budget, select_findings
from cyberops_kit.advisors.cache import ResponseCache
from cyberops_kit.advisors.errors import ProviderError
from cyberops_kit.advisors.providers import CompletionRequest, CompletionResponse
from cyberops_kit.advisors.providers.base import assert_redacted
from cyberops_kit.advisors.triage import (
    CONTEXT_LINES,
    LLMTriageEnricher,
    TriageResult,
    build_context,
)
from cyberops_kit.core.enrichment import run_enrichment
from cyberops_kit.core.models import Category, Finding, Location, PackageRef, ScannerRef, Severity

VALID_REPLY = (
    '{"assessment":"likely_exploitable",'
    '"rationale":"The user_id on line 42 reaches the query on line 47 unparameterized.",'
    '"confidence":"high","remediation":"Use a parameterized query.",'
    '"evidence_refs":["line 47"]}'
)


class ScriptedProvider:
    """Returns queued replies, or raises when told to."""

    name = "scripted"

    def __init__(self, *replies: str | Exception) -> None:
        """Queue the replies this provider will return, in order."""
        self._replies = list(replies)
        self.calls: list[CompletionRequest] = []

    def available(self) -> tuple[bool, str]:
        """Always usable."""
        return True, ""

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Return the next queued reply, or raise it if it is an exception."""
        assert_redacted(request, provider=self.name)
        self.calls.append(request)
        reply = self._replies.pop(0) if self._replies else VALID_REPLY
        if isinstance(reply, Exception):
            raise reply
        return CompletionResponse(text=reply, model_id="scripted-1", output_tokens=50)


def build_advisor(provider: ScriptedProvider, tmp_path, *, max_findings: int = 25) -> LLMAdvisor:
    """Wire a scripted provider into an advisor with caching disabled."""
    return LLMAdvisor(
        provider=provider,
        model_id="scripted-1",
        budget=Budget(max_findings=max_findings),
        cache=ResponseCache(tmp_path, enabled=False),
    )


def vuln(rule_id: str = "CVE-2021-0001", severity: Severity = Severity.HIGH) -> Finding:
    """Build a triageable vulnerability finding."""
    return Finding.build(
        scanner=ScannerRef(name="osv", version="1.0.0"),
        rule_id=rule_id,
        title=f"{rule_id} in lodash",
        description="Prototype pollution.",
        severity=severity,
        category=Category.VULNERABILITY,
        package=PackageRef(name="lodash", version="4.17.20", ecosystem="npm"),
        raw={},
    )


# --- applies_to ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("category", "severity", "expected"),
    [
        (Category.VULNERABILITY, Severity.CRITICAL, True),
        (Category.VULNERABILITY, Severity.HIGH, True),
        (Category.STATIC_ANALYSIS, Severity.MEDIUM, True),
        (Category.VULNERABILITY, Severity.LOW, False),
        (Category.VULNERABILITY, Severity.INFO, False),
        (Category.SECRET, Severity.CRITICAL, False),
        (Category.SUPPLY_CHAIN, Severity.HIGH, False),
        (Category.PRACTICE, Severity.HIGH, False),
    ],
)
def test_applies_to_scopes_triage_narrowly(category, severity, expected):
    """Only where context genuinely changes the answer."""
    finding = Finding.build(
        scanner=ScannerRef(name="s", version="1"),
        rule_id="r",
        title="t",
        description="d",
        severity=severity,
        category=category,
        raw={},
    )
    assert LLMTriageEnricher().applies_to(finding) is expected


def test_secrets_are_never_triaged():
    """The one category that must never be sent, stated as its own test.

    Gitleaks already knows it found a credential; a model adds nothing, and the
    context would be the secret itself. This is INV-4 expressed as scope.
    """
    secret = Finding.build(
        scanner=ScannerRef(name="gitleaks", version="8"),
        rule_id="aws-key",
        title="AWS key",
        description="d",
        severity=Severity.CRITICAL,
        category=Category.SECRET,
        raw={"Secret": "AKIAIOSFODNN7EXAMPLE"},
    )
    assert LLMTriageEnricher().applies_to(secret) is False


# --- The happy path --------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_valid_reply_becomes_an_advisory(run_context, tmp_path):
    """The end-to-end shape: reply in, populated Advisory out."""
    provider = ScriptedProvider(VALID_REPLY)
    enricher = LLMTriageEnricher(advisor=build_advisor(provider, tmp_path))

    result = await enricher.enrich([vuln()], run_context)

    advisory = result[0].advisory
    assert advisory is not None
    assert advisory.assessment == "likely_exploitable"
    assert advisory.confidence == "high"
    assert advisory.enricher == "llm-triage"
    assert advisory.provider == "scripted"
    assert advisory.prompt_version == "v1"


@pytest.mark.asyncio
async def test_provenance_is_recorded_on_every_advisory(run_context, tmp_path):
    """Any advisory must trace back to the exact prompt that produced it."""
    provider = ScriptedProvider(VALID_REPLY)
    enricher = LLMTriageEnricher(advisor=build_advisor(provider, tmp_path))

    advisory = (await enricher.enrich([vuln()], run_context))[0].advisory

    assert advisory is not None
    assert advisory.prompt_version
    assert advisory.model_id
    assert advisory.enricher_version
    assert advisory.generated_at is not None


@pytest.mark.asyncio
async def test_non_qualifying_findings_pass_through_untouched(run_context, tmp_path):
    """A LOW finding is returned unchanged and costs nothing."""
    provider = ScriptedProvider()
    low = vuln(severity=Severity.LOW)
    enricher = LLMTriageEnricher(advisor=build_advisor(provider, tmp_path))

    result = await enricher.enrich([low], run_context)

    assert result[0].advisory is None
    assert provider.calls == []


# --- Soft failure ----------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_reply",
    [
        "this is not json at all",
        "{",
        '{"assessment":"likely_exploitable"}',
        '{"assessment":"definitely_exploitable","rationale":"r","confidence":"high"}',
        '{"assessment":"unclear","rationale":"r","confidence":"very-high"}',
        '{"assessment":"unclear","rationale":"","confidence":"low"}',
        "[]",
        "null",
    ],
)
async def test_a_malformed_reply_drops_the_advisory_and_keeps_the_finding(
    run_context, tmp_path, bad_reply
):
    """A bad reply must never degrade the finding itself.

    Covers missing fields, a fourth assessment value, an invalid confidence, an
    empty rationale, and replies that are not JSON objects at all.
    """
    provider = ScriptedProvider(bad_reply)
    original = vuln()
    enricher = LLMTriageEnricher(advisor=build_advisor(provider, tmp_path))

    result = await enricher.enrich([original], run_context)

    assert len(result) == 1
    assert result[0].advisory is None
    assert result[0].model_dump(exclude={"advisory"}) == original.model_dump(exclude={"advisory"})


@pytest.mark.asyncio
async def test_a_provider_outage_leaves_every_finding_intact(run_context, tmp_path):
    """Inference failing is not a scan failing."""
    provider = ScriptedProvider(*[ProviderError("scripted", "503 unavailable") for _ in range(3)])
    enricher = LLMTriageEnricher(advisor=build_advisor(provider, tmp_path))

    result = await enricher.enrich([vuln()], run_context)

    assert result[0].advisory is None


@pytest.mark.asyncio
async def test_a_transient_failure_is_retried(run_context, tmp_path):
    """One 503 then success still produces an advisory."""
    provider = ScriptedProvider(ProviderError("scripted", "503"), VALID_REPLY)
    enricher = LLMTriageEnricher(advisor=build_advisor(provider, tmp_path))

    result = await enricher.enrich([vuln()], run_context)

    assert result[0].advisory is not None
    assert len(provider.calls) == 2


@pytest.mark.asyncio
async def test_offline_disables_the_enricher_entirely(run_context, tmp_path):
    """INV-6 defense in depth, at the last layer that could still call out."""
    provider = ScriptedProvider(VALID_REPLY)
    offline_ctx = run_context.model_copy(update={"offline": True})
    enricher = LLMTriageEnricher(advisor=build_advisor(provider, tmp_path))

    result = await enricher.enrich([vuln()], offline_ctx)

    assert provider.calls == []
    assert result[0].advisory is None


@pytest.mark.asyncio
async def test_a_reply_wrapped_in_a_code_fence_is_recovered(run_context, tmp_path):
    """Local models fence their JSON; that must not cost the user an advisory."""
    provider = ScriptedProvider(f"Here is my assessment:\n```json\n{VALID_REPLY}\n```")
    enricher = LLMTriageEnricher(advisor=build_advisor(provider, tmp_path))

    result = await enricher.enrich([vuln()], run_context)

    assert result[0].advisory is not None


# --- The enrichment contract -----------------------------------------------------


@pytest.mark.asyncio
async def test_the_enricher_satisfies_the_seam_2_contract(run_context, tmp_path, monkeypatch):
    """Run through ``run_enrichment``, which enforces the contract at runtime.

    Going through the real registry rather than calling ``enrich`` directly is the
    point: this asserts the enricher is acceptable to the guard that protects INV-2.
    """
    import cyberops_kit.core.enrichment as enrichment

    provider = ScriptedProvider(VALID_REPLY, VALID_REPLY)
    enricher = LLMTriageEnricher(advisor=build_advisor(provider, tmp_path))
    monkeypatch.setattr(enrichment, "ENRICHERS", [enricher])

    findings = [vuln("CVE-2021-0001"), vuln("CVE-2021-0002")]
    result = await run_enrichment(findings, run_context)

    assert len(result) == len(findings)
    assert [f.id for f in result] == [f.id for f in findings]


@pytest.mark.asyncio
async def test_order_and_count_are_preserved_when_only_some_are_annotated(run_context, tmp_path):
    """A partial annotation must not reorder or drop anything."""
    provider = ScriptedProvider(VALID_REPLY, "garbage")
    findings = [vuln("CVE-1"), vuln("CVE-2"), vuln("CVE-3", severity=Severity.LOW)]
    enricher = LLMTriageEnricher(advisor=build_advisor(provider, tmp_path))

    result = await enricher.enrich(findings, run_context)

    assert [f.id for f in result] == [f.id for f in findings]
    assert result[2].advisory is None


# --- Context assembly ------------------------------------------------------------


def test_context_includes_the_finding_and_the_package(run_context):
    """The judgment needs the rule, the severity, and the dependency."""
    context = build_context(vuln(), run_context)

    assert "CVE-2021-0001" in context
    assert "lodash" in context
    assert "4.17.20" in context
    assert "high" in context.lower()


def test_context_is_bounded_to_the_configured_window(run_context, tmp_path):
    """~60 lines, not the whole file. Every extra line is cost and exposure."""
    source = tmp_path / "big.py"
    source.write_text("\n".join(f"line_{n}" for n in range(1, 501)), encoding="utf-8")
    ctx = run_context.model_copy(update={"workspace": tmp_path})

    finding = Finding.build(
        scanner=ScannerRef(name="semgrep", version="1"),
        rule_id="rule",
        title="t",
        description="d",
        severity=Severity.HIGH,
        category=Category.STATIC_ANALYSIS,
        location=Location(path="big.py", start_line=250),
        raw={},
    )

    context = build_context(finding, ctx)

    assert "line_250" in context
    assert "line_1\n" not in context
    assert "line_500" not in context
    assert context.count("\n") < (CONTEXT_LINES * 2) + 30


def test_a_missing_source_file_is_reported_not_raised(run_context, tmp_path):
    """A deleted file yields 'not readable', and the model answers unclear."""
    ctx = run_context.model_copy(update={"workspace": tmp_path})
    finding = Finding.build(
        scanner=ScannerRef(name="semgrep", version="1"),
        rule_id="rule",
        title="t",
        description="d",
        severity=Severity.HIGH,
        category=Category.STATIC_ANALYSIS,
        location=Location(path="gone.py", start_line=10),
        raw={},
    )

    context = build_context(finding, ctx)

    assert "not readable" in context


# --- Budget ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_finding_ceiling_stops_enrichment_cleanly(run_context, tmp_path):
    """Exceeding the ceiling truncates; it does not fail the run."""
    provider = ScriptedProvider(*[VALID_REPLY] * 10)
    advisor = build_advisor(provider, tmp_path, max_findings=2)
    ctx = run_context.model_copy(
        update={"config": run_context.config.model_copy(update={"ai": _ai(max_findings=2)})}
    )
    enricher = LLMTriageEnricher(advisor=advisor)

    findings = [vuln(f"CVE-{n}") for n in range(5)]
    result = await enricher.enrich(findings, ctx)

    assert len(result) == 5
    assert sum(1 for f in result if f.advisory is not None) == 2
    assert len(provider.calls) == 2


def test_selection_is_severity_ordered_and_deterministic():
    """Which findings get analyzed must not depend on scanner completion order."""
    findings = [
        vuln("CVE-LOW", severity=Severity.MEDIUM),
        vuln("CVE-CRIT", severity=Severity.CRITICAL),
        vuln("CVE-HIGH", severity=Severity.HIGH),
    ]

    first = select_findings(findings, limit=2)
    second = select_findings(list(reversed(findings)), limit=2)

    assert [f.severity for f in first] == [Severity.CRITICAL, Severity.HIGH]
    assert [f.id for f in first] == [f.id for f in second]


def test_budget_records_the_first_truncation_reason_only():
    """The reported reason is the one that actually stopped the run."""
    budget = Budget(max_findings=1, max_tokens=100)
    budget.record(tokens=500)

    assert budget.can_analyze() is False
    assert "ai.max_findings" in budget.truncation_reason


# --- The parsed-result model -----------------------------------------------------


def test_triage_result_ignores_unknown_fields():
    """A model that adds a field must not fail validation over it."""
    result = TriageResult.model_validate(
        {
            "assessment": "unclear",
            "rationale": "r",
            "confidence": "low",
            "editorial_note": "ignored",
        }
    )
    assert result.assessment == "unclear"


def _ai(**kwargs):
    """Build an AISettings override for a test context."""
    from cyberops_kit.config import AISettings

    return AISettings(enabled=True, **kwargs)
