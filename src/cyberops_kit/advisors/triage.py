"""The triage enricher — the first thing Phase 2 actually ships.

Implements :class:`~cyberops_kit.core.enrichment.Enricher`, so the pipeline needs no
change: ``run_enrichment`` already calls it between normalize and score, and already
verifies at runtime that only ``advisory`` was touched.

Failure is always soft. A provider outage, a malformed reply, an exhausted budget,
and a finding whose file has since been deleted all produce the same outcome: that
finding keeps its scanner data and gets no advisory. The deterministic report is
identical either way, which is INV-2 restated as an operational property.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cyberops_kit.advisors.base import LLMAdvisor, load_prompt
from cyberops_kit.advisors.budget import Budget, select_findings
from cyberops_kit.advisors.cache import ResponseCache
from cyberops_kit.advisors.errors import ProviderNotAvailableError
from cyberops_kit.advisors.providers import get_provider
from cyberops_kit.core.enrichment import Enricher
from cyberops_kit.core.models import Advisory, Category, Finding, RunContext, Severity

logger = structlog.get_logger(__name__)

ENRICHER_NAME: Final = "llm-triage"
ENRICHER_VERSION: Final = "1.0.0"
PROMPT_NAME: Final = "triage.v1"

CONTEXT_LINES: Final = 30
"""Lines of source on each side of the finding. ~60 total, per the Phase 2 spec."""

MAX_CONCURRENCY: Final = 4
"""Concurrent inference calls against a hosted provider.

Hosted APIs genuinely parallelize independent requests. A single-instance local
daemon commonly does not: measured against a real Ollama server running a 14B model
on mixed CPU/GPU, three concurrent requests each ran ~45% *slower* than one request
alone (195s solo vs. ~280s each concurrent) — the daemon was serializing compute,
not adding throughput. See :data:`LOCAL_MAX_CONCURRENCY`.
"""

LOCAL_MAX_CONCURRENCY: Final = 1
"""Concurrent inference calls against the local provider.

Deliberately serial. Running requests one at a time against a resource-constrained
local daemon is not just safer, it is *faster* per finding — see the measurement
note on :data:`MAX_CONCURRENCY`. A user with a machine that genuinely can serve
several requests in parallel can still get there by running multiple Ollama model
instances themselves; this default protects the common case, a single laptop GPU.
"""

_TRIAGED_CATEGORIES: Final = frozenset({Category.VULNERABILITY, Category.STATIC_ANALYSIS})
_TRIAGED_SEVERITIES: Final = frozenset({Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM})


class TriageResult(BaseModel):
    """The parsed model reply, before it becomes an ``Advisory``.

    Validation happens here rather than against ``Advisory`` directly so that a
    malformed reply is rejected without ever constructing a partial advisory. A
    reply that fails this check is dropped and logged; the finding is untouched.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    assessment: str
    rationale: str = Field(min_length=1)
    confidence: str
    remediation: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class LLMTriageEnricher(Enricher):
    """Annotates findings with an exploitability assessment.

    Attributes:
        name: Registry name, recorded on every advisory it produces.
        version: Enricher version, recorded alongside the name.
    """

    name = ENRICHER_NAME
    version = ENRICHER_VERSION

    def __init__(self, *, advisor: LLMAdvisor | None = None) -> None:
        """Initialize the enricher.

        Args:
            advisor: Pre-built advisor. Tests inject a fake; in a real run this is
                ``None`` and the advisor is built from the run context, which is the
                only place provider configuration is known.
        """
        self._advisor = advisor
        self._system, self._prompt_version = load_prompt(PROMPT_NAME)

    def applies_to(self, finding: Finding) -> bool:
        """Return whether this finding is worth spending inference on.

        Scoped deliberately narrowly. Triage is only useful where context changes
        the answer: a dependency CVE or a SAST hit at meaningful severity. A secret
        is not triaged — Gitleaks already knows it found a credential, and sending
        its context to a model is the one thing INV-4 exists to prevent.

        Args:
            finding: The candidate finding.

        Returns:
            True when the finding should be sent for analysis.
        """
        return finding.category in _TRIAGED_CATEGORIES and finding.severity in _TRIAGED_SEVERITIES

    async def enrich(self, findings: list[Finding], ctx: RunContext) -> list[Finding]:
        """Attach advisories to the findings that qualify.

        Args:
            findings: Every normalized finding in the run.
            ctx: The current run context.

        Returns:
            The same findings in the same order, some with ``advisory`` populated.
            Never a different count, never a reordering — the enrichment contract
            checks both, and this method is written to satisfy it structurally by
            rebuilding the list by index.
        """
        if ctx.offline:
            # Defense in depth. Config validation already rejects offline+ai, and the
            # CLI checks again; reaching here would mean both were bypassed.
            logger.warning("advisors.triage.skipped", reason="offline")
            return findings

        advisor = self._advisor or self._build_advisor(ctx)
        if advisor is None:
            return findings

        candidates = select_findings(
            [f for f in findings if self.applies_to(f)],
            limit=ctx.config.ai.max_findings,
        )
        if not candidates:
            return findings

        concurrency = LOCAL_MAX_CONCURRENCY if advisor.provider.name == "local" else MAX_CONCURRENCY
        logger.info(
            "advisors.triage.started",
            candidates=len(candidates),
            provider=advisor.provider.name,
            eligible=sum(1 for f in findings if self.applies_to(f)),
            concurrency=concurrency,
            timeout_seconds=advisor.timeout_seconds,
        )
        if advisor.provider.name == "local":
            logger.info(
                "advisors.triage.local_provider_notice",
                detail=(
                    "local inference runs one finding at a time and can take minutes "
                    "per finding on CPU-bound hardware; this is expected, not a hang"
                ),
            )

        advisories = await self._analyze_all(candidates, findings, ctx, advisor)

        result = [
            finding.model_copy(update={"advisory": advisories[finding.id]})
            if finding.id in advisories
            else finding
            for finding in findings
        ]

        logger.info(
            "advisors.triage.completed",
            annotated=len(advisories),
            analyzed=advisor.budget.findings_analyzed,
            tokens=advisor.budget.tokens_used,
            truncated=advisor.budget.truncated,
            truncation_reason=advisor.budget.truncation_reason or None,
            **advisor.cache.stats(),
        )
        return result

    async def _analyze_all(
        self,
        candidates: list[Finding],
        all_findings: list[Finding],
        ctx: RunContext,
        advisor: LLMAdvisor,
    ) -> dict[str, Advisory]:
        """Analyze candidates concurrently, bounded by a semaphore.

        Args:
            candidates: Findings selected for analysis.
            all_findings: Every finding, passed to the redactor so a secret found in
                one place is scrubbed from another finding's context.
            ctx: The run context, for workspace paths and config.
            advisor: The configured advisor.

        Returns:
            A mapping of finding ID to advisory, containing only successes.
        """
        limit = LOCAL_MAX_CONCURRENCY if advisor.provider.name == "local" else MAX_CONCURRENCY
        semaphore = asyncio.Semaphore(limit)

        async def _one(finding: Finding) -> tuple[str, Advisory | None]:
            async with semaphore:
                return finding.id, await self._analyze(finding, all_findings, ctx, advisor)

        results = await asyncio.gather(*(_one(f) for f in candidates))
        return {fid: advisory for fid, advisory in results if advisory is not None}

    async def _analyze(
        self,
        finding: Finding,
        all_findings: list[Finding],
        ctx: RunContext,
        advisor: LLMAdvisor,
    ) -> Advisory | None:
        """Analyze one finding.

        Args:
            finding: The finding to assess.
            all_findings: Every finding, for redaction.
            ctx: The run context.
            advisor: The configured advisor.

        Returns:
            An advisory, or ``None`` when the call failed or the reply was invalid.
        """
        payload = build_context(finding, ctx)

        parsed = await advisor.complete(
            system=self._system,
            user=payload,
            findings=all_findings,
            prompt_version=self._prompt_version,
            enricher_version=self.version,
        )
        if parsed is None:
            return None

        try:
            result = TriageResult.model_validate(parsed)
        except ValidationError as exc:
            logger.warning(
                "advisors.triage.invalid_response",
                finding_id=finding.id,
                errors=exc.error_count(),
            )
            return None

        try:
            return Advisory(
                enricher=self.name,
                enricher_version=self.version,
                # `assessment` and `confidence` arrive as plain strings from the
                # model. Pydantic validates them against the Literal enums here, and
                # a fourth value raises rather than being coerced — which is what the
                # except branch below exists to catch.
                assessment=result.assessment,
                rationale=result.rationale,
                confidence=result.confidence,
                remediation=result.remediation,
                evidence_refs=result.evidence_refs,
                generated_at=datetime.now(UTC),
                provider=advisor.provider.name,
                model_id=advisor.model_id or None,
                prompt_version=self._prompt_version,
            )
        except ValidationError:
            # The enum values are the contract. A model that returns a fourth
            # assessment value gets its advisory dropped rather than coerced.
            logger.warning(
                "advisors.triage.invalid_enum",
                finding_id=finding.id,
                assessment=result.assessment,
                confidence=result.confidence,
            )
            return None

    def _build_advisor(self, ctx: RunContext) -> LLMAdvisor | None:
        """Construct an advisor from run configuration.

        Args:
            ctx: The run context.

        Returns:
            A configured advisor, or ``None`` when the provider is unusable. An
            unusable provider is logged and skipped, never fatal.
        """
        settings = ctx.config.ai
        try:
            provider = get_provider(settings.provider)
        except ProviderNotAvailableError as exc:
            logger.warning("advisors.triage.unavailable", error=exc.message)
            return None

        usable, reason = provider.available()
        if not usable:
            logger.warning("advisors.triage.unavailable", provider=provider.name, reason=reason)
            return None

        return LLMAdvisor(
            provider=provider,
            model_id=settings.model or "",
            budget=Budget(max_findings=settings.max_findings),
            cache=ResponseCache(ctx.config.output.directory),
            timeout_seconds=settings.timeout_seconds,
        )


def build_context(finding: Finding, ctx: RunContext) -> str:
    """Assemble the minimum context that supports a judgment.

    Deliberately bounded. The spec's rule is "the minimum that supports a judgment",
    and every extra line is both cost and exposure. The whole repository, `.env`
    files, and anything from a SECRET finding are never included — the last of these
    is enforced upstream by :meth:`LLMTriageEnricher.applies_to`, which does not
    select secrets at all.

    Args:
        finding: The finding to describe.
        ctx: The run context, supplying the workspace root and project profile.

    Returns:
        A plain-text block. Not yet redacted — redaction happens in
        :meth:`LLMAdvisor.complete`, which is the only place it is allowed to.
    """
    lines: list[str] = [
        "## Finding",
        f"Scanner: {finding.scanner.name} {finding.scanner.version}",
        f"Rule: {finding.rule_id}",
        f"Severity: {finding.severity.value}",
        f"Category: {finding.category.value}",
        f"Title: {finding.title}",
        f"Description: {finding.description}",
    ]

    if finding.cve_ids:
        lines.append(f"CVE identifiers: {', '.join(finding.cve_ids)}")
    if finding.cwe_ids:
        lines.append(f"CWE identifiers: {', '.join(finding.cwe_ids)}")

    if finding.package is not None:
        package = finding.package
        lines.extend(
            [
                "",
                "## Dependency",
                f"Package: {package.name}",
                f"Installed version: {package.version or 'unknown'}",
                f"Ecosystem: {package.ecosystem or 'unknown'}",
            ]
        )
        if finding.fixed_version:
            lines.append(f"Fixed in: {finding.fixed_version}")

    snippet = _read_snippet(finding, ctx.workspace)
    if snippet:
        lines.extend(["", "## Source context", snippet])
    elif finding.location is not None:
        lines.extend(
            ["", "## Source context", f"(source for {finding.location.path} was not readable)"]
        )

    if ctx.profile is not None:
        profile = ctx.profile
        managers = ", ".join(manager.value for manager in profile.package_managers)
        lines.extend(
            [
                "",
                "## Project profile",
                f"Languages: {', '.join(profile.language_names) or 'unknown'}",
                f"Package managers: {managers or 'unknown'}",
                # Whether this ships as a library or runs as an application changes
                # the exploitability answer for the same CVE, so it is worth the tokens.
                f"Distribution: {profile.distribution}",
            ]
        )

    return "\n".join(lines)


def _read_snippet(finding: Finding, workspace: Path) -> str:
    """Read a bounded excerpt around a finding's location.

    Args:
        finding: The finding whose location to read.
        workspace: Root of the checked-out target.

    Returns:
        A numbered excerpt, or an empty string when there is no readable location.
        A missing or unreadable file is not an error: the model is told the source
        was unavailable and answers ``unclear``.
    """
    location = finding.location
    if location is None or not location.path or location.start_line is None:
        return ""

    path = workspace / location.path
    try:
        if not path.is_file():
            return ""
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

    source = text.splitlines()
    if not source:
        return ""

    center = location.start_line
    start = max(1, center - CONTEXT_LINES)
    end = min(len(source), center + CONTEXT_LINES)

    width = len(str(end))
    return "\n".join(
        f"{number:>{width}} | {source[number - 1]}"
        + ("   <-- finding reported here" if number == center else "")
        for number in range(start, end + 1)
    )


__all__ = [
    "CONTEXT_LINES",
    "ENRICHER_NAME",
    "ENRICHER_VERSION",
    "LLMTriageEnricher",
    "TriageResult",
    "build_context",
]
