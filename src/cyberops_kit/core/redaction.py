"""Redaction boundary — the single chokepoint every outbound payload passes through.

Enforces INV-4: no secret leaves the process unredacted. Logs, reports, artifacts,
and (in Phase 2) every LLM request route through :func:`redact` first. There is no
bypass flag, and none may be added.

Three layers of defense, applied in order:

1. **Literal values** recovered from ``SECRET`` findings. If Gitleaks found it, we
   know the exact bytes and can remove them precisely.
2. **Pattern matches** for credential formats with recognizable structure — AWS
   keys, GitHub tokens, private key blocks, JWTs, connection strings.
3. **Entropy** for the long tail of secrets that match no known format.

The entropy layer deliberately ignores pure-hex strings. Hex tops out at 4.0
bits/char, below the 4.5 threshold, which is what keeps commit SHAs, finding IDs,
and file digests — all non-secret and all essential to a readable report — intact.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from typing import Any, Final

from pydantic import BaseModel, ConfigDict

from cyberops_kit.core.models import Category, Finding

PLACEHOLDER: Final = "[REDACTED]"
"""Substituted for any value that must not cross a process boundary."""

MIN_LITERAL_LENGTH: Final = 4
"""Shorter literals are too generic to remove without destroying the payload."""

DEFAULT_ENTROPY_THRESHOLD: Final = 4.5
"""Shannon bits per character. Above hex's 4.0 ceiling by construction."""

DEFAULT_MIN_ENTROPY_LENGTH: Final = 20


class SecretPattern(BaseModel):
    """A named credential format recognizable by structure alone."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    name: str
    pattern: re.Pattern[str]
    description: str


def _compile(name: str, pattern: str, description: str) -> SecretPattern:
    """Build a :class:`SecretPattern` with a compiled regex.

    Args:
        name: Short identifier used in the redaction placeholder.
        pattern: Regular expression matching the credential format.
        description: What the pattern detects.

    Returns:
        The compiled pattern.
    """
    return SecretPattern(name=name, pattern=re.compile(pattern), description=description)


DEFAULT_PATTERNS: Final[tuple[SecretPattern, ...]] = (
    _compile(
        "private-key",
        r"-----BEGIN[ A-Z]*PRIVATE KEY-----.*?-----END[ A-Z]*PRIVATE KEY-----",
        "PEM-encoded private key block",
    ),
    _compile("aws-access-key", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", "AWS access key ID"),
    _compile(
        "aws-secret-key",
        r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
        "AWS secret access key assignment",
    ),
    _compile(
        "github-token",
        r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,}\b",
        "GitHub personal access or app token",
    ),
    _compile("slack-token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b", "Slack API token"),
    _compile("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API key"),
    _compile("stripe-key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b", "Stripe secret key"),
    _compile("openai-key", r"\bsk-[A-Za-z0-9_\-]{20,}\b", "OpenAI-style API key"),
    _compile("anthropic-key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", "Anthropic API key"),
    _compile(
        "jwt",
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        "JSON Web Token",
    ),
    _compile(
        "connection-string",
        r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s/@]+)@",
        "Credential embedded in a URI",
    ),
    _compile(
        "generic-assignment",
        r"(?i)\b(?:password|passwd|secret|token|api_?key|access_?key|auth)\s*"
        r"[:=]\s*[\"']([^\"'\s]{8,})[\"']",
        "Secret-looking assignment to a named credential field",
    ),
)

_TOKEN_RE: Final = re.compile(rf"[A-Za-z0-9+/=_\-]{{{DEFAULT_MIN_ENTROPY_LENGTH},}}")
_HEX_RE: Final = re.compile(r"\A[0-9a-fA-F]+\Z")
_DIGITS_RE: Final = re.compile(r"\A[0-9]+\Z")

_SECRET_RAW_KEYS: Final[tuple[str, ...]] = (
    "secret",
    "match",
    "raw_secret",
    "rawsecret",
    "value",
    "line",
)
"""Keys in a scanner's raw record that may hold the literal secret text."""


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string in bits per character.

    Args:
        text: String to measure.

    Returns:
        Bits per character, or ``0.0`` for the empty string.
    """
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def secret_literals(findings: Iterable[Finding]) -> list[str]:
    """Extract literal secret values from ``SECRET`` findings.

    A scanner that found a credential also tells us its exact text. Removing that
    text by value is more reliable than any pattern.

    Args:
        findings: Findings to inspect. Non-secret categories are ignored.

    Returns:
        Distinct literal values, longest first so that redacting one never leaves a
        substring of another behind.
    """
    literals: set[str] = set()
    for finding in findings:
        if finding.category is not Category.SECRET:
            continue
        for key, value in finding.raw.items():
            if key.lower() not in _SECRET_RAW_KEYS:
                continue
            if isinstance(value, str) and len(value.strip()) >= MIN_LITERAL_LENGTH:
                literals.add(value.strip())
    return sorted(literals, key=len, reverse=True)


class Redactor:
    """Applies the three redaction layers to strings and nested structures.

    Reusable across many payloads in a run, so the literal set and compiled patterns
    are built once.
    """

    def __init__(
        self,
        *,
        findings: Sequence[Finding] = (),
        extra_literals: Sequence[str] = (),
        patterns: Sequence[SecretPattern] = DEFAULT_PATTERNS,
        entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
        min_entropy_length: int = DEFAULT_MIN_ENTROPY_LENGTH,
        use_entropy: bool = True,
    ) -> None:
        """Initialize a redactor.

        Args:
            findings: Findings whose ``SECRET`` entries supply literal values.
            extra_literals: Additional exact strings to remove, e.g. a token read
                from the environment.
            patterns: Credential formats to match structurally.
            entropy_threshold: Bits per character above which a token is treated as
                a secret.
            min_entropy_length: Shortest token considered by the entropy layer.
            use_entropy: Disable only where a caller has proven the payload cannot
                contain unstructured secrets.
        """
        candidates = [*secret_literals(findings), *(s.strip() for s in extra_literals if s)]
        self._literals = sorted(
            {lit for lit in candidates if len(lit) >= MIN_LITERAL_LENGTH},
            key=len,
            reverse=True,
        )
        self._patterns = tuple(patterns)
        self._entropy_threshold = entropy_threshold
        self._min_entropy_length = min_entropy_length
        self._use_entropy = use_entropy
        self.redaction_count = 0

    def redact_text(self, text: str) -> str:
        """Redact a single string.

        Args:
            text: Text that is about to cross a process boundary.

        Returns:
            The text with every detected secret replaced by a placeholder.
        """
        if not text:
            return text

        result = text
        for literal in self._literals:
            if literal in result:
                result = result.replace(literal, PLACEHOLDER)
                self.redaction_count += 1

        for spec in self._patterns:
            result, count = self._apply_pattern(spec, result)
            self.redaction_count += count

        if self._use_entropy:
            result = self._apply_entropy(result)

        return result

    def _apply_pattern(self, spec: SecretPattern, text: str) -> tuple[str, int]:
        """Replace matches of one pattern.

        When the pattern captures a group, only the captured credential is removed
        so the surrounding context stays readable — ``password=[REDACTED:...]`` is
        far more useful in a report than a wholly erased line.

        Args:
            spec: The pattern to apply.
            text: Text to scan.

        Returns:
            The redacted text and the number of replacements made.
        """
        placeholder = f"[REDACTED:{spec.name}]"
        count = 0

        def _replace(match: re.Match[str]) -> str:
            nonlocal count
            count += 1
            if match.groups() and match.group(1):
                start, end = match.span(1)
                return (
                    match.group(0)[: start - match.start()]
                    + placeholder
                    + match.group(0)[end - match.start() :]
                )
            return placeholder

        return spec.pattern.sub(_replace, text, count=0), count

    def _apply_entropy(self, text: str) -> str:
        """Redact high-entropy tokens that matched no known credential format.

        Args:
            text: Text to scan.

        Returns:
            The text with high-entropy tokens replaced.
        """

        def _replace(match: re.Match[str]) -> str:
            token = match.group(0)
            if self._is_high_entropy(token):
                self.redaction_count += 1
                return "[REDACTED:high-entropy]"
            return token

        return _TOKEN_RE.sub(_replace, text)

    def _is_high_entropy(self, token: str) -> bool:
        """Decide whether a token looks like an unstructured secret.

        Args:
            token: Candidate token.

        Returns:
            True when the token should be redacted.
        """
        if len(token) < self._min_entropy_length:
            return False
        # Hex and decimal digests top out below the threshold anyway; skipping them
        # explicitly documents that commit SHAs and finding IDs are intentionally
        # preserved.
        if _HEX_RE.match(token) or _DIGITS_RE.match(token):
            return False
        if token.startswith("[REDACTED"):
            return False
        return shannon_entropy(token) >= self._entropy_threshold

    def redact_value(self, value: Any) -> Any:
        """Recursively redact any JSON-compatible value.

        Args:
            value: String, mapping, sequence, or scalar.

        Returns:
            The same structure with all strings redacted. Mapping key order is
            preserved so redaction never perturbs deterministic output (INV-3).
        """
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, Mapping):
            return {key: self.redact_value(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            redacted = [self.redact_value(item) for item in value]
            return tuple(redacted) if isinstance(value, tuple) else redacted
        return value

    def redact_finding(self, finding: Finding) -> Finding:
        """Redact the free-text and raw fields of a finding.

        Identity fields — ``id``, ``rule_id``, ``severity``, ``category`` — are left
        alone. They are structural, never secret-bearing, and redacting them would
        break delta comparison across runs.

        Args:
            finding: Finding to sanitize.

        Returns:
            A new finding safe to write to a report.
        """
        return finding.model_copy(
            update={
                "title": self.redact_text(finding.title),
                "description": self.redact_text(finding.description),
                "raw": self.redact_value(finding.raw),
            }
        )


def redact(payload: str | dict[str, Any], findings: Sequence[Finding] = ()) -> str | dict[str, Any]:
    """Strip detected secrets and high-entropy strings from any outbound payload.

    The SEAM-5 entrypoint. Phase 2's LLM client is required to route every request
    through this same function, which makes the guarantee that no secret reaches a
    third party structural rather than a promise.

    Args:
        payload: The string or mapping about to cross a process boundary.
        findings: Findings from this run, supplying exact secret values to remove.

    Returns:
        The redacted payload, of the same type as the input.
    """
    redactor = Redactor(findings=findings)
    if isinstance(payload, str):
        return redactor.redact_text(payload)
    result: dict[str, Any] = redactor.redact_value(payload)
    return result


def redact_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Redact a full set of findings before they are written or displayed.

    Secrets appear in their own findings' ``raw`` blocks by construction, so this is
    applied to every report artifact.

    Args:
        findings: Findings to sanitize.

    Returns:
        New findings with text and raw fields redacted, in the input order.
    """
    redactor = Redactor(findings=findings)
    return [redactor.redact_finding(finding) for finding in findings]


def structlog_processor(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Redact every log event before it is emitted.

    Wired into the structlog pipeline by ``cli.py`` so that INV-4 covers logs
    without each call site having to remember.

    Args:
        _logger: Unused, required by the structlog processor protocol.
        _method: Unused, required by the structlog processor protocol.
        event_dict: The event being logged.

    Returns:
        The event with all string values redacted.
    """
    redactor = Redactor()
    return {key: redactor.redact_value(value) for key, value in event_dict.items()}
