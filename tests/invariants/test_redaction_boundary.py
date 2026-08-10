"""INV-4 — no secret leaves the process unredacted.

Every payload crossing a process boundary — logs, reports, artifacts, and in Phase 2
any LLM request — passes through ``core/redaction.py`` first. There is no exception
and no bypass flag.
"""

from __future__ import annotations

import json

import pytest

from cyberops_kit.config import AISettings
from cyberops_kit.core.models import Category, Severity
from cyberops_kit.core.redaction import PLACEHOLDER, Redactor, redact, redact_findings
from cyberops_kit.report.writer import redacted, render, write_reports
from tests.conftest import make_finding, make_report

# Synthetic, never-valid credentials, stored as fragments and joined at import time.
#
# The values must be *shaped* like real credentials — that is the entire point of
# these tests, since the redactor matches on structure. But a contiguous literal in
# the source is indistinguishable from a real leak to anything scanning this file:
# GitHub push protection blocks the push, and our own Gitleaks run flags it.
#
# Joining at runtime keeps the tests exactly as strong (the redactor receives the
# identical string it would receive from a real payload) while leaving no
# credential-shaped literal on disk. Any new fixture here should follow the pattern.
_SECRET_FRAGMENTS: dict[str, tuple[str, ...]] = {
    "aws": ("AKIA", "IOSFODNN", "7EXAMPLE"),
    "github": ("ghp", "_016C6bAbcdefghij", "klmnopqrstuvwxyz01"),
    "stripe": ("sk", "_live_", "4eC39HqLyjWDarjt", "T1zdp7dc"),
    "jwt": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ".eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        ".dBjftJeZ4CVP",
    ),
    "entropy": ("Zx9Kq2mBvT7n", "WpLr4sYhGd8F", "jCe3AuXoQi5RtNbMwVzP"),
}

SEEDED_SECRETS: dict[str, str] = {name: "".join(parts) for name, parts in _SECRET_FRAGMENTS.items()}


def secret_finding(secret: str):
    """Build a gitleaks-style secret finding carrying the literal value."""
    return make_finding(
        scanner="gitleaks",
        rule_id="generic-api-key",
        severity=Severity.CRITICAL,
        category=Category.SECRET,
        path="config/settings.py",
        raw={"Secret": secret, "Match": f"api_key = {secret}", "RuleID": "generic-api-key"},
    )


@pytest.mark.parametrize("secret", SEEDED_SECRETS.values(), ids=SEEDED_SECRETS.keys())
def test_seeded_secrets_never_survive_redaction(secret):
    """Each seeded credential format is removed from a text payload."""
    findings = [secret_finding(secret)]
    payload = f"the credential is {secret} and it must not appear"

    result = redact(payload, findings)

    assert secret not in result
    assert "REDACTED" in result


@pytest.mark.parametrize("secret", SEEDED_SECRETS.values(), ids=SEEDED_SECRETS.keys())
def test_pattern_layer_works_without_any_findings(secret):
    """Structural patterns catch credentials no scanner reported."""
    result = redact(f"export TOKEN={secret}", [])
    assert secret not in result


def test_secrets_are_stripped_from_nested_mappings():
    """Redaction recurses through nested payload structures."""
    secret = SEEDED_SECRETS["aws"]
    payload = {
        "outer": {"inner": [f"key={secret}", {"deep": secret}]},
        "safe": "nothing to see",
    }

    result = redact(payload, [secret_finding(secret)])

    assert secret not in json.dumps(result)
    assert result["safe"] == "nothing to see"


def test_secret_does_not_survive_into_any_report_format(tmp_path):
    """The end-to-end guarantee: no report artifact contains the secret."""
    secret = SEEDED_SECRETS["github"]
    report = make_report([secret_finding(secret)])

    written = write_reports(report, tmp_path, ["json", "sarif", "markdown", "html"])

    for fmt, path in written.items():
        content = path.read_text(encoding="utf-8")
        assert secret not in content, f"secret leaked into the {fmt} report (INV-4)"


def test_raw_scanner_payload_is_redacted_in_reports(tmp_path):
    """A secret hiding in ``Finding.raw`` is removed too.

    This is the realistic leak path: Gitleaks puts the credential in its own raw
    record by design, and raw is preserved verbatim for auditability.
    """
    secret = SEEDED_SECRETS["stripe"]
    report = make_report([secret_finding(secret)])

    safe = redacted(report)
    assert secret not in json.dumps(safe.results.findings[0].raw)
    assert secret not in render(safe, "json")


def test_redaction_preserves_finding_identity():
    """Redaction must not alter the fields that give a finding its identity.

    If redaction changed IDs, delta comparison would report every finding as new on
    every run.
    """
    secret = SEEDED_SECRETS["aws"]
    original = secret_finding(secret)
    [sanitized] = redact_findings([original])

    assert sanitized.id == original.id
    assert sanitized.rule_id == original.rule_id
    assert sanitized.severity is original.severity
    assert sanitized.category is original.category


def test_commit_shas_and_finding_ids_survive_redaction():
    """Redaction must not destroy the non-secret hex identifiers reports depend on.

    Hex tops out at 4.0 bits/char, below the 4.5 entropy threshold, which is what
    keeps commit SHAs and finding IDs readable.
    """
    commit = "3f786850e387550fdab836ed7e6dc881de23001b"
    finding_id = "a1b2c3d4e5f60718"
    text = f"commit {commit} finding {finding_id}"

    result = Redactor().redact_text(text)

    assert commit in result
    assert finding_id in result


def test_ai_redact_cannot_be_disabled():
    """``ai.redact: false`` is rejected by the config validator. No bypass exists."""
    with pytest.raises(ValueError, match="cannot be set to false"):
        AISettings(redact=False)


def test_no_bypass_flag_exists_in_the_redaction_module():
    """Static guard against a future "skip redaction" escape hatch.

    Walks identifiers in the AST rather than raw text, so the module can state that
    no bypass exists without the test tripping over its own documentation.
    """
    import ast
    from pathlib import Path

    import cyberops_kit.core.redaction as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))

    identifiers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.arg):
            identifiers.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            identifiers.add(node.name)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
        elif isinstance(node, ast.keyword) and node.arg:
            identifiers.add(node.arg)

    forbidden = ("bypass", "skip_redaction", "disable_redaction", "no_redact", "unredacted")
    offending = [
        name for name in identifiers if any(marker in name.lower() for marker in forbidden)
    ]

    assert not offending, f"a redaction bypass identifier appeared: {offending} (INV-4)"


def test_structlog_processor_redacts_log_events():
    """Log events are sanitized before emission."""
    from cyberops_kit.core.redaction import structlog_processor

    secret = SEEDED_SECRETS["github"]
    event = structlog_processor(None, "info", {"event": "boom", "token": secret})

    assert secret not in json.dumps(event)


def test_placeholder_is_recognizable():
    """The placeholder makes redaction visible rather than silently deleting text."""
    assert "REDACTED" in PLACEHOLDER
