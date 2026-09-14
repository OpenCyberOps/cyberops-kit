"""The CLI surface for the advisory layer.

Three properties matter here and none are visible from the enricher's own tests:
the flag defaults to off, ``--offline`` hard-disables it with a non-zero exit, and
the enricher is registered only when the user actually asked for it.
"""

from __future__ import annotations

import pytest
import structlog
from typer.testing import CliRunner

from cyberops_kit.cli import app
from cyberops_kit.config import Settings, load_settings
from cyberops_kit.core.enrichment import ENRICHERS, clear_registry
from cyberops_kit.core.errors import ExitCode

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clean_registry():
    """Keep registry and logging state from leaking between tests.

    Invoking the CLI runs ``_configure_logging``, which binds structlog's
    ``PrintLogger`` to the ``CliRunner``'s captured stderr. That handle is closed
    when the runner returns, but structlog's configuration is global and still
    points at it — so the *next* test in the session that logs anything dies with
    "I/O operation on closed file", far from the test that caused it.

    Resetting to defaults afterwards keeps that failure contained here rather than
    surfacing as an unrelated test blowing up.
    """
    clear_registry()
    yield
    clear_registry()
    structlog.reset_defaults()


# --- Off by default --------------------------------------------------------------


def test_ai_is_disabled_in_the_default_configuration():
    """A user who never reads the AI docs never sends a byte anywhere."""
    assert Settings().ai.enabled is False


def test_the_default_config_registers_no_enricher():
    """Phase 1 behavior is the default behavior."""
    assert ENRICHERS == []


def test_ai_triage_is_not_implied_by_any_other_flag(tmp_path):
    """Only ``--ai-triage`` (or explicit config) turns it on."""
    settings = load_settings(search_from=tmp_path, overrides={"offline": None})
    assert settings.ai.enabled is False


# --- INV-6: offline is absolute --------------------------------------------------


def test_offline_with_ai_triage_exits_non_zero():
    """It does not warn and continue, and does not silently skip."""
    result = runner.invoke(app, ["scan", ".", "--offline", "--ai-triage"])

    assert result.exit_code == ExitCode.USAGE


def test_offline_with_ai_triage_names_both_flags():
    """The error tells the user which two flags collided, not just 'invalid config'."""
    result = runner.invoke(app, ["scan", ".", "--offline", "--ai-triage"])
    combined = f"{result.stdout}{result.stderr or ''}"

    assert "--offline" in combined
    assert "--ai-triage" in combined


def test_offline_with_ai_enabled_in_config_is_also_rejected(tmp_path):
    """The config path is guarded too, not only the flag path.

    A user who sets ``ai.enabled: true`` in ``.cyberops.yml`` and then runs with
    ``--offline`` must hit the same wall as one who passed both flags.
    """
    from cyberops_kit.core.errors import ConfigError

    config = tmp_path / ".cyberops.yml"
    config.write_text("ai:\n  enabled: true\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="INV-6"):
        load_settings(config_path=config, overrides={"offline": True})


def test_offline_alone_still_works(tmp_path):
    """Offline mode without AI is unaffected by any of this."""
    settings = load_settings(search_from=tmp_path, overrides={"offline": True})

    assert settings.offline is True
    assert settings.ai.enabled is False


# --- Registration ----------------------------------------------------------------


def test_register_enrichers_is_idempotent():
    """Two calls must not cause two inference passes over the same findings."""
    from cyberops_kit.advisors import register_enrichers

    register_enrichers()
    register_enrichers()

    assert len(ENRICHERS) == 1
    assert ENRICHERS[0].name == "llm-triage"


def test_the_registered_enricher_is_the_triage_one():
    """Registration wires up what the flag advertises."""
    from cyberops_kit.advisors import register_enrichers
    from cyberops_kit.advisors.triage import LLMTriageEnricher

    register_enrichers()

    assert isinstance(ENRICHERS[0], LLMTriageEnricher)


# --- Config plumbing -------------------------------------------------------------


def test_provider_and_model_flow_from_config(tmp_path):
    """``--ai-provider`` / ``--ai-model`` reach the settings the enricher reads."""
    settings = load_settings(
        search_from=tmp_path,
        overrides={"ai": {"enabled": True, "provider": "local", "model": "llama3.1:8b"}},
    )

    assert settings.ai.provider == "local"
    assert settings.ai.model == "llama3.1:8b"


def test_max_findings_has_a_conservative_default():
    """25 per the spec — a ceiling the user opts out of, not into."""
    assert Settings().ai.max_findings == 25


def test_ai_timeout_defaults_above_a_typical_api_timeout():
    """The local provider is a first-class citizen, not an afterthought.

    A CPU-bound mid-size model routinely needs more than the ~60s a hosted API
    call would. The default has to already assume that, rather than force every
    local-model user to discover it by timing out first.
    """
    assert Settings().ai.timeout_seconds >= 120.0


def test_ai_timeout_flows_from_the_cli_flag(tmp_path):
    """``--ai-timeout`` reaches the setting the advisor actually reads."""
    settings = load_settings(
        search_from=tmp_path, overrides={"ai": {"enabled": True, "timeout_seconds": 300.0}}
    )
    assert settings.ai.timeout_seconds == 300.0
