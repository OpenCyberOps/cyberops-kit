"""The Phase 2 AI advisory layer.

**The AI layer annotates. It never grades.** See ``docs/adr/0004-ai-boundary.md``.
Nothing in this package may feed a value into ``compute_score()``, change a core
``Finding`` field, add or remove findings, or determine a CI exit code. Deleting
this directory must leave the test suite green.

Importing this package registers nothing. Registration is an explicit call to
:func:`register_enrichers`, made by ``cli.py`` only when the user asked for triage.
An import with a side effect would mean that merely importing ``cyberops_kit`` could
arm an outbound network path, which is exactly the property "off by default" is
supposed to guarantee.
"""

from __future__ import annotations

import structlog

from cyberops_kit.core.enrichment import ENRICHERS, register

logger = structlog.get_logger(__name__)


def register_enrichers() -> None:
    """Register the advisory enrichers with the core enrichment registry.

    Idempotent: calling it twice does not double-register, so a second call from a
    test or an embedding application cannot cause two inference passes.
    """
    from cyberops_kit.advisors.triage import ENRICHER_NAME, LLMTriageEnricher

    if any(enricher.name == ENRICHER_NAME for enricher in ENRICHERS):
        return

    register(LLMTriageEnricher())
    logger.debug("advisors.registered", enricher=ENRICHER_NAME)


__all__ = ["register_enrichers"]
