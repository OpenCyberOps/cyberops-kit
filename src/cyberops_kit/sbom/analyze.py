"""SBOM parsing and health analysis.

Reads the CycloneDX document Syft produced and derives three health signals:
resolution completeness, license clarity, and staleness.

Staleness is deliberately **not** measured here. Determining whether a component is
behind its latest release requires querying each ecosystem's registry, which is a
network call that ``--offline`` forbids and that would make the score depend on when
you ran it rather than on what you scanned. ``outdated_count`` is therefore left as
``None``, and the scoring model drops the freshness sub-metric and renormalizes
rather than assuming everything is current.
"""

from __future__ import annotations

import json
from typing import Any, Final

import structlog

from cyberops_kit.core.models import SBOMComponent, SBOMFormat, SBOMSummary

logger = structlog.get_logger(__name__)

_UNKNOWN_LICENSE_MARKERS: Final[frozenset[str]] = frozenset(
    {"", "unknown", "noassertion", "none", "not-declared"}
)
"""SPDX and CycloneDX both use placeholder strings where a license is undetermined."""


def parse_cyclonedx(document: str) -> list[SBOMComponent]:
    """Parse a CycloneDX JSON document into canonical components.

    Args:
        document: The serialized CycloneDX document.

    Returns:
        The cataloged components, sorted by purl then name so the resulting summary
        is stable across runs (INV-3). Empty when the document is unparseable.
    """
    try:
        payload = json.loads(document)
    except json.JSONDecodeError:
        logger.warning("sbom.parse_failed", format=SBOMFormat.CYCLONEDX_1_6.value)
        return []

    if not isinstance(payload, dict):
        return []

    components: list[SBOMComponent] = []
    for entry in payload.get("components") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        components.append(
            SBOMComponent(
                name=name,
                version=str(entry.get("version", "")).strip() or None,
                purl=str(entry.get("purl", "")).strip() or None,
                licenses=_licenses(entry),
            )
        )

    return sorted(components, key=lambda c: (c.purl or "", c.name, c.version or ""))


def analyze_sbom(documents: dict[str, str], *, component_count: int | None = None) -> SBOMSummary:
    """Derive SBOM health metrics from generated documents.

    Args:
        documents: Format name to serialized document, as returned by Syft.
        component_count: Component count reported by the scanner, used when the
            CycloneDX document is present but unparseable.

    Returns:
        The SBOM summary consumed by the ``sbom_health`` dimension.
    """
    if not documents:
        return SBOMSummary(generated=False)

    formats = sorted(
        (SBOMFormat(name) for name in documents if name in set(SBOMFormat)),
        key=lambda f: f.value,
    )

    cyclonedx = documents.get(SBOMFormat.CYCLONEDX_1_6.value)
    components = parse_cyclonedx(cyclonedx) if cyclonedx else []

    if not components:
        # Syft wrote something we could not parse. Record that the SBOM exists so the
        # "no SBOM" hard cap does not fire, but claim no health signal from it.
        return SBOMSummary(
            generated=True,
            component_count=int(component_count or 0),
            formats=formats,
        )

    unresolved = sum(1 for component in components if not component.version)
    license_unknown = sum(1 for component in components if not component.licenses)

    return SBOMSummary(
        generated=True,
        component_count=len(components),
        formats=formats,
        unresolved_count=unresolved,
        license_unknown_count=license_unknown,
        outdated_count=None,
    )


def _licenses(entry: dict[str, Any]) -> list[str]:
    """Extract license identifiers from a CycloneDX component.

    CycloneDX allows either an SPDX ``id`` or a free-text ``name`` per entry, and
    both appear in Syft output depending on how confident the catalog was.

    Args:
        entry: A CycloneDX component object.

    Returns:
        Sorted, deduplicated license identifiers, excluding placeholder values.
    """
    found: set[str] = set()
    for wrapper in entry.get("licenses") or []:
        if not isinstance(wrapper, dict):
            continue
        license_obj = wrapper.get("license")
        if isinstance(license_obj, dict):
            value = str(license_obj.get("id") or license_obj.get("name") or "").strip()
            if value and value.lower() not in _UNKNOWN_LICENSE_MARKERS:
                found.add(value)
        expression = wrapper.get("expression")
        if isinstance(expression, str) and expression.strip():
            found.add(expression.strip())
    return sorted(found)
