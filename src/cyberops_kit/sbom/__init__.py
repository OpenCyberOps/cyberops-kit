"""SBOM generation and analysis.

Generation is Syft's job (``scanners/syft.py``). This package parses what Syft
produced and derives the health metrics the ``sbom_health`` dimension scores.
"""

from cyberops_kit.sbom.analyze import analyze_sbom, parse_cyclonedx

__all__ = ["analyze_sbom", "parse_cyclonedx"]
