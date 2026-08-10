"""Report rendering — JSON, SARIF, Markdown, HTML, and badge.

Every renderer receives findings that have already passed through
``core/redaction.py`` (INV-4), and every human-readable renderer includes the
dormant advisory block (SEAM-4) so Phase 2 needs no template changes.
"""

from cyberops_kit.report.writer import render, write_reports

__all__ = ["render", "write_reports"]
