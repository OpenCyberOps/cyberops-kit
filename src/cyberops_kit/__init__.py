"""CyberOps Kit — reproducible, auditable security report cards.

The package orchestrates the OpenSSF tool ecosystem; it does not reimplement
scanning. See ``CONTRIBUTING.md`` for the invariants that govern every module
here, and ``docs/methodology/scoring.md`` for the published scoring model.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cyberops-kit")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
