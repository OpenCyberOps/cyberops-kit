"""Historical result storage, keyed by commit SHA.

Local filesystem only. There is no hosted backend and no phone-home, and there never
will be. See ``docs/adr/0002-no-telemetry.md``.
"""

from cyberops_kit.storage.history import History, compare

__all__ = ["History", "compare"]
