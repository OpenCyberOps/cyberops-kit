"""Content-addressed cache for provider responses.

Keyed on the hash of everything that could change the answer: the redacted payload,
the provider, the model, and the prompt version. Re-running a scan on an unchanged
commit therefore costs nothing, and a prompt edit or model change correctly misses
rather than serving a stale rationale under a new ``prompt_version``.

The key is derived from the **redacted** payload, so the cache directory never
contains a secret even if the cache outlives the run that wrote it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import structlog

logger = structlog.get_logger(__name__)

CACHE_DIRNAME: Final = "ai-cache"
_SCHEMA_VERSION: Final = 1


def cache_key(
    *, payload: str, provider: str, model_id: str, prompt_version: str, enricher_version: str
) -> str:
    """Derive a cache key from everything that affects the response.

    Args:
        payload: The redacted user payload.
        provider: Provider name.
        model_id: Model identifier.
        prompt_version: Version of the prompt file used.
        enricher_version: Version of the enricher, so a context-assembly change
            invalidates entries whose payload happens to be unchanged.

    Returns:
        A hex digest usable as a filename.
    """
    material = "\x00".join(
        [str(_SCHEMA_VERSION), provider, model_id, prompt_version, enricher_version, payload]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class ResponseCache:
    """A directory of JSON files, one per cached response.

    Deliberately not an LRU or a database. The working set is one run's findings,
    the entries are small, and a plain directory is inspectable by a user who wants
    to audit what was sent and what came back.
    """

    def __init__(self, directory: Path, *, enabled: bool = True) -> None:
        """Initialize the cache.

        Args:
            directory: Output directory for the run; entries live in a subdirectory.
            enabled: When False, every lookup misses and nothing is written.
        """
        self._directory = directory / CACHE_DIRNAME
        self._enabled = enabled
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> str | None:
        """Return a cached response body.

        Args:
            key: Key from :func:`cache_key`.

        Returns:
            The cached response text, or ``None`` on a miss.
        """
        if not self._enabled:
            return None

        path = self._path(key)
        if not path.is_file():
            self.misses += 1
            return None

        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # A corrupt entry is a miss, never an error. A cache must not be able to
            # break a run.
            logger.debug("advisors.cache.unreadable", key=key)
            self.misses += 1
            return None

        text = entry.get("response")
        if not isinstance(text, str):
            self.misses += 1
            return None

        self.hits += 1
        return text

    def put(self, key: str, response: str) -> None:
        """Store a response body.

        Args:
            key: Key from :func:`cache_key`.
            response: The provider's raw reply text.
        """
        if not self._enabled:
            return

        try:
            self._directory.mkdir(parents=True, exist_ok=True)
            self._path(key).write_text(
                json.dumps(
                    {
                        "schema": _SCHEMA_VERSION,
                        "cached_at": datetime.now(UTC).isoformat(),
                        "response": response,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            # An unwritable cache degrades cost, not correctness.
            logger.debug("advisors.cache.write_failed", key=key, error=str(exc))

    def stats(self) -> dict[str, Any]:
        """Return hit and miss counts for logging.

        Returns:
            A mapping with ``hits`` and ``misses``.
        """
        return {"hits": self.hits, "misses": self.misses}

    def _path(self, key: str) -> Path:
        """Return the file path for a key.

        Args:
            key: Cache key.

        Returns:
            Path to the entry.
        """
        return self._directory / f"{key}.json"


__all__ = ["CACHE_DIRNAME", "ResponseCache", "cache_key"]
