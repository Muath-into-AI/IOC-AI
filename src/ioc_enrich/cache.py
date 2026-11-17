"""Optional local SQLite cache for source results, with a TTL."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path

from ioc_enrich.sources.base import SourceResult

DEFAULT_TTL = 24 * 60 * 60
DEFAULT_PATH = Path("~/.cache/ioc-enrich/cache.sqlite")


def default_path() -> Path:
    """Cache path from ``IOC_ENRICH_CACHE`` or ``~/.cache/ioc-enrich/cache.sqlite``."""
    return Path(os.environ.get("IOC_ENRICH_CACHE") or DEFAULT_PATH).expanduser()


class Cache:
    """Key/value cache of ``(source, ioc) -> SourceResult``.

    Entries older than ``ttl`` seconds are ignored and purged lazily.
    Use ``":memory:"`` as the path for an in-memory cache.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        ttl: int = DEFAULT_TTL,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ttl = ttl
        self._clock = clock
        target = default_path() if path is None else path
        if str(target) != ":memory:":
            Path(target).expanduser().parent.mkdir(parents=True, exist_ok=True)
            target = Path(target).expanduser()
        self._db = sqlite3.connect(str(target))
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS results ("
            " source TEXT NOT NULL, ioc TEXT NOT NULL, payload TEXT NOT NULL,"
            " created REAL NOT NULL, PRIMARY KEY (source, ioc))"
        )
        self._db.commit()

    def get(self, source: str, ioc: str) -> SourceResult | None:
        """Return a cached result, or ``None`` if missing or expired."""
        row = self._db.execute(
            "SELECT payload, created FROM results WHERE source = ? AND ioc = ?",
            (source, ioc),
        ).fetchone()
        if row is None:
            return None
        payload, created = row
        if self._clock() - created > self.ttl:
            self._db.execute("DELETE FROM results WHERE source = ? AND ioc = ?", (source, ioc))
            self._db.commit()
            return None
        return SourceResult.from_dict(json.loads(payload))

    def set(self, source: str, ioc: str, result: SourceResult) -> None:
        """Store ``result``."""
        self._db.execute(
            "INSERT OR REPLACE INTO results (source, ioc, payload, created) VALUES (?, ?, ?, ?)",
            (source, ioc, json.dumps(result.to_dict()), self._clock()),
        )
        self._db.commit()

    def purge_expired(self) -> int:
        """Delete expired entries; return how many were removed."""
        cur = self._db.execute("DELETE FROM results WHERE created < ?", (self._clock() - self.ttl,))
        self._db.commit()
        return cur.rowcount

    def close(self) -> None:
        """Close the database."""
        self._db.close()
