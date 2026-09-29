"""Shared on-disk cache of enrichment lookups and a per-provider rate limiter.

The cache is one SQLite file (``~/.cache/sherlog/enrichment.db``) shared by
all cases, so repeated investigations do not spend API quota twice. It also
records every live API call, which is how daily limits are enforced across runs.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sherlog.core.config import default_cache_dir
from sherlog.core.errors import SherlogError

DAY = 86400.0


class QuotaExhausted(SherlogError):
    """A provider's daily request limit has been reached."""


@dataclass(frozen=True)
class CachedResponse:
    status: int
    body: Any
    fetched_at: float


class EnrichmentCache:
    """SQLite-backed response cache and API call log."""

    def __init__(self, path: Path | None = None, clock: Callable[[], float] = time.time) -> None:
        self.path = path or default_cache_dir() / "enrichment.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self._db = sqlite3.connect(self.path)
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS responses (
                provider TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
                status INTEGER NOT NULL, body TEXT, fetched_at REAL NOT NULL,
                PRIMARY KEY (provider, kind, value)
            );
            CREATE TABLE IF NOT EXISTS calls (provider TEXT NOT NULL, ts REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS calls_provider_ts ON calls (provider, ts);
            """
        )

    def close(self) -> None:
        self._db.close()

    def get(
        self, provider: str, kind: str, value: str, ttl_seconds: float
    ) -> CachedResponse | None:
        row = self._db.execute(
            "SELECT status, body, fetched_at FROM responses "
            "WHERE provider=? AND kind=? AND value=?",
            (provider, kind, value),
        ).fetchone()
        if row is None or self.clock() - row[2] > ttl_seconds:
            return None
        return CachedResponse(row[0], json.loads(row[1]) if row[1] else None, row[2])

    def put(self, provider: str, kind: str, value: str, status: int, body: Any) -> float:
        now = self.clock()
        self._db.execute(
            "INSERT OR REPLACE INTO responses VALUES (?, ?, ?, ?, ?, ?)",
            (provider, kind, value, status, json.dumps(body) if body is not None else None, now),
        )
        self._db.commit()
        return now

    def record_call(self, provider: str) -> None:
        self._db.execute("INSERT INTO calls VALUES (?, ?)", (provider, self.clock()))
        self._db.execute("DELETE FROM calls WHERE ts < ?", (self.clock() - 2 * DAY,))
        self._db.commit()

    def calls_since(self, provider: str, since: float) -> int:
        row = self._db.execute(
            "SELECT COUNT(*) FROM calls WHERE provider=? AND ts>=?", (provider, since)
        ).fetchone()
        return int(row[0])

    def last_call(self, provider: str) -> float | None:
        row = self._db.execute("SELECT MAX(ts) FROM calls WHERE provider=?", (provider,)).fetchone()
        return float(row[0]) if row and row[0] is not None else None


class RateLimiter:
    """Minimum spacing between calls plus a rolling 24-hour cap, persisted in the cache."""

    def __init__(
        self,
        provider: str,
        cache: EnrichmentCache,
        *,
        min_interval: float,
        daily_limit: int,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.provider = provider
        self.cache = cache
        self.min_interval = min_interval
        self.daily_limit = daily_limit
        self.sleep = sleep

    def remaining_today(self) -> int:
        used = self.cache.calls_since(self.provider, self.cache.clock() - DAY)
        return max(0, self.daily_limit - used)

    def acquire(self) -> None:
        """Wait until a call is allowed and record it; raise QuotaExhausted at the daily cap."""
        if self.remaining_today() <= 0:
            raise QuotaExhausted(f"{self.provider}: daily limit of {self.daily_limit} reached")
        last = self.cache.last_call(self.provider)
        if last is not None:
            wait = last + self.min_interval - self.cache.clock()
            if wait > 0:
                self.sleep(wait)
        self.cache.record_call(self.provider)
