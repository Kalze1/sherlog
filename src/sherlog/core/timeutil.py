"""Time helpers. SherLog stores every timestamp as timezone-aware UTC."""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.now(UTC)


def from_epoch_ns(ns: int) -> datetime:
    """Convert a nanosecond POSIX timestamp (as in ``os.stat_result.st_mtime_ns``) to UTC."""
    return datetime.fromtimestamp(ns / 1_000_000_000, UTC)


def iso(dt: datetime | None) -> str | None:
    """Format an aware datetime as ISO 8601 in UTC, or pass ``None`` through."""
    if dt is None:
        return None
    return dt.astimezone(UTC).isoformat()
