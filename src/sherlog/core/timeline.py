"""Query the normalized event timeline."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import joinedload

from sherlog.core.case import CaseHandle
from sherlog.core.errors import SherlogError
from sherlog.core.models import Event
from sherlog.core.timeutil import iso


def parse_time(value: str) -> datetime:
    """Parse an ISO 8601 date/time; values without an offset are taken as UTC."""
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SherlogError(f"Invalid time {value!r}; use ISO 8601, e.g. 2024-03-01T12:00") from exc
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


@dataclass
class TimelineQuery:
    """Filters for :func:`query_events`. Empty filters match everything."""

    start: datetime | None = None
    end: datetime | None = None
    grep: str | None = None  # case-insensitive regex on the raw line
    types: list[str] = field(default_factory=list)  # exact or prefix ("auth.login")
    artifact: str | None = None
    actor: str | None = None
    ip: str | None = None  # src or dst
    host: str | None = None
    ids: list[int] | None = None  # restrict to these event ids
    limit: int | None = 200
    offset: int = 0


def _apply(q: TimelineQuery, stmt: Select[Any]) -> Select[Any]:
    if q.start:
        stmt = stmt.where(Event.timestamp_utc >= q.start)
    if q.end:
        stmt = stmt.where(Event.timestamp_utc <= q.end)
    if q.types:
        stmt = stmt.where(
            or_(
                *[or_(Event.event_type == t, Event.event_type.startswith(f"{t}.")) for t in q.types]
            )
        )
    if q.artifact:
        stmt = stmt.where(Event.artifact_type == q.artifact)
    if q.actor:
        stmt = stmt.where(Event.actor == q.actor)
    if q.ip:
        stmt = stmt.where(or_(Event.src_ip == q.ip, Event.dst_ip == q.ip))
    if q.host:
        stmt = stmt.where(Event.host == q.host)
    if q.ids is not None:
        stmt = stmt.where(Event.id.in_(q.ids))
    if q.grep:
        try:
            re.compile(q.grep)
        except re.error as exc:
            raise SherlogError(f"Invalid --grep regex {q.grep!r}: {exc}") from exc
        stmt = stmt.where(Event.raw.regexp_match(f"(?i){q.grep}"))
    return stmt


def event_to_dict(e: Event) -> dict[str, Any]:
    """Serialize an event, including a reference to its source file and hash."""
    return {
        "id": e.id,
        "timestamp_utc": iso(e.timestamp_utc),
        "timestamp_raw": e.timestamp_raw,
        "timezone_assumed": e.timezone_assumed,
        "host": e.host,
        "artifact_type": e.artifact_type,
        "event_type": e.event_type,
        "actor": e.actor,
        "src_ip": e.src_ip,
        "dst_ip": e.dst_ip,
        "target": e.target,
        "command": e.command,
        "raw": e.raw,
        "tags": e.tags,
        "extra": e.extra,
        "source": {
            "rel_path": e.source_file.rel_path,
            "path": e.source_file.path,
            "sha256": e.source_file.sha256,
            "line_number": e.line_number,
        },
    }


def query_events(handle: CaseHandle, q: TimelineQuery) -> tuple[list[dict[str, Any]], int]:
    """Matching events in time order (undated events last) and the total match count."""
    with handle.session() as s:
        total = s.scalar(_apply(q, select(func.count()).select_from(Event))) or 0
        stmt = _apply(q, select(Event).options(joinedload(Event.source_file)))
        stmt = stmt.order_by(Event.timestamp_utc.is_(None), Event.timestamp_utc, Event.id)
        if q.limit:
            stmt = stmt.limit(q.limit)
        if q.offset:
            stmt = stmt.offset(q.offset)
        return [event_to_dict(e) for e in s.scalars(stmt)], total
