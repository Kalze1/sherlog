"""Parse identified evidence into normalized events stored in the case database."""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import delete, func, insert, select

from sherlog.core import audit
from sherlog.core.case import CaseHandle
from sherlog.core.errors import SherlogError
from sherlog.core.models import Artifact, Event, EvidenceFile
from sherlog.core.vocab import EVENT_TYPES
from sherlog.identify.service import identify_case
from sherlog.parsers.base import ParseContext, ParsedEvent, UnsupportedArtifact
from sherlog.parsers.registry import by_artifact_type

log = logging.getLogger(__name__)

BATCH = 5000


def _row(ev: ParsedEvent, case_id: str, file_id: int, artifact_type: str) -> dict[str, Any]:
    event_type, tags = ev.event_type, ev.tags
    if event_type not in EVENT_TYPES:
        log.warning("parser emitted unknown event type %r; storing as 'other'", event_type)
        event_type, tags = "other", [*tags, f"unknown_event_type:{ev.event_type}"]
    return {
        "case_id": case_id,
        "timestamp_utc": ev.timestamp_utc,
        "timestamp_raw": ev.timestamp_raw,
        "timezone_assumed": ev.timezone_assumed,
        "host": ev.host,
        "source_file_id": file_id,
        "line_number": ev.line_number,
        "artifact_type": artifact_type,
        "event_type": event_type,
        "actor": ev.actor,
        "src_ip": ev.src_ip,
        "dst_ip": ev.dst_ip,
        "target": ev.target,
        "command": ev.command,
        "raw": ev.raw,
        "tags": tags,
        "extra": ev.extra,
    }


def parse_case(
    handle: CaseHandle, overrides: list[tuple[str, str]] | None = None, *, force: bool = False
) -> dict[str, Any]:
    """Identify and parse all evidence. Refuses to re-parse unless ``force`` is set."""
    with handle.session() as s:
        existing = s.scalar(select(func.count()).select_from(Event)) or 0
        if existing and not force:
            raise SherlogError(
                f"Case already has {existing} events; re-run with --force to discard and re-parse"
            )
        if existing:
            s.execute(delete(Event))
        case = handle.case(s)
        case_id, tz = case.id, ZoneInfo(case.timezone)

    identify_case(handle, overrides)
    results: list[dict[str, Any]] = []
    with handle.session() as s:
        rows = s.execute(
            select(Artifact, EvidenceFile)
            .join(EvidenceFile, Artifact.file_id == EvidenceFile.id)
            .where(Artifact.status == "identified")
            .order_by(EvidenceFile.id)
        ).all()
        for art, f in rows:
            parser = by_artifact_type(art.artifact_type)
            if parser is None:  # pragma: no cover - identification guarantees a parser
                continue
            ctx = ParseContext(path=Path(f.path), case_tz=tz, mtime=f.mtime)
            counts: Counter[str] = Counter()
            savepoint = s.begin_nested()
            try:
                batch: list[dict[str, Any]] = []
                for ev in parser.parse(Path(f.path), ctx):
                    batch.append(_row(ev, case_id, f.id, art.artifact_type))
                    counts[batch[-1]["event_type"]] += 1
                    if len(batch) >= BATCH:
                        s.execute(insert(Event), batch)
                        batch.clear()
                if batch:
                    s.execute(insert(Event), batch)
                savepoint.commit()
                art.status = "parsed"
                art.message = None
            except UnsupportedArtifact as exc:
                savepoint.rollback()
                art.status, art.message = "unsupported", str(exc)
                counts.clear()
            except Exception as exc:  # parser bug or unreadable file: record, keep going
                savepoint.rollback()
                log.exception("parser %s failed on %s", parser.name, f.rel_path)
                art.status, art.message = "error", f"{type(exc).__name__}: {exc}"
                counts.clear()
            art.event_count = sum(counts.values())
            art.parse_error_count = counts["parse_error"]
            results.append(
                {
                    "rel_path": f.rel_path,
                    "artifact_type": art.artifact_type,
                    "parser": f"{parser.name}@{parser.version}",
                    "status": art.status,
                    "events": art.event_count,
                    "parse_errors": art.parse_error_count,
                    "message": art.message,
                }
            )
        total = sum(r["events"] for r in results)
        audit.record(
            s,
            "evidence.parse",
            forced=force,
            discarded_events=existing,
            total_events=total,
            files={
                r["rel_path"]: {k: r[k] for k in ("parser", "status", "events")} for r in results
            },
        )
    return {"total_events": total, "discarded_events": existing, "files": results}
