"""systemd journal: ``journalctl -o json`` exports and (optionally) binary journal files.

Binary journals are parsed only if the ``systemd`` Python bindings are installed
(``python3-systemd``); otherwise they are identified and reported with export
instructions rather than silently skipped.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import (
    ParseContext,
    ParsedEvent,
    Parser,
    Sample,
    UnsupportedArtifact,
    parse_error,
)
from sherlog.parsers.linux_messages import classify
from sherlog.parsers.registry import register

JOURNAL_MAGIC = b"LPKSHHRH"
EXPORT_HINT = (
    "Binary systemd journal. Install python3-systemd to parse it directly, or export it on a "
    "Linux host with `journalctl --file <journal> -o json > export.json` and add the export as "
    "evidence."
)


def _message(value: Any) -> str:
    """journald stores non-UTF-8 messages as arrays of byte values."""
    if isinstance(value, list):
        return bytes(v for v in value if isinstance(v, int) and 0 <= v < 256).decode(
            "utf-8", errors="replace"
        )
    return "" if value is None else str(value)


def entry_to_event(entry: dict[str, Any], raw: str, line_number: int | None) -> ParsedEvent:
    """Convert one journal entry (JSON field mapping) to a normalized event."""
    ts: datetime | None = None
    ts_raw = entry.get("__REALTIME_TIMESTAMP")
    tags = []
    try:
        ts = datetime.fromtimestamp(int(ts_raw) / 1_000_000, UTC) if ts_raw is not None else None
    except (TypeError, ValueError, OverflowError):
        tags.append("timestamp_invalid")
    program = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")
    if entry.get("_TRANSPORT") == "kernel":
        program = "kernel"
    c = classify(str(program) if program else None, _message(entry.get("MESSAGE")))
    if program:
        tags.append(f"program:{program}")
    if unit := entry.get("_SYSTEMD_UNIT"):
        tags.append(f"unit:{unit}")
    return ParsedEvent(
        event_type=c.event_type,
        raw=raw,
        line_number=line_number,
        timestamp_utc=ts,
        timestamp_raw=str(ts_raw) if ts_raw is not None else None,
        timezone_assumed=False,
        host=entry.get("_HOSTNAME"),
        actor=c.actor,
        src_ip=c.src_ip,
        dst_ip=c.dst_ip,
        target=c.target,
        command=c.command,
        tags=[*tags, *c.tags],
    )


@register
class JournaldJsonParser(Parser):
    name = "journald_json"
    artifact_type = "journald.json"
    description = "journalctl -o json export (one JSON object per line)"

    def can_parse(self, sample: Sample) -> float:
        lines = [line for line in sample.lines if line.strip()][:20]
        if sample.is_binary or not lines:
            return 0.0
        hits = 0
        for line in lines:
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and "__REALTIME_TIMESTAMP" in obj:
                hits += 1
        # The last sampled line may be truncated mid-object.
        return 0.97 if hits >= max(1, len(lines) - 1) else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        with open_evidence(path) as fh:
            for n, raw_bytes in enumerate(fh, 1):
                line = raw_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    yield parse_error(line, n, "invalid_json")
                    continue
                if not isinstance(entry, dict):
                    yield parse_error(line, n, "not_an_object")
                    continue
                yield entry_to_event(entry, line, n)


@register
class JournaldBinaryParser(Parser):
    name = "journald_binary"
    artifact_type = "journald.binary"
    description = "systemd binary journal (*.journal)"

    def can_parse(self, sample: Sample) -> float:
        return 1.0 if sample.head.startswith(JOURNAL_MAGIC) else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        try:
            from systemd import journal  # type: ignore[import-not-found]
        except ImportError as exc:
            raise UnsupportedArtifact(EXPORT_HINT) from exc
        # The bindings open the file themselves (read-only via sd_journal_open_files).
        # Keep the realtime stamp as integer microseconds (the default converter
        # returns a naive local datetime, which would be ambiguous).
        reader = journal.Reader(files=[str(path)], converters={"__REALTIME_TIMESTAMP": int})
        for n, entry in enumerate(reader, 1):
            fields = {k: v if isinstance(v, str | int) else str(v) for k, v in entry.items()}
            yield entry_to_event(fields, json.dumps(fields, sort_keys=True, default=str), n)
