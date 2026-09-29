"""Kernel ring buffer dumps (``dmesg`` output).

Plain ``dmesg`` prefixes seconds since boot (``[   12.345678]``), which cannot be
placed on the timeline without the boot time; such events keep the uptime in
``extra`` and have no timestamp. ``dmesg -T`` output (``[Tue May  1 10:00:00 2024]``)
is dated in the case timezone. ``kern.log`` (syslog format) is handled by the
syslog parsers.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import ParseContext, ParsedEvent, Parser, Sample, parse_error
from sherlog.parsers.linux_messages import classify
from sherlog.parsers.registry import register

_UPTIME = re.compile(r"^(?:<\d>)?\[\s*(?P<uptime>\d+\.\d+)\] ?(?P<msg>.*)$")
_HUMAN = re.compile(
    r"^\[(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\] ?(?P<msg>.*)$"
)


@register
class DmesgParser(Parser):
    name = "dmesg"
    artifact_type = "linux.dmesg"
    description = "dmesg output (uptime or -T human timestamps)"

    def can_parse(self, sample: Sample) -> float:
        lines = [line for line in sample.lines if line.strip()]
        if sample.is_binary or not lines:
            return 0.0
        hits = sum(1 for line in lines if _UPTIME.match(line) or _HUMAN.match(line))
        return 0.9 if hits >= len(lines) * 0.8 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        with open_evidence(path) as fh:
            for n, raw in enumerate(fh, 1):
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line.strip():
                    continue
                ts: datetime | None = None
                extra: dict[str, float] | None = None
                if m := _UPTIME.match(line):
                    ts_raw, msg = m["uptime"], m["msg"]
                    extra = {"uptime_seconds": float(m["uptime"])}
                    assumed = False
                elif m := _HUMAN.match(line):
                    ts_raw, msg = m["ts"], m["msg"]
                    ts = (
                        datetime.strptime(" ".join(m["ts"].split()), "%a %b %d %H:%M:%S %Y")
                        .replace(tzinfo=ctx.case_tz)
                        .astimezone(UTC)
                    )
                    assumed = True
                else:
                    yield parse_error(line, n, "not_a_dmesg_line")
                    continue
                c = classify("kernel", msg)
                yield ParsedEvent(
                    event_type=c.event_type,
                    raw=line,
                    line_number=n,
                    timestamp_utc=ts,
                    timestamp_raw=ts_raw,
                    timezone_assumed=assumed,
                    src_ip=c.src_ip,
                    dst_ip=c.dst_ip,
                    target=c.target,
                    tags=[*c.tags, *([] if ts else ["uptime_only"])],
                    extra=extra,
                )
