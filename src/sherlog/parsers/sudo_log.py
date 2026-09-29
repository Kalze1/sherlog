"""sudo's own logfile (``Defaults logfile=/var/log/sudo.log``).

Format: ``Mmm dd hh:mm:ss[ yyyy] : user : TTY=... ; PWD=... ; USER=... ; COMMAND=...``.
There is no host field. sudo wraps long entries (``loglinelen``, default 80)
onto continuation lines indented with spaces; these are joined back together.
Without ``log_year`` the year is inferred as for syslog.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import ParseContext, ParsedEvent, Parser, Sample, parse_error
from sherlog.parsers.linux_messages import classify
from sherlog.parsers.registry import register
from sherlog.parsers.syslog import YearTracker, rfc3164_datetime

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}
_ENTRY = re.compile(
    r"^(?P<ts>(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2})"
    r"(?: (?P<year>\d{4}))?) : (?P<rest>\S+ : .*)$"
)


def _entries(path: Path) -> Iterator[tuple[int, str]]:
    """(first line number, joined entry) with continuation lines folded in."""
    current: tuple[int, str] | None = None
    with open_evidence(path) as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.startswith((" ", "\t")) and current:
                current = (current[0], f"{current[1]} {line.strip()}")
                continue
            if current:
                yield current
            current = (n, line) if line.strip() else None
    if current:
        yield current


@register
class SudoLogParser(Parser):
    name = "sudo_log"
    artifact_type = "sudo.log"
    description = "sudo logfile (Defaults logfile)"

    def can_parse(self, sample: Sample) -> float:
        lines = [line for line in sample.lines if line.strip() and not line[0].isspace()]
        if sample.is_binary or not lines:
            return 0.0
        hits = sum(1 for line in lines if (m := _ENTRY.match(line)) and m["mon"] in _MONTHS)
        return 0.95 if hits >= len(lines) * 0.8 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        months = [
            _MONTHS[m["mon"]]
            for _, e in _entries(path)
            if (m := _ENTRY.match(e)) and m["mon"] in _MONTHS and not m["year"]
        ]
        years = YearTracker(months, ctx.mtime, ctx.case_tz)
        for n, entry in _entries(path):
            m = _ENTRY.match(entry)
            if m is None or m["mon"] not in _MONTHS:
                yield parse_error(entry, n, "not_a_sudo_entry")
                continue
            month = _MONTHS[m["mon"]]
            tags = ["sudo_log"]
            if m["year"]:
                year = int(m["year"])
            else:
                year = years.year_for(month)
                tags.append("year_inferred")
            ts = rfc3164_datetime(year, month, int(m["day"]), m["hms"], ctx.case_tz)
            c = classify("sudo", m["rest"])
            yield ParsedEvent(
                event_type=c.event_type,
                raw=entry,
                line_number=n,
                timestamp_utc=ts,
                timestamp_raw=m["ts"],
                timezone_assumed=True,
                actor=c.actor,
                target=c.target,
                command=c.command,
                tags=[*tags, *c.tags] + ([] if ts else ["timestamp_invalid"]),
            )
