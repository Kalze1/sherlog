"""Syslog-format text logs: ``auth.log``/``secure`` and ``syslog``/``messages``.

Both artifact types share one line format, so one implementation serves two
registered parsers that differ only in how they score content: a file whose
lines come mostly from authentication programs is ``linux.auth``.

Supported timestamp formats:

* RFC 3164 (``Jan  2 03:04:05``): no year and no zone. The year is inferred
  from the file mtime, counting December->January rollovers; the case timezone
  is assumed. Such events carry ``timezone_assumed`` and the ``year_inferred`` tag.
* RFC 3339 / rsyslog high-precision (``2024-01-02T03:04:05.123456+03:00``), the
  default on Ubuntu 24.04+. Zone-less variants assume the case timezone.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from pathlib import Path

from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import ParseContext, ParsedEvent, Parser, Sample, parse_error
from sherlog.parsers.linux_messages import (
    AUTH_PROGRAMS,
    CRON_PROGRAMS,
    classify,
    normalize_program,
)
from sherlog.parsers.registry import register

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}

_RFC3164 = re.compile(
    r"^(?:<\d{1,3}>)?(?P<ts>(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}"
    r"(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2}))(?:\.\d+)? (?P<host>\S+) (?P<rest>.*)$"
)
_ISO = re.compile(
    r"^(?:<\d{1,3}>)?(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?P<zone>Z|[+-]\d{2}:?\d{2})?) (?P<host>\S+) (?P<rest>.*)$"
)
_PROGRAM = re.compile(r"^(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")


@dataclass
class _Header:
    ts_raw: str
    host: str
    program: str | None
    message: str
    month: int | None = None  # set for RFC 3164 (year missing)
    day: int = 0
    hms: str = ""
    iso_zone: bool = False


def split_header(line: str) -> _Header | None:
    if m := _RFC3164.match(line):
        header = _Header(
            m["ts"], m["host"], None, m["rest"], _MONTHS[m["mon"]], int(m["day"]), m["hms"]
        )
    elif m := _ISO.match(line):
        header = _Header(m["ts"], m["host"], None, m["rest"], iso_zone=bool(m["zone"]))
    else:
        return None
    if pm := _PROGRAM.match(header.message):
        header.program, header.message = pm["prog"], pm["msg"]
    return header


def _lines(path: Path) -> Iterator[tuple[int, str]]:
    with open_evidence(path) as fh:
        for n, raw in enumerate(fh, 1):
            yield n, raw.decode("utf-8", errors="replace").rstrip("\r\n")


def infer_start_year(months: list[int], reference: datetime) -> int:
    """Year of the first line, given the month of every RFC 3164 line in file order.

    ``reference`` (the file mtime in the case timezone) dates the *last* line: if
    the last month is later in the year than the reference month, the last line
    belongs to the previous year. Each backwards month jump is a year rollover.
    """
    rollovers = sum(1 for a, b in itertools.pairwise(months) if b < a)
    end_year = reference.year if months[-1] <= reference.month else reference.year - 1
    return end_year - rollovers


class YearTracker:
    """Assigns years to year-less timestamps read in file order (see :func:`infer_start_year`)."""

    def __init__(self, months: list[int], mtime: datetime | None, tz: tzinfo) -> None:
        reference = (mtime or datetime.now(UTC)).astimezone(tz)
        self.year = infer_start_year(months, reference) if months else reference.year
        self._prev: int | None = None

    def year_for(self, month: int) -> int:
        """Year of the next timestamp, given its month."""
        if self._prev is not None and month < self._prev:
            self.year += 1
        self._prev = month
        return self.year


def rfc3164_datetime(year: int, month: int, day: int, hms: str, tz: tzinfo) -> datetime | None:
    """Build a UTC datetime from year-less syslog parts; ``None`` if the date is impossible."""
    try:
        hh, mm, ss = map(int, hms.split(":"))
        return datetime(year, month, day, hh, mm, ss, tzinfo=tz).astimezone(UTC)
    except ValueError:  # e.g. Feb 29 in an inferred non-leap year
        return None


@dataclass
class HeaderStats:
    """Share of sampled lines with a syslog header, and program mix among those."""

    header_ratio: float = 0.0
    # Share of header lines naming a program ("sshd[1]:"). Near 1 for real syslog; near 0
    # for other "timestamp word ..." formats (dpkg.log, yum.log) that merely look similar.
    program_ratio: float = 0.0
    auth_ratio: float = 0.0
    cron_ratio: float = 0.0
    kernel_ratio: float = 0.0

    @property
    def specialised_ratio(self) -> float:
        return max(self.auth_ratio, self.cron_ratio, self.kernel_ratio)


def header_stats(sample: Sample) -> HeaderStats:
    """Compute :class:`HeaderStats` for a sample."""
    lines = [line for line in sample.lines if line.strip()]
    if sample.is_binary or not lines:
        return HeaderStats()
    headers = [h for h in map(split_header, lines) if h]
    if not headers:
        return HeaderStats()
    progs = [normalize_program(h.program) for h in headers]
    n = len(headers)
    auth = sum(
        1
        for p, h in zip(progs, headers, strict=True)
        if p in AUTH_PROGRAMS or "pam_unix(" in h.message
    )
    return HeaderStats(
        header_ratio=n / len(lines),
        program_ratio=sum(1 for h in headers if h.program) / n,
        auth_ratio=auth / n,
        cron_ratio=sum(1 for p in progs if p in CRON_PROGRAMS) / n,
        kernel_ratio=sum(1 for p in progs if p == "kernel") / n,
    )


def _specialised_score(stats: HeaderStats, ratio: float) -> float:
    """Score for a parser specialised in one family of programs making up ``ratio``."""
    if stats.header_ratio < 0.5 or ratio < 0.5:
        return 0.0
    return round(stats.header_ratio * (0.5 + 0.45 * ratio), 3)


class _SyslogBase(Parser):
    """Shared implementation for syslog-format parsers.

    All syslog-format parsers produce identical events; they differ only in the
    artifact type they report, so a borderline identification is harmless.
    """

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        months = [h.month for _, line in _lines(path) if (h := split_header(line)) and h.month]
        years = YearTracker(months, ctx.mtime, ctx.case_tz)

        for n, line in _lines(path):
            if not line.strip():
                continue
            header = split_header(line)
            if header is None:
                yield parse_error(line, n, "no_syslog_header")
                continue
            tags: list[str] = []
            if header.month is not None:
                year = years.year_for(header.month)
                ts = rfc3164_datetime(year, header.month, header.day, header.hms, ctx.case_tz)
                assumed = True
                tags.append("year_inferred")
            else:
                ts, assumed = self._iso_time(header.ts_raw, ctx.case_tz), not header.iso_zone
            if ts is None:
                tags.append("timestamp_invalid")
            c = classify(header.program, header.message)
            if header.program:
                tags.append(f"program:{header.program}")
            yield ParsedEvent(
                event_type=c.event_type,
                raw=line,
                line_number=n,
                timestamp_utc=ts,
                timestamp_raw=header.ts_raw,
                timezone_assumed=assumed,
                host=header.host,
                actor=c.actor,
                src_ip=c.src_ip,
                dst_ip=c.dst_ip,
                target=c.target,
                command=c.command,
                tags=[*tags, *c.tags],
            )

    @staticmethod
    def _iso_time(raw: str, tz: tzinfo) -> datetime | None:
        try:
            dt = datetime.fromisoformat(raw.replace(" ", "T", 1))
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz)
        return dt.astimezone(UTC)


@register
class LinuxAuthParser(_SyslogBase):
    name = "linux_auth"
    artifact_type = "linux.auth"
    description = "auth.log / secure: sshd, sudo, su, PAM, shadow-utils"

    def can_parse(self, sample: Sample) -> float:
        stats = header_stats(sample)
        return _specialised_score(stats, stats.auth_ratio)


@register
class CronLogParser(_SyslogBase):
    name = "linux_cron"
    artifact_type = "linux.cron"
    description = "cron log (e.g. RHEL /var/log/cron): CROND, crontab, anacron, run-parts"

    def can_parse(self, sample: Sample) -> float:
        stats = header_stats(sample)
        return _specialised_score(stats, stats.cron_ratio)


@register
class KernelLogParser(_SyslogBase):
    name = "linux_kernel"
    artifact_type = "linux.kernel"
    description = "kern.log: kernel messages in syslog format"

    def can_parse(self, sample: Sample) -> float:
        stats = header_stats(sample)
        return _specialised_score(stats, stats.kernel_ratio)


@register
class SyslogParser(_SyslogBase):
    name = "linux_syslog"
    artifact_type = "linux.syslog"
    description = "syslog / messages: general system log in syslog format"

    def can_parse(self, sample: Sample) -> float:
        stats = header_stats(sample)
        if stats.header_ratio < 0.5:
            return 0.0
        base = stats.header_ratio * (0.9 - 0.4 * stats.specialised_ratio)
        return round(base * (0.5 + 0.5 * stats.program_ratio), 3)
