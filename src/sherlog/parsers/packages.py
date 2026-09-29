"""Package manager logs: dpkg.log, apt history.log, yum.log and dnf.rpm.log.

Timestamps in these logs carry no zone and are taken in the case timezone,
except dnf.rpm.log which records an offset. yum.log omits the year, which is
inferred as for syslog. apt history.log is block-structured; each block yields
one event per action (Install/Upgrade/Remove/Purge) with the invoking command
line and requesting user.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import ParseContext, ParsedEvent, Parser, Sample, parse_error
from sherlog.parsers.registry import register
from sherlog.parsers.syslog import YearTracker, rfc3164_datetime

_DPKG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<action>\S+)(?: (?P<rest>.*))?$"
)
_DPKG_ACTIONS = {
    "install": "package.install",
    "upgrade": "package.upgrade",
    "remove": "package.remove",
    "purge": "package.remove",
}
_YUM = re.compile(
    r"^(?P<ts>(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2})) "
    r"(?P<action>Installed|Updated|Erased|Dep-Installed|Obsoleted): (?P<pkg>\S+)"
)
_YUM_ACTIONS = {
    "Installed": "package.install",
    "Dep-Installed": "package.install",
    "Updated": "package.upgrade",
    "Erased": "package.remove",
    "Obsoleted": "package.remove",
}
_DNF = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{4}|Z)) (?P<level>[A-Z]+) "
    r"(?P<action>[A-Z][a-z]+): (?P<pkg>\S+)"
)
# Completed actions only; in-progress markers (Upgrade, Reinstall, ...) map to "other"
# so one transaction step is not counted twice.
_DNF_ACTIONS = {
    "Installed": "package.install",
    "Reinstalled": "package.install",
    "Upgraded": "package.upgrade",
    "Downgraded": "package.upgrade",
    "Erase": "package.remove",
    "Removed": "package.remove",
    "Obsoleted": "package.remove",
}
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}


def _dpkg_package(action: str, tokens: list[str]) -> tuple[str | None, str | None]:
    """(package, version) from the tokens after a dpkg.log action."""
    if action == "status" and len(tokens) >= 3:  # status <state> <pkg> <version>
        return tokens[1], tokens[2]
    if action in ("install", "upgrade") and len(tokens) >= 3:  # <pkg> <old> <new>
        return tokens[0], tokens[2]
    if action in ("remove", "purge", "configure", "trigproc") and len(tokens) >= 2:
        return tokens[0], tokens[1]  # <pkg> <version> ...
    return None, None


def _lines(path: Path) -> Iterator[tuple[int, str]]:
    with open_evidence(path) as fh:
        for n, raw in enumerate(fh, 1):
            yield n, raw.decode("utf-8", errors="replace").rstrip("\r\n")


def _ratio(sample: Sample, pattern: re.Pattern[str]) -> float:
    lines = [line for line in sample.lines if line.strip()]
    if sample.is_binary or not lines:
        return 0.0
    return sum(1 for line in lines if pattern.match(line)) / len(lines)


def _local(value: str, fmt: str, ctx: ParseContext) -> datetime | None:
    try:
        return datetime.strptime(value, fmt).replace(tzinfo=ctx.case_tz).astimezone(UTC)
    except ValueError:
        return None


@register
class DpkgLogParser(Parser):
    name = "dpkg_log"
    artifact_type = "pkg.dpkg"
    description = "Debian/Ubuntu dpkg.log"

    def can_parse(self, sample: Sample) -> float:
        ratio = _ratio(sample, _DPKG)
        if ratio < 0.8:
            return 0.0
        # Require dpkg vocabulary so other "date time word ..." logs do not match.
        vocab = ("status ", "configure ", "install ", "upgrade ", "startup ", "trigproc ")
        hits = sum(1 for line in sample.lines if any(f" {v}" in line for v in vocab))
        return 0.93 if hits >= len(sample.lines) * 0.5 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        for n, line in _lines(path):
            if not line.strip():
                continue
            m = _DPKG.match(line)
            if m is None:
                yield parse_error(line, n, "not_a_dpkg_line")
                continue
            action = m["action"]
            etype = _DPKG_ACTIONS.get(action, "other")
            target, version = _dpkg_package(action, (m["rest"] or "").split())
            yield ParsedEvent(
                event_type=etype,
                raw=line,
                line_number=n,
                timestamp_utc=_local(m["ts"], "%Y-%m-%d %H:%M:%S", ctx),
                timestamp_raw=m["ts"],
                timezone_assumed=True,
                target=target,
                tags=["dpkg", f"action:{action}"],
                extra={"action": action, "detail": m["rest"], "version": version},
            )


@register
class AptHistoryParser(Parser):
    name = "apt_history"
    artifact_type = "pkg.apt_history"
    description = "apt history.log (Start-Date/Commandline/Requested-By blocks)"

    _KEYS = ("Start-Date:", "Commandline:", "Requested-By:", "End-Date:", "Install:", "Upgrade:")

    def can_parse(self, sample: Sample) -> float:
        lines = [line for line in sample.lines if line.strip()]
        if sample.is_binary or not lines:
            return 0.0
        hits = sum(1 for line in lines if line.startswith((*self._KEYS, "Remove:", "Purge:")))
        starts = sum(1 for line in lines if line.startswith("Start-Date:"))
        return 0.95 if starts and hits >= len(lines) * 0.8 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        block: dict[str, str] = {}
        block_line = 0
        raw_lines: list[str] = []
        for n, line in [*_lines(path), (-1, "")]:
            if not line.strip():
                if block:
                    yield from self._block_events(block, block_line, "\n".join(raw_lines), ctx)
                block, raw_lines = {}, []
                continue
            key, sep, value = line.partition(": ")
            if not sep:
                yield parse_error(line, n, "not_a_history_field")
                continue
            if not block:
                block_line = n
            block[key] = value.strip()
            raw_lines.append(line)

    @staticmethod
    def _block_events(
        block: dict[str, str], n: int, raw: str, ctx: ParseContext
    ) -> Iterator[ParsedEvent]:
        start = block.get("Start-Date", "")
        ts = _local(" ".join(start.split()), "%Y-%m-%d %H:%M:%S", ctx)
        requested = block.get("Requested-By")
        actor = requested.split(" (", 1)[0] if requested else None
        for key, etype in (
            ("Install", "package.install"),
            ("Upgrade", "package.upgrade"),
            ("Downgrade", "package.upgrade"),
            ("Reinstall", "package.install"),
            ("Remove", "package.remove"),
            ("Purge", "package.remove"),
        ):
            if key not in block:
                continue
            packages = re.findall(r"([^\s,()]+) \(", block[key])
            yield ParsedEvent(
                event_type=etype,
                raw=raw,
                line_number=n,
                timestamp_utc=ts,
                timestamp_raw=start,
                timezone_assumed=True,
                actor=actor,
                target=", ".join(packages)[:1000] or None,
                command=block.get("Commandline"),
                tags=["apt", f"action:{key.lower()}"],
                extra={
                    "packages": packages,
                    "requested_by": requested,
                    "end": block.get("End-Date"),
                },
            )


@register
class YumLogParser(Parser):
    name = "yum_log"
    artifact_type = "pkg.yum"
    description = "yum.log (RHEL/CentOS 7 and earlier)"

    def can_parse(self, sample: Sample) -> float:
        ratio = _ratio(sample, _YUM)
        return 0.93 if ratio >= 0.8 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        months = [_MONTHS[m["mon"]] for _, line in _lines(path) if (m := _YUM.match(line))]
        years = YearTracker(months, ctx.mtime, ctx.case_tz)
        for n, line in _lines(path):
            if not line.strip():
                continue
            m = _YUM.match(line)
            if m is None:
                yield parse_error(line, n, "not_a_yum_line")
                continue
            month = _MONTHS[m["mon"]]
            ts = rfc3164_datetime(
                years.year_for(month), month, int(m["day"]), m["hms"], ctx.case_tz
            )
            yield ParsedEvent(
                event_type=_YUM_ACTIONS[m["action"]],
                raw=line,
                line_number=n,
                timestamp_utc=ts,
                timestamp_raw=m["ts"],
                timezone_assumed=True,
                target=m["pkg"],
                tags=["yum", f"action:{m['action']}", "year_inferred"],
            )


@register
class DnfRpmLogParser(Parser):
    name = "dnf_rpm_log"
    artifact_type = "pkg.dnf_rpm"
    description = "dnf.rpm.log (RHEL/Fedora 8+)"

    def can_parse(self, sample: Sample) -> float:
        lines = [line for line in sample.lines if line.strip()]
        if sample.is_binary or not lines:
            return 0.0
        stamped = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{4}|Z) [A-Z]+ ")
        base = sum(1 for line in lines if stamped.match(line)) / len(lines)
        return 0.9 if base >= 0.8 and any(_DNF.match(line) for line in lines) else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        for n, line in _lines(path):
            if not line.strip():
                continue
            m = _DNF.match(line)
            if m is None:
                # Non-transaction lines (e.g. "INFO --- logging initialized ---") are context.
                ts_m = re.match(r"^(\S+) ", line)
                ts = _parse_dnf_ts(ts_m[1]) if ts_m else None
                if ts is None:
                    yield parse_error(line, n, "not_a_dnf_line")
                    continue
                yield ParsedEvent(
                    "other",
                    raw=line,
                    line_number=n,
                    timestamp_utc=ts,
                    timestamp_raw=ts_m[1] if ts_m else None,
                    tags=["dnf"],
                )
                continue
            action = m["action"]
            yield ParsedEvent(
                event_type=_DNF_ACTIONS.get(action, "other"),
                raw=line,
                line_number=n,
                timestamp_utc=_parse_dnf_ts(m["ts"]),
                timestamp_raw=m["ts"],
                target=m["pkg"],
                tags=["dnf", f"action:{action}"],
            )


def _parse_dnf_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z").astimezone(UTC)
    except ValueError:
        return None
