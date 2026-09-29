"""Crontab files: user crontabs (``/var/spool/cron/...``) and system crontabs
(``/etc/crontab``, ``/etc/cron.d/*``).

These describe state rather than dated activity, so each entry becomes a
``cron.entry`` event without a timestamp; the file's mtime is kept in
``extra`` as the best available indication of when it last changed. System
crontabs carry a user column; this is decided from the evidence path, since
the content alone is ambiguous.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from sherlog.core.timeutil import iso
from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import ParseContext, ParsedEvent, Parser, Sample, parse_error
from sherlog.parsers.registry import register

_FIELD = r"[\d*/,\-A-Za-z]+"
_SCHEDULE = re.compile(
    rf"^(?P<sched>@(?:reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|"
    rf"{_FIELD}\s+{_FIELD}\s+{_FIELD}\s+{_FIELD}\s+{_FIELD})\s+(?P<rest>\S.*)$"
)
_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
_SYSTEM_PATH = re.compile(r"(?:^|/)etc/(?:crontab$|cron\.d/)")
_SPOOL_PATH = re.compile(r"/spool/cron/(?:crontabs/)?(?P<user>[^/]+)$")


def _is_entry(line: str) -> bool:
    m = _SCHEDULE.match(line)
    if m is None:
        return False
    # Guard against prose: minute/hour fields must contain a digit, '*' or be '@...'.
    return m["sched"].startswith("@") or re.match(r"^[\d*]", m["sched"]) is not None


@register
class CrontabParser(Parser):
    name = "crontab"
    artifact_type = "cron.crontab"
    description = "crontab file (user or system)"

    def can_parse(self, sample: Sample) -> float:
        lines = [line.strip() for line in sample.lines]
        body = [
            line for line in lines if line and not line.startswith("#") and not _ENV.match(line)
        ]
        if sample.is_binary or not body:
            return 0.0
        hits = sum(1 for line in body if _is_entry(line))
        if hits < len(body) * 0.6:
            return 0.0
        header = any("m h" in line and "dom" in line for line in lines if line.startswith("#"))
        return 0.9 if header else 0.8

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        posix = ctx.path.as_posix()
        system = bool(_SYSTEM_PATH.search(posix))
        spool = _SPOOL_PATH.search(posix)
        owner = spool["user"] if spool else None
        with open_evidence(path) as fh:
            for n, raw in enumerate(fh, 1):
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or _ENV.match(stripped):
                    continue
                m = _SCHEDULE.match(stripped)
                if not m or not _is_entry(stripped):
                    yield parse_error(line, n, "not_a_crontab_entry")
                    continue
                user, command = owner, m["rest"]
                if system:  # "<user><whitespace><command>"; the separator is often a tab
                    parts = m["rest"].split(maxsplit=1)
                    user, command = parts[0], parts[1] if len(parts) > 1 else ""
                yield ParsedEvent(
                    event_type="cron.entry",
                    raw=line,
                    line_number=n,
                    actor=user,
                    command=command,
                    tags=["crontab", f"schedule:{m['sched']}"]
                    + (["system_crontab"] if system else []),
                    extra={"schedule": m["sched"], "file_mtime": iso(ctx.mtime)},
                )
