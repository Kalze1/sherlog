"""Shared helpers for the sample-evidence generators.

Generation is deterministic: a fixed seed per scenario, fixed dates and
explicit file modification times (syslog year inference depends on mtimes,
which git does not preserve - so the evidence is generated, not committed).
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import ipaddress
import json
import os
import random
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any

UTMP = struct.Struct("<h2xi32s4s32s256shhi2i16s20s")  # glibc 64-bit struct utmp (384 bytes)
USER_PROCESS, DEAD_PROCESS, LOGIN_PROCESS, BOOT_TIME = 7, 8, 6, 2


def rfc3164(dt: datetime) -> str:
    """``Mar  5 02:13:07`` (local time as written by classic syslog)."""
    return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S}"


def iso_ts(dt: datetime) -> str:
    """rsyslog high-precision format: ``2024-04-18T14:02:00.123456+00:00``."""
    return dt.isoformat(timespec="microseconds")


def apache_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S %z")


def ed25519_key(seed: str) -> str:
    """A syntactically valid ssh-ed25519 public key blob (base64), derived from ``seed``."""
    name = b"ssh-ed25519"
    pub = hashlib.sha256(seed.encode()).digest()
    blob = struct.pack(">I", len(name)) + name + struct.pack(">I", len(pub)) + pub
    return base64.b64encode(blob).decode()


def key_fingerprint(blob_b64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(blob_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def utmp_record(
    ut_type: int, ts: datetime, *, user: str = "", line: str = "", host: str = "", pid: int = 1000
) -> bytes:
    addr = b"\0" * 16
    try:
        packed = ipaddress.ip_address(host).packed
        addr = packed + b"\0" * (16 - len(packed))
    except ValueError:
        pass
    sec = int(ts.timestamp())
    return UTMP.pack(
        ut_type, pid, line.encode(), line[-4:].encode(), user.encode(), host.encode(),
        0, 0, 0, sec, 0, addr, b"\0" * 20,
    )  # fmt: skip


@dataclass
class Log:
    """Collects (time, line) pairs and writes them in time order."""

    lines: list[tuple[datetime, str]] = field(default_factory=list)

    def add(self, when: datetime, line: str) -> None:
        self.lines.append((when, line))

    def text(self) -> str:
        return "".join(f"{line}\n" for _, line in sorted(self.lines, key=lambda x: x[0]))


@dataclass
class Scenario:
    """Output location, RNG and answer key for one scenario."""

    name: str
    root: Path
    seed: int
    tz: tzinfo = UTC
    answer: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.rng = random.Random(self.seed)
        self.evidence = self.root / "evidence"

    def path(self, rel: str) -> Path:
        p = self.evidence / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write(self, rel: str, content: str | bytes, mtime: datetime, *, gz: bool = False) -> Path:
        p = self.path(rel)
        data = content.encode() if isinstance(content, str) else content
        if gz:
            data = gzip.compress(data, mtime=0)  # mtime=0 keeps the archive bytes reproducible
        p.write_bytes(data)
        set_mtime(p, mtime)
        return p

    def pid(self) -> int:
        return self.rng.randint(1000, 60000)

    def finish(self, newest: datetime) -> Path:
        """Write the answer key and fix directory mtimes; returns the scenario directory."""
        key = self.root / "answer_key.json"
        key.write_text(json.dumps(self.answer, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        for d in sorted((p for p in self.evidence.rglob("*") if p.is_dir()), reverse=True):
            set_mtime(d, newest)
        set_mtime(self.evidence, newest)
        return self.root


def set_mtime(path: Path, when: datetime) -> None:
    ts = when.astimezone(UTC).timestamp()
    os.utime(path, (ts, ts))


def local(tz: tzinfo, *args: int) -> datetime:
    return datetime(*args, tzinfo=tz)  # type: ignore[misc]


def minutes(n: float) -> timedelta:
    return timedelta(minutes=n)


def utc(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def tree_digest(root: Path) -> str:
    """SHA-256 over every file's relative path, content and mtime (determinism check)."""
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode())
            h.update(hashlib.sha256(p.read_bytes()).digest())
            h.update(str(int(p.stat().st_mtime)).encode())
    return h.hexdigest()
