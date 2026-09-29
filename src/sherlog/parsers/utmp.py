"""wtmp / btmp (utmp records) and lastlog, parsed directly from their C struct layout.

Layouts are those of glibc on 64-bit Linux (x86_64, aarch64), little endian:

* ``struct utmp`` - 384 bytes: type, pid, line, id, user, host, exit status,
  session, timeval (32-bit sec/usec), 16-byte address, 20 bytes reserved.
* ``struct lastlog`` - 292 bytes per UID: 32-bit time, line[32], host[256].

wtmp and btmp share the record format; btmp holds only failed attempts, which
are recorded as ``LOGIN_PROCESS`` entries, so a file consisting solely of those
is classified as btmp.
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import ParseContext, ParsedEvent, Parser, Sample, parse_error
from sherlog.parsers.registry import register

UTMP = struct.Struct("<h2xi32s4s32s256shhi2i16s20s")
LASTLOG = struct.Struct("<i32s256s")
assert UTMP.size == 384 and LASTLOG.size == 292

RUN_LVL, BOOT_TIME, NEW_TIME, OLD_TIME = 1, 2, 3, 4
INIT_PROCESS, LOGIN_PROCESS, USER_PROCESS, DEAD_PROCESS, ACCOUNTING = 5, 6, 7, 8, 9
_TYPE_NAMES = {
    0: "EMPTY",
    1: "RUN_LVL",
    2: "BOOT_TIME",
    3: "NEW_TIME",
    4: "OLD_TIME",
    5: "INIT_PROCESS",
    6: "LOGIN_PROCESS",
    7: "USER_PROCESS",
    8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}
# Plausible record timestamps: 1990-01-01 .. 2100-01-01.
_MIN_TS, _MAX_TS = 631152000, 4102444800


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _addr(raw: bytes) -> str | None:
    if not any(raw):
        return None
    if not any(raw[4:]):
        return str(ipaddress.IPv4Address(raw[:4]))
    return str(ipaddress.IPv6Address(raw))


def _valid_utmp(rec: tuple[object, ...]) -> bool:
    ut_type, pid, sec = rec[0], rec[1], rec[9]
    assert isinstance(ut_type, int) and isinstance(pid, int) and isinstance(sec, int)
    return 0 <= ut_type <= 9 and pid >= 0 and (ut_type == 0 or _MIN_TS <= sec <= _MAX_TS)


def _utmp_records(sample: Sample) -> list[tuple[object, ...]] | None:
    """Records in the sample if it looks like utmp, else None."""
    if not sample.is_binary:
        return None
    if sample.size == 0 or sample.size % UTMP.size:
        return None
    n = len(sample.head) // UTMP.size
    if n == 0:
        return None
    recs = [UTMP.unpack_from(sample.head, i * UTMP.size) for i in range(n)]
    return recs if all(_valid_utmp(r) for r in recs) else None


class _UtmpBase(Parser):
    failed_logins = False

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        with open_evidence(path) as fh:
            n = 0
            while chunk := fh.read(UTMP.size):
                n += 1
                if len(chunk) < UTMP.size:
                    yield parse_error(chunk.hex(), n, "truncated_record")
                    break
                yield self._event(UTMP.unpack(chunk), n)

    def _event(self, rec: tuple[object, ...], n: int) -> ParsedEvent:
        ut_type, pid, line_b, _id, user_b, host_b, _t, _e, _session, sec, usec, addr_b, _ = rec
        assert isinstance(ut_type, int) and isinstance(sec, int) and isinstance(usec, int)
        assert isinstance(line_b, bytes) and isinstance(user_b, bytes)
        assert isinstance(host_b, bytes) and isinstance(addr_b, bytes)
        user, line, host = _cstr(user_b), _cstr(line_b), _cstr(host_b)
        ip = _addr(addr_b)
        ts = datetime.fromtimestamp(sec + usec / 1_000_000, UTC) if sec else None
        type_name = _TYPE_NAMES.get(ut_type, str(ut_type))
        raw = f"type={type_name} pid={pid} line={line} user={user} host={host} addr={ip or ''}"

        if self.failed_logins:
            etype = "auth.login.failure"
        elif ut_type == USER_PROCESS:
            etype = "auth.login.success"
        elif ut_type == DEAD_PROCESS:
            etype = "auth.logout"
        elif ut_type == BOOT_TIME:
            etype = "system.boot"
        elif ut_type == RUN_LVL and user == "shutdown":
            etype = "system.shutdown"
        else:
            etype = "other"
        return ParsedEvent(
            event_type=etype,
            raw=raw,
            line_number=n,  # record index
            timestamp_utc=ts,
            timestamp_raw=str(sec),
            actor=user or None,
            src_ip=ip,
            target=line or None,
            tags=[f"utmp_type:{type_name}", *([f"remote_host:{host}"] if host else [])],
        )


@register
class WtmpParser(_UtmpBase):
    name = "wtmp"
    artifact_type = "utmp.wtmp"
    description = "wtmp: login/logout, boot and shutdown records"

    def can_parse(self, sample: Sample) -> float:
        recs = _utmp_records(sample)
        if recs is None:
            return 0.0
        return 0.95 if any(r[0] != LOGIN_PROCESS for r in recs) else 0.6


@register
class BtmpParser(_UtmpBase):
    name = "btmp"
    artifact_type = "utmp.btmp"
    description = "btmp: failed login attempts"
    failed_logins = True

    def can_parse(self, sample: Sample) -> float:
        recs = _utmp_records(sample)
        if recs is None:
            return 0.0
        return 0.9 if all(r[0] == LOGIN_PROCESS for r in recs) else 0.0


@register
class LastlogParser(Parser):
    name = "lastlog"
    artifact_type = "lastlog"
    description = "lastlog: most recent login per UID (sparse file indexed by UID)"

    def can_parse(self, sample: Sample) -> float:
        if sample.size == 0 or sample.size % LASTLOG.size or sample.size % UTMP.size == 0:
            return 0.0
        n = len(sample.head) // LASTLOG.size
        if n == 0:
            return 0.0
        used = 0
        for i in range(n):
            sec, line_b, host_b = LASTLOG.unpack_from(sample.head, i * LASTLOG.size)
            if sec == 0 and not any(line_b) and not any(host_b):
                continue
            if not _MIN_TS <= sec <= _MAX_TS:
                return 0.0
            used += 1
        if used:
            return 0.85
        # Sparse file: regular users (UID >= 1000) live beyond the sampled head, which is
        # then all zeros. Plausible, but weaker evidence.
        return 0.55 if sample.size > len(sample.head) and not any(sample.head) else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        with open_evidence(path) as fh:
            uid = -1
            while chunk := fh.read(LASTLOG.size):
                uid += 1
                if len(chunk) < LASTLOG.size:
                    yield parse_error(chunk.hex(), uid, "truncated_record")
                    break
                sec, line_b, host_b = LASTLOG.unpack(chunk)
                if sec == 0:
                    continue
                line, host = _cstr(line_b), _cstr(host_b)
                yield ParsedEvent(
                    event_type="auth.login.success",
                    raw=f"uid={uid} time={sec} line={line} host={host}",
                    line_number=uid,
                    timestamp_utc=datetime.fromtimestamp(sec, UTC),
                    timestamp_raw=str(sec),
                    actor=f"uid:{uid}",
                    src_ip=host if _is_ip(host) else None,
                    target=line or None,
                    tags=["lastlog", *([f"remote_host:{host}"] if host else [])],
                )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
