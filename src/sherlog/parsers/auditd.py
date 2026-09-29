"""Linux audit log (``/var/log/audit/audit.log``).

Each line is one record: ``[node=H ]type=T msg=audit(<epoch>.<ms>:<serial>): k=v ...``.
Records sharing a serial belong to one audit event; the serial is kept in
``extra['serial']`` so they can be correlated. Untrusted string fields are
hex-encoded by auditd when they contain spaces or special characters and are
decoded here. With ``log_format = ENRICHED``, resolved names follow a ``\\x1d``
separator as upper-case keys (``AUID="alice"``) and are preferred for actors.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import ParseContext, ParsedEvent, Parser, Sample, parse_error
from sherlog.parsers.registry import register

_RECORD = re.compile(
    r"^(?:node=(?P<node>\S+) )?type=(?P<type>[A-Z0-9_]+) "
    r"msg=audit\((?P<sec>\d+)\.(?P<ms>\d+):(?P<serial>\d+)\):\s?(?P<body>.*)$"
)
_KV = re.compile(r"""([A-Za-z_][\w-]*)=("[^"]*"|'[^']*'|\S+)""")
_HEX = re.compile(r"^(?:[0-9A-F]{2})+$")
# Fields auditd may hex-encode (untrusted strings).
_UNTRUSTED = re.compile(r"^(?:acct|cmd|comm|exe|proctitle|name|cwd|key|data|path)$")
# EXECVE arguments are untrusted strings; in SYSCALL records a0..a3 are register values.
_EXECVE_ARG = re.compile(r"^a\d+$")
_UNSET_ID = {"4294967295", "-1", "unset"}


def _decode(key: str, value: str, rtype: str = "") -> str:
    if value[:1] in "\"'" and value[-1:] == value[:1] and len(value) >= 2:
        return value[1:-1]
    untrusted = _UNTRUSTED.match(key) or (rtype == "EXECVE" and _EXECVE_ARG.match(key))
    if untrusted and _HEX.match(value):
        try:
            text = bytes.fromhex(value).decode("utf-8", errors="replace")
        except ValueError:
            return value
        return text.replace("\0", " ").strip() if key == "proctitle" else text
    return value


def parse_fields(body: str, rtype: str = "") -> dict[str, str]:
    """Parse ``k=v`` pairs, flattening a nested ``msg='...'`` and enriched fields."""
    fields: dict[str, str] = {}
    for key, value in _KV.findall(body.replace("\x1d", " ")):
        if key == "msg" and value.startswith("'"):
            fields.update(parse_fields(value[1:-1], rtype))
            continue
        fields.setdefault(key, _decode(key, value, rtype))
    return fields


def _ok(fields: dict[str, str]) -> bool | None:
    res = fields.get("res", fields.get("success"))
    if res is None:
        return None
    return res.lower() in ("success", "yes", "1")


def _actor(fields: dict[str, str]) -> str | None:
    for key in ("AUID", "acct", "UID"):
        if (v := fields.get(key)) and v not in ("?", "(null)", "unset"):
            return v
    for key in ("auid", "uid"):
        if (v := fields.get(key)) and v not in _UNSET_ID:
            return f"uid:{v}"
    return None


def _addr(fields: dict[str, str]) -> str | None:
    v = fields.get("addr")
    return None if v in (None, "?", "") else v


_TYPE_MAP = {
    "USER_START": "auth.session.open",
    "USER_END": "auth.session.close",
    "ADD_USER": "user.create",
    "DEL_USER": "user.delete",
    "USER_MGMT": "user.modify",
    "ACCT_LOCK": "user.modify",
    "ACCT_UNLOCK": "user.modify",
    "ADD_GROUP": "group.modify",
    "DEL_GROUP": "group.modify",
    "GRP_MGMT": "group.modify",
    "USER_CHAUTHTOK": "password.change",
    "SERVICE_START": "service.start",
    "SERVICE_STOP": "service.stop",
    "SYSTEM_BOOT": "system.boot",
    "SYSTEM_SHUTDOWN": "system.shutdown",
    "EXECVE": "process.exec",
    "USER_CMD": "auth.sudo",
}


def record_to_event(
    rtype: str, fields: dict[str, str], ts: datetime, raw: str, n: int
) -> ParsedEvent:
    """Map one audit record to a normalized event."""
    ok = _ok(fields)
    etype = _TYPE_MAP.get(rtype, "other")
    tags = [f"audit_type:{rtype}"]
    if ok is not None:
        tags.append("res:success" if ok else "res:failed")
    target: str | None = None
    command: str | None = None

    if rtype == "USER_LOGIN":
        etype = "auth.login.failure" if ok is False else "auth.login.success"
    elif rtype in ("ADD_USER", "DEL_USER", "USER_MGMT", "USER_CHAUTHTOK", "ACCT_LOCK"):
        target = fields.get("acct") or fields.get("id")
    elif rtype in ("ADD_GROUP", "DEL_GROUP", "GRP_MGMT"):
        target = fields.get("grp") or fields.get("acct") or fields.get("id")
    elif rtype in ("SERVICE_START", "SERVICE_STOP"):
        target = fields.get("unit")
    elif rtype == "EXECVE":
        argc = int(fields.get("argc", "0") or 0)
        command = " ".join(fields.get(f"a{i}", "") for i in range(argc)).strip() or None
    elif rtype == "USER_CMD":
        command = fields.get("cmd")
        tags.append(f"cwd:{fields.get('cwd', '')}")
    elif rtype == "PROCTITLE":
        command = fields.get("proctitle")
    elif rtype == "SYSCALL":
        command = fields.get("exe")
        tags.append(f"syscall:{fields.get('syscall', '')}")
    elif rtype in ("DAEMON_START", "DAEMON_RESUME"):
        etype, target = "service.start", "auditd"
        tags.append("logging")
    elif rtype in ("DAEMON_END", "DAEMON_ABORT"):
        etype, target = "service.stop", "auditd"
        tags += ["logging", "audit_stopped"]
    elif rtype == "CONFIG_CHANGE":
        tags.append("audit_config_change")
        if fields.get("audit_enabled") == "0":
            tags.append("audit_disabled")
    elif rtype == "AVC":
        tags.append("selinux_denial")
    elif rtype.startswith("ANOM_"):
        tags.append("anomaly")

    if (key := fields.get("key")) and key not in ("(null)", "?"):
        tags.append(f"key:{key}")
    return ParsedEvent(
        event_type=etype,
        raw=raw,
        line_number=n,
        timestamp_utc=ts,
        timestamp_raw=f"{int(ts.timestamp())}",
        host=fields.get("node"),
        actor=_actor(fields),
        src_ip=_addr(fields),
        target=target or (fields.get("terminal") if etype.startswith("auth.") else None),
        command=command,
        tags=tags,
        extra=fields,
    )


@register
class AuditdParser(Parser):
    name = "auditd"
    artifact_type = "linux.audit"
    description = "Linux audit log (auditd)"

    def can_parse(self, sample: Sample) -> float:
        lines = [line for line in sample.lines if line.strip()]
        if sample.is_binary or not lines:
            return 0.0
        hits = sum(1 for line in lines if _RECORD.match(line))
        return 0.97 if hits >= len(lines) * 0.8 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        with open_evidence(path) as fh:
            for n, raw_bytes in enumerate(fh, 1):
                line = raw_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line.strip():
                    continue
                m = _RECORD.match(line)
                if m is None:
                    yield parse_error(line, n, "not_an_audit_record")
                    continue
                fields = parse_fields(m["body"], m["type"])
                fields["serial"] = m["serial"]
                if m["node"]:
                    fields["node"] = m["node"]
                ts = datetime.fromtimestamp(int(m["sec"]) + int(m["ms"]) / 1000, UTC)
                yield record_to_event(m["type"], fields, ts, line, n)
