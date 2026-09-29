"""SSH server artifacts: ``authorized_keys`` and ``sshd_config``.

Both describe state, so their events carry no timestamp. Key fingerprints are
computed like ``ssh-keygen -l`` (``SHA256:`` + unpadded base64 of the SHA-256 of
the key blob) so they can be matched against ``Accepted publickey`` log lines.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import shlex
from collections.abc import Iterator
from pathlib import Path

from sherlog.core.timeutil import iso
from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import (
    ParseContext,
    ParsedEvent,
    Parser,
    Sample,
    parse_error,
    user_from_path,
)
from sherlog.parsers.registry import register

_KEY = re.compile(
    r"(?:^|\s)(?P<type>ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|"
    r"sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+"
    r"(?P<blob>[A-Za-z0-9+/]+={0,3})(?:\s+(?P<comment>.*))?$"
)
_OPTION_TOKEN = re.compile(r'(?P<key>[\w-]+)(?:="(?P<value>(?:[^"\\]|\\.)*)")?(?:,|$)')
_OPTION_FLAGS = frozenset(
    [
        "agent-forwarding",
        "cert-authority",
        "no-agent-forwarding",
        "no-port-forwarding",
        "no-pty",
        "no-user-rc",
        "no-X11-forwarding",
        "no-touch-required",
        "port-forwarding",
        "pty",
        "restrict",
        "touch-required",
        "user-rc",
        "verify-required",
        "X11-forwarding",
    ]
)
_OPTION_KEYS = frozenset(
    [
        "command",
        "environment",
        "expiry-time",
        "from",
        "permitlisten",
        "permitopen",
        "principals",
        "tunnel",
    ]
)


def fingerprint(blob_b64: str) -> str | None:
    """``SHA256:...`` fingerprint of a base64 key blob, or ``None`` if it is not base64."""
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _options_ok(prefix: str) -> bool:
    """True if ``prefix`` looks like authorized_keys options (not known_hosts host names)."""
    pos = 0
    while pos < len(prefix):
        m = _OPTION_TOKEN.match(prefix, pos)
        if not m or m.end() == pos:
            return False
        key = m["key"]
        if m["value"] is not None:
            if key.lower() not in _OPTION_KEYS:
                return False
        elif key not in _OPTION_FLAGS:
            return False
        pos = m.end()
    return True


def _key_line(line: str) -> tuple[re.Match[str], str] | None:
    m = _KEY.search(line)
    if not m:
        return None
    prefix = line[: m.start()].strip()
    return (m, prefix) if _options_ok(prefix) else None


@register
class AuthorizedKeysParser(Parser):
    name = "authorized_keys"
    artifact_type = "ssh.authorized_keys"
    description = "OpenSSH authorized_keys"

    def can_parse(self, sample: Sample) -> float:
        body = [s for line in sample.lines if (s := line.strip()) and not s.startswith("#")]
        if sample.is_binary or not body:
            return 0.0
        hits = sum(1 for line in body if _key_line(line))
        return 0.95 if hits >= len(body) * 0.6 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        owner = user_from_path(ctx.path)
        with open_evidence(path) as fh:
            for n, raw in enumerate(fh, 1):
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parsed = _key_line(stripped)
                fp = fingerprint(parsed[0]["blob"]) if parsed else None
                if not parsed or fp is None:
                    yield parse_error(line, n, "not_an_authorized_key")
                    continue
                m, options = parsed
                tags = ["authorized_keys", f"key:{fp}", f"key_type:{m['type']}"]
                forced = re.search(r'command="([^"]*)"', options)
                if forced:
                    tags.append("forced_command")
                if "from=" in options:
                    tags.append("source_restricted")
                yield ParsedEvent(
                    event_type="ssh.key.present",
                    raw=line,
                    line_number=n,
                    actor=owner,
                    target=fp,
                    command=forced[1] if forced else None,
                    tags=tags,
                    extra={
                        "fingerprint": fp,
                        "key_type": m["type"],
                        "comment": m["comment"],
                        "options": options or None,
                        "file_mtime": iso(ctx.mtime),
                    },
                )


# Keywords only valid in sshd_config (not the client ssh_config).
_SSHD_ONLY = frozenset(
    k.lower()
    for k in [
        "PermitRootLogin",
        "AuthorizedKeysFile",
        "Subsystem",
        "UsePAM",
        "ChallengeResponseAuthentication",
        "KbdInteractiveAuthentication",
        "PermitEmptyPasswords",
        "AllowUsers",
        "AllowGroups",
        "DenyUsers",
        "DenyGroups",
        "ListenAddress",
        "HostKey",
        "PrintMotd",
        "AcceptEnv",
        "ClientAliveInterval",
        "MaxAuthTries",
        "MaxSessions",
        "PermitTunnel",
        "AllowTcpForwarding",
        "X11Forwarding",
        "AuthorizedKeysCommand",
        "AuthorizedKeysCommandUser",
        "PermitUserEnvironment",
        "UsePrivilegeSeparation",
        "LoginGraceTime",
    ]
)
_SSHD_COMMON = frozenset(
    k.lower()
    for k in [
        "Port",
        "PasswordAuthentication",
        "PubkeyAuthentication",
        "Include",
        "Match",
        "LogLevel",
        "SyslogFacility",
        "Ciphers",
        "MACs",
        "KexAlgorithms",
        "HostKeyAlgorithms",
        "GSSAPIAuthentication",
        "Banner",
        "Compression",
    ]
)
# (keyword, value) -> risk tag
_RISKY = {
    ("permitrootlogin", "yes"): "risky:root_login",
    ("passwordauthentication", "yes"): "risky:password_auth",
    ("permitemptypasswords", "yes"): "risky:empty_passwords",
    ("permituserenvironment", "yes"): "risky:user_environment",
    ("permittunnel", "yes"): "risky:tunnel",
}


@register
class SshdConfigParser(Parser):
    name = "sshd_config"
    artifact_type = "ssh.sshd_config"
    description = "OpenSSH server configuration"

    def can_parse(self, sample: Sample) -> float:
        body = [s for line in sample.lines if (s := line.strip()) and not s.startswith("#")]
        if sample.is_binary or not body:
            return 0.0
        words = [line.split(maxsplit=1)[0].lower() for line in body]
        known = sum(1 for w in words if w in _SSHD_ONLY or w in _SSHD_COMMON)
        server_only = sum(1 for w in words if w in _SSHD_ONLY)
        if server_only == 0 or known < len(body) * 0.6:
            return 0.0
        return 0.9 if server_only >= 2 else 0.7

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        match_block: str | None = None
        with open_evidence(path) as fh:
            for n, raw in enumerate(fh, 1):
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split(maxsplit=1)
                keyword = parts[0]
                value = parts[1].strip() if len(parts) > 1 else ""
                if "=" in keyword:  # "Keyword=value" form
                    keyword, _, value = keyword.partition("=")
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", keyword):
                    yield parse_error(line, n, "not_a_config_line")
                    continue
                if keyword.lower() == "match":
                    match_block = value
                tags = ["sshd_config"]
                first_value = (shlex.split(value) or [""])[0].lower() if value else ""
                if risk := _RISKY.get((keyword.lower(), first_value)):
                    tags.append(risk)
                if match_block and keyword.lower() != "match":
                    tags.append(f"match:{match_block}")
                yield ParsedEvent(
                    event_type="config.entry",
                    raw=line,
                    line_number=n,
                    target=keyword,
                    command=value or None,
                    tags=tags,
                    extra={"keyword": keyword, "value": value, "file_mtime": iso(ctx.mtime)},
                )
