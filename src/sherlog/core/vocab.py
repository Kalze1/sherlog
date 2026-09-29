"""Controlled vocabularies used across the data model."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerifiedBy(StrEnum):
    """Provenance of a finding. Reports must render these distinctly."""

    RULE = "rule"
    ANALYST = "analyst"
    AI_PROPOSED = "ai_proposed"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACCEPTED = "accepted"  # analyst confirmed
    REJECTED = "rejected"  # analyst dismissed (false positive / out of scope)


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    MD5 = "md5"
    USERNAME = "username"
    PATH = "path"


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class FileKind(StrEnum):
    """What an evidence path is. Only ``file`` entries are ever opened."""

    FILE = "file"
    SYMLINK = "symlink"
    SPECIAL = "special"  # FIFO, socket, device: recorded, never read
    UNREADABLE = "unreadable"


class CustodyAction(StrEnum):
    ACQUIRED = "acquired"
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"


# Normalized event types. Parsers must emit one of these; extend deliberately.
EVENT_TYPES: frozenset[str] = frozenset(
    {
        "auth.login.success",
        "auth.login.failure",
        "auth.logout",
        "auth.sudo",
        "auth.su",
        "auth.session.open",
        "auth.session.close",
        "user.create",
        "user.delete",
        "user.modify",
        "group.modify",
        "password.change",
        "ssh.key.added",
        "ssh.key.present",  # authorized_keys entry (state, not a dated event)
        "cron.exec",
        "cron.modify",
        "cron.entry",  # crontab line (state, not a dated event)
        "config.entry",  # security-relevant configuration setting
        "service.start",
        "service.stop",
        "service.create",
        "process.exec",
        "package.install",
        "package.upgrade",
        "package.remove",
        "web.request",
        "web.error",
        "kernel.message",
        "system.boot",
        "system.shutdown",
        "log.gap",
        "log.cleared",
        "shell.command",
        "parse_error",
        "other",
    }
)
