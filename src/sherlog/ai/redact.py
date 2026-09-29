"""Redaction layer: stable pseudonyms for sensitive values sent to an AI provider.

Replaced (on by default): host names, internal (non-global) IP addresses,
usernames, e-mail addresses and internal domains known to the case.
Public IPs, public domains and hashes are kept, since they are what the
analysis is about and are not personal data of the victim organisation.

Pseudonyms are ``HMAC-SHA256(case secret, category:value)`` prefixes, so the
same value always maps to the same pseudonym within a case (the model can
correlate) while nothing about the original can be recovered without the secret.
The model's tool arguments are passed through :meth:`Redactor.restore` before
they touch the database.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select

from sherlog.core.models import IOC, Event
from sherlog.core.vocab import IOCType

# Generic accounts whose names carry no personal information and matter for analysis.
SYSTEM_ACCOUNTS = frozenset(
    """
    root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats
    nobody systemd-network systemd-resolve systemd-timesync messagebus syslog sshd apache nginx
    mysql postgres redis ftp ntp polkitd dbus chrony admin ubuntu ec2-user centos debian
    """.split()
)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w-])")
_HOME = re.compile(r"/home/([^/\s'\"]+)")
_PREFIX = {"host": "host", "ip": "ip", "user": "user", "email": "email", "domain": "domain"}


def new_secret() -> str:
    return secrets.token_hex(32)


class Redactor:
    """Maps sensitive values to pseudonyms and back."""

    def __init__(self, secret: str, *, enabled: bool = True) -> None:
        self.enabled = enabled
        self._key = bytes.fromhex(secret)
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        self._pattern: re.Pattern[str] | None = None
        self._restore_pattern: re.Pattern[str] | None = None

    # --- building the map -------------------------------------------------------------------

    def _pseudonym(self, category: str, value: str) -> str:
        digest = hmac.new(self._key, f"{category}:{value}".encode(), hashlib.sha256).hexdigest()
        tag = digest[:6]
        if category == "email":
            return f"email-{tag}@redacted.invalid"
        if category == "domain":
            return f"domain-{tag}.redacted.invalid"
        if category == "ip":
            return f"PRIVATE-IP-{tag}"
        return f"{_PREFIX[category]}-{tag}"

    def add(self, category: str, value: str | None) -> None:
        """Register a sensitive value (ignored if too generic to redact safely)."""
        if not value or not self.enabled:
            return
        value = value.strip()
        if len(value) < 2 or value in self.forward:
            return
        if category == "user" and (value in SYSTEM_ACCOUNTS or value.startswith("uid:")):
            return
        pseudo = self._pseudonym(category, value)
        self.forward[value] = pseudo
        self.reverse[pseudo] = value
        self._pattern = self._restore_pattern = None

    def add_many(self, category: str, values: Iterable[str | None]) -> None:
        for v in values:
            self.add(category, v)

    # --- applying it ------------------------------------------------------------------------

    def _compiled(self) -> re.Pattern[str] | None:
        if self._pattern is None and self.forward:
            alts = sorted(self.forward, key=len, reverse=True)
            self._pattern = re.compile(
                r"(?<![\w.@-])(" + "|".join(re.escape(a) for a in alts) + r")(?![\w@-]|\.\w)"
            )
        return self._pattern

    def redact(self, text: str) -> str:
        """Pseudonymize known values and any e-mail address in ``text``."""
        if not self.enabled or not text:
            return text
        for email in set(_EMAIL.findall(text)):
            if not email.endswith("redacted.invalid"):
                self.add("email", email)
        pattern = self._compiled()
        if pattern is None:
            return text
        return pattern.sub(lambda m: self.forward[m.group(1)], text)

    def restore(self, text: str) -> str:
        """Map pseudonyms in model output back to the real values."""
        if not self.enabled or not text or not self.reverse:
            return text
        if self._restore_pattern is None:
            alts = sorted(self.reverse, key=len, reverse=True)
            self._restore_pattern = re.compile("|".join(re.escape(a) for a in alts))
        return self._restore_pattern.sub(lambda m: self.reverse[m.group(0)], text)

    def redact_obj(self, obj: Any) -> Any:
        return _walk(obj, self.redact)

    def restore_obj(self, obj: Any) -> Any:
        return _walk(obj, self.restore)


def _walk(obj: Any, fn: Any) -> Any:
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_walk(v, fn) for v in obj]
    if isinstance(obj, dict):
        return {k: _walk(v, fn) for k, v in obj.items()}
    return obj


# Internal address space (RFC 1918, CGNAT, link-local, IPv6 unique-local/link-local).
# Documentation and other reserved ranges are not the organisation's addresses.
_INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
)


def is_internal_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS if net.version == addr.version)


def build_redactor(
    session: Any, secret: str, *, enabled: bool = True, brief: str | None = None
) -> Redactor:
    """Collect the case's sensitive values: hosts, internal IPs, usernames, internal domains."""
    r = Redactor(secret, enabled=enabled)
    if not enabled:
        return r
    r.add_many("host", session.scalars(select(Event.host).distinct()))
    users: set[str | None] = set(session.scalars(select(Event.actor).distinct()))
    user_targets = (
        select(Event.target)
        .where(
            Event.event_type.in_(
                (
                    "user.create",
                    "user.delete",
                    "user.modify",
                    "group.modify",
                    "password.change",
                    "auth.su",
                    "auth.sudo",
                    "auth.session.open",
                    "auth.session.close",
                )
            )
        )
        .distinct()
    )
    users |= set(session.scalars(user_targets))
    for (raw,) in session.execute(select(Event.raw).where(Event.raw.like("%/home/%")).limit(20000)):
        users.update(_HOME.findall(raw))
    ips: set[str] = set()
    for src, dst in session.execute(select(Event.src_ip, Event.dst_ip).distinct()):
        ips.update(ip for ip in (src, dst) if is_internal_ip(ip))
    for ioc in session.scalars(select(IOC)):
        if ioc.type == IOCType.USERNAME:
            users.add(ioc.value)
        elif ioc.type in (IOCType.IPV4, IOCType.IPV6) and is_internal_ip(ioc.value):
            ips.add(ioc.value)
        elif ioc.type == IOCType.DOMAIN and "internal" in (ioc.tags or []):
            r.add("domain", ioc.value)
    r.add_many("ip", sorted(ips))
    r.add_many("user", sorted(u for u in users if u))
    if brief:
        r.redact(brief)  # registers e-mail addresses mentioned in the brief
    return r
