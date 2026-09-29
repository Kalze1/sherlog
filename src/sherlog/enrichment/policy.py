"""Egress policy: which indicators may be sent to an external service.

This is the enrichment side of SherLog's privacy layer. Only public
indicators ever leave the machine: global IP addresses, public domain names
and file hashes. Usernames, paths and full URLs (which can embed internal
hostnames, paths and tokens) are never sent; for URLs only the host is looked
up, as a separate domain IOC. Private/reserved IPs are sent only when the
analyst passes ``--enrich-private``.
"""

from __future__ import annotations

from sherlog.core.vocab import IOCType

NEVER_SENT = frozenset({IOCType.USERNAME, IOCType.PATH, IOCType.URL})


def blocked_reason(
    kind: IOCType, tags: list[str] | None, *, enrich_private: bool = False
) -> str | None:
    """Why this IOC must not be sent externally, or None if it may be."""
    tags = tags or []
    if kind in NEVER_SENT:
        return f"{kind.value} values are never sent to external services"
    if "internal" in tags:
        return "internal domain"
    if "private" in tags and not enrich_private:
        return "private/reserved address (use --enrich-private to allow)"
    return None
