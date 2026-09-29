"""Extract indicators of compromise (IOCs) from the normalized events of a case.

Extraction is local and deterministic. Every IOC keeps links to the events it
came from and to the (non-rejected) findings those events support, so the
report and enrichment can focus on indicators that matter.

Precision over recall, to keep the IOC list useful:

* IPs come from structured fields (``src_ip``/``dst_ip``/``X-Forwarded-For``)
  and dotted quads in raw text; loopback/unspecified addresses are dropped and
  non-global ones tagged ``private``.
* Hashes are taken only from command lines; raw journald/audit records are full
  of harmless hex (boot IDs, hex-encoded arguments).
* Domains come from URLs, or from command lines when the TLD is a common one;
  a bare ``update.sh`` would otherwise be read as a domain in ``.sh``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import delete, insert, select

from sherlog.core import audit
from sherlog.core.case import CaseHandle
from sherlog.core.models import IOC, Event, Finding, finding_events, ioc_events
from sherlog.core.vocab import FindingStatus, IOCType

log = logging.getLogger(__name__)

MAX_EVENT_LINKS = 500

_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_IPV4 = re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?![\d.])")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>|;`)\]}]+", re.IGNORECASE)
_SHA256 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_MD5 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
_TMP_PATH = re.compile(r"(?<![\w/])(?:/tmp|/dev/shm|/var/tmp)/[^\s'\";|&<>()`]+")
_FQDN = re.compile(
    r"(?<![\w.@/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-])", re.I
)
# Common TLDs only; deliberately excludes TLDs that collide with file extensions (sh, py, pl...).
COMMON_TLDS = frozenset(
    [
        "com",
        "net",
        "org",
        "info",
        "biz",
        "io",
        "co",
        "xyz",
        "top",
        "site",
        "online",
        "club",
        "shop",
        "store",
        "app",
        "dev",
        "cloud",
        "tech",
        "live",
        "pro",
        "ru",
        "cn",
        "uk",
        "de",
        "fr",
        "nl",
        "br",
        "in",
        "jp",
        "kr",
        "it",
        "es",
        "pl",
        "ir",
        "tr",
        "ua",
        "vn",
        "id",
        "cc",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "su",
        "me",
        "tv",
        "us",
        "ca",
        "au",
        "eu",
        "ch",
        "se",
        "no",
        "fi",
        "dk",
        "be",
        "at",
        "cz",
        "ro",
        "hu",
        "gr",
        "pt",
        "il",
        "za",
        "mx",
        "ar",
        "cl",
        "sg",
        "hk",
        "tw",
        "my",
        "th",
        "ph",
        "pk",
        "bd",
        "ng",
        "ke",
        "et",
        "eg",
    ]
)
INTERNAL_SUFFIXES = (
    ".local",
    ".localdomain",
    ".internal",
    ".lan",
    ".corp",
    ".home.arpa",
    ".intranet",
)
PRIV_GROUP_TAG = re.compile(r"^group:(sudo|wheel|admin|adm|root)$")


@dataclass
class _Seen:
    first: datetime | None = None
    last: datetime | None = None
    event_ids: set[int] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)

    def add(self, event_id: int, ts: datetime | None, tag: str) -> None:
        self.event_ids.add(event_id)
        self.tags.add(tag)
        if ts is not None:
            self.first = ts if self.first is None or ts < self.first else self.first
            self.last = ts if self.last is None or ts > self.last else self.last


def normalize_ip(value: str | None) -> tuple[IOCType, str, bool] | None:
    """(type, canonical value, is_global) for a usable IP, else None."""
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return None
    kind = IOCType.IPV4 if addr.version == 4 else IOCType.IPV6
    return kind, str(addr), addr.is_global


def is_internal_domain(domain: str, extra_suffixes: tuple[str, ...] = ()) -> bool:
    d = domain.lower().rstrip(".")
    if "." not in d:
        return True
    suffixes = INTERNAL_SUFFIXES + tuple("." + s.lstrip(".").lower() for s in extra_suffixes)
    return any(d.endswith(s) or d == s[1:] for s in suffixes)


def _clean_url(url: str) -> str:
    return url.rstrip(".,:'\"")


def extract_from_record(rec: dict[str, Any]) -> list[tuple[IOCType, str, str]]:
    """(type, value, how-seen tag) candidates from one event."""
    out: list[tuple[IOCType, str, str]] = []

    def add_ip(value: str | None, tag: str) -> None:
        if norm := normalize_ip(value):
            kind, canonical, is_global = norm
            out.append((kind, canonical, tag))
            if not is_global:
                out.append((kind, canonical, "private"))

    add_ip(rec.get("src_ip"), "src_ip")
    add_ip(rec.get("dst_ip"), "dst_ip")
    extra = rec.get("extra") or {}
    for xff in str(extra.get("x_forwarded_for") or "").split(","):
        add_ip(xff, "x_forwarded_for")

    command = rec.get("command") or ""
    texts = [t for t in (rec.get("raw") or "", command, rec.get("target") or "") if t]
    texts += [str(v) for k, v in extra.items() if k in ("referer", "url", "request") and v]
    for text in texts:
        for ip in _IPV4.findall(text):
            add_ip(ip, "text")
        for url in _URL.findall(text):
            url = _clean_url(url)
            out.append((IOCType.URL, url, "url"))
            host = urlsplit(url).hostname or ""
            if host and normalize_ip(host) is None and "." in host:
                out.append((IOCType.DOMAIN, host.lower().rstrip("."), "url_host"))

    if command:
        for h in _SHA256.findall(command):
            out.append((IOCType.SHA256, h.lower(), "command"))
        for h in _MD5.findall(command):
            out.append((IOCType.MD5, h.lower(), "command"))
        for m in _FQDN.finditer(command):
            if m[2].lower() in COMMON_TLDS and normalize_ip(m[1]) is None:
                out.append((IOCType.DOMAIN, m[1].lower(), "command"))
    path_sources = [command, str(extra.get("exe") or ""), str(extra.get("name") or "")]
    for text in path_sources:
        for p in _TMP_PATH.findall(text):
            out.append((IOCType.PATH, p.rstrip(".,"), "tmp_path"))

    etype = rec.get("event_type")
    target = rec.get("target")
    if target and etype == "user.create":
        out.append((IOCType.USERNAME, str(target), "user_created"))
    privileged = any(PRIV_GROUP_TAG.match(t) for t in rec.get("tags") or [])
    if target and etype == "group.modify" and privileged:
        out.append((IOCType.USERNAME, str(target), "added_to_privileged_group"))
    return out


def _finding_links(session: Any) -> dict[int, set[int]]:
    rows = session.execute(
        select(finding_events.c.event_id, finding_events.c.finding_id)
        .join(Finding, Finding.id == finding_events.c.finding_id)
        .where(Finding.status != FindingStatus.REJECTED)
    ).all()
    links: dict[int, set[int]] = defaultdict(set)
    for event_id, finding_id in rows:
        links[event_id].add(finding_id)
    return links


def extract_iocs(handle: CaseHandle, *, internal_domains: tuple[str, ...] = ()) -> dict[str, Any]:
    """Rebuild the case's IOC table from its events, keeping earlier enrichment results."""
    seen: dict[tuple[IOCType, str], _Seen] = defaultdict(_Seen)
    with handle.session() as s:
        cols = (
            Event.id,
            Event.timestamp_utc,
            Event.event_type,
            Event.src_ip,
            Event.dst_ip,
            Event.command,
            Event.target,
            Event.raw,
            Event.tags,
            Event.extra,
        )
        for row in s.execute(select(*cols).order_by(Event.id).execution_options(yield_per=5000)):
            rec = row._asdict()
            for kind, value, tag in extract_from_record(rec):
                seen[(kind, value)].add(rec["id"], rec["timestamp_utc"], tag)

        for (kind, value), info in seen.items():
            if kind == IOCType.DOMAIN and is_internal_domain(value, internal_domains):
                info.tags.add("internal")

        links = _finding_links(s)
        existing = {(i.type, i.value): i for i in s.scalars(select(IOC))}
        created = updated = 0
        for key in sorted(seen, key=lambda k: (k[0].value, k[1])):
            info = seen[key]
            ioc = existing.pop(key, None)
            if ioc is None:
                ioc = IOC(type=key[0], value=key[1], enrichment={})
                s.add(ioc)
                created += 1
            else:
                updated += 1
            ioc.first_seen, ioc.last_seen = info.first, info.last
            ioc.event_count = len(info.event_ids)
            ioc.tags = sorted(info.tags)
            ioc.finding_ids = sorted({f for e in info.event_ids for f in links.get(e, ())}) or None
            s.flush()
            s.execute(delete(ioc_events).where(ioc_events.c.ioc_id == ioc.id))
            ids = sorted(info.event_ids)[:MAX_EVENT_LINKS]
            if ids:
                s.execute(insert(ioc_events), [{"ioc_id": ioc.id, "event_id": e} for e in ids])
        for stale in existing.values():
            s.delete(stale)
        counts: dict[str, int] = defaultdict(int)
        for kind, _ in seen:
            counts[kind.value] += 1
        in_findings = sum(1 for k in seen if any(links.get(e) for e in seen[k].event_ids))
        audit.record(
            s,
            "ioc.extract",
            total=len(seen),
            by_type=dict(counts),
            in_findings=in_findings,
            created=created,
            removed=len(existing),
        )
    return {
        "total": len(seen),
        "by_type": dict(counts),
        "in_findings": in_findings,
        "created": created,
        "updated": updated,
        "removed": len(existing),
    }
