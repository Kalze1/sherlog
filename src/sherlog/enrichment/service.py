"""Enrich a case's IOCs with GeoIP (local) and threat intelligence (AbuseIPDB, VirusTotal).

Order of checks for every IOC/provider pair:

1. egress policy (never send usernames, paths, URLs, internal or private values);
2. cache (usable offline; ``--refresh`` bypasses it);
3. offline mode / missing API key -> skipped;
4. rate limiter (daily cap and spacing), then the live call.

Every decision is recorded in one audit entry for the run. Each IOC is
committed as soon as it is done, so an interrupted run keeps its progress.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from sherlog.core import audit
from sherlog.core.case import CaseHandle
from sherlog.core.config import get_setting
from sherlog.core.errors import SherlogError
from sherlog.core.models import IOC
from sherlog.core.timeutil import iso, utcnow
from sherlog.core.vocab import IOCType, Verdict
from sherlog.enrichment.cache import EnrichmentCache, QuotaExhausted, RateLimiter
from sherlog.enrichment.extract import extract_iocs
from sherlog.enrichment.geoip import open_geoip
from sherlog.enrichment.policy import blocked_reason
from sherlog.enrichment.providers import (
    PROVIDERS,
    TIMEOUT,
    HttpGet,
    NetworkError,
    Provider,
    combine_verdicts,
    urllib_get,
)

log = logging.getLogger(__name__)

# HTTP statuses that are worth caching (a definitive answer about the indicator).
_CACHEABLE = {200, 404}


def _settings(prefix: str) -> dict[str, Any]:
    return {
        "key": get_setting(f"enrichment.{prefix}_key"),
        "daily_limit": get_setting(f"enrichment.{prefix}_daily_limit"),
        "min_interval": get_setting(f"enrichment.{prefix}_min_interval"),
    }


def enrich_case(
    handle: CaseHandle,
    *,
    offline: bool | None = None,
    providers: list[str] | None = None,
    all_iocs: bool = False,
    enrich_private: bool = False,
    refresh: bool = False,
    ioc_values: list[str] | None = None,
    http_get: HttpGet = urllib_get,
    cache: EnrichmentCache | None = None,
    sleep: Callable[[float], None] = time.sleep,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Extract IOCs, then enrich them. Returns counts and per-provider status."""
    offline = bool(get_setting("offline", offline))
    internal = tuple(get_setting("enrichment.internal_domains") or ())
    extracted = extract_iocs(handle, internal_domains=internal)
    ttl = float(get_setting("enrichment.cache_ttl_hours")) * 3600

    wanted = providers or list(PROVIDERS)
    unknown = set(wanted) - set(PROVIDERS)
    if unknown:
        raise SherlogError(f"Unknown provider(s): {', '.join(sorted(unknown))}")
    own_cache = cache is None
    cache = cache or EnrichmentCache()

    active: dict[str, tuple[Provider | None, RateLimiter | None]] = {}
    provider_state: dict[str, str] = {}
    for name in wanted:
        cfg = _settings(name)
        provider = PROVIDERS[name](cfg["key"]) if cfg["key"] else None
        limiter = (
            RateLimiter(
                name,
                cache,
                min_interval=float(cfg["min_interval"]),
                daily_limit=int(cfg["daily_limit"]),
                sleep=sleep,
            )
            if provider
            else None
        )
        active[name] = (provider, limiter)
        if offline:
            provider_state[name] = "offline (cache only)"
        else:
            provider_state[name] = "ready" if provider else "no API key (cache only)"

    geo, geo_reason = open_geoip(get_setting("enrichment.geoip_db"))
    calls: list[dict[str, Any]] = []
    sources: Counter[str] = Counter()

    with handle.session() as s:
        stmt = select(IOC.id).order_by(IOC.type, IOC.value)
        if ioc_values is not None:
            stmt = stmt.where(IOC.value.in_(ioc_values))
        elif not all_iocs:
            stmt = stmt.where(IOC.finding_ids.is_not(None))
        ioc_ids = list(s.scalars(stmt))

    try:
        for n, ioc_id in enumerate(ioc_ids, 1):
            with handle.session() as s:
                ioc = s.get(IOC, ioc_id)
                assert ioc is not None
                kind, value = IOCType(ioc.type), ioc.value
                if progress:
                    progress(f"[{n}/{len(ioc_ids)}] {kind.value} {value}")
                enrichment: dict[str, Any] = dict(ioc.enrichment or {})
                reason = blocked_reason(kind, ioc.tags, enrich_private=enrich_private)
                verdicts: list[Verdict] = []

                is_ip = kind in (IOCType.IPV4, IOCType.IPV6)
                if geo and is_ip and (loc := geo.lookup(value)):
                    enrichment["geoip"] = {"source": str(geo.path), **loc}

                for name in wanted:
                    provider_cls = PROVIDERS[name]
                    if kind not in provider_cls.types:
                        continue
                    call = {"provider": name, "type": kind.value, "value": value}
                    if reason:
                        calls.append({**call, "source": "blocked", "reason": reason})
                        sources["blocked"] += 1
                        continue
                    cached = None if refresh else cache.get(name, kind.value, value, ttl)
                    provider, limiter = active[name]
                    if cached is not None:
                        status, body, fetched_at, source = (
                            cached.status,
                            cached.body,
                            cached.fetched_at,
                            "cache",
                        )
                    elif offline or provider is None or limiter is None:
                        why = "offline" if offline else "no API key"
                        calls.append({**call, "source": "skipped", "reason": why})
                        sources["skipped"] += 1
                        continue
                    elif provider_state[name] not in ("ready",):
                        calls.append({**call, "source": "skipped", "reason": provider_state[name]})
                        sources["skipped"] += 1
                        continue
                    else:
                        try:
                            limiter.acquire()
                            url, headers = provider.request(kind, value)
                            status, body = http_get(url, headers, TIMEOUT)
                        except QuotaExhausted as exc:
                            provider_state[name] = f"stopped: {exc}"
                            calls.append({**call, "source": "skipped", "reason": str(exc)})
                            sources["skipped"] += 1
                            continue
                        except NetworkError as exc:
                            calls.append({**call, "source": "error", "reason": str(exc)})
                            sources["error"] += 1
                            continue
                        source = "live"
                        if status in (401, 403):
                            provider_state[name] = f"stopped: authentication failed (HTTP {status})"
                        elif status == 429:
                            provider_state[name] = "stopped: rate limited by provider (HTTP 429)"
                        fetched_at = (
                            cache.put(name, kind.value, value, status, body)
                            if (status in _CACHEABLE)
                            else time.time()
                        )

                    sources[source] += 1
                    entry: dict[str, Any] = {
                        "fetched_at": iso(_ts(fetched_at)),
                        "http_status": status,
                        "cached": source == "cache",
                    }
                    if status == 200:
                        pv = PROVIDERS[name]("")
                        verdict, summary = pv.summarize(body)
                        entry.update(status="ok", verdict=verdict.value, summary=summary, raw=body)
                        verdicts.append(verdict)
                    elif status == 404:
                        entry.update(status="not_found", verdict=Verdict.UNKNOWN.value)
                    else:
                        entry.update(status="error", error=_error_text(body))
                    enrichment[name] = entry
                    calls.append(
                        {
                            **call,
                            "source": source,
                            "http_status": status,
                            "verdict": entry.get("verdict"),
                        }
                    )

                if reason:
                    enrichment["egress"] = {"blocked": reason}
                else:
                    enrichment.pop("egress", None)
                prior = [
                    Verdict(e["verdict"])
                    for k, e in enrichment.items()
                    if k in PROVIDERS and isinstance(e, dict) and e.get("status") == "ok"
                ]
                ioc.enrichment = enrichment
                ioc.verdict = combine_verdicts(prior or verdicts)
    finally:
        if geo:
            geo.close()
        if own_cache:
            cache.close()

    with handle.session() as s:
        verdict_counts = Counter(
            str(v) for v in s.scalars(select(IOC.verdict).where(IOC.id.in_(ioc_ids)))
        )
        audit.record(
            s,
            "enrich",
            offline=offline,
            providers=provider_state,
            iocs_considered=len(ioc_ids),
            all_iocs=all_iocs,
            enrich_private=enrich_private,
            refresh=refresh,
            geoip=None if geo else geo_reason,
            sources=dict(sources),
            verdicts=dict(verdict_counts),
            calls=calls,
            at=iso(utcnow()),
        )
    return {
        "extracted": extracted,
        "iocs_considered": len(ioc_ids),
        "offline": offline,
        "providers": provider_state,
        "geoip": "enabled" if geo else geo_reason,
        "lookups": dict(sources),
        "verdicts": dict(verdict_counts),
    }


def _ts(value: float) -> datetime:
    return datetime.fromtimestamp(value, UTC)


def _error_text(body: Any) -> str | None:
    if isinstance(body, dict):
        errors = body.get("errors") or body.get("error")
        if errors:
            return str(errors)[:300]
    return None


def list_iocs(
    handle: CaseHandle, *, all_iocs: bool = False, verdict: Verdict | None = None
) -> list[dict[str, Any]]:
    """IOCs (finding-linked only unless ``all_iocs``) with summaries, most severe first."""
    rank = {"malicious": 0, "suspicious": 1, "clean": 2, "unknown": 3}
    with handle.session() as s:
        stmt = select(IOC)
        if not all_iocs:
            stmt = stmt.where(IOC.finding_ids.is_not(None))
        if verdict is not None:
            stmt = stmt.where(IOC.verdict == verdict)
        rows = list(s.scalars(stmt))
        out = [ioc_to_dict(i) for i in rows]
    out.sort(key=lambda d: (rank.get(d["verdict"], 9), d["type"], d["value"]))
    return out


def ioc_to_dict(i: IOC, *, include_raw: bool = False) -> dict[str, Any]:
    """Serialize an IOC; provider raw responses only on request (they are large)."""
    enrichment = {}
    for name, entry in (i.enrichment or {}).items():
        if isinstance(entry, dict) and not include_raw:
            entry = {k: v for k, v in entry.items() if k != "raw"}
        enrichment[name] = entry
    return {
        "id": i.id,
        "type": str(i.type),
        "value": i.value,
        "verdict": str(i.verdict),
        "first_seen": iso(i.first_seen),
        "last_seen": iso(i.last_seen),
        "event_count": i.event_count,
        "finding_ids": i.finding_ids or [],
        "tags": i.tags or [],
        "enrichment": enrichment,
    }
