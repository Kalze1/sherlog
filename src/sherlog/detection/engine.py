"""Detection engine: run Sigma rules, correlations and analytics over a case.

Findings are grouped so that one finding describes one entity's burst of
activity ("SSH brute force from 203.0.113.50: 143 failures 23:58-00:05")
rather than one row per matching line. Matches of a base rule are grouped by
the rule's ``x-sherlog.group_by`` fields and split where consecutive matches
are further apart than ``cluster_gap``.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from sherlog.core import audit
from sherlog.core.case import CaseHandle
from sherlog.core.config import get_setting
from sherlog.core.errors import SherlogError
from sherlog.core.models import Event
from sherlog.core.timeutil import iso
from sherlog.detection.analytics import run_analytics
from sherlog.detection.correlation import Match, evidence_refs, run_correlation, run_ruleset
from sherlog.detection.findings import FindingDraft, fingerprint_for, store_drafts
from sherlog.detection.sigma import Record, Rule, RuleSet, build_ruleset, load_rule_file, load_rules
from sherlog.enrichment.extract import extract_iocs
from sherlog.identify.sample import read_sample
from sherlog.identify.service import identify_sample
from sherlog.parsers.base import ParseContext, ParsedEvent
from sherlog.parsers.service import parse_case

log = logging.getLogger(__name__)

DEFAULT_GAP_THRESHOLD = timedelta(hours=6)
MAX_EVIDENCE_REFS = 5


# --- records ----------------------------------------------------------------------------------


def _derived(ts: datetime | None, tz: ZoneInfo) -> dict[str, Any]:
    if ts is None:
        return {"hour_local": None, "weekday_local": None, "hour_utc": None}
    local = ts.astimezone(tz)
    return {"hour_local": local.hour, "weekday_local": local.weekday(), "hour_utc": ts.hour}


def record_from_event(e: Event, tz: ZoneInfo) -> Record:
    """Matcher view of a stored event."""
    return {
        "id": e.id,
        "timestamp_utc": e.timestamp_utc,
        "timestamp_raw": e.timestamp_raw,
        "timezone_assumed": e.timezone_assumed,
        "host": e.host,
        "artifact_type": e.artifact_type,
        "event_type": e.event_type,
        "actor": e.actor,
        "src_ip": e.src_ip,
        "dst_ip": e.dst_ip,
        "target": e.target,
        "command": e.command,
        "raw": e.raw,
        "tags": list(e.tags or []),
        "extra": dict(e.extra or {}),
        "line_number": e.line_number,
        "source_rel_path": e.source_file.rel_path,
        "source_sha256": e.source_file.sha256,
        **_derived(e.timestamp_utc, tz),
    }


def record_from_parsed(
    pe: ParsedEvent, index: int, tz: ZoneInfo, artifact_type: str, rel_path: str, sha256: str | None
) -> Record:
    """Matcher view of a freshly parsed event (``rules test``, no database)."""
    return {
        "id": index,
        "timestamp_utc": pe.timestamp_utc,
        "timestamp_raw": pe.timestamp_raw,
        "timezone_assumed": pe.timezone_assumed,
        "host": pe.host,
        "artifact_type": artifact_type,
        "event_type": pe.event_type,
        "actor": pe.actor,
        "src_ip": pe.src_ip,
        "dst_ip": pe.dst_ip,
        "target": pe.target,
        "command": pe.command,
        "raw": pe.raw,
        "tags": list(pe.tags),
        "extra": dict(pe.extra or {}),
        "line_number": pe.line_number,
        "source_rel_path": rel_path,
        "source_sha256": sha256,
        **_derived(pe.timestamp_utc, tz),
    }


def iter_records(session: Session, tz: ZoneInfo) -> Iterator[Record]:
    """Stream all events in timeline order."""
    stmt = (
        select(Event)
        .options(joinedload(Event.source_file))
        .order_by(Event.timestamp_utc.is_(None), Event.timestamp_utc, Event.id)
        .execution_options(yield_per=2000)
    )
    for e in session.scalars(stmt):
        yield record_from_event(e, tz)


# --- findings from matches --------------------------------------------------------------------


def entity_label(fields: dict[str, Any], group_by: tuple[str, ...]) -> str:
    """Human phrase for what a finding is about, e.g. 'from 203.0.113.50 by root on web01'."""
    parts = []
    phrases = {
        "src_ip": "from {}",
        "actor": "by {}",
        "host": "on {}",
        "target": "target {}",
        "dst_ip": "to {}",
    }
    for name in (*group_by, "host"):
        value = fields.get(name)
        if value is not None and name in phrases and phrases[name].format(value) not in parts:
            parts.append(phrases[name].format(value))
    return " ".join(parts)


def _cluster_by_gap(matches: list[Match], gap: timedelta) -> list[list[Match]]:
    dated = sorted(
        (m for m in matches if m.timestamp is not None), key=lambda m: (m.timestamp, m.event_ids)
    )
    undated = sorted((m for m in matches if m.timestamp is None), key=lambda m: m.event_ids)
    clusters: list[list[Match]] = []
    for m in dated:
        if clusters and m.timestamp - clusters[-1][-1].timestamp <= gap:  # type: ignore[operator]
            clusters[-1].append(m)
        else:
            clusters.append([m])
    if undated:
        clusters.append(undated)
    return clusters


def _draft(
    rule: Rule, cluster: list[Match], fields: dict[str, Any], group_by: tuple[str, ...]
) -> FindingDraft:
    event_ids = [eid for m in cluster for eid in m.event_ids]
    # Correlation matches carry their own window; base matches are single events.
    dated = [
        t
        for m in cluster
        for t in (m.fields.get("first_seen"), m.fields.get("last_seen"), m.timestamp)
        if t is not None
    ]
    first, last = (min(dated), max(dated)) if dated else (None, None)
    entity = entity_label(fields, group_by)
    count = fields.get("count", len(event_ids))
    when = (
        f"between {iso(first)} and {iso(last)}"
        if first and last and first != last
        else f"at {iso(first)}"
        if first
        else "(undated evidence)"
    )
    refs = evidence_refs(cluster, MAX_EVIDENCE_REFS)
    extra = len(event_ids) - len(refs)
    more = f" and {extra} more" if refs and extra > 0 else ""
    narrative = (
        f"{rule.description}\n\n"
        f"Rule '{rule.title}' matched {count} event(s) {when}"
        f"{' ' + entity if entity else ''}."
        + (f" Evidence: {', '.join(refs)}{more}." if refs else "")
    )
    if rule.falsepositives:
        narrative += "\n\nKnown false positives: " + "; ".join(rule.falsepositives) + "."
    context = {
        "rule_uuid": rule.id,
        "rule_name": rule.name,
        "entity": {k: fields[k] for k in (*group_by, "host") if fields.get(k) is not None},
        "count": count,
        "sources": sorted(
            {str(m.fields["source_rel_path"]) for m in cluster if m.fields.get("source_rel_path")}
            | {s for m in cluster for s in m.fields.get("sources", [])}
        ),
    }
    for extra_key in ("peak_in_window", "sequence"):
        if extra_key in fields:
            context[extra_key] = fields[extra_key]
    for k, v in fields.items():
        if k.startswith("distinct_"):
            context[k] = v
    first_ref = cluster[0]
    key_ref = f"{first_ref.fields.get('source_sha256')}:{first_ref.fields.get('line_number')}"
    entity_key = "|".join(f"{k}={fields.get(k)}" for k in group_by)
    return FindingDraft(
        rule_id=rule.key,
        title=f"{rule.title}{' — ' + entity if entity else ''}",
        severity=rule.level,
        confidence=rule.confidence,
        techniques=list(rule.techniques),
        recommendations=[rule.recommendation],
        narrative=narrative,
        context=context,
        event_ids=event_ids,
        event_count=len(event_ids),
        first_seen=first,
        last_seen=last,
        fingerprint=fingerprint_for(rule.id, entity_key, key_ref),
    )


def drafts_from_matches(rule: Rule, matches: list[Match]) -> list[FindingDraft]:
    """Turn a rule's matches into findings (one per correlation hit, or per entity burst)."""
    if not matches:
        return []
    if rule.correlation is not None:
        group_by = rule.correlation.group_by
        return [_draft(rule, [m], m.fields, group_by) for m in matches]
    groups: dict[tuple[Any, ...], list[Match]] = defaultdict(list)
    for m in matches:
        groups[tuple(m.fields.get(g) for g in rule.group_by)].append(m)
    drafts = []
    for key, members in sorted(groups.items(), key=lambda kv: str(kv[0])):
        fields = dict(zip(rule.group_by, key, strict=True))
        hosts = {m.fields.get("host") for m in members} - {None}
        if len(hosts) == 1:
            fields["host"] = hosts.pop()
        for cluster in _cluster_by_gap(members, rule.cluster_gap):
            drafts.append(
                _draft(
                    rule,
                    cluster,
                    {**fields, "count": sum(len(m.event_ids) for m in cluster)},
                    rule.group_by,
                )
            )
    return drafts


# --- analyze ----------------------------------------------------------------------------------


def analyze_case(
    handle: CaseHandle,
    rules_dirs: list[Path] | None = None,
    *,
    gap_threshold: timedelta = DEFAULT_GAP_THRESHOLD,
    reparse: bool = False,
    overrides: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Parse if needed, then run all detections and store findings."""
    with handle.session() as s:
        n_events = s.scalar(select(func.count()).select_from(Event)) or 0
        case = handle.case(s)
        tz = ZoneInfo(case.timezone)
    parsed = None
    if reparse or n_events == 0:
        parsed = parse_case(handle, overrides, force=reparse)
        n_events = parsed["total_events"]
    if n_events == 0:
        raise SherlogError("no events to analyze; add evidence that SherLog can parse first")

    ruleset = load_rules(rules_dirs)
    with handle.session() as s:
        matches = run_ruleset(ruleset, iter_records(s, tz))
        drafts: list[FindingDraft] = []
        for rule in ruleset.rules:
            if rule.key in ruleset.suppressed:
                continue
            drafts += drafts_from_matches(rule, matches[rule.key])
        drafts += run_analytics(s, gap_threshold=gap_threshold)
        stored = store_drafts(s, drafts)
        s.flush()
        match_counts = {k: len(v) for k, v in matches.items() if v}
        audit.record(
            s,
            "analyze",
            events=n_events,
            reparsed=parsed is not None,
            rules={r.key: r.sha256[:16] for r in ruleset.rules},
            rule_matches=match_counts,
            findings=stored,
            gap_threshold_seconds=int(gap_threshold.total_seconds()),
        )
    # IOC extraction is local and needs the stored findings for its links.
    iocs = extract_iocs(
        handle, internal_domains=tuple(get_setting("enrichment.internal_domains") or ())
    )
    warnings = [f"{r.key}: {w}" for r in ruleset.rules for w in r.warnings]
    by_severity: dict[str, int] = defaultdict(int)
    for d in drafts:
        by_severity[str(d.severity)] += 1
    return {
        "events": n_events,
        "reparsed": parsed is not None,
        "rules_loaded": len(ruleset.rules),
        "rules_matched": match_counts,
        "findings": stored,
        "findings_by_severity": dict(by_severity),
        "rule_warnings": warnings,
        "iocs": iocs,
    }


# --- rules test -------------------------------------------------------------------------------


def rule_with_dependencies(ruleset: RuleSet, rule: Rule) -> list[Rule]:
    """The rule plus everything it (transitively) references, dependencies first."""
    out: list[Rule] = []
    seen: set[str] = set()

    def visit(r: Rule) -> None:
        if r.key in seen:
            return
        seen.add(r.key)
        if r.correlation:
            for ref in r.correlation.rules:
                dep = ruleset.get(ref)
                if dep is not None:
                    visit(dep)
        out.append(r)

    visit(rule)
    return out


def run_rule_test(
    rule_ref: str,
    path: Path,
    *,
    rules_dirs: list[Path] | None = None,
    tz: str = "UTC",
) -> dict[str, Any]:
    """Parse one evidence file (no case) and run one rule (and its dependencies) over it."""
    base = load_rules(rules_dirs)
    candidate = Path(rule_ref)
    if candidate.is_file():
        file_rules = load_rule_file(candidate)
        merged = {r.key: r for r in base.rules}
        merged.update({r.key: r for r in file_rules})
        ruleset = build_ruleset(list(merged.values()))
        rule = file_rules[0]
    else:
        ruleset = base
        found = ruleset.get(rule_ref)
        if found is None:
            raise SherlogError(f"Unknown rule {rule_ref!r}; pass a rule name, id or YAML path")
        rule = found

    path = path.expanduser().resolve()
    if not path.is_file():
        raise SherlogError(f"Not a file: {path}")
    ident = identify_sample(read_sample(path, path.stat().st_size))
    if ident.parser is None:
        raise SherlogError(f"{path.name}: unclassified (candidates: {ident.candidates or 'none'})")
    zone = ZoneInfo(tz)
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=zone)
    ctx = ParseContext(path=path, case_tz=zone, mtime=mtime)
    records = [
        record_from_parsed(pe, i, zone, ident.artifact_type, path.name, None)
        for i, pe in enumerate(ident.parser.parse(path, ctx), 1)
    ]
    needed = rule_with_dependencies(ruleset, rule)
    base_rules = [r for r in needed if not r.is_correlation]
    matches: dict[str, list[Match]] = {r.key: [] for r in needed}
    for rec in records:
        for r in base_rules:
            if r.matches(rec):
                matches[r.key].append(Match.from_record(r.key, rec))
    for r in needed:
        if r.is_correlation:
            matches[r.key] = run_correlation(r, matches)
    by_id = {r["id"]: r for r in records}
    hits = []
    for m in matches[rule.key]:
        hits.append(
            {
                "timestamp_utc": iso(m.timestamp),
                "line_numbers": [by_id[i]["line_number"] for i in m.event_ids][:50],
                "event_count": len(m.event_ids),
                "fields": {k: v for k, v in m.fields.items() if k not in ("source_sha256",)},
                "raw": [by_id[i]["raw"] for i in m.event_ids][:5],
            }
        )
    return {
        "rule": {
            "key": rule.key,
            "id": rule.id,
            "title": rule.title,
            "type": "correlation" if rule.is_correlation else "detection",
        },
        "file": str(path),
        "artifact_type": ident.artifact_type,
        "events": len(records),
        "dependency_matches": {r.key: len(matches[r.key]) for r in needed if r is not rule},
        "matches": hits,
    }
