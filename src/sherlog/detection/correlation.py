"""Evaluate base rules over event records and Sigma correlation rules over their matches."""

from __future__ import annotations

import itertools
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sherlog.detection.sigma import Correlation, Record, Rule, RuleSet

# Record fields carried on every match; correlations group by these and findings
# derive their entity ("from 203.0.113.50", "by deploy") from them.
MATCH_FIELDS = (
    "src_ip",
    "dst_ip",
    "actor",
    "host",
    "target",
    "event_type",
    "artifact_type",
    "source_rel_path",
    "source_sha256",
    "line_number",
)


@dataclass
class Match:
    """One rule hit: a single event for base rules, a group of events for correlations."""

    rule_key: str
    timestamp: datetime | None
    event_ids: tuple[int, ...]
    fields: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_record(cls, rule_key: str, record: Record) -> Match:
        fields = {k: record.get(k) for k in MATCH_FIELDS if record.get(k) is not None}
        return cls(rule_key, record.get("timestamp_utc"), (record["id"],), fields)


def match_base_rules(rules: Sequence[Rule], records: Iterable[Record]) -> dict[str, list[Match]]:
    """Run every base rule over every record (single pass)."""
    matches: dict[str, list[Match]] = {r.key: [] for r in rules}
    for record in records:
        for rule in rules:
            if rule.matches(record):
                matches[rule.key].append(Match.from_record(rule.key, record))
    return matches


def _group_key(m: Match, group_by: Sequence[str]) -> tuple[Any, ...] | None:
    key = tuple(m.fields.get(g) for g in group_by)
    return None if any(v is None for v in key) else key


def _grouped(
    matches: Iterable[Match], group_by: Sequence[str]
) -> dict[tuple[Any, ...], list[Match]]:
    groups: dict[tuple[Any, ...], list[Match]] = defaultdict(list)
    for m in matches:
        if m.timestamp is None:
            continue  # undated events cannot be placed in a time window
        key = _group_key(m, group_by)
        if key is not None:
            groups[key].append(m)
    for members in groups.values():
        members.sort(key=lambda m: (m.timestamp, m.event_ids))
    return groups


def _clusters(sorted_matches: list[Match], gap: Any) -> list[list[Match]]:
    """Split a time-ordered list where consecutive matches are more than ``gap`` apart."""
    out: list[list[Match]] = []
    for m in sorted_matches:
        if out and m.timestamp - out[-1][-1].timestamp <= gap:  # type: ignore[operator]
            out[-1].append(m)
        else:
            out.append([m])
    return out


def _compare(count: int, condition: dict[str, int]) -> bool:
    ops = {
        "gt": count > condition.get("gt", -1),
        "gte": count >= condition.get("gte", 0),
        "lt": count < condition.get("lt", 1 << 62),
        "lte": count <= condition.get("lte", 1 << 62),
        "eq": count == condition.get("eq", count),
    }
    return all(ops[k] for k in condition)


def _identity(m: Match) -> tuple[Any, ...]:
    """What makes two matches 'the same occurrence'.

    The same login failure is often recorded twice (auth.log and the journal,
    or btmp and audit.log). Counting distinct (time, actor, source, type)
    tuples keeps thresholds honest across duplicated sources.
    """
    return (m.timestamp, m.fields.get("actor"), m.fields.get("src_ip"), m.fields.get("event_type"))


def _max_window(cluster: list[Match], corr: Correlation) -> int:
    """Largest distinct count (or distinct-value count) inside any ``timespan`` window."""
    best, start = 0, 0
    for end in range(len(cluster)):
        while cluster[end].timestamp - cluster[start].timestamp > corr.timespan:  # type: ignore[operator]
            start += 1
        window = cluster[start : end + 1]
        if corr.field:
            count = len({m.fields.get(corr.field) for m in window} - {None})
        else:
            count = len({_identity(m) for m in window})
        best = max(best, count)
    return best


def _summary(key: tuple[Any, ...], corr: Correlation, cluster: list[Match]) -> dict[str, Any]:
    fields: dict[str, Any] = dict(zip(corr.group_by, key, strict=True))
    fields["count"] = len({_identity(m) for m in cluster})
    fields["raw_count"] = sum(len(m.event_ids) for m in cluster)
    fields["first_seen"] = cluster[0].timestamp
    fields["last_seen"] = cluster[-1].timestamp
    fields["evidence_refs"] = evidence_refs(cluster)
    fields["sources"] = sorted(
        {str(m.fields["source_rel_path"]) for m in cluster if m.fields.get("source_rel_path")}
        | {s for m in cluster for s in m.fields.get("sources", [])}
    )
    # Carry entity fields that are constant across the cluster (e.g. host).
    for name in ("host", "actor", "src_ip", "target"):
        if name not in fields:
            values = {m.fields.get(name) for m in cluster} - {None}
            if len(values) == 1:
                fields[name] = values.pop()
    return fields


def evidence_refs(matches: Iterable[Match], limit: int = 5) -> list[str]:
    """``path:line`` references for matches; correlation matches pass theirs through."""
    refs: list[str] = []
    for m in matches:
        if "evidence_refs" in m.fields:
            refs.extend(m.fields["evidence_refs"])
        elif m.fields.get("source_rel_path"):
            line = m.fields.get("line_number")
            path = m.fields["source_rel_path"]
            refs.append(f"{path}:{line}" if line is not None else str(path))
        if len(refs) >= limit:
            break
    return refs[:limit]


def _count_correlation(rule: Rule, matches: dict[str, list[Match]]) -> list[Match]:
    corr = rule.correlation
    assert corr is not None
    pooled = [m for ref in corr.rules for m in matches.get(ref, [])]
    out: list[Match] = []
    for key, members in sorted(_grouped(pooled, corr.group_by).items(), key=str):
        for cluster in _clusters(members, corr.timespan):
            peak = _max_window(cluster, corr)
            if not _compare(peak, corr.condition):
                continue
            fields = _summary(key, corr, cluster)
            fields["peak_in_window"] = peak
            if corr.field:
                fields["distinct_" + corr.field] = sorted(
                    {str(m.fields.get(corr.field)) for m in cluster} - {"None"}
                )
            event_ids = tuple(eid for m in cluster for eid in m.event_ids)
            out.append(Match(rule.key, cluster[-1].timestamp, event_ids, fields))
    return out


def _ordered_ok(window: list[Match], order: Sequence[str]) -> bool:
    first_index: dict[str, int] = {}
    for i, m in enumerate(window):
        first_index.setdefault(m.rule_key, i)
    positions = [first_index[r] for r in order if r in first_index]
    if len(positions) != len(order):
        return False
    return all(a < b for a, b in itertools.pairwise(positions))


def _temporal_correlation(rule: Rule, matches: dict[str, list[Match]]) -> list[Match]:
    corr = rule.correlation
    assert corr is not None
    pooled = [m for ref in corr.rules for m in matches.get(ref, [])]
    needed = set(corr.rules)
    out: list[Match] = []
    for key, members in sorted(_grouped(pooled, corr.group_by).items(), key=str):
        i = 0
        while i < len(members):
            j = i
            while (
                j < len(members) and members[j].timestamp - members[i].timestamp <= corr.timespan  # type: ignore[operator]
            ):
                j += 1
            window = members[i:j]
            present = {m.rule_key for m in window}
            ok = needed <= present and (
                corr.type != "temporal_ordered" or _ordered_ok(window, corr.rules)
            )
            if ok:
                fields = _summary(key, corr, window)
                fields["sequence"] = [m.rule_key for m in window]
                event_ids = tuple(eid for m in window for eid in m.event_ids)
                out.append(Match(rule.key, window[-1].timestamp, event_ids, fields))
                i = j  # do not report overlapping windows
            else:
                i += 1
    return out


def run_correlation(rule: Rule, matches: dict[str, list[Match]]) -> list[Match]:
    """Matches of one correlation rule, given matches of the rules it references."""
    assert rule.correlation is not None
    if rule.correlation.type in ("event_count", "value_count"):
        return _count_correlation(rule, matches)
    return _temporal_correlation(rule, matches)


def run_ruleset(ruleset: RuleSet, records: Iterable[Record]) -> dict[str, list[Match]]:
    """Evaluate all base rules over ``records`` and then all correlations, in dependency order."""
    matches = match_base_rules(ruleset.base_rules, records)
    for rule in ruleset.correlations:
        matches[rule.key] = run_correlation(rule, matches)
    return matches
