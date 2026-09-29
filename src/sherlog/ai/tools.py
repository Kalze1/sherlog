"""The constrained tool interface offered to the AI assistant.

Exactly these tools exist: search_events, pivot_on_ioc, get_timeline_window,
list_artifacts, run_rule, propose_finding, propose_hypothesis and
request_enrichment. They read the case database through the same code as the
CLI; only propose_* write, and only as AI-proposed findings or hypotheses.
Arguments arrive already de-pseudonymized; results are redacted by the caller.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import select

from sherlog.ai.providers import ToolSpec
from sherlog.core.case import CaseHandle
from sherlog.core.errors import SherlogError
from sherlog.core.models import IOC, AIHypothesis, Event, Finding
from sherlog.core.timeline import TimelineQuery, parse_time, query_events
from sherlog.core.timeutil import iso, utcnow
from sherlog.core.vocab import FindingStatus, IOCType, Severity, VerifiedBy
from sherlog.detection.attack import TECHNIQUE_RE, load_bundle
from sherlog.detection.correlation import Match, run_correlation
from sherlog.detection.engine import iter_records, rule_with_dependencies
from sherlog.detection.sigma import load_rules
from sherlog.enrichment.policy import blocked_reason
from sherlog.enrichment.summary import intel_summary
from sherlog.identify.service import list_artifacts

MAX_EVENTS = 50
MAX_PROPOSED_EVENTS = 200


class ToolError(SherlogError):
    """A tool call was invalid; the message is returned to the model."""


_TIME = {"type": "string", "description": "ISO 8601 time; UTC if no offset."}
TOOL_SPECS = [
    ToolSpec(
        "search_events",
        "Search the normalized event timeline. All filters are optional and combined with AND. "
        "Returns matching events in time order with their ids, the total match count, and the "
        "source file and line of each event.",
        {
            "type": "object",
            "properties": {
                "event_type": {
                    "type": "string",
                    "description": "Event type or prefix, e.g. auth.login, auth.login.failure, "
                    "user.create, shell.command, web.request, process.exec, cron.",
                },
                "actor": {"type": "string", "description": "Exact user/actor name."},
                "ip": {"type": "string", "description": "Source or destination IP address."},
                "host": {"type": "string", "description": "Host name recorded in the log."},
                "artifact_type": {"type": "string", "description": "e.g. linux.auth, web.access."},
                "text": {
                    "type": "string",
                    "description": "Case-insensitive regular expression matched against the "
                    "raw line.",
                },
                "start": _TIME,
                "end": _TIME,
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_EVENTS, "default": 20},
            },
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        "pivot_on_ioc",
        "Everything known about one indicator (IP, domain, URL, hash, path or username): "
        "threat-intel verdict, the findings it appears in and the events that contain it.",
        {
            "type": "object",
            "properties": {"value": {"type": "string", "description": "The indicator value."}},
            "required": ["value"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        "get_timeline_window",
        "All events between two times (inclusive), in order. Use it to see what happened "
        "immediately before and after an event of interest.",
        {
            "type": "object",
            "properties": {
                "start": _TIME,
                "end": _TIME,
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_EVENTS, "default": 30},
            },
            "required": ["start", "end"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        "list_artifacts",
        "The evidence files in the case: artifact type, parse status, event and parse-error "
        "counts. Unclassified or unsupported files were not analyzed.",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
    ToolSpec(
        "run_rule",
        "Run one detection rule (by name or id, as in the findings' rule field) over the "
        "whole timeline and return its matches, without creating findings.",
        {
            "type": "object",
            "properties": {"rule_id": {"type": "string"}},
            "required": ["rule_id"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        "propose_finding",
        "Propose a finding for the analyst to review. It is stored as AI-proposed, never as "
        "confirmed. Every claim in the narrative must be supported by the listed event_ids, "
        "which must exist; cite them in the narrative.",
        {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "One line, specific."},
                "severity": {"type": "string", "enum": [s.value for s in Severity]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "narrative": {
                    "type": "string",
                    "description": "What the events show, which parts are inference, and caveats.",
                },
                "event_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "minItems": 1,
                    "maxItems": MAX_PROPOSED_EVENTS,
                },
                "attack_techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "MITRE ATT&CK technique ids such as T1110.001.",
                },
                "recommendations": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["title", "severity", "confidence", "narrative", "event_ids"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        "propose_hypothesis",
        "Record a hypothesis that the evidence suggests but does not prove, with the checks "
        "that would confirm or refute it. Hypotheses are never findings.",
        {
            "type": "object",
            "properties": {
                "statement": {"type": "string"},
                "rationale": {"type": "string"},
                "supporting_event_ids": {"type": "array", "items": {"type": "integer"}},
                "suggested_checks": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["statement", "rationale"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        "request_enrichment",
        "Ask for a threat-intelligence lookup of one extracted indicator (public IP, domain or "
        "hash). Refused when SherLog is offline, has no API keys, or policy forbids sending it.",
        {
            "type": "object",
            "properties": {"ioc": {"type": "string", "description": "Indicator value."}},
            "required": ["ioc"],
            "additionalProperties": False,
        },
    ),
]


def compact_event(e: dict[str, Any]) -> dict[str, Any]:
    """A token-efficient event view for the model."""
    out = {
        "id": e["id"],
        "time_utc": e["timestamp_utc"],
        "type": e["event_type"],
        "host": e["host"],
        "actor": e["actor"],
        "src_ip": e["src_ip"],
        "dst_ip": e["dst_ip"],
        "target": e["target"],
        "command": e["command"],
        "raw": (e["raw"] or "")[:400],
        "source": f"{e['source']['rel_path']}:{e['source']['line_number']}",
    }
    if e.get("timezone_assumed"):
        out["tz_assumed"] = True
    if any(t == "year_inferred" for t in e.get("tags") or []):
        out["year_inferred"] = True
    return {k: v for k, v in out.items() if v not in (None, "")}


@dataclass
class ToolContext:
    """Executes tool calls against one case for one AI run."""

    handle: CaseHandle
    run_id: int
    model: str
    offline: bool = False
    enrich: Callable[[str], dict[str, Any]] | None = None
    created_findings: list[int] = field(default_factory=list)
    created_hypotheses: list[int] = field(default_factory=list)

    def execute(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        handler = getattr(self, f"_t_{name}", None)
        if handler is None:
            raise ToolError(f"Unknown tool {name!r}")
        if "_invalid_json" in args:
            raise ToolError("Tool arguments were not valid JSON")
        return handler(args)

    # --- read-only tools ----------------------------------------------------------------------

    @staticmethod
    def _limit(args: dict[str, Any], default: int) -> int:
        try:
            return max(1, min(MAX_EVENTS, int(args.get("limit") or default)))
        except (TypeError, ValueError) as exc:
            raise ToolError("limit must be an integer") from exc

    def _t_search_events(self, a: dict[str, Any]) -> dict[str, Any]:
        text = a.get("text")
        if text:
            try:
                re.compile(text)
            except re.error as exc:
                raise ToolError(f"Invalid regular expression: {exc}") from exc
        q = TimelineQuery(
            start=parse_time(a["start"]) if a.get("start") else None,
            end=parse_time(a["end"]) if a.get("end") else None,
            grep=text or None,
            types=[a["event_type"]] if a.get("event_type") else [],
            artifact=a.get("artifact_type"),
            actor=a.get("actor"),
            ip=a.get("ip"),
            host=a.get("host"),
            limit=self._limit(a, 20),
        )
        events, total = query_events(self.handle, q)
        return {
            "total_matches": total,
            "returned": len(events),
            "events": [compact_event(e) for e in events],
        }

    def _t_get_timeline_window(self, a: dict[str, Any]) -> dict[str, Any]:
        start, end = parse_time(a["start"]), parse_time(a["end"])
        if end < start:
            raise ToolError("end is before start")
        events, total = query_events(
            self.handle, TimelineQuery(start=start, end=end, limit=self._limit(a, 30))
        )
        return {
            "total_in_window": total,
            "returned": len(events),
            "events": [compact_event(e) for e in events],
        }

    def _t_list_artifacts(self, a: dict[str, Any]) -> dict[str, Any]:
        rows = list_artifacts(self.handle)
        return {
            "artifacts": [
                {
                    "file": r["rel_path"],
                    "type": r["artifact_type"],
                    "status": r["status"],
                    "events": r["event_count"],
                    "parse_errors": r["parse_error_count"],
                }
                for r in rows
            ]
        }

    def _t_pivot_on_ioc(self, a: dict[str, Any]) -> dict[str, Any]:
        value = str(a.get("value") or "").strip()
        if not value:
            raise ToolError("value is required")
        with self.handle.session() as s:
            ioc = s.scalars(select(IOC).where(IOC.value == value)).first()
            info: dict[str, Any] = {"value": value}
            event_ids: list[int] = []
            if ioc is not None:
                info.update(
                    type=str(ioc.type),
                    verdict=str(ioc.verdict),
                    intel=intel_summary(ioc.enrichment or {}),
                    finding_ids=ioc.finding_ids or [],
                    first_seen=iso(ioc.first_seen),
                    last_seen=iso(ioc.last_seen),
                    total_events=ioc.event_count,
                )
                event_ids = [e.id for e in ioc.events][:25]
            else:
                info["note"] = "not an extracted IOC; showing events whose raw text contains it"
        if event_ids:
            events, _ = query_events(self.handle, TimelineQuery(ids=event_ids, limit=25))
        else:
            events, _ = query_events(self.handle, TimelineQuery(grep=re.escape(value), limit=25))
        info["events"] = [compact_event(e) for e in events[:25]]
        return info

    def _t_run_rule(self, a: dict[str, Any]) -> dict[str, Any]:
        ref = str(a.get("rule_id") or "")
        ruleset = load_rules()
        rule = ruleset.get(ref)
        if rule is None:
            raise ToolError(f"Unknown rule {ref!r}; use a rule_id from the findings")
        needed = rule_with_dependencies(ruleset, rule)
        base = [r for r in needed if not r.is_correlation]
        matches: dict[str, list[Match]] = {r.key: [] for r in needed}
        with self.handle.session() as s:
            tz = ZoneInfo(self.handle.case(s).timezone)
            for rec in iter_records(s, tz):
                for r in base:
                    if r.matches(rec):
                        matches[r.key].append(Match.from_record(r.key, rec))
        for r in needed:
            if r.is_correlation:
                matches[r.key] = run_correlation(r, matches)
        hits = matches[rule.key]
        return {
            "rule": {"id": rule.id, "title": rule.title, "level": str(rule.level)},
            "match_count": len(hits),
            "matches": [
                {
                    "time_utc": iso(m.timestamp),
                    "event_ids": list(m.event_ids[:30]),
                    "fields": {
                        k: v
                        for k, v in m.fields.items()
                        if k in ("src_ip", "actor", "host", "target", "count", "event_type")
                    },
                }
                for m in hits[:15]
            ],
        }

    # --- write tools --------------------------------------------------------------------------

    def _existing_events(self, ids: list[Any]) -> tuple[list[int], list[Any]]:
        clean: list[int] = []
        bad: list[Any] = []
        for i in ids:
            try:
                clean.append(int(i))
            except (TypeError, ValueError):
                bad.append(i)
        with self.handle.session() as s:
            found = set(s.scalars(select(Event.id).where(Event.id.in_(clean))))
        missing = [i for i in clean if i not in found] + bad
        return sorted(found), missing

    def _t_propose_finding(self, a: dict[str, Any]) -> dict[str, Any]:
        title = str(a.get("title") or "").strip()
        narrative = str(a.get("narrative") or "").strip()
        if not title or not narrative:
            raise ToolError("title and narrative are required")
        try:
            severity = Severity(str(a.get("severity", "")).lower())
        except ValueError as exc:
            raise ToolError(f"severity must be one of {[s.value for s in Severity]}") from exc
        try:
            confidence = float(a.get("confidence"))  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ToolError("confidence must be a number between 0 and 1") from exc
        if not 0 <= confidence <= 1:
            raise ToolError("confidence must be between 0 and 1")
        ids = a.get("event_ids") or []
        if not isinstance(ids, list) or not ids:
            raise ToolError("event_ids is required: cite the events that support the finding")
        if len(ids) > MAX_PROPOSED_EVENTS:
            raise ToolError(f"at most {MAX_PROPOSED_EVENTS} event_ids")
        found, missing = self._existing_events(ids)
        if missing:
            raise ToolError(
                f"Rejected: event ids {missing[:20]} do not exist. Only cite ids returned by the "
                "tools. The finding was not created."
            )
        bundle = load_bundle()
        techniques: list[str] = []
        unknown: list[str] = []
        for t in a.get("attack_techniques") or []:
            tid = str(t).strip().upper()
            (techniques if TECHNIQUE_RE.match(tid) and bundle.get(tid) else unknown).append(tid)
        fingerprint = hashlib.sha256(
            ("ai\x1f" + title.lower() + "\x1f" + ",".join(map(str, found))).encode()
        ).hexdigest()
        with self.handle.session() as s:
            existing = s.scalars(select(Finding).where(Finding.fingerprint == fingerprint)).first()
            if existing is not None:
                if existing.id not in self.created_findings:
                    self.created_findings.append(existing.id)
                return {"finding_id": existing.id, "status": "already proposed (duplicate ignored)"}
            events = list(s.scalars(select(Event).where(Event.id.in_(found))))
            times = [e.timestamp_utc for e in events if e.timestamp_utc]
            f = Finding(
                title=title,
                severity=severity,
                confidence=confidence,
                verified_by=VerifiedBy.AI_PROPOSED,
                rule_id=f"ai.run.{self.run_id}",
                attack_techniques=techniques,
                cves=[],
                narrative=narrative,
                recommendations=[str(r) for r in a.get("recommendations") or []],
                created_at=utcnow(),
                updated_at=utcnow(),
                status=FindingStatus.OPEN,
                fingerprint=fingerprint,
                context={"proposed_by": "ai", "run_id": self.run_id, "model": self.model},
                first_seen=min(times) if times else None,
                last_seen=max(times) if times else None,
                event_count=len(events),
            )
            f.events = events
            s.add(f)
            s.flush()
            fid = f.id
        self.created_findings.append(fid)
        out: dict[str, Any] = {
            "finding_id": fid,
            "status": "created as AI-proposed; the analyst will accept or reject it",
        }
        if unknown:
            out["dropped_techniques"] = unknown
            out["note"] = "Techniques not in SherLog's ATT&CK set were dropped."
        return out

    def _t_propose_hypothesis(self, a: dict[str, Any]) -> dict[str, Any]:
        statement = str(a.get("statement") or "").strip()
        if not statement:
            raise ToolError("statement is required")
        found, missing = self._existing_events(a.get("supporting_event_ids") or [])
        with self.handle.session() as s:
            h = AIHypothesis(
                run_id=self.run_id,
                statement=statement,
                rationale=str(a.get("rationale") or "").strip() or None,
                event_ids=found,
                suggested_checks=[str(c) for c in a.get("suggested_checks") or []],
                created_at=utcnow(),
            )
            s.add(h)
            s.flush()
            hid = h.id
        self.created_hypotheses.append(hid)
        out: dict[str, Any] = {"hypothesis_id": hid, "status": "recorded (unverified)"}
        if missing:
            out["ignored_event_ids"] = missing[:20]
        return out

    def _t_request_enrichment(self, a: dict[str, Any]) -> dict[str, Any]:
        value = str(a.get("ioc") or "").strip()
        if self.offline:
            raise ToolError("Refused: SherLog is running offline; no external lookups.")
        with self.handle.session() as s:
            ioc = s.scalars(select(IOC).where(IOC.value == value)).first()
            if ioc is None:
                raise ToolError("Not an extracted IOC; use pivot_on_ioc to see known indicators.")
            reason = blocked_reason(IOCType(ioc.type), ioc.tags)
        if reason:
            raise ToolError(f"Refused by privacy policy: {reason}.")
        if self.enrich is None:
            raise ToolError("Enrichment is not available in this run.")
        result = self.enrich(value)
        with self.handle.session() as s:
            ioc = s.scalars(select(IOC).where(IOC.value == value)).one()
            return {
                "value": value,
                "verdict": str(ioc.verdict),
                "intel": intel_summary(ioc.enrichment or {}) or "no provider data",
                "providers": result.get("providers"),
            }
