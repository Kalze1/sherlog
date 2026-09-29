"""Findings store: drafts produced by detection, persistence, listing and analyst review.

Rule findings are regenerated on every ``analyze`` run. Each carries a
``fingerprint`` (rule + key evidence) so that an analyst's accept/reject
decision and note survive re-analysis; open findings that no longer occur are
removed, reviewed ones are kept and marked stale.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from sherlog.core import audit
from sherlog.core.case import CaseHandle
from sherlog.core.errors import SherlogError
from sherlog.core.models import Event, Finding
from sherlog.core.timeline import event_to_dict
from sherlog.core.timeutil import iso, utcnow
from sherlog.core.vocab import FindingStatus, Severity, VerifiedBy
from sherlog.detection.attack import load_bundle

MAX_LINKED_EVENTS = 500
SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}  # info=0 ... critical=4


@dataclass
class FindingDraft:
    """A finding as produced by a rule, correlation or analytic, before storage."""

    rule_id: str
    title: str
    severity: Severity
    confidence: float
    techniques: list[str]
    recommendations: list[str]
    narrative: str
    context: dict[str, Any]
    event_ids: list[int]
    event_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    fingerprint: str
    verified_by: VerifiedBy = VerifiedBy.RULE
    cves: list[dict[str, str]] = field(default_factory=list)


def fingerprint_for(*parts: str) -> str:
    """Stable identity for a finding across runs."""
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def store_drafts(session: Session, drafts: list[FindingDraft]) -> dict[str, int]:
    """Upsert rule findings by fingerprint; prune open findings that disappeared."""
    existing = {
        f.fingerprint: f
        for f in session.scalars(
            select(Finding).where(
                Finding.verified_by == VerifiedBy.RULE, Finding.fingerprint.is_not(None)
            )
        )
    }
    now = utcnow()
    seen: set[str] = set()
    created = updated = 0
    for d in sorted(
        drafts, key=lambda d: (d.rule_id, iso(d.first_seen) or "~", d.title, d.fingerprint)
    ):
        if d.fingerprint in seen:
            continue  # two drafts for the same evidence: keep the first
        seen.add(d.fingerprint)
        f = existing.get(d.fingerprint)
        if f is None:
            f = Finding(verified_by=d.verified_by, created_at=now, status=FindingStatus.OPEN)
            created += 1
        else:
            updated += 1
        f.title = d.title
        f.severity = d.severity
        f.confidence = d.confidence
        f.rule_id = d.rule_id
        f.attack_techniques = list(d.techniques)
        f.cves = list(d.cves)
        f.narrative = d.narrative
        f.recommendations = list(d.recommendations)
        f.context = {k: v for k, v in d.context.items() if k != "stale"}
        f.first_seen = d.first_seen
        f.last_seen = d.last_seen
        f.event_count = d.event_count
        f.fingerprint = d.fingerprint
        f.updated_at = now
        ids = d.event_ids[:MAX_LINKED_EVENTS]
        f.events = list(session.scalars(select(Event).where(Event.id.in_(ids)))) if ids else []
        session.add(f)

    removed = stale = 0
    for fp, f in existing.items():
        if fp in seen:
            continue
        if f.status == FindingStatus.OPEN:
            session.delete(f)
            removed += 1
        else:
            f.context = {**(f.context or {}), "stale": True}
            stale += 1
    session.flush()
    return {"created": created, "updated": updated, "removed": removed, "stale": stale}


def finding_to_dict(f: Finding, *, include_events: bool = False) -> dict[str, Any]:
    """Serialize a finding (events only when asked, they can be large)."""
    bundle = load_bundle()
    techniques = []
    for tid in f.attack_techniques:
        t = bundle.get(tid)
        techniques.append(
            {
                "id": tid,
                "name": t.name if t else None,
                "tactics": list(t.tactics) if t else [],
                "url": t.url if t else None,
            }
        )
    out: dict[str, Any] = {
        "id": f.id,
        "title": f.title,
        "severity": str(f.severity),
        "confidence": f.confidence,
        "verified_by": str(f.verified_by),
        "status": str(f.status),
        "rule_id": f.rule_id,
        "attack_techniques": techniques,
        "cves": f.cves,
        "narrative": f.narrative,
        "recommendations": f.recommendations,
        "context": f.context or {},
        "first_seen": iso(f.first_seen),
        "last_seen": iso(f.last_seen),
        "event_count": f.event_count,
        "linked_events": len(f.events),
        "analyst_note": f.analyst_note,
        "created_at": iso(f.created_at),
        "updated_at": iso(f.updated_at),
    }
    if include_events:
        out["events"] = [event_to_dict(e) for e in f.events]
    return out


def list_findings(
    handle: CaseHandle,
    *,
    status: FindingStatus | None = None,
    min_severity: Severity | None = None,
    verified_by: VerifiedBy | None = None,
) -> list[dict[str, Any]]:
    """Findings ordered by severity (highest first), then time."""
    with handle.session() as s:
        stmt = select(Finding).options(selectinload(Finding.events))
        if status is not None:
            stmt = stmt.where(Finding.status == status)
        if verified_by is not None:
            stmt = stmt.where(Finding.verified_by == verified_by)
        rows = list(s.scalars(stmt))
    if min_severity is not None:
        rows = [f for f in rows if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min_severity]]
    rows.sort(
        key=lambda f: (
            -SEVERITY_ORDER[f.severity],
            f.first_seen is None,
            f.first_seen or f.created_at,
            f.id,
        )
    )
    return [finding_to_dict(f) for f in rows]


def get_finding(handle: CaseHandle, finding_id: int) -> dict[str, Any]:
    with handle.session() as s:
        f = s.get(
            Finding,
            finding_id,
            options=[selectinload(Finding.events).selectinload(Event.source_file)],
        )
        if f is None:
            raise SherlogError(f"No finding with id {finding_id}")
        return finding_to_dict(f, include_events=True)


def review_finding(
    handle: CaseHandle,
    finding_id: int,
    status: FindingStatus,
    *,
    note: str | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """Record an analyst decision. Accepting an AI proposal makes it analyst-verified."""
    with handle.session() as s:
        f = s.get(Finding, finding_id, options=[selectinload(Finding.events)])
        if f is None:
            raise SherlogError(f"No finding with id {finding_id}")
        actor = actor or handle.case(s).investigator
        previous = str(f.status)
        f.status = status
        if note is not None:
            f.analyst_note = note
        if status == FindingStatus.ACCEPTED and f.verified_by == VerifiedBy.AI_PROPOSED:
            f.context = {**(f.context or {}), "proposed_by": "ai"}
            f.verified_by = VerifiedBy.ANALYST
        f.updated_at = utcnow()
        audit.record(
            s,
            "finding.review",
            actor=actor,
            finding_id=f.id,
            previous_status=previous,
            status=str(status),
            note=note,
        )
        s.flush()
        return finding_to_dict(f)


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {str(s): 0 for s in Severity}
    for f in findings:
        counts[f["severity"]] += 1
    return counts
