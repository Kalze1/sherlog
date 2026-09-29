"""Gather everything a report needs from the case database into plain data.

Templates only format what this module produces; all selection, grouping and
wording decisions live here so they can be tested without rendering.
"""

from __future__ import annotations

import platform
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session, selectinload

from sherlog import __version__
from sherlog.ai.orchestrator import latest_draft, list_hypotheses, list_runs
from sherlog.core.case import CaseHandle
from sherlog.core.models import (
    IOC,
    AIRun,
    Artifact,
    AuditEntry,
    Event,
    EvidenceFile,
    EvidenceItem,
    Finding,
)
from sherlog.core.timeline import event_to_dict
from sherlog.core.timeutil import iso, utcnow
from sherlog.core.vocab import FileKind, FindingStatus, Severity
from sherlog.detection.analytics import ANALYTICS
from sherlog.detection.attack import load_bundle
from sherlog.detection.findings import SEVERITY_ORDER, finding_to_dict
from sherlog.enrichment.summary import intel_summary, is_reportable
from sherlog.intake.manifest import custody_to_dict
from sherlog.intake.service import verify_evidence
from sherlog.reporting.standards import (
    METHODOLOGY,
    RESPONSE_PHASE_TITLES,
    RESPONSE_PHASES,
    STANDARDS,
    response_phase,
)

MAX_TIMELINE_EVENTS = 300
MAX_FILES_LISTED = 1000
SEVERITIES_DESC = [s.value for s in sorted(Severity, key=lambda s: -SEVERITY_ORDER[s])]


def _findings(session: Session) -> list[Finding]:
    rows = list(
        session.scalars(
            select(Finding).options(selectinload(Finding.events).joinedload(Event.source_file))
        )
    )
    rows.sort(
        key=lambda f: (
            -SEVERITY_ORDER[f.severity],
            f.first_seen is None,
            f.first_seen or f.created_at,
            f.id,
        )
    )
    return rows


def _finding_entry(f: Finding) -> dict[str, Any]:
    d = finding_to_dict(f)
    tactics = sorted({t for tech in d["attack_techniques"] for t in tech["tactics"]})
    d["tactics"] = tactics
    d["response_phase"] = response_phase(tactics)
    d["evidence_refs"] = [
        {
            "event_id": e.id,
            "rel_path": e.source_file.rel_path,
            "sha256": e.source_file.sha256,
            "line_number": e.line_number,
            "timestamp_utc": iso(e.timestamp_utc),
            "raw": e.raw,
        }
        for e in f.events[:10]
    ]
    return d


def _evidence(session: Session) -> dict[str, Any]:
    items = list(
        session.scalars(
            select(EvidenceItem)
            .options(selectinload(EvidenceItem.files), selectinload(EvidenceItem.custody))
            .order_by(EvidenceItem.id)
        )
    )
    artifacts = {a.file_id: a for a in session.scalars(select(Artifact))}
    out_items = []
    total_files = 0
    for item in items:
        files: list[dict[str, Any]] = []
        for f in item.files:
            art = artifacts.get(f.id)
            files.append(
                {
                    "rel_path": f.rel_path,
                    "kind": str(f.kind),
                    "size": f.size,
                    "sha256": f.sha256,
                    "md5": f.md5,
                    "mtime": iso(f.mtime),
                    "artifact_type": art.artifact_type if art else None,
                    "status": art.status if art else None,
                    "events": art.event_count if art else 0,
                }
            )
        total_files += len(files)
        out_items.append(
            {
                "id": item.id,
                "label": item.label,
                "source_path": item.source_path,
                "added_at": iso(item.added_at),
                "added_by": item.added_by,
                "source_note": item.source_note,
                "item_digest": item.item_digest,
                "file_count": len(files),
                "total_bytes": sum(f["size"] or 0 for f in files if f["sha256"]),
                "files": files[:MAX_FILES_LISTED],
                "files_truncated": len(files) > MAX_FILES_LISTED,
                "custody": [custody_to_dict(c) for c in item.custody],
            }
        )
    return {"items": out_items, "total_files": total_files}


def _artifact_summary(session: Session) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            Artifact.artifact_type, Artifact.status, func.count(), func.sum(Artifact.event_count)
        )
        .group_by(Artifact.artifact_type, Artifact.status)
        .order_by(Artifact.artifact_type, Artifact.status)
    ).all()
    return [
        {"artifact_type": t, "status": s, "files": n, "events": int(ev or 0)}
        for t, s, n, ev in rows
    ]


def _timeline(findings: list[Finding]) -> list[dict[str, Any]]:
    """Events supporting reportable findings, in time order, each tagged with its finding ids."""
    by_event: dict[int, dict[str, Any]] = {}
    for f in findings:
        for e in f.events:
            entry = by_event.get(e.id)
            if entry is None:
                entry = event_to_dict(e)
                entry["finding_ids"] = []
                entry["severity"] = str(f.severity)
                by_event[e.id] = entry
            entry["finding_ids"].append(f.id)
            if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[Severity(entry["severity"])]:
                entry["severity"] = str(f.severity)
    events = sorted(
        by_event.values(),
        key=lambda e: (e["timestamp_utc"] is None, e["timestamp_utc"] or "", e["id"]),
    )
    return events


def _limitations(
    session: Session,
    case_tz: str,
    findings: list[dict[str, Any]],
    verification: dict[str, Any] | None,
    evidence: dict[str, Any],
) -> list[str]:
    out: list[str] = []
    if verification is None:
        out.append(
            "Evidence was NOT re-verified for this report (--skip-verify); integrity since "
            "intake is asserted only by the earlier custody records."
        )
    elif not verification["ok"]:
        out.append(
            "Evidence verification FAILED: at least one file changed, disappeared or appeared "
            "since intake (see Scope and evidence). Conclusions drawn from the affected files "
            "must be treated with caution."
        )

    assumed = session.execute(
        select(Event.artifact_type, func.count())
        .where(Event.timezone_assumed.is_(True))
        .group_by(Event.artifact_type)
        .order_by(Event.artifact_type)
    ).all()
    if assumed:
        detail = ", ".join(f"{t} ({n})" for t, n in assumed)
        out.append(
            f"Timestamps without a timezone were interpreted in the case timezone {case_tz}: "
            f"{detail}. If a source host used a different zone, those times are shifted."
        )
    year_inferred = session.scalar(
        select(func.count())
        .select_from(Event)
        .where(cast(Event.tags, String).like('%"year_inferred"%'))
    )
    if year_inferred:
        out.append(
            f"{year_inferred} events come from logs whose timestamps omit the year; the year "
            "was inferred from each file's modification time and December-to-January "
            "rollovers. A file modified long after its last entry would be dated wrongly."
        )
    undated = session.scalar(
        select(func.count()).select_from(Event).where(Event.timestamp_utc.is_(None))
    )
    if undated:
        out.append(
            f"{undated} events have no usable timestamp (e.g. shell history without "
            "HISTTIMEFORMAT, crontab and configuration entries, dmesg uptime lines) and cannot "
            "be placed on the timeline; they are listed after dated events."
        )
    parse_errors = session.scalar(
        select(func.count()).select_from(Event).where(Event.event_type == "parse_error")
    )
    if parse_errors:
        out.append(
            f"{parse_errors} lines/records could not be parsed; they are preserved as "
            "parse_error events but not interpreted."
        )
    unanalyzed = session.execute(
        select(EvidenceFile.rel_path, Artifact.status, Artifact.artifact_type)
        .join(Artifact, Artifact.file_id == EvidenceFile.id)
        .where(Artifact.status.in_(("unclassified", "unsupported", "error")))
        .order_by(EvidenceFile.rel_path)
    ).all()
    if unanalyzed:
        names = ", ".join(f"{p} ({s})" for p, s, _ in unanalyzed[:20])
        more = f" and {len(unanalyzed) - 20} more" if len(unanalyzed) > 20 else ""
        out.append(f"Files not analyzed: {names}{more}.")
    not_read = session.scalar(
        select(func.count()).select_from(EvidenceFile).where(EvidenceFile.kind != FileKind.FILE)
    )
    if not_read:
        out.append(
            f"{not_read} evidence entries are symlinks, special or unreadable files; they "
            "were recorded but their content was not read."
        )
    gaps = [f for f in findings if f["rule_id"] == "sherlog.analytic.log_gap"]
    if gaps:
        out.append(
            f"{len(gaps)} gap(s) were found in otherwise continuous logs; activity during "
            "those periods is not visible in the affected sources."
        )
    if not any(f["cves"] for f in findings):
        out.append(
            "No CVE could be attributed: no finding is tied to a concrete vulnerable version "
            "string or known exploit signature in the evidence."
        )
    iocs = list(session.scalars(select(IOC)))
    if not iocs:
        out.append("No IOCs were extracted for this case (run 'sherlog analyze').")
    else:
        enriched = [
            i for i in iocs if any(k in ("abuseipdb", "virustotal") for k in (i.enrichment or {}))
        ]
        if not enriched:
            out.append(
                "IOCs were not enriched with external threat intelligence (not run, offline, "
                "or no API keys); verdicts are 'unknown'."
            )
        else:
            out.append(
                "Threat-intelligence verdicts reflect third-party data at lookup time; "
                "'unknown' means no provider had information, not that an indicator is benign."
            )
        if any(i.enrichment and "egress" in i.enrichment for i in iocs):
            out.append(
                "Private addresses, internal domains, usernames, paths and full URLs were not "
                "sent to external services and were not enriched."
            )
    runs = list(session.scalars(select(AIRun).order_by(AIRun.id)))
    if not runs:
        out.append(
            "No AI-assisted investigation was run; all findings come from deterministic "
            "rules or analyst review."
        )
    else:
        models = sorted({f"{r.provider}/{r.model}" for r in runs})
        out.append(
            f"{len(runs)} AI-assisted investigation run(s) used {', '.join(models)}. "
            "AI-proposed findings and hypotheses are unverified until the analyst accepts them; "
            "accepted ones are labelled as analyst-verified."
        )
        unredacted = [r.id for r in runs if not r.redaction]
        if unredacted:
            out.append(
                f"Redaction was disabled for AI run(s) {unredacted}: real host names, internal "
                "addresses and usernames were sent to the model provider."
            )
    out.append(
        "Detection covers only the artifacts collected. Absence of a finding is not evidence "
        "that the corresponding activity did not happen."
    )
    if evidence["total_files"] == 0:
        out.append("No evidence files were recorded in this case.")
    return out


def _recommendations(
    findings: list[dict[str, Any]], session: Session
) -> dict[str, list[dict[str, Any]]]:
    """Unique recommendations grouped by response activity, with the findings that raise them."""
    grouped: dict[str, dict[str, dict[str, Any]]] = {p: {} for p in RESPONSE_PHASES}
    for f in findings:
        for text in f["recommendations"]:
            entry = grouped[f["response_phase"]].setdefault(
                text, {"text": text, "finding_ids": [], "severity": f["severity"]}
            )
            entry["finding_ids"].append(f["id"])
            if (
                SEVERITY_ORDER[Severity(f["severity"])]
                > SEVERITY_ORDER[Severity(entry["severity"])]
            ):
                entry["severity"] = f["severity"]

    def add(phase: str, text: str) -> None:
        grouped[phase].setdefault(text, {"text": text, "finding_ids": [], "severity": "info"})

    # Evidence-driven hardening advice (not tied to one finding).
    risky = session.execute(
        select(Event.raw, Event.tags).where(Event.event_type == "config.entry")
    ).all()
    for raw, tags in risky:
        for tag in tags:
            if tag.startswith("risky:"):
                add(
                    "long_term",
                    f"Review sshd_config setting '{raw.strip()}' ({tag[6:].replace('_', ' ')}).",
                )
    tactics = {t for f in findings for t in f["tactics"]}
    if "defense_evasion" in tactics:
        add(
            "long_term",
            "Forward logs in real time to a central, access-controlled store so that local "
            "tampering cannot remove the record.",
        )
    has_audit = session.scalar(
        select(func.count()).select_from(Event).where(Event.artifact_type == "linux.audit")
    )
    if not has_audit:
        add(
            "long_term",
            "Enable and retain Linux audit (auditd) logs; no audit log was available for this "
            "investigation, which limits visibility of process execution and file changes.",
        )
    if findings:
        add(
            "long_term",
            "Hold a post-incident review and update detection rules and runbooks with what was "
            "learned (NIST SP 800-61r3).",
        )
    out = {}
    for phase in RESPONSE_PHASES:
        entries = sorted(
            grouped[phase].values(),
            key=lambda e: (-SEVERITY_ORDER[Severity(e["severity"])], e["text"]),
        )
        out[phase] = entries
    return out


def _executive_summary(
    case: dict[str, Any],
    findings: list[dict[str, Any]],
    evidence: dict[str, Any],
    stats: dict[str, Any],
    verification: dict[str, Any] | None,
) -> list[str]:
    counts = Counter(f["severity"] for f in findings)
    paras = []
    span = (
        f" covering {stats['first_event']} to {stats['last_event']} (UTC)"
        if stats["first_event"]
        else ""
    )
    hosts = f" from host(s) {', '.join(stats['hosts'][:8])}" if stats["hosts"] else ""
    paras.append(
        f"SherLog examined {stats['events']} events parsed from {evidence['total_files']} "
        f"evidence files{hosts}{span}."
    )
    if findings:
        sev = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES_DESC if counts[s])
        accepted = sum(1 for f in findings if f["status"] == "accepted")
        paras.append(
            f"{len(findings)} finding(s) are reported ({sev}); {accepted} have been confirmed by "
            "the analyst and the remainder are unreviewed rule results."
        )
        top = [f for f in findings if f["severity"] in ("critical", "high")][:5]
        if top:
            paras.append(
                "Most significant: " + "; ".join(f"#{f['id']} {f['title']}" for f in top) + "."
            )
        tactics = sorted({t for f in findings for t in f["tactics"]})
        if tactics:
            bundle = load_bundle()
            paras.append(
                "Observed ATT&CK tactics: "
                + ", ".join(bundle.tactic_name(t) for t in tactics)
                + "."
            )
    else:
        paras.append("No findings were produced by the rules and analytics that were run.")
    if verification is not None:
        paras.append(
            "All evidence matched its intake hashes when this report was generated."
            if verification["ok"]
            else "WARNING: evidence integrity verification failed for at least one file."
        )
    paras.append(
        "This summary was generated automatically from the findings; it contains no "
        "statements beyond what the findings and their linked evidence support."
    )
    return paras


def _rules_appendix(audits: list[AuditEntry]) -> list[dict[str, Any]]:
    last = next((a for a in reversed(audits) if a.action == "analyze"), None)
    if last is None:
        return []
    try:
        from sherlog.detection.sigma import load_rules

        titles = {r.key: r for r in load_rules().rules}
    except Exception:  # custom rule dirs may have been used; titles are optional
        titles = {}
    matched = last.details.get("rule_matches", {})
    out = []
    for key, sha in sorted(last.details.get("rules", {}).items()):
        r = titles.get(key)
        out.append(
            {
                "key": key,
                "title": r.title if r else None,
                "level": str(r.level) if r else None,
                "sha256_prefix": sha,
                "matches": matched.get(key, 0),
            }
        )
    for a in ANALYTICS:
        out.append(
            {
                "key": a.rule_id,
                "title": a.title,
                "level": str(a.level),
                "sha256_prefix": f"built-in {__version__}",
                "matches": None,
            }
        )
    return out


def build_context(
    handle: CaseHandle,
    *,
    verify: bool = True,
    include_rejected: bool = False,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Collect all report data. Re-verifies evidence first unless ``verify`` is False."""
    verification = verify_evidence(handle) if verify else None
    with handle.session() as s:
        case = handle.case(s)
        case_d = {
            "id": case.id,
            "name": case.name,
            "investigator": case.investigator,
            "timezone": case.timezone,
            "created_at": iso(case.created_at),
            "brief": case.brief,
            "sherlog_version_at_creation": case.sherlog_version,
        }
        all_findings = _findings(s)
        reportable = [
            f for f in all_findings if include_rejected or f.status != FindingStatus.REJECTED
        ]
        rejected = [f for f in all_findings if f.status == FindingStatus.REJECTED]
        findings = [_finding_entry(f) for f in reportable]
        by_severity: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in findings:
            by_severity[f["severity"]].append(f)

        evidence = _evidence(s)
        first_last = s.execute(
            select(func.min(Event.timestamp_utc), func.max(Event.timestamp_utc))
        ).one()
        hosts = sorted(
            h
            for (h,) in s.execute(select(Event.host).where(Event.host.is_not(None)).distinct())
            if h
        )
        stats = {
            "events": s.scalar(select(func.count()).select_from(Event)) or 0,
            "first_event": iso(first_last[0]),
            "last_event": iso(first_last[1]),
            "hosts": hosts,
            "artifacts": _artifact_summary(s),
        }
        timeline = _timeline(reportable)
        techniques = sorted({t["id"] for f in findings for t in f["attack_techniques"]})
        bundle = load_bundle()
        coverage = [
            {
                "tactic": key,
                "name": bundle.tactic_name(key),
                "techniques": [
                    {
                        "id": t.id,
                        "name": t.name,
                        "url": t.url,
                        "finding_ids": [
                            f["id"]
                            for f in findings
                            if any(x["id"] == t.id for x in f["attack_techniques"])
                        ],
                    }
                    for t in techs
                ],
            }
            for key, techs in bundle.coverage(techniques).items()
        ]
        all_iocs = list(s.scalars(select(IOC)))
        reportable_iocs = [i for i in all_iocs if is_reportable(i)]
        rank = {"malicious": 0, "suspicious": 1, "clean": 2, "unknown": 3}
        iocs = sorted(
            (
                {
                    "value": i.value,
                    "type": str(i.type),
                    "first_seen": iso(i.first_seen),
                    "last_seen": iso(i.last_seen),
                    "verdict": str(i.verdict),
                    "finding_ids": i.finding_ids or [],
                    "intel": intel_summary(i.enrichment or {}),
                    "providers": sorted(k for k in (i.enrichment or {}) if k != "egress"),
                }
                for i in reportable_iocs
            ),
            key=lambda d: (rank.get(str(d["verdict"]), 9), str(d["type"]), str(d["value"])),
        )
        audits = list(s.scalars(select(AuditEntry).order_by(AuditEntry.id)))
        audit_log = [
            {
                "id": a.id,
                "timestamp": iso(a.timestamp),
                "actor": a.actor,
                "action": a.action,
                "details": a.details,
                "sherlog_version": a.sherlog_version,
            }
            for a in audits
        ]
        limitations = _limitations(s, case.timezone, findings, verification, evidence)
        recommendations = _recommendations(findings, s)
        rules = _rules_appendix(audits)

    ai_runs = [
        {
            k: r[k]
            for k in (
                "id",
                "started_at",
                "provider",
                "model",
                "redaction",
                "iterations",
                "input_tokens",
                "output_tokens",
                "status",
                "stop_reason",
                "replay_of",
            )
        }
        | {"proposed": len(r["stats"].get("findings_proposed", []))}
        for r in list_runs(handle)
    ]
    ai_hypotheses = list_hypotheses(handle)
    ai_draft = latest_draft(handle, status="accepted")
    return {
        "generated_at": iso(generated_at or utcnow()),
        "tool": {
            "name": "SherLog",
            "version": __version__,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "case": case_d,
        "executive_summary": _executive_summary(case_d, findings, evidence, stats, verification),
        "evidence": evidence,
        "verification": verification,
        "stats": stats,
        "standards": STANDARDS,
        "methodology": METHODOLOGY,
        "findings": findings,
        "findings_by_severity": [(s, by_severity[s]) for s in SEVERITIES_DESC if by_severity[s]],
        "severity_counts": {s: len(by_severity[s]) for s in SEVERITIES_DESC},
        "rejected": [
            {"id": f.id, "title": f.title, "analyst_note": f.analyst_note, "rule_id": f.rule_id}
            for f in rejected
        ]
        if not include_rejected
        else [],
        "timeline": timeline[:MAX_TIMELINE_EVENTS],
        "timeline_total": len(timeline),
        "coverage": coverage,
        "iocs": iocs,
        "ioc_other_count": len(all_iocs) - len(iocs),
        "recommendations": [
            (phase, RESPONSE_PHASE_TITLES[phase], recommendations[phase])
            for phase in RESPONSE_PHASES
            if recommendations[phase]
        ],
        "limitations": limitations,
        "audit_log": audit_log,
        "rules": rules,
        "ai": {
            "used": bool(ai_runs),
            "runs": ai_runs,
            "hypotheses": ai_hypotheses,
            "draft": ai_draft,
        },
    }
