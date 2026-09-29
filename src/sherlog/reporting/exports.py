"""Machine-readable exports: findings.json, events.jsonl and a STIX 2.1 bundle."""

from __future__ import annotations

import json
import posixpath
import uuid
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import stix2
from sqlalchemy import select
from sqlalchemy.orm import joinedload, selectinload

from sherlog import __version__
from sherlog.core.case import CaseHandle
from sherlog.core.models import IOC, Event, Finding
from sherlog.core.timeline import event_to_dict
from sherlog.core.timeutil import iso
from sherlog.core.vocab import FindingStatus
from sherlog.detection.attack import load_bundle
from sherlog.detection.findings import finding_to_dict
from sherlog.enrichment.summary import is_reportable

# Fixed namespace so STIX ids are stable for the same case and content.
STIX_NAMESPACE = uuid.UUID("6c1f8d3e-2b7a-5e44-9a0d-5f3c8b1e7a21")


def _sid(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, '|'.join((kind, *parts)))}"


def iter_events_jsonl(handle: CaseHandle) -> Iterator[str]:
    """Every event as one JSON line, in timeline order."""
    with handle.session() as s:
        stmt = (
            select(Event)
            .options(joinedload(Event.source_file))
            .order_by(Event.timestamp_utc.is_(None), Event.timestamp_utc, Event.id)
            .execution_options(yield_per=2000)
        )
        for e in s.scalars(stmt):
            yield json.dumps(event_to_dict(e), sort_keys=True, default=str)


def findings_document(
    handle: CaseHandle, context: dict[str, Any], *, include_rejected: bool = False
) -> dict[str, Any]:
    """findings.json: every reportable finding with all linked events."""
    with handle.session() as s:
        rows = list(
            s.scalars(
                select(Finding)
                .options(selectinload(Finding.events).joinedload(Event.source_file))
                .order_by(Finding.id)
            )
        )
        findings = [
            finding_to_dict(f, include_events=True)
            for f in rows
            if include_rejected or f.status != FindingStatus.REJECTED
        ]
    return {
        "schema": "sherlog.findings/1",
        "generated_at": context["generated_at"],
        "tool": context["tool"],
        "case": {k: context["case"][k] for k in ("id", "name", "investigator", "timezone")},
        "evidence_verified": None
        if context["verification"] is None
        else context["verification"]["ok"],
        "findings": findings,
    }


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(ioc_type: str, value: str) -> str | None:
    """STIX 2.1 pattern for an IOC, or None for types without a sensible mapping."""
    v = _escape(value)
    mapping = {
        "ipv4": f"[ipv4-addr:value = '{v}']",
        "ipv6": f"[ipv6-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']",
        "url": f"[url:value = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "md5": f"[file:hashes.MD5 = '{v}']",
        "username": f"[user-account:account_login = '{v}']",
        "path": f"[file:name = '{_escape(posixpath.basename(value) or value)}']",
    }
    return mapping.get(ioc_type)


def stix_bundle(handle: CaseHandle, context: dict[str, Any]) -> stix2.Bundle:
    """A STIX 2.1 bundle: tool identity, ATT&CK attack-patterns, IOC indicators and a report."""
    case = context["case"]
    case_id = case["id"]
    created = datetime.fromisoformat(case["created_at"])
    published = datetime.fromisoformat(context["generated_at"])
    identity = stix2.Identity(
        id=_sid("identity", case_id, "sherlog"),
        name=f"SherLog {__version__} (investigator: {case['investigator']})",
        identity_class="system",
        created=created,
        modified=created,
    )
    objects: list[Any] = [identity]

    bundle = load_bundle()
    technique_ids = sorted({t["id"] for f in context["findings"] for t in f["attack_techniques"]})
    patterns: dict[str, Any] = {}
    for tid in technique_ids:
        t = bundle.get(tid)
        ap = stix2.AttackPattern(
            id=_sid("attack-pattern", case_id, tid),
            name=t.name if t else tid,
            created=created,
            modified=created,
            created_by_ref=identity.id,
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": tid,
                    **({"url": t.url} if t else {}),
                }
            ],
            kill_chain_phases=[
                {"kill_chain_name": "mitre-attack", "phase_name": tactic.replace("_", "-")}
                for tactic in (t.tactics if t else ())
            ]
            or None,
        )
        patterns[tid] = ap
        objects.append(ap)

    with handle.session() as s:
        iocs = list(s.scalars(select(IOC).order_by(IOC.type, IOC.value)))
        for ioc in (i for i in iocs if is_reportable(i)):
            pattern = stix_pattern(str(ioc.type), ioc.value)
            if pattern is None:
                continue
            valid_from = ioc.first_seen or created
            objects.append(
                stix2.Indicator(
                    id=_sid("indicator", case_id, str(ioc.type), ioc.value),
                    name=f"{ioc.type}: {ioc.value}",
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=valid_from,
                    created=created,
                    modified=created,
                    created_by_ref=identity.id,
                    indicator_types=[
                        "malicious-activity"
                        if str(ioc.verdict) == "malicious"
                        else "anomalous-activity"
                    ],
                    description=f"Verdict: {ioc.verdict}; first seen {iso(ioc.first_seen)}, "
                    f"last seen {iso(ioc.last_seen)}.",
                )
            )

    summary = " ".join(context["executive_summary"])
    objects.append(
        stix2.Report(
            id=_sid("report", case_id),
            name=f"SherLog investigation: {case['name']}",
            description=summary,
            published=published,
            created=created,
            modified=published,
            created_by_ref=identity.id,
            report_types=["attack-pattern", "indicator"] if patterns else ["threat-report"],
            object_refs=[o.id for o in objects],
        )
    )
    return stix2.Bundle(objects=objects, id=_sid("bundle", case_id, context["generated_at"]))


def write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
