"""Short, human-readable summaries of an IOC's enrichment, shared by CLI and reports."""

from __future__ import annotations

from typing import Any

from sherlog.core.models import IOC
from sherlog.core.vocab import Verdict


def is_reportable(ioc: IOC) -> bool:
    """IOCs worth listing in a report: linked to a finding, or flagged by intelligence."""
    return bool(ioc.finding_ids) or str(ioc.verdict) in (
        Verdict.MALICIOUS.value,
        Verdict.SUSPICIOUS.value,
    )


def intel_summary(enrichment: dict[str, Any]) -> str:
    """e.g. 'AbuseIPDB 100% (523 reports); VT 12/94; CN AS4134 Chinanet'."""
    parts = []
    if (a := enrichment.get("abuseipdb")) and a.get("status") == "ok":
        s = a["summary"]
        parts.append(f"AbuseIPDB {s['abuse_confidence_score']}% ({s['total_reports']} reports)")
    v = enrichment.get("virustotal")
    if v and v.get("status") == "ok":
        s = v["summary"]
        total = s["malicious"] + s["suspicious"] + s["harmless"] + s["undetected"]
        parts.append(f"VT {s['malicious']}/{total} malicious")
    elif v and v.get("status") == "not_found":
        parts.append("VT: not found")
    if g := enrichment.get("geoip"):
        asn = f"AS{g['asn']}" if g.get("asn") else None
        parts.append(" ".join(str(x) for x in (g.get("country"), asn, g.get("as_org")) if x))
    if b := enrichment.get("egress"):
        parts.append(f"not sent: {b['blocked']}")
    return "; ".join(parts)
