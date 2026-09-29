"""Built-in deterministic analytics that Sigma rules cannot express.

Each analytic queries the case database and returns :class:`FindingDraft`
objects with ``rule_id`` ``sherlog.analytic.<name>``. They are listed by
``sherlog rules list`` next to the YAML rules. Like rules, they only ever
report what the evidence shows; heuristics and their thresholds are stated in
the narrative so a reader can judge them.
"""

from __future__ import annotations

import ipaddress
import itertools
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sherlog.core.models import Artifact, Event, EvidenceFile
from sherlog.core.timeutil import iso
from sherlog.core.vocab import Severity
from sherlog.detection.findings import FindingDraft, fingerprint_for


@dataclass(frozen=True)
class AnalyticInfo:
    key: str
    title: str
    level: Severity
    confidence: float
    techniques: tuple[str, ...]
    description: str
    recommendation: str

    @property
    def rule_id(self) -> str:
        return f"sherlog.analytic.{self.key}"


LOG_GAP = AnalyticInfo(
    "log_gap",
    "Gap in a continuously written log",
    Severity.LOW,
    0.4,
    ("T1070.002",),
    "A log that normally records events steadily has a long period with nothing at all. "
    "Possible causes: the service was stopped, the host was down, entries were deleted, or the "
    "log simply was quiet. Compare with boot/shutdown events and other logs before concluding.",
    "Check whether other sources cover the gap; if the gap coincides with attacker activity "
    "seen elsewhere, treat the log as tampered and rely on the other sources.",
)
UTMP_TRUNCATION = AnalyticInfo(
    "utmp_truncation",
    "wtmp/btmp starts after logins recorded elsewhere",
    Severity.HIGH,
    0.6,
    ("T1070.002",),
    "wtmp/btmp should contain every login/failed login since log rotation. When the binary "
    "record starts well after logins that auth.log or the journal recorded, or is empty while "
    "logins exist, the file was likely truncated or replaced.",
    "Treat wtmp/btmp as unreliable; reconstruct sessions from auth.log, the journal and audit "
    "records, and look for the command that cleared the file in shell history and audit logs.",
)
UNUSUAL_LOGIN_IP = AnalyticInfo(
    "unusual_login_ip",
    "Login from an IP not otherwise used by this account",
    Severity.MEDIUM,
    0.5,
    ("T1078",),
    "An account with an established pattern of source addresses logged in once from a public "
    "address that it never used otherwise.",
    "Confirm with the account owner whether they used this address; if not, treat the session "
    "as attacker activity and review everything the account did afterwards.",
)
LOGGING_RESTART = AnalyticInfo(
    "logging_restart_without_boot",
    "Logging service restarted outside a boot",
    Severity.MEDIUM,
    0.5,
    ("T1562.006",),
    "rsyslog or journald stopped or started with no system boot/shutdown recorded within "
    "15 minutes. Restarting the logger is a common way to interrupt logging or apply a "
    "modified configuration.",
    "Check the logger's configuration and the surrounding commands (shell history, audit) for "
    "who restarted it and why.",
)
SSH_KEY_UNKNOWN = AnalyticInfo(
    "ssh_login_key_not_in_authorized_keys",
    "SSH public-key login with a key absent from collected authorized_keys",
    Severity.MEDIUM,
    0.5,
    ("T1098.004", "T1078"),
    "A successful publickey login used a fingerprint that does not appear in any "
    "authorized_keys file collected as evidence. Either the key was removed afterwards, the "
    "collection is incomplete, or authentication used another source (e.g. AuthorizedKeysCommand).",
    "Collect authorized_keys for every account (including root) and any AuthorizedKeysCommand "
    "output; if the key is still unexplained, treat the login as unauthorized.",
)
ANALYTICS = (LOG_GAP, UTMP_TRUNCATION, UNUSUAL_LOGIN_IP, LOGGING_RESTART, SSH_KEY_UNKNOWN)

CONTINUOUS_TYPES = (
    "linux.auth",
    "linux.syslog",
    "linux.kernel",
    "linux.cron",
    "journald.json",
    "linux.audit",
    "web.access",
)
MIN_EVENTS_FOR_GAP = 20
GAP_MEDIAN_FACTOR = 50


def _draft(
    info: AnalyticInfo,
    *,
    title_suffix: str,
    narrative: str,
    context: dict[str, Any],
    event_ids: list[int],
    first_seen: datetime | None,
    last_seen: datetime | None,
    key_parts: list[str],
) -> FindingDraft:
    return FindingDraft(
        rule_id=info.rule_id,
        title=f"{info.title} — {title_suffix}" if title_suffix else info.title,
        severity=info.level,
        confidence=info.confidence,
        techniques=list(info.techniques),
        recommendations=[info.recommendation],
        narrative=f"{info.description}\n\n{narrative}",
        context={"analytic": info.key, **context},
        event_ids=event_ids,
        event_count=len(event_ids),
        first_seen=first_seen,
        last_seen=last_seen,
        fingerprint=fingerprint_for(info.rule_id, *key_parts),
    )


def log_gaps(session: Session, threshold: timedelta) -> list[FindingDraft]:
    """Long silences in logs that are otherwise written steadily."""
    drafts: list[FindingDraft] = []
    rows = session.execute(
        select(Artifact.file_id, Artifact.artifact_type, EvidenceFile.rel_path, EvidenceFile.sha256)
        .join(EvidenceFile, Artifact.file_id == EvidenceFile.id)
        .where(Artifact.artifact_type.in_(CONTINUOUS_TYPES), Artifact.status == "parsed")
        .order_by(EvidenceFile.id)
    ).all()
    for file_id, artifact_type, rel_path, sha in rows:
        rows_pts = session.execute(
            select(Event.id, Event.timestamp_utc)
            .where(Event.source_file_id == file_id, Event.timestamp_utc.is_not(None))
            .order_by(Event.timestamp_utc, Event.id)
        ).all()
        if len(rows_pts) < MIN_EVENTS_FOR_GAP:
            continue
        points: list[tuple[int, datetime]] = [(r[0], r[1]) for r in rows_pts if r[1] is not None]
        intervals = [(b[1] - a[1]).total_seconds() for a, b in itertools.pairwise(points)]
        median = statistics.median(intervals)
        floor = max(threshold.total_seconds(), median * GAP_MEDIAN_FACTOR)
        for (id_a, ts_a), (id_b, ts_b) in itertools.pairwise(points):
            gap = (ts_b - ts_a).total_seconds()
            if gap <= floor:
                continue
            hours = gap / 3600
            drafts.append(
                _draft(
                    LOG_GAP,
                    title_suffix=f"{rel_path} silent for {hours:.1f} h",
                    narrative=(
                        f"{rel_path} ({artifact_type}) has no entries between {iso(ts_a)} and "
                        f"{iso(ts_b)} ({hours:.1f} hours). The file's median interval between "
                        f"entries is {median:.0f} s over {len(points)} dated events; the gap is "
                        f"reported because it exceeds both the {threshold} threshold and "
                        f"{GAP_MEDIAN_FACTOR}x the median."
                    ),
                    context={
                        "file": rel_path,
                        "gap_seconds": int(gap),
                        "median_interval_seconds": round(median, 1),
                    },
                    event_ids=[id_a, id_b],
                    first_seen=ts_a,
                    last_seen=ts_b,
                    key_parts=[sha or rel_path, iso(ts_a) or ""],
                )
            )
    return drafts


def _earliest(
    session: Session, event_type: str, exclude_prefix: str
) -> tuple[int, datetime] | None:
    row = session.execute(
        select(Event.id, Event.timestamp_utc)
        .where(
            Event.event_type == event_type,
            Event.timestamp_utc.is_not(None),
            Event.artifact_type.not_like(f"{exclude_prefix}%"),
        )
        .order_by(Event.timestamp_utc, Event.id)
        .limit(1)
    ).first()
    return (row[0], row[1]) if row and row[1] is not None else None


def utmp_truncation(session: Session) -> list[FindingDraft]:
    """wtmp/btmp files that are empty or start long after logins seen in text logs."""
    drafts: list[FindingDraft] = []
    checks = (
        ("utmp.wtmp", "auth.login.success", "logins"),
        ("utmp.btmp", "auth.login.failure", "failed logins"),
    )
    for artifact_type, event_type, label in checks:
        arts = session.execute(
            select(Artifact, EvidenceFile)
            .join(EvidenceFile, Artifact.file_id == EvidenceFile.id)
            .where(Artifact.artifact_type == artifact_type)
        ).all()
        if not arts:
            continue
        other = _earliest(session, event_type, "utmp.")
        if other is None:
            continue
        other_id, other_ts = other
        for art, f in arts:
            first = session.execute(
                select(Event.id, Event.timestamp_utc)
                .where(Event.source_file_id == f.id, Event.timestamp_utc.is_not(None))
                .order_by(Event.timestamp_utc, Event.id)
                .limit(1)
            ).first()
            first_ev_ts = first[1] if first is not None else None
            if first is None or first_ev_ts is None:
                narrative = (
                    f"{f.rel_path} contains no records ({art.event_count} events parsed, size "
                    f"{f.size} bytes) although {label} were recorded elsewhere from {iso(other_ts)}."  # noqa: E501
                )
                event_ids, first_ts = [other_id], other_ts
                lag = None
                last_ts = other_ts
            else:
                lag = first_ev_ts - other_ts
                if lag <= timedelta(days=1):
                    continue
                last_ts = first_ev_ts
                narrative = (
                    f"The first record in {f.rel_path} is dated {iso(first_ev_ts)}, but {label} were "  # noqa: E501
                    f"recorded in other logs from {iso(other_ts)} ({lag.days} days earlier). "
                    "Log rotation can explain this only if rotated copies were not collected."
                )
                event_ids, first_ts = [other_id, first[0]], other_ts
            drafts.append(
                _draft(
                    UTMP_TRUNCATION,
                    title_suffix=f.rel_path,
                    narrative=narrative,
                    context={"file": f.rel_path, "lag_days": lag.days if lag else None},
                    event_ids=event_ids,
                    first_seen=first_ts,
                    last_seen=last_ts,
                    key_parts=[f.sha256 or f.rel_path],
                )
            )
    return drafts


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


def unusual_login_ip(session: Session, min_logins: int = 5) -> list[FindingDraft]:
    """One-off public source addresses for accounts with an established login pattern."""
    rows = session.execute(
        select(Event.id, Event.actor, Event.src_ip, Event.timestamp_utc, Event.host)
        .where(
            Event.event_type == "auth.login.success",
            Event.actor.is_not(None),
            Event.src_ip.is_not(None),
            Event.artifact_type != "lastlog",
        )
        .order_by(Event.timestamp_utc, Event.id)
    ).all()
    per_actor: dict[str, list[Any]] = defaultdict(list)
    for row in rows:
        per_actor[row.actor].append(row)
    drafts: list[FindingDraft] = []
    for actor, logins in sorted(per_actor.items()):
        if len(logins) < min_logins:
            continue
        by_ip: dict[str, list[Any]] = defaultdict(list)
        for row in logins:
            by_ip[row.src_ip].append(row)
        for ip, hits in sorted(by_ip.items()):
            if len(hits) != 1 or not _is_public(ip):
                continue
            others = sorted(set(by_ip) - {ip})
            row = hits[0]
            drafts.append(
                _draft(
                    UNUSUAL_LOGIN_IP,
                    title_suffix=f"{actor} from {ip}",
                    narrative=(
                        f"Account {actor} logged in {len(logins)} times; {len(logins) - 1} of those "  # noqa: E501
                        f"came from {len(others)} other address(es) ({', '.join(others[:5])}"
                        f"{', ...' if len(others) > 5 else ''}) and exactly one, at "
                        f"{iso(row.timestamp_utc)}, from the public address {ip}."
                    ),
                    context={"actor": actor, "src_ip": ip, "total_logins": len(logins)},
                    event_ids=[row.id],
                    first_seen=row.timestamp_utc,
                    last_seen=row.timestamp_utc,
                    key_parts=[actor, ip],
                )
            )
    return drafts


def logging_restart_without_boot(
    session: Session, window: timedelta = timedelta(minutes=15)
) -> list[FindingDraft]:
    """rsyslog/journald start or stop events with no boot or shutdown nearby."""
    boots = session.execute(
        select(Event.timestamp_utc, Event.host).where(
            Event.event_type.in_(("system.boot", "system.shutdown")),
            Event.timestamp_utc.is_not(None),
        )
    ).all()
    restarts = session.execute(
        select(Event.id, Event.timestamp_utc, Event.host, Event.target, Event.event_type, Event.raw)
        .where(
            Event.event_type.in_(("service.start", "service.stop")),
            Event.target.in_(("rsyslogd", "systemd-journald")),
            Event.timestamp_utc.is_not(None),
        )
        .order_by(Event.timestamp_utc, Event.id)
    ).all()
    drafts: list[FindingDraft] = []
    for row in restarts:
        near_boot = any(
            abs((b_ts - row.timestamp_utc).total_seconds()) <= window.total_seconds()
            and (b_host is None or row.host is None or b_host == row.host)
            for b_ts, b_host in boots
        )
        if near_boot:
            continue
        action = "started" if row.event_type == "service.start" else "stopped"
        drafts.append(
            _draft(
                LOGGING_RESTART,
                title_suffix=f"{row.target} {action} at {iso(row.timestamp_utc)}",
                narrative=(
                    f"{row.target} {action} at {iso(row.timestamp_utc)} on {row.host or 'unknown host'} "  # noqa: E501
                    f"with no boot or shutdown event within {window}. Raw entry: {row.raw}"
                ),
                context={"service": row.target, "action": action, "host": row.host},
                event_ids=[row.id],
                first_seen=row.timestamp_utc,
                last_seen=row.timestamp_utc,
                key_parts=[str(row.target), iso(row.timestamp_utc) or "", str(row.host)],
            )
        )
    return drafts


def ssh_key_not_in_authorized_keys(session: Session) -> list[FindingDraft]:
    """Publickey logins whose fingerprint is missing from every collected authorized_keys."""
    present = (
        session.execute(select(Event.tags).where(Event.event_type == "ssh.key.present"))
        .scalars()
        .all()
    )
    known = {t[4:] for tags in present for t in tags if t.startswith("key:")}
    if not known:
        return []
    logins = session.execute(
        select(Event.id, Event.actor, Event.src_ip, Event.timestamp_utc, Event.tags, Event.host)
        .where(Event.event_type == "auth.login.success")
        .order_by(Event.timestamp_utc, Event.id)
    ).all()
    groups: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for row in logins:
        fps = [t[4:] for t in row.tags if t.startswith("key:")]
        for fp in fps:
            if fp not in known:
                groups[(row.actor or "?", fp)].append(row)
    drafts: list[FindingDraft] = []
    for (actor, fp), rows in sorted(groups.items()):
        ips = sorted({r.src_ip for r in rows if r.src_ip})
        drafts.append(
            _draft(
                SSH_KEY_UNKNOWN,
                title_suffix=f"{actor} with {fp}",
                narrative=(
                    f"{len(rows)} publickey login(s) as {actor} used key {fp}, which is not present "  # noqa: E501
                    f"in any of the collected authorized_keys files ({len(known)} known keys). "
                    f"Source address(es): {', '.join(ips) or 'unknown'}."
                ),
                context={"actor": actor, "fingerprint": fp, "src_ips": ips},
                event_ids=[r.id for r in rows],
                first_seen=rows[0].timestamp_utc,
                last_seen=rows[-1].timestamp_utc,
                key_parts=[actor, fp],
            )
        )
    return drafts


def run_analytics(session: Session, *, gap_threshold: timedelta) -> list[FindingDraft]:
    """Run every built-in analytic."""
    drafts: list[FindingDraft] = []
    drafts += log_gaps(session, gap_threshold)
    drafts += utmp_truncation(session)
    drafts += unusual_login_ip(session)
    drafts += logging_restart_without_boot(session)
    drafts += ssh_key_not_in_authorized_keys(session)
    return drafts
