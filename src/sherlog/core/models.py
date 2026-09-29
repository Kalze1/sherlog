"""ORM models for the per-case database.

One SQLite database per case holds the case record, evidence manifest, chain of
custody, audit log, normalized events, findings and IOCs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column, Enum, Float, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sherlog.core.db import Base, UTCDateTime
from sherlog.core.vocab import (
    CustodyAction,
    FileKind,
    FindingStatus,
    IOCType,
    Severity,
    Verdict,
    VerifiedBy,
)


def _enum(cls: type) -> Enum:
    """Store StrEnum values (not names) as plain strings."""
    return Enum(cls, native_enum=False, values_callable=lambda e: [m.value for m in e], length=32)


class Case(Base):
    """The single case record stored in each case database."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    investigator: Mapped[str] = mapped_column(String(128))
    timezone: Mapped[str] = mapped_column(String(64))
    brief: Mapped[str | None] = mapped_column(Text)
    sherlog_version: Mapped[str] = mapped_column(String(32))
    schema_version: Mapped[int] = mapped_column(Integer)


class EvidenceItem(Base):
    """One ``evidence add`` invocation: a source path and everything under it."""

    __tablename__ = "evidence_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    label: Mapped[str] = mapped_column(String(128))
    source_path: Mapped[str] = mapped_column(Text, unique=True)
    added_at: Mapped[datetime] = mapped_column(UTCDateTime)
    added_by: Mapped[str] = mapped_column(String(128))
    source_note: Mapped[str | None] = mapped_column(Text)
    # SHA-256 over the sorted (relative path, sha256) pairs of all hashed files.
    item_digest: Mapped[str] = mapped_column(String(64))

    files: Mapped[list[EvidenceFile]] = relationship(
        back_populates="item", cascade="all, delete-orphan", order_by="EvidenceFile.rel_path"
    )
    custody: Mapped[list[CustodyRecord]] = relationship(
        back_populates="item", cascade="all, delete-orphan", order_by="CustodyRecord.id"
    )


class EvidenceFile(Base):
    """A single path within an evidence item, with hashes and filesystem metadata."""

    __tablename__ = "evidence_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("evidence_items.id", ondelete="CASCADE"))
    path: Mapped[str] = mapped_column(Text)
    rel_path: Mapped[str] = mapped_column(Text)
    kind: Mapped[FileKind] = mapped_column(_enum(FileKind))
    size: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    md5: Mapped[str | None] = mapped_column(String(32))
    mtime: Mapped[datetime | None] = mapped_column(UTCDateTime)
    atime: Mapped[datetime | None] = mapped_column(UTCDateTime)
    ctime: Mapped[datetime | None] = mapped_column(UTCDateTime)
    uid: Mapped[int | None] = mapped_column(Integer)
    gid: Mapped[int | None] = mapped_column(Integer)
    mode: Mapped[str | None] = mapped_column(String(16))
    inode: Mapped[int | None] = mapped_column(Integer)
    symlink_target: Mapped[str | None] = mapped_column(Text)
    compression: Mapped[str | None] = mapped_column(String(8))
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    content_size: Mapped[int | None] = mapped_column(Integer)
    rotation_base: Mapped[str | None] = mapped_column(Text)
    rotation_index: Mapped[int | None] = mapped_column(Integer)
    note: Mapped[str | None] = mapped_column(Text)

    item: Mapped[EvidenceItem] = relationship(back_populates="files")


class CustodyRecord(Base):
    """Chain-of-custody entry: who did what to an evidence item, when and from where."""

    __tablename__ = "custody_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("evidence_items.id", ondelete="CASCADE"))
    action: Mapped[CustodyAction] = mapped_column(_enum(CustodyAction))
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime)
    actor: Mapped[str] = mapped_column(String(128))
    os_user: Mapped[str] = mapped_column(String(128))
    workstation: Mapped[str] = mapped_column(String(255))
    source_path: Mapped[str] = mapped_column(Text)
    item_digest: Mapped[str] = mapped_column(String(64))
    note: Mapped[str | None] = mapped_column(Text)

    item: Mapped[EvidenceItem] = relationship(back_populates="custody")


class AuditEntry(Base):
    """Append-only record of every action taken on the case (reproducibility)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sherlog_version: Mapped[str] = mapped_column(String(32))


class Artifact(Base):
    """Identification (and parse outcome) for one evidence file."""

    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[int] = mapped_column(
        ForeignKey("evidence_files.id", ondelete="CASCADE"), unique=True
    )
    artifact_type: Mapped[str] = mapped_column(String(64))
    parser: Mapped[str | None] = mapped_column(String(64))
    parser_version: Mapped[str | None] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    overridden: Mapped[bool] = mapped_column(default=False)
    # Top candidate scores, e.g. {"linux.auth": 0.95, "linux.syslog": 0.6}.
    candidates: Mapped[dict[str, float]] = mapped_column(JSON, default=dict)
    # identified | parsed | unclassified | unsupported | empty | error
    status: Mapped[str] = mapped_column(String(16))
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    parse_error_count: Mapped[int] = mapped_column(Integer, default=0)
    preview: Mapped[str | None] = mapped_column(Text)
    message: Mapped[str | None] = mapped_column(Text)

    file: Mapped[EvidenceFile] = relationship()


class Event(Base):
    """A normalized log event (see the data model in the project brief)."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"))
    timestamp_utc: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    timestamp_raw: Mapped[str | None] = mapped_column(Text)
    timezone_assumed: Mapped[bool] = mapped_column(default=False)
    host: Mapped[str | None] = mapped_column(String(255))
    source_file_id: Mapped[int] = mapped_column(ForeignKey("evidence_files.id"))
    line_number: Mapped[int | None] = mapped_column(Integer)
    artifact_type: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(Text)
    command: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[str] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Artifact-specific structured fields (HTTP status, user agent, audit fields, ...).
    extra: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    source_file: Mapped[EvidenceFile] = relationship()


finding_events = Table(
    "finding_events",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
)

ioc_events = Table(
    "ioc_events",
    Base.metadata,
    Column("ioc_id", ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
)


class Finding(Base):
    """A finding. ``verified_by`` separates rule facts, analyst calls and AI hypotheses."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(_enum(Severity))
    confidence: Mapped[float] = mapped_column(Float)
    verified_by: Mapped[VerifiedBy] = mapped_column(_enum(VerifiedBy))
    rule_id: Mapped[str | None] = mapped_column(String(128))
    attack_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Each entry: {"id": "CVE-...", "evidence_reference": "..."}; reference is mandatory.
    cves: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)
    narrative: Mapped[str | None] = mapped_column(Text)
    recommendations: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # Analyst review state; rule findings are re-generated on every analyze run but
    # keep their status via ``fingerprint`` (stable hash of rule + key evidence).
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus), default=FindingStatus.OPEN, server_default=FindingStatus.OPEN.value
    )
    analyst_note: Mapped[str | None] = mapped_column(Text)
    fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)
    # Entity the finding is about (src_ip, actor, host, ...) and rule-specific counts.
    context: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    first_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    event_count: Mapped[int | None] = mapped_column(Integer)

    events: Mapped[list[Event]] = relationship(
        secondary=finding_events, order_by="Event.timestamp_utc, Event.id"
    )


class IOC(Base):
    """An indicator of compromise extracted from events."""

    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    type: Mapped[IOCType] = mapped_column(_enum(IOCType))
    first_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    enrichment: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    verdict: Mapped[Verdict] = mapped_column(_enum(Verdict), default=Verdict.UNKNOWN)
    # Findings (not rejected) whose linked events contain this IOC.
    # none_as_null: store None as SQL NULL (not JSON null) so IS NULL filters work.
    finding_ids: Mapped[list[int] | None] = mapped_column(JSON(none_as_null=True))
    # How it was seen, e.g. ["src_ip", "command", "url"], and "private" for non-global IPs.
    tags: Mapped[list[str] | None] = mapped_column(JSON(none_as_null=True))
    event_count: Mapped[int | None] = mapped_column(Integer)

    events: Mapped[list[Event]] = relationship(secondary=ioc_events)


class AIRun(Base):
    """One AI-assisted investigation run (provider, limits, outcome)."""

    __tablename__ = "ai_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    redaction: Mapped[bool] = mapped_column(default=True)
    # HMAC key for stable pseudonyms; kept so a run can be replayed on this case.
    redaction_secret: Mapped[str] = mapped_column(String(64))
    replay_of: Mapped[str | None] = mapped_column(String(255))
    question: Mapped[str | None] = mapped_column(Text)
    max_iterations: Mapped[int] = mapped_column(Integer)
    token_budget: Mapped[int] = mapped_column(Integer)
    iterations: Mapped[int] = mapped_column(Integer, default=0)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16))  # running | completed | stopped | error
    stop_reason: Mapped[str | None] = mapped_column(Text)
    final_text: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    messages: Mapped[list[AIMessage]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="AIMessage.seq"
    )


class AIMessage(Base):
    """Transcript entry, stored exactly as exchanged with the provider (i.e. redacted)."""

    __tablename__ = "ai_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("ai_runs.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    # system | user | assistant | tool | draft_request | draft_response
    role: Mapped[str] = mapped_column(String(24))
    content: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)

    run: Mapped[AIRun] = relationship(back_populates="messages")


class AIHypothesis(Base):
    """An unverified hypothesis proposed by the AI assistant (never a finding)."""

    __tablename__ = "ai_hypotheses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("ai_runs.id", ondelete="CASCADE"))
    statement: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str | None] = mapped_column(Text)
    event_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    suggested_checks: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)


class AIDraft(Base):
    """AI-drafted executive summary and narrative awaiting analyst review."""

    __tablename__ = "ai_drafts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("ai_runs.id", ondelete="SET NULL"))
    model: Mapped[str] = mapped_column(String(128))
    executive_summary: Mapped[str] = mapped_column(Text)
    narrative: Mapped[str | None] = mapped_column(Text)
    finding_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16))  # draft | accepted | rejected | superseded
    edited: Mapped[bool] = mapped_column(default=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(128))
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
