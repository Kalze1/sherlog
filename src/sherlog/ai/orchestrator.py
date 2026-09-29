"""The AI investigation loop, the summary draft, and draft review.

Flow of one run:

1. Build a redactor for the case and an initial briefing (brief, artifacts,
   findings, top IOCs, sample events) - all redacted.
2. Loop: model turn -> execute its tool calls locally (arguments restored from
   pseudonyms, results redacted) -> send results back. Stops when the model
   answers without tool calls, or at the iteration limit or token budget.
3. Draft: a separate, tool-less request writes an executive summary and a
   narrative from the confirmed findings only; stored as a draft for review.

Everything sent to or received from the provider is stored in ``ai_messages``
exactly as exchanged, so the transcript shows what left the machine.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from sherlog.ai.prompts import DRAFT_SYSTEM_PROMPT, DRAFT_TEMPLATE, INITIAL_TEMPLATE, SYSTEM_PROMPT
from sherlog.ai.providers import Provider, ProviderError, ReplayProvider, ToolResult, Turn
from sherlog.ai.redact import Redactor, build_redactor, new_secret
from sherlog.ai.tools import TOOL_SPECS, ToolContext, ToolError, compact_event
from sherlog.core import audit
from sherlog.core.case import CaseHandle
from sherlog.core.errors import SherlogError
from sherlog.core.models import IOC, AIDraft, AIHypothesis, AIMessage, AIRun, Event, Finding
from sherlog.core.timeline import TimelineQuery, query_events
from sherlog.core.timeutil import iso, utcnow
from sherlog.core.vocab import FindingStatus, VerifiedBy
from sherlog.detection.findings import SEVERITY_ORDER, list_findings
from sherlog.enrichment.summary import intel_summary
from sherlog.identify.service import list_artifacts

log = logging.getLogger(__name__)

MAX_TOOL_RESULT_CHARS = 12000
TRANSCRIPT_FORMAT = "sherlog.ai-transcript/1"


# --- briefing ---------------------------------------------------------------------------------


def _findings_text(findings: list[dict[str, Any]], limit: int = 40) -> str:
    lines = []
    for f in findings[:limit]:
        techs = ",".join(t["id"] for t in f["attack_techniques"])
        window = f"{f['first_seen'] or 'undated'} -> {f['last_seen'] or ''}"
        extra = f"; {techs}" if techs else ""
        lines.append(
            f"#{f['id']} [{f['severity']}, {f['verified_by']}, {f['status']}] {f['title']} "
            f"({window}; {f['event_count']} events; rule {f['rule_id']}{extra})"
        )
    if len(findings) > limit:
        lines.append(f"... and {len(findings) - limit} more")
    return "\n".join(lines) or "(none)"


def briefing(handle: CaseHandle, question: str | None) -> str:
    """The initial user message (not yet redacted)."""
    findings = [f for f in list_findings(handle) if f["status"] != "rejected"]
    with handle.session() as s:
        case = handle.case(s)
        first, last = s.execute(
            select(func.min(Event.timestamp_utc), func.max(Event.timestamp_utc))
        ).one()
        count = s.scalar(select(func.count()).select_from(Event)) or 0
        iocs = list(
            s.scalars(
                select(IOC)
                .where(IOC.finding_ids.is_not(None))
                .order_by(IOC.type, IOC.value)
                .limit(30)
            )
        )
        ioc_lines = [
            f"{i.type} {i.value} verdict={i.verdict} findings={i.finding_ids} "
            f"{intel_summary(i.enrichment or {})}".rstrip()
            for i in iocs
        ]
        brief, name, tz = case.brief, case.name, case.timezone
    artifacts = "\n".join(
        f"- {a['rel_path']}: {a['artifact_type']} ({a['status']}, {a['event_count']} events)"
        for a in list_artifacts(handle)
    )
    top = sorted(findings, key=lambda f: -SEVERITY_ORDER_BY_NAME[f["severity"]])[:5]
    sample_ids: list[int] = []
    with handle.session() as s:
        for f in top:
            row = s.get(Finding, f["id"])
            if row is not None:
                sample_ids.extend(e.id for e in row.events[:4])
    samples: list[dict[str, Any]] = []
    if sample_ids:
        events, _ = query_events(handle, TimelineQuery(ids=sample_ids, limit=40))
        samples = [compact_event(e) for e in events]
    return INITIAL_TEMPLATE.format(
        case_name=name,
        timezone=tz,
        brief=brief or "(no brief provided)",
        artifacts=artifacts or "(none)",
        first_event=iso(first) or "n/a",
        last_event=iso(last) or "n/a",
        event_count=count,
        finding_count=len(findings),
        findings=_findings_text(findings),
        iocs="\n".join(ioc_lines) or "(none linked to findings)",
        samples="\n".join(json.dumps(e, sort_keys=True) for e in samples) or "(none)",
        question=f"\nThe analyst asks: {question}\n" if question else "",
    )


SEVERITY_ORDER_BY_NAME = {s.value: v for s, v in SEVERITY_ORDER.items()}


# --- transcript -------------------------------------------------------------------------------


class _Transcript:
    def __init__(self, handle: CaseHandle, run_id: int) -> None:
        self.handle = handle
        self.run_id = run_id
        self.seq = 0

    def add(self, role: str, content: dict[str, Any]) -> None:
        self.seq += 1
        with self.handle.session() as s:
            s.add(
                AIMessage(
                    run_id=self.run_id,
                    seq=self.seq,
                    role=role,
                    content=content,
                    created_at=utcnow(),
                )
            )


def _result_text(obj: Any) -> str:
    text = json.dumps(obj, sort_keys=True, default=str)
    if len(text) > MAX_TOOL_RESULT_CHARS:
        text = text[:MAX_TOOL_RESULT_CHARS] + '..." [truncated: narrow the query]'
    return text


# --- the run ----------------------------------------------------------------------------------


def run_investigation(
    handle: CaseHandle,
    provider: Provider,
    *,
    max_iterations: int = 15,
    token_budget: int = 200_000,
    redact: bool = True,
    question: str | None = None,
    offline: bool = False,
    secret: str | None = None,
    replay_of: str | None = None,
    enrich: Callable[[str], dict[str, Any]] | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run one investigation and the summary draft; returns the run summary."""
    if max_iterations < 1:
        raise SherlogError("max_iterations must be at least 1")
    with handle.session() as s:
        case = handle.case(s)
        secret = secret or _case_secret(s) or new_secret()
        run = AIRun(
            started_at=utcnow(),
            provider=provider.name,
            model=provider.model,
            redaction=redact,
            redaction_secret=secret,
            replay_of=replay_of,
            question=question,
            max_iterations=max_iterations,
            token_budget=token_budget,
            status="running",
        )
        s.add(run)
        s.flush()
        run_id = run.id
        redactor = build_redactor(s, secret, enabled=redact, brief=case.brief)

    transcript = _Transcript(handle, run_id)
    ctx = ToolContext(handle, run_id, provider.model, offline=offline, enrich=enrich)
    tool_log: list[dict[str, Any]] = []
    iterations = in_tok = out_tok = 0
    status, stop_reason, final_text = "completed", "model finished", ""
    say = progress or (lambda _m: None)

    try:
        system = redactor.redact(SYSTEM_PROMPT)
        transcript.add(
            "system", {"text": system, "tools": [t.name for t in TOOL_SPECS], "redaction": redact}
        )
        session = provider.start(system, TOOL_SPECS)
        user_text = redactor.redact(briefing(handle, question))
        transcript.add("user", {"text": user_text})
        results: list[ToolResult] | None = None
        pending_text: str | None = user_text
        while True:
            if iterations >= max_iterations:
                status, stop_reason = "stopped", f"iteration limit ({max_iterations}) reached"
                break
            if in_tok + out_tok >= token_budget:
                status, stop_reason = "stopped", f"token budget ({token_budget}) reached"
                break
            iterations += 1
            say(f"AI round {iterations}/{max_iterations}")
            turn = session.send(user_text=pending_text, tool_results=results)
            pending_text = None
            in_tok += turn.input_tokens
            out_tok += turn.output_tokens
            transcript.add("assistant", turn.to_dict())
            if not turn.tool_calls:
                final_text = redactor.restore(turn.text)
                if turn.stop_reason == "max_tokens":
                    status, stop_reason = "stopped", "response hit the max_tokens limit"
                break
            results = []
            for call in turn.tool_calls:
                args = redactor.restore_obj(call.arguments)
                say(f"AI tool: {call.name}")
                try:
                    output = ctx.execute(call.name, args)
                    content, is_error = _result_text(redactor.redact_obj(output)), False
                except (ToolError, SherlogError) as exc:
                    content, is_error = redactor.redact(f"Error: {exc}"), True
                except Exception as exc:  # a tool bug must not end the run
                    log.exception("tool %s failed", call.name)
                    content, is_error = f"Error: internal tool failure ({type(exc).__name__})", True
                results.append(ToolResult(call.id, content, is_error))
                transcript.add(
                    "tool",
                    {
                        "call_id": call.id,
                        "name": call.name,
                        "content": content,
                        "is_error": is_error,
                    },
                )
                tool_log.append({"name": call.name, "arguments": args, "error": is_error})
    except ProviderError as exc:
        status, stop_reason = "error", str(exc)

    draft_id = None
    if status != "error":
        try:
            draft_id = _draft(handle, provider, redactor, transcript, run_id)
        except ProviderError as exc:
            stop_reason = f"{stop_reason}; draft failed: {exc}"

    stats = {
        "findings_proposed": ctx.created_findings,
        "hypotheses": ctx.created_hypotheses,
        "tool_calls": len(tool_log),
        "draft_id": draft_id,
        "pseudonyms": len(redactor.forward),
    }
    with handle.session() as s:
        row = s.get(AIRun, run_id)
        assert row is not None
        row.ended_at = utcnow()
        row.iterations = iterations
        row.input_tokens, row.output_tokens = in_tok, out_tok
        row.status, row.stop_reason, row.final_text = status, stop_reason, final_text
        row.stats = stats
        audit.record(
            s,
            "ai.investigate",
            run_id=run_id,
            provider=provider.name,
            model=provider.model,
            redaction=redact,
            replay_of=replay_of,
            status=status,
            stop_reason=stop_reason,
            iterations=iterations,
            tokens={"input": in_tok, "output": out_tok},
            tool_calls=tool_log,
            stats=stats,
        )
    return {
        "run_id": run_id,
        "status": status,
        "stop_reason": stop_reason,
        "iterations": iterations,
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "final_text": final_text,
        **stats,
    }


def _case_secret(session: Any) -> str | None:
    """Reuse the case's first redaction secret so pseudonyms stay stable across runs."""
    return session.scalar(select(AIRun.redaction_secret).order_by(AIRun.id).limit(1))


# --- summary draft ----------------------------------------------------------------------------


def confirmed_findings(handle: CaseHandle) -> list[dict[str, Any]]:
    """Findings the draft may use: rule or analyst provenance, not rejected."""
    return [
        f
        for f in list_findings(handle)
        if f["verified_by"] in (VerifiedBy.RULE.value, VerifiedBy.ANALYST.value)
        and f["status"] != FindingStatus.REJECTED.value
    ]


def _parse_draft(text: str) -> tuple[str, str | None]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(0))
            summary = str(data.get("executive_summary") or "").strip()
            if summary:
                return summary, (str(data.get("narrative") or "").strip() or None)
        except ValueError:
            pass
    return text.strip(), None


def _draft(
    handle: CaseHandle, provider: Provider, redactor: Redactor, transcript: _Transcript, run_id: int
) -> int | None:
    findings = confirmed_findings(handle)
    if not findings:
        return None
    body = []
    for f in findings:
        entity = ", ".join(f"{k}={v}" for k, v in (f["context"].get("entity") or {}).items())
        window = f"{f['first_seen'] or 'undated'} -> {f['last_seen'] or ''}"
        techs = ", ".join(t["id"] + " " + (t["name"] or "") for t in f["attack_techniques"])
        body.append(
            f"#{f['id']} [{f['severity']}] {f['title']}\n"
            f"  window: {window}; events: {f['event_count']}"
            f"{'; ' + entity if entity else ''}\n"
            f"  techniques: {techs or 'none'}\n"
            f"  narrative: {(f['narrative'] or '')[:1200]}"
        )
    prompt = redactor.redact(
        DRAFT_TEMPLATE.format(
            case_name=_case_name(handle), count=len(findings), findings="\n\n".join(body)
        )
    )
    transcript.add("draft_request", {"system": DRAFT_SYSTEM_PROMPT, "text": prompt})
    turn: Turn = provider.start(DRAFT_SYSTEM_PROMPT, []).send(user_text=prompt)
    transcript.add("draft_response", turn.to_dict())
    summary, narrative = _parse_draft(redactor.restore(turn.text))
    if not summary:
        return None
    with handle.session() as s:
        d = AIDraft(
            run_id=run_id,
            model=provider.model,
            executive_summary=summary,
            narrative=narrative,
            finding_ids=[f["id"] for f in findings],
            status="draft",
            created_at=utcnow(),
        )
        s.add(d)
        s.flush()
        return d.id


def _case_name(handle: CaseHandle) -> str:
    with handle.session() as s:
        return handle.case(s).name


# --- review, listing, export/replay -----------------------------------------------------------


def draft_to_dict(d: AIDraft) -> dict[str, Any]:
    return {
        "id": d.id,
        "run_id": d.run_id,
        "model": d.model,
        "status": d.status,
        "edited": d.edited,
        "executive_summary": d.executive_summary,
        "narrative": d.narrative,
        "finding_ids": d.finding_ids,
        "reviewed_by": d.reviewed_by,
        "reviewed_at": iso(d.reviewed_at),
        "created_at": iso(d.created_at),
    }


def latest_draft(handle: CaseHandle, *, status: str | None = None) -> dict[str, Any] | None:
    with handle.session() as s:
        stmt = select(AIDraft).order_by(AIDraft.id.desc())
        if status:
            stmt = stmt.where(AIDraft.status == status)
        d = s.scalars(stmt).first()
        return draft_to_dict(d) if d else None


def review_draft(
    handle: CaseHandle,
    draft_id: int,
    decision: str,
    *,
    executive_summary: str | None = None,
    narrative: str | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """Accept (optionally with edited text) or reject a draft. One draft is accepted at a time."""
    if decision not in ("accepted", "rejected"):
        raise SherlogError("decision must be accepted or rejected")
    with handle.session() as s:
        d = s.get(AIDraft, draft_id)
        if d is None:
            raise SherlogError(f"No draft with id {draft_id}")
        actor = actor or handle.case(s).investigator
        if executive_summary is not None:
            d.executive_summary = executive_summary.strip()
            d.edited = True
        if narrative is not None:
            d.narrative = narrative.strip() or None
            d.edited = True
        if decision == "accepted":
            for other in s.scalars(
                select(AIDraft).where(AIDraft.status == "accepted", AIDraft.id != d.id)
            ):
                other.status = "superseded"
        d.status = decision
        d.reviewed_by = actor
        d.reviewed_at = utcnow()
        audit.record(
            s, "ai.draft.review", actor=actor, draft_id=d.id, decision=decision, edited=d.edited
        )
        s.flush()
        return draft_to_dict(d)


def run_to_dict(r: AIRun) -> dict[str, Any]:
    return {
        "id": r.id,
        "started_at": iso(r.started_at),
        "ended_at": iso(r.ended_at),
        "provider": r.provider,
        "model": r.model,
        "redaction": r.redaction,
        "replay_of": r.replay_of,
        "question": r.question,
        "iterations": r.iterations,
        "input_tokens": r.input_tokens,
        "output_tokens": r.output_tokens,
        "status": r.status,
        "stop_reason": r.stop_reason,
        "final_text": r.final_text,
        "stats": r.stats or {},
    }


def list_runs(handle: CaseHandle) -> list[dict[str, Any]]:
    with handle.session() as s:
        return [run_to_dict(r) for r in s.scalars(select(AIRun).order_by(AIRun.id))]


def get_run(handle: CaseHandle, run_id: int) -> dict[str, Any]:
    with handle.session() as s:
        r = s.get(AIRun, run_id)
        if r is None:
            raise SherlogError(f"No AI run with id {run_id}")
        out = run_to_dict(r)
        out["messages"] = [{"seq": m.seq, "role": m.role, "content": m.content} for m in r.messages]
        return out


def list_hypotheses(handle: CaseHandle) -> list[dict[str, Any]]:
    with handle.session() as s:
        return [
            {
                "id": h.id,
                "run_id": h.run_id,
                "statement": h.statement,
                "rationale": h.rationale,
                "event_ids": h.event_ids,
                "suggested_checks": h.suggested_checks,
                "created_at": iso(h.created_at),
            }
            for h in s.scalars(select(AIHypothesis).order_by(AIHypothesis.id))
        ]


def export_run(handle: CaseHandle, run_id: int) -> dict[str, Any]:
    """A replayable transcript: the model's turns plus the pseudonym key used."""
    with handle.session() as s:
        r = s.get(AIRun, run_id)
        if r is None:
            raise SherlogError(f"No AI run with id {run_id}")
        investigation = [m.content for m in r.messages if m.role == "assistant"]
        draft = [m.content for m in r.messages if m.role == "draft_response"]
        return {
            "format": TRANSCRIPT_FORMAT,
            "case": handle.case(s).name,
            "run_id": r.id,
            "provider": r.provider,
            "model": r.model,
            "redaction": r.redaction,
            "redaction_secret": r.redaction_secret,
            "turns": investigation,
            "draft_turns": draft,
        }


def replay_provider(source: dict[str, Any]) -> tuple[ReplayProvider, dict[str, Any]]:
    """Build a replay provider (and run options) from an exported transcript."""
    if source.get("format") != TRANSCRIPT_FORMAT:
        raise SherlogError("Not a SherLog AI transcript export")
    provider = ReplayProvider(
        f"replay:{source.get('model')}",
        [Turn.from_dict(t) for t in source.get("turns", [])],
        [Turn.from_dict(t) for t in source.get("draft_turns", [])],
    )
    options = {
        "redact": bool(source.get("redaction", True)),
        "secret": source.get("redaction_secret"),
        "max_iterations": max(1, len(source.get("turns", []))),
    }
    return provider, options


def load_replay(handle: CaseHandle, ref: str) -> tuple[ReplayProvider, dict[str, Any], str]:
    """``ref`` is a run id of this case or a path to an exported transcript JSON."""
    if ref.isdigit():
        data = export_run(handle, int(ref))
        label = f"run {ref}"
    else:
        path = Path(ref).expanduser()
        if not path.is_file():
            raise SherlogError(f"No run id or transcript file {ref!r}")
        data = json.loads(path.read_text(encoding="utf-8"))
        label = str(path)
    provider, options = replay_provider(data)
    return provider, options, label
