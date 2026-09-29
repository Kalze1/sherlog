"""``sherlog investigate`` and ``sherlog ai ...``: the AI investigation assistant."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.markup import escape
from rich.table import Table

from sherlog.cli.common import JsonOption, console, emit_json, err_console, opened_case, user_errors
from sherlog.cli.evidence_cmd import CaseArg
from sherlog.core.case import CaseHandle
from sherlog.core.config import get_setting
from sherlog.core.errors import SherlogError

app = typer.Typer(help="AI runs, transcripts, hypotheses and drafts.", no_args_is_help=True)

_DRAFT_HEADINGS = ("# Executive summary", "# Narrative")


def run_ai(
    handle: CaseHandle,
    *,
    provider_name: str | None = None,
    model: str | None = None,
    max_iterations: int | None = None,
    token_budget: int | None = None,
    no_redact: bool = False,
    question: str | None = None,
    replay: str | None = None,
    offline: bool = False,
    progress: Any = None,
) -> dict[str, Any] | None:
    """Run an investigation with the configured (or given) provider.

    Returns None when no AI provider is configured.
    """
    from sherlog.ai.orchestrator import load_replay, run_investigation
    from sherlog.ai.providers import provider_from_config
    from sherlog.enrichment.service import enrich_case

    offline = bool(get_setting("offline", True if offline else None))
    options: dict[str, Any] = {}
    replay_label = None
    if replay:
        provider, options, replay_label = load_replay(handle, replay)
    else:
        if offline:
            raise SherlogError("AI is disabled in offline mode")
        provider = provider_from_config(provider_name, model)  # type: ignore[assignment]
        if provider is None:
            return None
    redact = options.get("redact", bool(get_setting("ai.redact")) and not no_redact)
    return run_investigation(
        handle,
        provider,
        max_iterations=options.get("max_iterations")
        or int(max_iterations or get_setting("ai.max_iterations")),
        token_budget=int(token_budget or get_setting("ai.token_budget")),
        redact=redact,
        question=question,
        offline=offline or replay is not None,
        secret=options.get("secret"),
        replay_of=replay_label,
        enrich=lambda value: enrich_case(handle, ioc_values=[value]),
        progress=progress,
    )


def print_run_summary(result: dict[str, Any]) -> None:
    style = {"completed": "green", "stopped": "yellow", "error": "red"}.get(result["status"], "")
    console.print(
        f"AI run #{result['run_id']}: [{style}]{result['status']}[/] "
        f"({escape(result['stop_reason'])}); "
        f"{result['iterations']} rounds, {result['tool_calls']} tool calls, "
        f"{result['input_tokens'] + result['output_tokens']} tokens."
    )
    console.print(
        f"Proposed findings: {len(result['findings_proposed'])} "
        f"{['#' + str(i) for i in result['findings_proposed']] or ''}; "
        f"hypotheses: {len(result['hypotheses'])}; "
        f"draft: {'#' + str(result['draft_id']) if result['draft_id'] else 'none'}."
    )
    if result["final_text"]:
        console.rule("Assistant summary")
        console.print(result["final_text"], markup=False, highlight=False)
    if result["findings_proposed"]:
        console.print(
            "[magenta]AI-proposed findings are unverified.[/] Review with "
            "'sherlog findings <case> --verified-by ai_proposed' and --accept/--reject."
        )
    if result["draft_id"]:
        console.print("Review the summary draft with 'sherlog ai draft <case>'.")


def investigate(
    ctx: typer.Context,
    case: CaseArg,
    provider: Annotated[
        str | None, typer.Option(help="anthropic, openai or ollama (default: ai.provider).")
    ] = None,
    model: Annotated[str | None, typer.Option(help="Model name (default: ai.model).")] = None,
    max_iterations: Annotated[
        int | None, typer.Option(help="Tool-use rounds (default: ai.max_iterations, 15).")
    ] = None,
    token_budget: Annotated[
        int | None, typer.Option(help="Token cap (default: ai.token_budget).")
    ] = None,
    question: Annotated[
        str | None, typer.Option("--question", "-q", help="A question or lead for the assistant.")
    ] = None,
    no_redact: Annotated[
        bool,
        typer.Option("--no-redact", help="Send real host names, internal IPs, usernames, e-mails."),
    ] = False,
    replay: Annotated[
        str | None,
        typer.Option(help="Replay a recorded run (run id or exported transcript file)."),
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Refuse; AI needs a provider.")
    ] = False,
    as_json: JsonOption = False,
) -> None:
    """Run the AI investigation assistant over the case (after 'sherlog analyze')."""
    with opened_case(ctx, case) as handle:
        if no_redact and not as_json:
            err_console.print(
                "[yellow]Redaction disabled:[/] real host names, internal addresses and "
                "usernames will be sent to the model provider."
            )
        if as_json:
            result = run_ai(
                handle,
                provider_name=provider,
                model=model,
                max_iterations=max_iterations,
                token_budget=token_budget,
                no_redact=no_redact,
                question=question,
                replay=replay,
                offline=offline,
            )
        else:
            with console.status("Investigating ...") as status:
                result = run_ai(
                    handle,
                    provider_name=provider,
                    model=model,
                    max_iterations=max_iterations,
                    token_budget=token_budget,
                    no_redact=no_redact,
                    question=question,
                    replay=replay,
                    offline=offline,
                    progress=lambda m: status.update(m),
                )
    if result is None:
        raise typer.BadParameter(
            "No AI provider configured. Set one, e.g. `sherlog config set ai.provider anthropic`."
        )
    if as_json:
        emit_json(result)
    else:
        print_run_summary(result)
    if result["status"] == "error":
        raise typer.Exit(1)


@app.command("runs")
def runs(ctx: typer.Context, case: CaseArg, as_json: JsonOption = False) -> None:
    """List AI runs."""
    from sherlog.ai.orchestrator import list_runs

    with opened_case(ctx, case) as handle:
        rows = list_runs(handle)
    if as_json:
        emit_json(rows)
        return
    table = Table(
        "Run",
        "Started (UTC)",
        "Provider/model",
        "Redacted",
        "Rounds",
        "Tokens",
        "Status",
        "Proposed",
    )
    for r in rows:
        table.add_row(
            str(r["id"]),
            (r["started_at"] or "")[:19],
            f"{r['provider']}/{r['model']}",
            "yes" if r["redaction"] else "[red]no[/]",
            str(r["iterations"]),
            str(r["input_tokens"] + r["output_tokens"]),
            r["status"],
            str(len(r["stats"].get("findings_proposed", []))),
        )
    console.print(table)


@app.command("show")
def show(
    ctx: typer.Context,
    case: CaseArg,
    run_id: Annotated[int, typer.Argument(help="Run id.")],
    as_json: JsonOption = False,
) -> None:
    """Show a run's transcript exactly as exchanged with the provider (redacted)."""
    from sherlog.ai.orchestrator import get_run

    with opened_case(ctx, case) as handle:
        run = get_run(handle, run_id)
    if as_json:
        emit_json(run)
        return
    console.print(
        f"Run #{run['id']} {run['provider']}/{run['model']} — {run['status']}: "
        f"{escape(run['stop_reason'] or '')}"
    )
    for m in run["messages"]:
        c = m["content"]
        console.rule(f"{m['seq']}. {m['role']}")
        if m["role"] in ("assistant", "draft_response"):
            if c.get("text"):
                console.print(c["text"], markup=False, highlight=False)
            for call in c.get("tool_calls", []):
                console.print(
                    f"→ {call['name']} {json.dumps(call['arguments'])}",
                    markup=False,
                    highlight=False,
                )
        elif m["role"] == "tool":
            prefix = "ERROR " if c.get("is_error") else ""
            console.print(
                f"{prefix}{c['name']}: {c['content'][:1500]}", markup=False, highlight=False
            )
        else:
            console.print(str(c.get("text", ""))[:3000], markup=False, highlight=False)


@app.command("export")
def export(
    ctx: typer.Context,
    case: CaseArg,
    run_id: Annotated[int, typer.Argument(help="Run id.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output JSON file.")],
) -> None:
    """Export a run for replay ('sherlog investigate --replay FILE'). Contains the pseudonym key."""
    from sherlog.ai.orchestrator import export_run

    with opened_case(ctx, case) as handle:
        data = export_run(handle, run_id)
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out.chmod(0o600)
    console.print(f"Exported run #{run_id} to {out} (keep private: it contains the pseudonym key).")


@app.command("hypotheses")
def hypotheses(ctx: typer.Context, case: CaseArg, as_json: JsonOption = False) -> None:
    """List unverified hypotheses proposed by the assistant."""
    from sherlog.ai.orchestrator import list_hypotheses

    with opened_case(ctx, case) as handle:
        rows = list_hypotheses(handle)
    if as_json:
        emit_json(rows)
        return
    if not rows:
        console.print("No hypotheses.")
    for h in rows:
        console.rule(f"H{h['id']} (run {h['run_id']}) — unverified")
        console.print(h["statement"], markup=False, highlight=False)
        if h["rationale"]:
            console.print(f"Rationale: {h['rationale']}", markup=False, highlight=False)
        if h["event_ids"]:
            console.print(f"Events: {h['event_ids']}")
        for c in h["suggested_checks"]:
            console.print(f"  - check: {c}", markup=False, highlight=False)


def _parse_edit(text: str) -> tuple[str, str | None]:
    lower = text.lower()
    s_idx = lower.find(_DRAFT_HEADINGS[0].lower())
    n_idx = lower.find(_DRAFT_HEADINGS[1].lower())
    if s_idx < 0:
        return text.strip(), None
    summary_end = n_idx if n_idx > s_idx else len(text)
    summary = text[s_idx + len(_DRAFT_HEADINGS[0]) : summary_end].strip()
    narrative = text[n_idx + len(_DRAFT_HEADINGS[1]) :].strip() if n_idx >= 0 else None
    return summary, narrative


@app.command("draft")
def draft(
    ctx: typer.Context,
    case: CaseArg,
    draft_id: Annotated[
        int | None, typer.Option("--id", help="Draft id (default: latest).")
    ] = None,
    accept: Annotated[
        bool, typer.Option("--accept", help="Accept the draft for the report.")
    ] = False,
    reject: Annotated[bool, typer.Option("--reject", help="Reject the draft.")] = False,
    write: Annotated[
        Path | None, typer.Option("--write", help="Write the draft to a file for editing.")
    ] = None,
    edit: Annotated[
        Path | None,
        typer.Option("--edit", help="Accept the text from an edited file (see --write)."),
    ] = None,
    as_json: JsonOption = False,
) -> None:
    """Show, edit, accept or reject the AI-drafted executive summary and narrative."""
    from sherlog.ai.orchestrator import latest_draft, review_draft

    with opened_case(ctx, case) as handle:
        current = latest_draft(handle) if draft_id is None else None
        target = draft_id if draft_id is not None else (current["id"] if current else None)
        if target is None:
            raise SherlogError("No AI draft yet; run 'sherlog investigate' first")
        if sum(bool(x) for x in (accept, reject, edit)) > 1:
            raise typer.BadParameter("use only one of --accept, --reject, --edit")
        with user_errors():
            if accept or reject:
                result = review_draft(handle, target, "accepted" if accept else "rejected")
            elif edit:
                summary, narrative = _parse_edit(edit.read_text(encoding="utf-8"))
                result = review_draft(
                    handle, target, "accepted", executive_summary=summary, narrative=narrative or ""
                )
            else:
                from sherlog.ai.orchestrator import draft_to_dict
                from sherlog.core.models import AIDraft

                with handle.session() as s:
                    row = s.get(AIDraft, target)
                    if row is None:
                        raise SherlogError(f"No draft with id {target}")
                    result = draft_to_dict(row)
    if write:
        write.write_text(
            f"{_DRAFT_HEADINGS[0]}\n\n{result['executive_summary']}\n\n"
            f"{_DRAFT_HEADINGS[1]}\n\n{result['narrative'] or ''}\n",
            encoding="utf-8",
        )
        console.print(f"Draft written to {write}; edit it, then run with --edit {write}.")
    if as_json:
        emit_json(result)
        return
    console.rule(
        f"Draft #{result['id']} ({result['status']}{', edited' if result['edited'] else ''}) "
        f"— {result['model']}"
    )
    console.print("[bold]Executive summary[/]")
    console.print(result["executive_summary"], markup=False, highlight=False)
    if result["narrative"]:
        console.print("\n[bold]Narrative[/]")
        console.print(result["narrative"], markup=False, highlight=False)
    console.print(f"\nBased on confirmed findings {['#' + str(i) for i in result['finding_ids']]}.")
