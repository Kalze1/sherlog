"""``sherlog findings``: list, inspect and review findings."""

from __future__ import annotations

from typing import Annotated, Any

import typer
from rich.table import Table

from sherlog.cli.common import JsonOption, console, emit_json, opened_case
from sherlog.cli.evidence_cmd import CaseArg
from sherlog.core.vocab import FindingStatus, Severity, VerifiedBy

_BADGE = {"rule": "[green]rule[/]", "analyst": "[blue]analyst[/]", "ai_proposed": "[magenta]AI?[/]"}
_SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _sev(s: str) -> str:
    return f"[{_SEV_STYLE[s]}]{s}[/]"


def print_finding(f: dict[str, Any]) -> None:
    """Full detail of one finding, including linked events."""
    console.rule(f"#{f['id']} {f['title']}")
    meta = Table(show_header=False, box=None)
    meta.add_row("Severity", _sev(f["severity"]))
    meta.add_row("Verified by", _BADGE[f["verified_by"]])
    meta.add_row("Status", f["status"] + (" (stale)" if f["context"].get("stale") else ""))
    meta.add_row("Confidence", f"{f['confidence']:.2f}")
    meta.add_row("Rule", f["rule_id"] or "-")
    meta.add_row("Window", f"{f['first_seen'] or '-'} → {f['last_seen'] or '-'}")
    meta.add_row("Events", f"{f['event_count']} ({f['linked_events']} linked)")
    techs = ", ".join(f"{t['id']} {t['name'] or ''}".strip() for t in f["attack_techniques"]) or "-"
    meta.add_row("ATT&CK", techs)
    if f["cves"]:
        meta.add_row("CVEs", ", ".join(c["id"] for c in f["cves"]))
    if f["analyst_note"]:
        meta.add_row("Analyst note", f["analyst_note"])
    console.print(meta)
    console.print(f["narrative"] or "", markup=False, highlight=False)
    if f["recommendations"]:
        console.print("[bold]Recommendation:[/] " + " ".join(f["recommendations"]), highlight=False)
    if f.get("events"):
        t = Table("Time (UTC)", "Source", "Line", "Raw", title="Linked events")
        for e in f["events"][:50]:
            t.add_row(
                (e["timestamp_utc"] or "-")[:19],
                e["source"]["rel_path"],
                str(e["source"]["line_number"] or ""),
                e["raw"][:160],
            )
        console.print(t)
        if len(f["events"]) > 50:
            console.print(f"... {len(f['events']) - 50} more linked events (use --json).")


def findings(
    ctx: typer.Context,
    case: CaseArg,
    show: Annotated[int | None, typer.Option("--show", help="Show one finding in full.")] = None,
    accept: Annotated[
        int | None, typer.Option("--accept", help="Mark a finding as confirmed.")
    ] = None,
    reject: Annotated[
        int | None, typer.Option("--reject", help="Mark a finding as dismissed.")
    ] = None,
    reopen: Annotated[
        int | None, typer.Option("--reopen", help="Set a finding back to open.")
    ] = None,
    note: Annotated[
        str | None, typer.Option(help="Analyst note recorded with --accept/--reject.")
    ] = None,
    status: Annotated[FindingStatus | None, typer.Option(help="Filter by review status.")] = None,
    min_severity: Annotated[
        Severity | None, typer.Option(help="Hide findings below this severity.")
    ] = None,
    verified_by: Annotated[VerifiedBy | None, typer.Option(help="Filter by provenance.")] = None,
    as_json: JsonOption = False,
) -> None:
    """List findings (highest severity first) or review one with --accept/--reject."""
    from sherlog.detection.findings import get_finding, list_findings, review_finding

    with opened_case(ctx, case) as handle:
        actions = [
            (accept, FindingStatus.ACCEPTED),
            (reject, FindingStatus.REJECTED),
            (reopen, FindingStatus.OPEN),
        ]
        chosen = [(fid, st) for fid, st in actions if fid is not None]
        if len(chosen) > 1:
            raise typer.BadParameter("use only one of --accept/--reject/--reopen")
        if chosen:
            fid, st = chosen[0]
            result = review_finding(handle, fid, st, note=note)
            if as_json:
                emit_json(result)
            else:
                badge = _BADGE[result["verified_by"]]
                console.print(f"Finding #{fid} is now [bold]{result['status']}[/] ({badge}).")
            return
        if show is not None:
            f = get_finding(handle, show)
            if as_json:
                emit_json(f)
            else:
                print_finding(f)
            return
        rows = list_findings(
            handle, status=status, min_severity=min_severity, verified_by=verified_by
        )
    if as_json:
        emit_json(rows)
        return
    if not rows:
        console.print("No findings. Run 'sherlog analyze' first.")
        return
    table = Table("ID", "Sev", "By", "Status", "Title", "Events", "ATT&CK", "First seen (UTC)")
    for f in rows:
        table.add_row(
            str(f["id"]),
            _sev(f["severity"]),
            _BADGE[f["verified_by"]],
            f["status"],
            f["title"][:80],
            str(f["event_count"]),
            ", ".join(t["id"] for t in f["attack_techniques"])[:40],
            (f["first_seen"] or "-")[:19],
        )
    console.print(table)
    console.print(
        f"{len(rows)} finding(s). Use --show ID for details, --accept/--reject ID to review."
    )
