"""``sherlog timeline``: browse and filter the normalized event timeline."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from sherlog.cli.common import JsonOption, console, emit_json, opened_case, user_errors
from sherlog.cli.evidence_cmd import CaseArg
from sherlog.core.timeline import TimelineQuery, parse_time, query_events


def _summary(e: dict[str, object]) -> str:
    """Command if there is one, else the raw line minus its timestamp/host prefix.

    State entries (crontab lines, authorized keys, config settings) have no
    timestamp; for those, show target and command rather than the raw line.
    """
    if e.get("timestamp_raw") is None:
        state = " ".join(str(e[k]) for k in ("target", "command") if e.get(k))
        if state:
            return state
    if e.get("command"):
        return str(e["command"])
    raw, ts, host = str(e["raw"]), e.get("timestamp_raw"), e.get("host")
    if ts and raw.startswith(str(ts)):
        raw = raw[len(str(ts)) :].lstrip()
        if host and raw.startswith(f"{host} "):
            raw = raw[len(str(host)) + 1 :]
    return raw


def timeline(
    ctx: typer.Context,
    case: CaseArg,
    from_: Annotated[
        str | None, typer.Option("--from", help="Start time, ISO 8601 (UTC if no offset).")
    ] = None,
    to: Annotated[
        str | None, typer.Option("--to", help="End time, ISO 8601 (UTC if no offset).")
    ] = None,
    grep: Annotated[
        str | None, typer.Option(help="Case-insensitive regex matched against the raw line.")
    ] = None,
    type_: Annotated[
        list[str] | None,
        typer.Option("--type", help="Event type or prefix, e.g. auth.login (repeatable)."),
    ] = None,
    artifact: Annotated[str | None, typer.Option(help="Artifact type, e.g. linux.auth.")] = None,
    actor: Annotated[str | None, typer.Option(help="Actor (user) name.")] = None,
    ip: Annotated[str | None, typer.Option(help="Source or destination IP.")] = None,
    host: Annotated[str | None, typer.Option(help="Host name recorded in the log.")] = None,
    limit: Annotated[int, typer.Option(help="Maximum events to show (0 = no limit).")] = 200,
    offset: Annotated[int, typer.Option(help="Skip this many matching events.")] = 0,
    as_json: JsonOption = False,
) -> None:
    """Show events in time order (events without a timestamp come last)."""
    with user_errors():
        q = TimelineQuery(
            start=parse_time(from_) if from_ else None,
            end=parse_time(to) if to else None,
            grep=grep,
            types=type_ or [],
            artifact=artifact,
            actor=actor,
            ip=ip,
            host=host,
            limit=limit or None,
            offset=offset,
        )
    with opened_case(ctx, case) as handle:
        events, total = query_events(handle, q)
    if as_json:
        emit_json({"total": total, "offset": offset, "events": events})
        return
    table = Table("Time (UTC)", "Host", "Type", "Actor", "Src IP", "Detail", show_lines=False)
    for e in events:
        ts = e["timestamp_utc"]
        when = "-" if ts is None else str(ts)[:19].replace("T", " ")
        if e["timezone_assumed"]:
            when += "*"
        table.add_row(
            when,
            e["host"] or "",
            e["event_type"],
            e["actor"] or "",
            e["src_ip"] or "",
            _summary(e)[:120],
        )
    console.print(table)
    shown = len(events)
    note = f"{shown} of {total} matching events"
    if offset + shown < total:
        note += f" (use --offset {offset + shown} or --limit 0 for more)"
    console.print(note + ".  * = source timezone assumed from case settings.")
