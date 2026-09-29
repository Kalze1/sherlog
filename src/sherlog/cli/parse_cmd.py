"""``sherlog parse``: identify and parse evidence into the event timeline."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from sherlog.cli.common import JsonOption, console, emit_json, opened_case
from sherlog.cli.evidence_cmd import CaseArg, TypeOverride


def parse(
    ctx: typer.Context,
    case: CaseArg,
    type_: TypeOverride = None,
    force: Annotated[
        bool, typer.Option("--force", help="Discard existing events and parse again.")
    ] = False,
    as_json: JsonOption = False,
) -> None:
    """Identify and parse all evidence into normalized events."""
    from sherlog.identify.service import parse_overrides
    from sherlog.parsers.service import parse_case

    with opened_case(ctx, case) as handle:
        overrides = parse_overrides(type_ or [])
        if as_json:
            result = parse_case(handle, overrides, force=force)
        else:
            with console.status("Parsing evidence ..."):
                result = parse_case(handle, overrides, force=force)
    if as_json:
        emit_json(result)
        return
    table = Table("File", "Type", "Parser", "Status", "Events", "Parse errors")
    for f in result["files"]:
        style = {"error": "red", "unsupported": "yellow"}.get(f["status"])
        status = f"[{style}]{f['status']}[/]" if style else f["status"]
        errors = str(f["parse_errors"]) if f["parse_errors"] else ""
        table.add_row(
            f["rel_path"], f["artifact_type"], f["parser"], status, str(f["events"]), errors
        )
    console.print(table)
    for f in result["files"]:
        if f["message"]:
            console.print(f"[yellow]{f['rel_path']}:[/] {f['message']}", highlight=False)
    console.print(f"[green]{result['total_events']} events[/] stored.")
    if result["discarded_events"]:
        console.print(f"Discarded {result['discarded_events']} previously parsed events.")
