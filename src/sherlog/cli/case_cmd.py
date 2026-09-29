"""``sherlog case``: create, list, show and delete cases."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from sherlog.cli.common import JsonOption, console, emit_json, opened_case, settings, user_errors
from sherlog.core import case as case_mod

app = typer.Typer(help="Create and manage cases.", no_args_is_help=True)


@app.command("new")
def new(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Case name (letters, digits, '.', '_', '-').")],
    brief: Annotated[
        str | None, typer.Option(help="Case brief: a path to a text file, or the text itself.")
    ] = None,
    tz: Annotated[
        str, typer.Option("--tz", help="IANA timezone assumed for logs without one.")
    ] = "UTC",
    investigator: Annotated[
        str | None, typer.Option(help="Investigator name (default: OS user).")
    ] = None,
    as_json: JsonOption = False,
) -> None:
    """Create a new case directory and database."""
    with user_errors():
        handle = case_mod.create_case(
            settings(ctx), name, brief=brief, timezone=tz, investigator=investigator
        )
        try:
            summary = case_mod.summarize(handle)
        finally:
            handle.close()
    if as_json:
        emit_json(summary)
    else:
        console.print(f"[green]Created case[/] [bold]{name}[/] at {summary['directory']}")


@app.command("list")
def list_(ctx: typer.Context, as_json: JsonOption = False) -> None:
    """List cases in the cases directory."""
    with user_errors():
        cases = case_mod.list_cases(settings(ctx))
    if as_json:
        emit_json(cases)
        return
    if not cases:
        console.print(f"No cases in {settings(ctx).cases_dir}")
        return
    table = Table("Name", "Created (UTC)", "Investigator", "TZ", "Evidence", "Files", "Events")
    for c in cases:
        table.add_row(
            c["name"],
            c["created_at"][:19],
            c["investigator"],
            c["timezone"],
            str(c["evidence_items"]),
            str(c["evidence_files"]),
            str(c["events"]),
        )
    console.print(table)


@app.command("show")
def show(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Case name.")],
    as_json: JsonOption = False,
) -> None:
    """Show case metadata and counts."""
    with opened_case(ctx, name) as handle:
        summary = case_mod.summarize(handle)
    if as_json:
        emit_json(summary)
        return
    table = Table(show_header=False, box=None)
    for key, value in summary.items():
        if key != "brief":
            table.add_row(f"[bold]{key}[/]", str(value))
    console.print(table)
    if summary["brief"]:
        console.rule("Brief")
        console.print(summary["brief"], markup=False)


@app.command("delete")
def delete(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Case name.")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
    as_json: JsonOption = False,
) -> None:
    """Delete a case's working data (original evidence is not touched)."""
    if not yes:
        typer.confirm(
            f"Delete case {name!r} and all its analysis data? Original evidence is not affected.",
            abort=True,
        )
    with user_errors():
        directory = case_mod.delete_case(settings(ctx), name)
    if as_json:
        emit_json({"deleted": name, "directory": str(directory)})
    else:
        console.print(f"Deleted case [bold]{name}[/] ({directory})")
