"""``sherlog evidence``: add, list and verify evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer
from rich.table import Table

from sherlog.cli.common import JsonOption, console, emit_json, err_console, opened_case
from sherlog.intake import service

app = typer.Typer(help="Add, list and verify evidence.", no_args_is_help=True)

CaseArg = Annotated[str, typer.Argument(help="Case name.")]


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"  # pragma: no cover


@app.command("add")
def add(
    ctx: typer.Context,
    case: CaseArg,
    path: Annotated[Path, typer.Argument(help="File or directory of collected logs.")],
    label: Annotated[str | None, typer.Option(help="Label for this evidence item.")] = None,
    by: Annotated[
        str | None,
        typer.Option("--by", help="Person handling the evidence (default: case investigator)."),
    ] = None,
    note: Annotated[
        str | None, typer.Option(help="Provenance note, e.g. 'scp from web01 by J. Doe'.")
    ] = None,
    as_json: JsonOption = False,
) -> None:
    """Hash every file under PATH (read-only) and record it with chain of custody."""
    with opened_case(ctx, case) as handle:
        if not as_json:
            with console.status(f"Hashing {path} ..."):
                result = service.add_evidence(handle, path, label=label, actor=by, source_note=note)
        else:
            result = service.add_evidence(handle, path, label=label, actor=by, source_note=note)
    if as_json:
        emit_json(result)
        return
    counts = ", ".join(f"{k}={v}" for k, v in sorted(result["counts"].items()))
    console.print(
        f"[green]Added evidence #{result['id']}[/] [bold]{result['label']}[/]: {counts}, "
        f"{_human_bytes(result['total_bytes'])}"
    )
    console.print(f"item digest  {result['item_digest']}")
    for warning in result["warnings"]:
        err_console.print(f"[yellow]warning:[/] {warning}", markup=True, highlight=False)


@app.command("list")
def list_(
    ctx: typer.Context,
    case: CaseArg,
    files: Annotated[bool, typer.Option("--files", help="List every file with hashes.")] = False,
    as_json: JsonOption = False,
) -> None:
    """List evidence items in a case."""
    with opened_case(ctx, case) as handle:
        items = service.list_evidence(handle, include_files=files)
    if as_json:
        emit_json(items)
        return
    if not items:
        console.print("No evidence in this case yet.")
        return
    table = Table("#", "Label", "Source", "Files", "Size", "Added (UTC)", "By")
    for i in items:
        table.add_row(
            str(i["id"]),
            i["label"],
            i["source_path"],
            str(i["file_count"]),
            _human_bytes(i["total_bytes"]),
            i["added_at"][:19],
            i["added_by"],
        )
    console.print(table)
    if files:
        for i in items:
            ft = Table("Path", "Kind", "Size", "SHA-256", title=f"#{i['id']} {i['label']}")
            for f in i["files"]:
                ft.add_row(f["rel_path"], f["kind"], str(f["size"] or ""), f["sha256"] or "")
            console.print(ft)


@app.command("verify")
def verify(
    ctx: typer.Context,
    case: CaseArg,
    item: Annotated[int | None, typer.Option(help="Verify only this evidence item id.")] = None,
    by: Annotated[str | None, typer.Option("--by", help="Person performing verification.")] = None,
    as_json: JsonOption = False,
) -> None:
    """Re-hash evidence and compare with intake. Exits 1 if anything changed."""
    with opened_case(ctx, case) as handle:
        result: dict[str, Any] = service.verify_evidence(handle, item_id=item, actor=by)
    if as_json:
        emit_json(result)
    else:
        for r in result["items"]:
            mark = "[green]OK[/]" if r["ok"] else "[bold red]FAILED[/]"
            console.print(f"{mark} #{r['item_id']} {r['label']} ({r['files_checked']} files)")
            for p in r["problems"]:
                detail = f" - {p['detail']}" if p["detail"] else ""
                console.print(f"    {p['status']:<10} {p['rel_path']}{detail}", highlight=False)
    if not result["ok"]:
        raise typer.Exit(1)


TypeOverride = Annotated[
    list[str] | None,
    typer.Option(
        "--type",
        help="Force an artifact type for matching files: GLOB=TYPE (repeatable), "
        "e.g. '*secure*=linux.auth'. Globs match the evidence-relative path.",
    ),
]


def print_artifacts(rows: list[dict[str, Any]]) -> None:
    """Render identification results, with previews for unclassified files."""
    table = Table("File", "Type", "Conf.", "Parser", "Status")
    for r in rows:
        conf = f"{r['confidence']:.2f}" + (" (override)" if r["overridden"] else "")
        style = {"unclassified": "yellow", "error": "red", "unsupported": "yellow"}.get(r["status"])
        status = f"[{style}]{r['status']}[/]" if style else r["status"]
        table.add_row(r["rel_path"], r["artifact_type"], conf, r["parser"] or "-", status)
    console.print(table)
    for r in rows:
        if r["status"] == "unclassified" and r["preview"]:
            console.rule(f"[yellow]unclassified[/] {r['rel_path']}")
            console.print(r["preview"], markup=False, highlight=False)
        if r["message"]:
            console.print(f"[yellow]{r['rel_path']}:[/] {r['message']}", highlight=False)


@app.command("identify")
def identify(
    ctx: typer.Context,
    case: CaseArg,
    type_: TypeOverride = None,
    as_json: JsonOption = False,
) -> None:
    """Identify each evidence file's artifact type by sampling its content."""
    from sherlog.identify.service import identify_case, parse_overrides

    with opened_case(ctx, case) as handle:
        rows = identify_case(handle, parse_overrides(type_ or []))
    if as_json:
        emit_json(rows)
    else:
        print_artifacts(rows)
