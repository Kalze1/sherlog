"""``sherlog report``: produce the investigation report and exports."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from sherlog.cli.common import JsonOption, console, emit_json, err_console, opened_case
from sherlog.cli.evidence_cmd import CaseArg


class ReportFormat(StrEnum):
    md = "md"
    html = "html"
    pdf = "pdf"
    all = "all"


def report(
    ctx: typer.Context,
    case: CaseArg,
    format_: Annotated[
        list[ReportFormat] | None,
        typer.Option(
            "--format",
            "-f",
            help="Report format (repeatable). 'all' also writes findings.json, events.jsonl "
            "and iocs.stix.json.",
        ),
    ] = None,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output directory (default: <case>/report).")
    ] = None,
    skip_verify: Annotated[
        bool,
        typer.Option(
            "--skip-verify",
            help="Do not re-hash evidence first (the report will say it was not verified).",
        ),
    ] = False,
    include_rejected: Annotated[
        bool, typer.Option(help="Include findings the analyst rejected in the main findings.")
    ] = False,
    as_json: JsonOption = False,
) -> None:
    """Re-verify evidence and write the report (Markdown, HTML, PDF, JSON, STIX, JSONL)."""
    from sherlog.reporting.service import FORMATS, generate_report

    chosen = set(format_ or [ReportFormat.all])
    formats = FORMATS if ReportFormat.all in chosen else tuple(str(f) for f in chosen)
    with opened_case(ctx, case) as handle:
        if as_json:
            result = generate_report(
                handle,
                out,
                formats=formats,
                verify=not skip_verify,
                include_rejected=include_rejected,
            )
        else:
            with console.status("Verifying evidence and writing report ..."):
                result = generate_report(
                    handle,
                    out,
                    formats=formats,
                    verify=not skip_verify,
                    include_rejected=include_rejected,
                )
    if as_json:
        emit_json(result)
        return
    if result["evidence_verified"] is False:
        err_console.print(
            "[bold red]WARNING:[/] evidence changed since intake; see the report's scope section."
        )
    elif result["evidence_verified"] is None:
        err_console.print("[yellow]Evidence was not re-verified (--skip-verify).[/]")
    table = Table("Output", "File", "SHA-256")
    for name, info in result["files"].items():
        table.add_row(name, info["path"], info["sha256"][:16] + "…")
    console.print(table)
    for name, reason in result["skipped"].items():
        err_console.print(f"[yellow]{name} skipped:[/] {escape(reason)}")
    console.print(
        f"[green]Report written[/] to {result['out_dir']} "
        f"({result['findings']} findings; hashes in SHA256SUMS)."
    )
