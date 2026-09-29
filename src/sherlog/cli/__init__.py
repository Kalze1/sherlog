"""SherLog command-line interface (Typer + Rich)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.logging import RichHandler

from sherlog import __version__
from sherlog.cli import (
    ai_cmd,
    analyze_cmd,
    case_cmd,
    config_cmd,
    enrich_cmd,
    evidence_cmd,
    findings_cmd,
    parse_cmd,
    report_cmd,
    rules_cmd,
    timeline_cmd,
)
from sherlog.cli.common import console, err_console, user_errors
from sherlog.core.config import resolve_settings

app = typer.Typer(
    name="sherlog",
    help="AI-assisted Linux log forensics and incident response.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(case_cmd.app, name="case")
app.add_typer(evidence_cmd.app, name="evidence")
app.command("parse")(parse_cmd.parse)
app.command("timeline")(timeline_cmd.timeline)
app.command("analyze")(analyze_cmd.analyze)
app.command("findings")(findings_cmd.findings)
app.command("report")(report_cmd.report)
app.command("enrich")(enrich_cmd.enrich)
app.command("iocs")(enrich_cmd.iocs)
app.add_typer(config_cmd.app, name="config")
app.command("investigate")(ai_cmd.investigate)
app.add_typer(ai_cmd.app, name="ai")
app.add_typer(rules_cmd.app, name="rules")


def configure_logging(verbosity: int) -> None:
    """Configure root logging: WARNING by default, INFO with -v, DEBUG with -vv."""
    level = {0: logging.WARNING, 1: logging.INFO}.get(verbosity, logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=err_console, show_path=verbosity > 1)],
        force=True,
    )


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"sherlog {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the SherLog version and exit.",
        ),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase log verbosity (-v, -vv)."),
    ] = 0,
    cases_dir: Annotated[
        Path | None,
        typer.Option(
            "--cases-dir",
            envvar="SHERLOG_CASES_DIR",
            help="Where case data is stored (default: ~/.local/share/sherlog/cases).",
        ),
    ] = None,
) -> None:
    """SherLog: investigate Linux logs with evidence integrity and a verifiable timeline."""
    configure_logging(verbose)
    with user_errors():
        ctx.obj = resolve_settings(cases_dir)
