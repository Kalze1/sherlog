"""Helpers shared by CLI command modules."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated, Any

import typer
from rich.console import Console

from sherlog.core.case import CaseHandle, open_case
from sherlog.core.config import Settings, resolve_settings
from sherlog.core.errors import SherlogError

console = Console()
err_console = Console(stderr=True)

JsonOption = Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON.")]


def settings(ctx: typer.Context) -> Settings:
    """Settings resolved by the root callback (or defaults when invoked directly)."""
    obj = ctx.find_root().obj
    return obj if isinstance(obj, Settings) else resolve_settings()


@contextmanager
def user_errors() -> Iterator[None]:
    """Turn SherlogError into a one-line message and exit code 2."""
    try:
        yield
    except SherlogError as exc:
        err_console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(2) from exc


@contextmanager
def opened_case(ctx: typer.Context, name: str) -> Iterator[CaseHandle]:
    """Open a case for the duration of a command, reporting errors cleanly."""
    with user_errors():
        handle = open_case(settings(ctx), name)
    try:
        with user_errors():
            yield handle
    finally:
        handle.close()


def emit_json(data: Any) -> None:
    """Print JSON to stdout without Rich markup or wrapping."""
    typer.echo(json.dumps(data, indent=2, sort_keys=True, default=str))
