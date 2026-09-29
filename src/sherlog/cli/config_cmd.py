"""``sherlog config``: show and change settings in ~/.config/sherlog/config.toml."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from sherlog.cli.common import JsonOption, console, emit_json, user_errors
from sherlog.core.config import (
    KEYS,
    default_config_path,
    get_setting,
    mask,
    set_setting,
    setting_source,
    unset_setting,
)

app = typer.Typer(help="Show and change settings.", no_args_is_help=True)


@app.command("show")
def show(
    reveal: Annotated[bool, typer.Option("--reveal", help="Show secrets in full.")] = False,
    as_json: JsonOption = False,
) -> None:
    """Effective settings and where each value comes from (env, file or default)."""
    rows = []
    with user_errors():
        for name, key in KEYS.items():
            value = get_setting(name)
            shown = mask(value) if key.secret and value and not reveal else value
            rows.append(
                {"key": name, "value": shown, "source": setting_source(name), "help": key.help}
            )
    if as_json:
        emit_json({"config_file": str(default_config_path()), "settings": rows})
        return
    table = Table("Key", "Value", "Source", "Description")
    for r in rows:
        value = "" if r["value"] in (None, []) else str(r["value"])
        table.add_row(r["key"], value, r["source"], r["help"])
    console.print(table)
    console.print(f"Config file: {default_config_path()}")


@app.command("set")
def set_(
    key: Annotated[str, typer.Argument(help="Setting name, e.g. enrichment.virustotal_key.")],
    value: Annotated[str, typer.Argument(help="Value (lists: comma-separated).")],
) -> None:
    """Store a setting (the file is created with mode 0600)."""
    with user_errors():
        stored = set_setting(key, value)
    shown = mask(stored) if KEYS[key].secret else stored
    console.print(f"{key} = {shown}  ({default_config_path()})")
    if (src := setting_source(key)).startswith("env:"):
        console.print(f"[yellow]Note:[/] {src[4:]} is set and takes precedence over the file.")


@app.command("unset")
def unset(key: Annotated[str, typer.Argument(help="Setting name.")]) -> None:
    """Remove a setting from the config file."""
    with user_errors():
        removed = unset_setting(key)
    console.print(f"{key} {'removed' if removed else 'was not set'}.")


@app.command("path")
def path() -> None:
    """Print the config file location."""
    typer.echo(str(default_config_path()))
