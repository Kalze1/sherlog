"""``sherlog rules``: list the rule set and test a rule against a file."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from sherlog.cli.analyze_cmd import RulesOption, rule_dirs
from sherlog.cli.common import JsonOption, console, emit_json, err_console, user_errors

app = typer.Typer(help="Inspect and test detection rules.", no_args_is_help=True)


@app.command("list")
def list_(
    rules: RulesOption = None,
    no_bundled_rules: Annotated[bool, typer.Option("--no-bundled-rules")] = False,
    as_json: JsonOption = False,
) -> None:
    """List Sigma rules, correlation rules and built-in analytics."""
    from sherlog.detection.analytics import ANALYTICS
    from sherlog.detection.sigma import load_rules

    with user_errors():
        ruleset = load_rules(rule_dirs(rules, no_bundled_rules))
    rows = [
        {
            "key": r.key,
            "id": r.id,
            "title": r.title,
            "type": "correlation" if r.is_correlation else "detection",
            "level": str(r.level),
            "techniques": list(r.techniques),
            "suppressed": r.key in ruleset.suppressed,
            "path": str(r.path) if r.path else None,
            "warnings": r.warnings,
        }
        for r in ruleset.rules
    ] + [
        {
            "key": a.rule_id,
            "id": None,
            "title": a.title,
            "type": "analytic",
            "level": str(a.level),
            "techniques": list(a.techniques),
            "suppressed": False,
            "path": None,
            "warnings": [],
        }
        for a in ANALYTICS
    ]
    if as_json:
        emit_json(rows)
        return
    table = Table("Rule", "Type", "Level", "ATT&CK", "Title")
    for r in rows:
        techniques = r["techniques"]
        assert isinstance(techniques, list)
        suffix = " [dim](feeds a correlation)[/]" if r["suppressed"] else ""
        table.add_row(
            f"{r['key']}{suffix}",
            str(r["type"]),
            str(r["level"]),
            ", ".join(techniques),
            str(r["title"]),
        )
    console.print(table)
    n_rules = sum(1 for r in rows if r["type"] != "analytic")
    console.print(f"{n_rules} rules, {len(ANALYTICS)} analytics.")
    for r in rows:
        warnings = r["warnings"]
        assert isinstance(warnings, list)
        for w in warnings:
            err_console.print(f"[yellow]{r['key']}:[/] {w}")


@app.command("test")
def test(
    rule: Annotated[str, typer.Argument(help="Rule name, id, or path to a YAML rule file.")],
    file: Annotated[Path, typer.Argument(help="Evidence file to parse and match against.")],
    tz: Annotated[str, typer.Option("--tz", help="Timezone for zone-less timestamps.")] = "UTC",
    rules: RulesOption = None,
    no_bundled_rules: Annotated[bool, typer.Option("--no-bundled-rules")] = False,
    as_json: JsonOption = False,
) -> None:
    """Parse FILE (no case needed) and show what RULE would match."""
    from sherlog.detection.engine import run_rule_test

    with user_errors():
        result = run_rule_test(rule, file, rules_dirs=rule_dirs(rules, no_bundled_rules), tz=tz)
    if as_json:
        emit_json(result)
        return
    r = result["rule"]
    console.print(
        f"[bold]{r['title']}[/] ({r['key']}, {r['type']}) against {result['file']} "
        f"[{result['artifact_type']}, {result['events']} events]"
    )
    for dep, n in result["dependency_matches"].items():
        console.print(f"  dependency {dep}: {n} match(es)")
    if not result["matches"]:
        console.print("[yellow]No matches.[/]")
        raise typer.Exit(1)
    table = Table("Time (UTC)", "Events", "Lines", "Fields / first raw line")
    for m in result["matches"]:
        fields = ", ".join(
            f"{k}={v}"
            for k, v in m["fields"].items()
            if k in ("src_ip", "actor", "count", "host", "target")
        )
        detail = fields + ("\n" if fields else "") + (m["raw"][0][:140] if m["raw"] else "")
        lines = ", ".join(str(n) for n in m["line_numbers"][:8]) + (
            " ..." if len(m["line_numbers"]) > 8 else ""
        )
        table.add_row((m["timestamp_utc"] or "-")[:19], str(m["event_count"]), lines, detail)
    console.print(table)
    console.print(f"[green]{len(result['matches'])} match(es).[/]")
