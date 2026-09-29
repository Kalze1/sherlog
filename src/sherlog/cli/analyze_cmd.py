"""``sherlog analyze``: parse (if needed) and run detection rules over a case."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from sherlog.cli.common import JsonOption, console, emit_json, err_console, opened_case, user_errors
from sherlog.cli.evidence_cmd import CaseArg, TypeOverride
from sherlog.core.config import get_setting
from sherlog.core.errors import SherlogError

RulesOption = Annotated[
    list[Path] | None,
    typer.Option(
        "--rules",
        help="Additional rule directory (repeatable). The bundled rules are always loaded "
        "unless --no-bundled-rules is given.",
    ),
]


def rule_dirs(rules: list[Path] | None, no_bundled: bool) -> list[Path] | None:
    """Resolve --rules/--no-bundled-rules into the directories to load."""
    from sherlog.detection.sigma import default_rules_dir

    dirs = [p.expanduser().resolve() for p in rules or []]
    if not no_bundled:
        with user_errors():
            dirs.insert(0, default_rules_dir())
    if no_bundled and not dirs:
        raise typer.BadParameter("--no-bundled-rules requires at least one --rules DIR")
    return dirs or None


def analyze(
    ctx: typer.Context,
    case: CaseArg,
    rules: RulesOption = None,
    no_bundled_rules: Annotated[
        bool, typer.Option("--no-bundled-rules", help="Use only the --rules directories.")
    ] = False,
    gap_hours: Annotated[
        float, typer.Option(help="Report gaps in continuous logs longer than this many hours.")
    ] = 6.0,
    reparse: Annotated[
        bool, typer.Option("--reparse", help="Discard events and parse evidence again first.")
    ] = False,
    type_: TypeOverride = None,
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Skip the AI investigation step.")] = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="No AI and no external lookups.")
    ] = False,
    as_json: JsonOption = False,
) -> None:
    """Run deterministic detection (Sigma rules, correlations, analytics) and store findings."""
    from sherlog.detection.engine import analyze_case
    from sherlog.detection.findings import list_findings, severity_counts
    from sherlog.identify.service import parse_overrides

    dirs = rule_dirs(rules, no_bundled_rules)
    with opened_case(ctx, case) as handle:
        overrides = parse_overrides(type_ or [])
        if as_json:
            result = analyze_case(
                handle,
                dirs,
                gap_threshold=timedelta(hours=gap_hours),
                reparse=reparse,
                overrides=overrides,
            )
        else:
            with console.status("Analyzing ..."):
                result = analyze_case(
                    handle,
                    dirs,
                    gap_threshold=timedelta(hours=gap_hours),
                    reparse=reparse,
                    overrides=overrides,
                )
        ai_result = None
        ai_error = None
        ai_skip = "--no-ai" if no_ai else "offline" if offline or get_setting("offline") else None
        if ai_skip is None:
            from sherlog.cli.ai_cmd import run_ai

            try:
                if as_json:
                    ai_result = run_ai(handle)
                else:
                    with console.status("AI investigation ...") as status:
                        ai_result = run_ai(handle, progress=lambda m: status.update(m))
            except SherlogError as exc:  # AI problems must not fail the deterministic analysis
                ai_error = str(exc)
            if ai_result is None and ai_error is None:
                ai_skip = "no provider configured"
        findings = list_findings(handle)
    if as_json:
        emit_json(
            {
                **result,
                "severity_counts": severity_counts(findings),
                "ai": ai_result or {"skipped": ai_skip, "error": ai_error},
            }
        )
        return
    for w in result["rule_warnings"]:
        err_console.print(f"[yellow]rule warning:[/] {w}", highlight=False)
    stored = result["findings"]
    console.print(
        f"Analyzed [bold]{result['events']}[/] events with {result['rules_loaded']} rules; "
        f"{len(result['rules_matched'])} rules matched. Findings: {stored['created']} new, "
        f"{stored['updated']} updated, {stored['removed']} removed"
        + (f", {stored['stale']} stale (reviewed, no longer matching)" if stored["stale"] else "")
        + "."
    )
    counts = severity_counts(findings)
    table = Table("Critical", "High", "Medium", "Low", "Info", title="Findings by severity")
    table.add_row(*(str(counts[s]) for s in ("critical", "high", "medium", "low", "info")))
    console.print(table)
    top = [f for f in findings if f["status"] != "rejected"][:15]
    if top:
        t = Table("ID", "Sev", "Title", "Events", "First seen (UTC)")
        for f in top:
            t.add_row(
                str(f["id"]),
                f["severity"],
                f["title"][:90],
                str(f["event_count"]),
                (f["first_seen"] or "-")[:19],
            )
        console.print(t)
        if len(findings) > len(top):
            console.print(f"... {len(findings) - len(top)} more; see 'sherlog findings {case}'.")
    if ai_result is not None:
        from sherlog.cli.ai_cmd import print_run_summary

        print_run_summary(ai_result)
    elif ai_error:
        err_console.print(f"[yellow]AI investigation skipped:[/] {escape(ai_error)}")
    else:
        console.print(f"[dim]AI investigation skipped ({ai_skip}); deterministic rules only.[/]")
