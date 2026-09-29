"""``sherlog enrich`` and ``sherlog iocs``: IOC enrichment and listing."""

from __future__ import annotations

from typing import Annotated, Any

import typer
from rich.table import Table

from sherlog.cli.common import JsonOption, console, emit_json, err_console, opened_case
from sherlog.cli.evidence_cmd import CaseArg
from sherlog.core.vocab import Verdict
from sherlog.enrichment.summary import intel_summary

_VERDICT_STYLE = {
    "malicious": "bold red",
    "suspicious": "yellow",
    "clean": "green",
    "unknown": "dim",
}


def print_iocs(rows: list[dict[str, Any]]) -> None:
    table = Table("Type", "Value", "Verdict", "Findings", "Events", "Intel")
    for i in rows:
        style = _VERDICT_STYLE.get(i["verdict"], "")
        table.add_row(
            i["type"],
            i["value"][:70],
            f"[{style}]{i['verdict']}[/]",
            ", ".join(f"#{f}" for f in i["finding_ids"][:6]),
            str(i["event_count"] or ""),
            intel_summary(i["enrichment"]),
        )
    console.print(table)


def enrich(
    ctx: typer.Context,
    case: CaseArg,
    offline: Annotated[
        bool, typer.Option("--offline", help="Use only the local cache and GeoIP; no API calls.")
    ] = False,
    provider: Annotated[
        list[str] | None,
        typer.Option("--provider", help="abuseipdb and/or virustotal (repeatable; default both)."),
    ] = None,
    all_iocs: Annotated[
        bool,
        typer.Option("--all", help="Enrich every extracted IOC, not only those in findings."),
    ] = False,
    enrich_private: Annotated[
        bool,
        typer.Option("--enrich-private", help="Also send private/reserved IP addresses."),
    ] = False,
    refresh: Annotated[bool, typer.Option("--refresh", help="Ignore cached results.")] = False,
    as_json: JsonOption = False,
) -> None:
    """Extract IOCs and look them up in AbuseIPDB/VirusTotal (with cache and rate limits)."""
    from sherlog.enrichment.service import enrich_case, list_iocs

    with opened_case(ctx, case) as handle:
        kwargs: dict[str, Any] = {
            "offline": True if offline else None,
            "providers": provider,
            "all_iocs": all_iocs,
            "enrich_private": enrich_private,
            "refresh": refresh,
        }
        if as_json:
            result = enrich_case(handle, **kwargs)
        else:
            with console.status("Enriching IOCs ...") as status:
                result = enrich_case(handle, **kwargs, progress=lambda m: status.update(m))
        rows = list_iocs(handle, all_iocs=all_iocs)
    if as_json:
        emit_json({**result, "iocs": rows})
        return
    ex = result["extracted"]
    console.print(
        f"Extracted {ex['total']} IOCs ({ex['in_findings']} linked to findings); "
        f"enriching {result['iocs_considered']}."
    )
    for name, state in result["providers"].items():
        style = "green" if state == "ready" else "yellow"
        console.print(f"  {name}: [{style}]{state}[/]")
    console.print(f"  geoip: {result['geoip']}")
    looked = ", ".join(f"{k}={v}" for k, v in sorted(result["lookups"].items())) or "none"
    console.print(f"Lookups: {looked}")
    if rows:
        print_iocs(rows)
    if not all_iocs:
        console.print("[dim]Only IOCs linked to findings are shown; use --all for every IOC.[/]")
    if any(v.startswith("stopped") for v in result["providers"].values()):
        err_console.print("[yellow]A provider stopped early; re-run later to continue.[/]")


def iocs(
    ctx: typer.Context,
    case: CaseArg,
    all_iocs: Annotated[
        bool, typer.Option("--all", help="Include IOCs not in any finding.")
    ] = False,
    verdict: Annotated[Verdict | None, typer.Option(help="Only this verdict.")] = None,
    as_json: JsonOption = False,
) -> None:
    """List extracted IOCs with their verdicts (most severe first)."""
    from sherlog.enrichment.service import list_iocs

    with opened_case(ctx, case) as handle:
        rows = list_iocs(handle, all_iocs=all_iocs, verdict=verdict)
    if as_json:
        emit_json(rows)
    elif rows:
        print_iocs(rows)
        console.print(f"{len(rows)} IOC(s).")
    else:
        console.print("No IOCs. Run 'sherlog analyze' (extraction) or use --all.")
