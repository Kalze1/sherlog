"""Report context, rendering, exports and the report command."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
import stix2
from sqlalchemy import func, select
from typer.testing import CliRunner

from sherlog.cli import app
from sherlog.core.case import CaseHandle
from sherlog.core.models import IOC, AuditEntry, Event, Finding
from sherlog.core.timeutil import utcnow
from sherlog.core.vocab import FindingStatus, Severity, Verdict, VerifiedBy
from sherlog.detection.engine import analyze_case
from sherlog.detection.findings import list_findings, review_finding
from sherlog.intake.service import add_evidence
from sherlog.reporting.context import build_context
from sherlog.reporting.exports import stix_bundle, stix_pattern
from sherlog.reporting.render import _cell, render_html, render_markdown
from sherlog.reporting.service import generate_report
from sherlog.reporting.standards import response_phase
from tests.helpers import build_incident

runner = CliRunner()


@pytest.fixture
def analyzed(case: CaseHandle, tmp_path: Path) -> tuple[CaseHandle, Path]:
    evidence = build_incident(tmp_path / "evidence")
    add_evidence(case, evidence)
    analyze_case(case, gap_threshold=timedelta(hours=6))
    return case, evidence


# --- context ----------------------------------------------------------------------------------


def test_context_sections(analyzed: tuple[CaseHandle, Path]) -> None:
    case, _ = analyzed
    ctx = build_context(case)
    assert ctx["verification"]["ok"] is True
    assert ctx["findings"] and ctx["findings"][0]["severity"] == "critical"
    # Severity groups in descending order.
    order = [s for s, _ in ctx["findings_by_severity"]]
    assert order == [s for s in ["critical", "high", "medium", "low", "info"] if s in order]
    assert ctx["coverage"] and all(c["techniques"] for c in ctx["coverage"])
    stamps = [e["timestamp_utc"] for e in ctx["timeline"] if e["timestamp_utc"]]
    assert stamps == sorted(stamps)
    assert all(e["finding_ids"] for e in ctx["timeline"])
    phases = [p for p, _, _ in ctx["recommendations"]]
    assert phases[0] == "containment" and "long_term" in phases
    joined = " ".join(ctx["limitations"])
    assert "No CVE could be attributed" in joined
    assert "not enriched" in joined and "No AI-assisted" in joined
    assert any("analyze" in r["key"] or r["title"] for r in ctx["rules"])
    assert ctx["executive_summary"][0].startswith("SherLog examined")


def test_correlation_findings_cite_evidence(analyzed: tuple[CaseHandle, Path]) -> None:
    case, _ = analyzed
    ctx = build_context(case, verify=False)
    brute = next(f for f in ctx["findings"] if f["title"].startswith("SSH brute-force"))
    assert "Evidence: var/log/auth.log:" in brute["narrative"]
    assert brute["context"]["sources"] == ["var/log/auth.log"]


def test_verification_failure_is_reported(analyzed: tuple[CaseHandle, Path]) -> None:
    case, evidence = analyzed
    (evidence / "var/log/auth.log").write_text("tampered\n")
    ctx = build_context(case)
    assert ctx["verification"]["ok"] is False
    assert any("verification FAILED" in lim for lim in ctx["limitations"])
    md = render_markdown(ctx)
    assert "**FAILED**" in md and "modified `var/log/auth.log`" in md


def test_skip_verify_is_stated(analyzed: tuple[CaseHandle, Path]) -> None:
    case, _ = analyzed
    ctx = build_context(case, verify=False)
    assert ctx["verification"] is None
    assert any("NOT re-verified" in lim for lim in ctx["limitations"])


def test_rejected_findings_moved_to_appendix(analyzed: tuple[CaseHandle, Path]) -> None:
    case, _ = analyzed
    target = list_findings(case)[0]
    review_finding(case, target["id"], FindingStatus.REJECTED, note="authorised pentest")
    ctx = build_context(case, verify=False)
    assert target["id"] not in {f["id"] for f in ctx["findings"]}
    assert ctx["rejected"][0]["analyst_note"] == "authorised pentest"
    assert "Appendix D" in render_markdown(ctx)
    ctx_all = build_context(case, verify=False, include_rejected=True)
    assert target["id"] in {f["id"] for f in ctx_all["findings"]}


def test_response_phase_mapping() -> None:
    assert response_phase(["credential_access", "persistence"]) == "containment"
    assert response_phase(["persistence"]) == "eradication"
    assert response_phase(["defense_evasion"]) == "recovery"
    assert response_phase([]) == "long_term"


# --- rendering --------------------------------------------------------------------------------


def test_markdown_cell_escaping() -> None:
    assert _cell("a|b\nc") == "a\\|b c"
    assert _cell(None) == ""


def test_html_escapes_untrusted_text(analyzed: tuple[CaseHandle, Path]) -> None:
    case, _ = analyzed
    with case.session() as s:
        s.add(
            Finding(
                title="<script>alert(1)</script>",
                severity=Severity.LOW,
                confidence=0.5,
                verified_by=VerifiedBy.ANALYST,
                created_at=utcnow(),
                status=FindingStatus.OPEN,
                narrative="x | y",
            )
        )
    html = render_html(build_context(case, verify=False))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_provenance_badges(analyzed: tuple[CaseHandle, Path]) -> None:
    case, _ = analyzed
    ctx = build_context(case, verify=False)
    md, html = render_markdown(ctx), render_html(ctx)
    assert "**[RULE]**" in md
    assert 'class="badge by-rule"' in html


# --- exports ----------------------------------------------------------------------------------


def test_generate_report_writes_all_outputs(
    analyzed: tuple[CaseHandle, Path], tmp_path: Path
) -> None:
    case, _ = analyzed
    out = tmp_path / "out"
    result = generate_report(case, out)
    for name in ("report.md", "report.html", "findings.json", "events.jsonl", "iocs.stix.json"):
        assert (out / name).is_file(), name
    # SHA256SUMS matches the files on disk.
    for line in (out / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest
    from sherlog.reporting.render import pdf_available

    assert ("pdf" in result["files"]) == pdf_available()
    assert ("pdf" in result["skipped"]) != pdf_available()

    with case.session() as s:
        n_events = s.scalar(select(func.count()).select_from(Event))
        entry = s.scalars(select(AuditEntry).where(AuditEntry.action == "report.generate")).one()
    lines = (out / "events.jsonl").read_text().splitlines()
    assert len(lines) == n_events and json.loads(lines[0])["source"]["sha256"]
    assert entry.details["files"]["report.md"] == result["files"]["md"]["sha256"]

    findings = json.loads((out / "findings.json").read_text())
    assert findings["evidence_verified"] is True
    assert findings["findings"][0]["events"]


def test_stix_bundle_valid_and_deterministic(analyzed: tuple[CaseHandle, Path]) -> None:
    case, _ = analyzed
    with case.session() as s:
        ioc = s.scalars(select(IOC).where(IOC.value == "203.0.113.50")).one()
        ioc.verdict = Verdict.MALICIOUS
    ctx = build_context(case, verify=False)
    first = stix_bundle(case, ctx)
    second = stix_bundle(case, ctx)
    parsed = stix2.parse(first.serialize(), allow_custom=False)
    types = {o["type"] for o in parsed.objects}
    assert {"identity", "attack-pattern", "indicator", "report"} <= types
    ids = lambda b: sorted(o["id"] for o in b.objects)  # noqa: E731
    assert ids(first) == ids(second)
    patterns = {o["pattern"] for o in parsed.objects if o["type"] == "indicator"}
    assert "[ipv4-addr:value = '203.0.113.50']" in patterns
    report = next(o for o in parsed.objects if o["type"] == "report")
    assert len(report["object_refs"]) == len(parsed.objects) - 1


def test_stix_pattern_escaping() -> None:
    assert stix_pattern("url", "http://x/?q='a'") == "[url:value = 'http://x/?q=\\'a\\'']"
    assert stix_pattern("path", "/tmp/.x/run.sh") == "[file:name = 'run.sh']"
    assert stix_pattern("sha256", "ab") == "[file:hashes.'SHA-256' = 'ab']"


def test_report_on_case_without_findings(case: CaseHandle, tmp_path: Path) -> None:
    ev = tmp_path / "quiet"
    ev.mkdir()
    (ev / "notes.txt").write_text("nothing here\n")
    add_evidence(case, ev)
    result = generate_report(case, tmp_path / "out", formats=("md", "html", "stix"))
    md = (tmp_path / "out/report.md").read_text()
    assert "No findings." in md and "has not been run" in md
    assert result["findings"] == 0


# --- CLI --------------------------------------------------------------------------------------


def test_cli_report(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    evidence = build_incident(tmp_path / "evidence")
    for args in (
        ["case", "new", "c1"],
        ["evidence", "add", "c1", str(evidence)],
        ["analyze", "c1"],
    ):
        r = runner.invoke(app, ["--cases-dir", str(cases), *args])
        assert r.exit_code == 0, r.output

    r = runner.invoke(app, ["--cases-dir", str(cases), "report", "c1", "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["evidence_verified"] is True
    assert Path(data["out_dir"]) == (cases / "c1" / "report").resolve()

    out = tmp_path / "md-only"
    r = runner.invoke(
        app,
        ["--cases-dir", str(cases), "report", "c1", "-f", "md", "-o", str(out), "--skip-verify"],
    )
    assert r.exit_code == 0, r.output
    assert sorted(p.name for p in out.iterdir()) == ["SHA256SUMS", "report.md"]
    assert "not re-verified" in (out / "report.md").read_text()
