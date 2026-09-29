"""End-to-end: generate each sample scenario, run analyze + report, check its answer key.

Generic over ``samples.generate.SCENARIOS``: a new scenario is covered as soon
as it is registered there and ships an answer key.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from samples.generate import SCENARIOS
from samples.generate.common import tree_digest
from sqlalchemy import select

from sherlog.core.case import CaseHandle, create_case
from sherlog.core.config import Settings
from sherlog.core.models import Event, EvidenceFile
from sherlog.detection.engine import analyze_case
from sherlog.detection.findings import list_findings
from sherlog.enrichment.service import list_iocs
from sherlog.intake.service import add_evidence
from sherlog.reporting.context import build_context
from sherlog.reporting.service import generate_report

HIGH = ("high", "critical")


@pytest.fixture(scope="module", params=sorted(SCENARIOS))
def scenario(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> dict[str, Any]:
    """Generate, ingest, analyze (no AI) and report once per scenario."""
    base = tmp_path_factory.mktemp(f"sample-{request.param}")
    root = SCENARIOS[request.param](base / "out")
    key = json.loads((root / "answer_key.json").read_text())
    handle = create_case(
        Settings(cases_dir=base / "cases"), request.param, timezone=key["timezone"]
    )
    add_evidence(handle, root / "evidence")
    analysis = analyze_case(handle)
    report = generate_report(
        handle, base / "report", formats=("md", "html", "json", "stix", "events")
    )
    yield {"key": key, "handle": handle, "analysis": analysis, "report": report, "base": base}
    handle.close()


def test_expected_findings(scenario: dict[str, Any]) -> None:
    findings = list_findings(scenario["handle"])
    for exp in scenario["key"]["expected_findings"]:
        hits = [
            f
            for f in findings
            if f["rule_id"] in (exp["rule_id"], exp.get("rule_name"))
            and exp.get("title_contains", "") in f["title"]
        ]
        assert hits, f"missing: {exp['why']} ({exp['rule_id']})"


def test_no_unexpected_high_severity(scenario: dict[str, Any]) -> None:
    key = scenario["key"]
    allowed = {e["rule_id"] for e in key["expected_findings"]} | set(
        key.get("allowed_high_findings", [])
    )
    unexpected = [
        (f["rule_id"], f["title"])
        for f in list_findings(scenario["handle"])
        if f["severity"] in HIGH and f["rule_id"] not in allowed
    ]
    assert not unexpected, f"false positives: {unexpected}"


def test_benign_sources_not_in_findings(scenario: dict[str, Any]) -> None:
    benign = set(scenario["key"].get("benign_ips", []))
    for f in list_findings(scenario["handle"]):
        entity = f["context"].get("entity") or {}
        assert entity.get("src_ip") not in benign, f["title"]


def test_expected_techniques(scenario: dict[str, Any]) -> None:
    seen = {t["id"] for f in list_findings(scenario["handle"]) for t in f["attack_techniques"]}
    missing = set(scenario["key"]["expected_techniques"]) - seen
    assert not missing, f"techniques not covered: {sorted(missing)}"


def test_expected_iocs(scenario: dict[str, Any]) -> None:
    iocs = {(i["type"], i["value"]): i for i in list_iocs(scenario["handle"], all_iocs=True)}
    for exp in scenario["key"]["expected_iocs"]:
        ioc = iocs.get((exp["type"], exp["value"]))
        assert ioc is not None, f"IOC not extracted: {exp}"
        if exp.get("in_findings"):
            assert ioc["finding_ids"], f"IOC not linked to a finding: {exp}"


def test_timeline_times(scenario: dict[str, Any]) -> None:
    """Key events are parsed with the right UTC time (timezone and year inference)."""
    handle: CaseHandle = scenario["handle"]
    with handle.session() as s:
        for step in scenario["key"]["timeline"]:
            rows = s.execute(
                select(Event.timestamp_utc)
                .join(EvidenceFile, Event.source_file_id == EvidenceFile.id)
                .where(EvidenceFile.rel_path == step["file"], Event.raw.contains(step["contains"]))
            ).all()
            assert rows, f"event not found: {step['step']}"
            want = datetime.fromisoformat(step["time_utc"])
            assert any(ts == want for (ts,) in rows), (
                f"{step['step']}: {[r[0] for r in rows]} != {want}"
            )


def test_report_outputs(scenario: dict[str, Any]) -> None:
    report = scenario["report"]
    assert report["evidence_verified"] is True
    assert set(report["files"]) >= {"md", "html", "json", "stix", "events"}
    for info in report["files"].values():
        assert Path(info["path"]).stat().st_size > 0
    limitations = " ".join(build_context(scenario["handle"], verify=False)["limitations"]).lower()
    for text in scenario["key"].get("expected_limitations_contain", []):
        assert text.lower() in limitations, text


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_generation_is_deterministic(name: str, tmp_path: Path) -> None:
    first = SCENARIOS[name](tmp_path / "one")
    second = SCENARIOS[name](tmp_path / "two")
    assert tree_digest(first) == tree_digest(second)
