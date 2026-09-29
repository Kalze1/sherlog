"""End-to-end detection: analytics, engine, findings store and CLI."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sherlog.cli import app
from sherlog.core.case import CaseHandle
from sherlog.core.vocab import FindingStatus, Severity, VerifiedBy
from sherlog.detection.engine import analyze_case, entity_label, run_rule_test
from sherlog.detection.findings import list_findings, review_finding
from sherlog.intake.service import add_evidence
from tests.helpers import (
    BRUTE_IP,
    FIXTURES,
    build_incident,
)
from tests.helpers import (
    auth_log as _auth_log,
)
from tests.helpers import (
    bash_history as _bash_history,
)

runner = CliRunner()


@pytest.fixture
def incident_evidence(tmp_path: Path) -> Path:
    return build_incident(tmp_path / "evidence")


def _analyze(handle: CaseHandle) -> dict:
    return analyze_case(handle, gap_threshold=timedelta(hours=6))


def _by_rule(handle: CaseHandle) -> dict[str, dict]:
    return {f["rule_id"]: f for f in list_findings(handle)}


# --- engine end to end ------------------------------------------------------------------------


def test_analyze_produces_expected_findings(case: CaseHandle, incident_evidence: Path) -> None:
    add_evidence(case, incident_evidence)
    result = _analyze(case)
    assert result["events"] > 0
    findings = _by_rule(case)

    titles = " ".join(findings)
    for expected in (
        "5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1003",  # brute force
        "5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1005",  # success after failures
        "8a2b1c4d-1111-4e22-8a01-2b3c4d5e2005",  # UID 0 account
        "1a2b3c4d-4444-4c55-9d04-5e6f7a8b5001",  # reverse shell
        "1a2b3c4d-4444-4c55-9d04-5e6f7a8b5002",  # curl | bash
        "9d8c7b6a-3333-4b44-9c03-4d5e6f7a4001",  # sqli
        "9d8c7b6a-3333-4b44-9c03-4d5e6f7a4004",  # web shell
    ):
        assert expected in findings, f"missing rule {expected}; got {titles}"

    # Brute force: one finding, grouped by source IP, ~12 failures.
    bf = findings["5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1003"]
    assert BRUTE_IP in bf["title"]
    assert bf["context"]["count"] >= 10
    assert bf["severity"] == "high"
    assert bf["verified_by"] == "rule"

    # UID 0 account is critical.
    uid0 = findings["8a2b1c4d-1111-4e22-8a01-2b3c4d5e2005"]
    assert uid0["severity"] == "critical" and "backdoor" in uid0["title"]

    # audit_stopped from the audit.log fixture.
    assert "1a2b3c4d-4444-4c55-9d04-5e6f7a8b5007" in findings


def test_findings_link_evidence_with_hashes(case: CaseHandle, incident_evidence: Path) -> None:
    add_evidence(case, incident_evidence)
    _analyze(case)
    from sherlog.detection.findings import get_finding

    findings = list_findings(case, verified_by=VerifiedBy.RULE)
    detail = get_finding(case, findings[0]["id"])
    assert detail["events"], "finding should link at least one event"
    ev = detail["events"][0]
    assert ev["source"]["sha256"] and ev["source"]["rel_path"]


def test_reanalyze_is_idempotent_and_preserves_review(
    case: CaseHandle, incident_evidence: Path
) -> None:
    add_evidence(case, incident_evidence)
    _analyze(case)
    findings = list_findings(case)
    n = len(findings)
    # Accept one finding, then re-analyze.
    target = findings[0]["id"]
    review_finding(case, target, FindingStatus.ACCEPTED, note="confirmed by analyst")
    second = _analyze(case)
    assert second["findings"]["created"] == 0  # nothing new the second time
    again = list_findings(case)
    assert len(again) == n  # stable count
    kept = next(f for f in again if f["id"] == target)
    assert kept["status"] == "accepted" and kept["analyst_note"] == "confirmed by analyst"


def test_accepting_ai_finding_becomes_analyst_verified(case: CaseHandle) -> None:
    from sherlog.core.models import Finding
    from sherlog.core.timeutil import utcnow

    with case.session() as s:
        s.add(
            Finding(
                title="AI hypothesis",
                severity=Severity.MEDIUM,
                confidence=0.5,
                verified_by=VerifiedBy.AI_PROPOSED,
                created_at=utcnow(),
                status=FindingStatus.OPEN,
                fingerprint="ai-1",
            )
        )
    fid = list_findings(case)[0]["id"]
    result = review_finding(case, fid, FindingStatus.ACCEPTED)
    assert result["verified_by"] == "analyst"


def test_analyze_requires_events(case: CaseHandle, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "notes.txt").write_text("nothing to parse here\n")
    add_evidence(case, empty)
    with pytest.raises(Exception, match="no events"):
        _analyze(case)


def test_entity_label() -> None:
    assert (
        entity_label({"src_ip": "1.2.3.4", "actor": "root"}, ("src_ip", "actor"))
        == "from 1.2.3.4 by root"
    )
    assert entity_label({}, ("src_ip",)) == ""


# --- analytics --------------------------------------------------------------------------------


def test_unusual_login_ip_uses_global_addresses(case: CaseHandle, tmp_path: Path) -> None:
    # Build an auth log: five logins for alice from a stable public IP, one from another.
    root = tmp_path / "ev"
    (root / "var/log").mkdir(parents=True)
    lines = []
    for i in range(5):
        ts = datetime(2024, 5, 1, 8, i, 0, tzinfo=UTC)
        lines.append(
            f"{ts.isoformat()} h sshd[{i}]: Accepted password for alice from 45.33.32.10 port 22 ssh2"  # noqa: E501
        )
    odd = datetime(2024, 5, 1, 9, 0, 0, tzinfo=UTC)
    lines.append(
        f"{odd.isoformat()} h sshd[99]: Accepted password for alice from 45.55.10.20 port 22 ssh2"
    )
    (root / "var/log/auth.log").write_text("\n".join(lines) + "\n")
    add_evidence(case, root)
    _analyze(case)
    findings = _by_rule(case)
    unusual = findings.get("sherlog.analytic.unusual_login_ip")
    assert unusual and "45.55.10.20" in unusual["title"]


def test_log_gap_analytic(case: CaseHandle, tmp_path: Path) -> None:
    root = tmp_path / "ev"
    (root / "var/log").mkdir(parents=True)
    lines = []
    # 30 entries one minute apart, then a 10-hour gap, then more.
    base = datetime(2024, 5, 1, 0, 0, 0, tzinfo=UTC)
    for i in range(30):
        ts = base + timedelta(minutes=i)
        lines.append(f"{ts.isoformat()} h cron[1]: (root) CMD (/usr/bin/true)")
    after = base + timedelta(hours=11)
    for i in range(10):
        ts = after + timedelta(minutes=i)
        lines.append(f"{ts.isoformat()} h cron[1]: (root) CMD (/usr/bin/true)")
    (root / "var/log/syslog").write_text("\n".join(lines) + "\n")
    add_evidence(case, root)
    _analyze(case)
    assert "sherlog.analytic.log_gap" in _by_rule(case)


# --- rules test (no case) ---------------------------------------------------------------------


def test_rule_test_on_file_by_id() -> None:
    result = run_rule_test("5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1006", FIXTURES / "auth.log", tz="UTC")
    assert result["rule"]["type"] == "detection"
    assert result["events"] > 0


def test_rule_test_correlation_reports_dependencies(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    _auth_log(log)
    result = run_rule_test("5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1003", log, tz="UTC")
    assert result["rule"]["type"] == "correlation"
    assert result["matches"] and result["matches"][0]["event_count"] >= 10
    assert "ssh_auth_failure" in result["dependency_matches"]


def test_rule_test_reverse_shell_in_history(tmp_path: Path) -> None:
    hist = tmp_path / ".bash_history"
    _bash_history(hist)
    res = run_rule_test("1a2b3c4d-4444-4c55-9d04-5e6f7a8b5001", hist, tz="UTC")
    assert res["matches"], "reverse shell rule should match the history fixture"


def test_rule_test_unknown_rule(tmp_path: Path) -> None:
    f = tmp_path / "auth.log"
    _auth_log(f)
    with pytest.raises(Exception, match="Unknown rule"):
        run_rule_test("no-such-rule", f)


# --- CLI --------------------------------------------------------------------------------------


def _cli(cases: Path, *args: str) -> tuple[int, str]:
    r = runner.invoke(app, ["--cases-dir", str(cases), *args])
    return r.exit_code, r.output


def test_cli_analyze_findings_rules(tmp_path: Path, incident_evidence: Path) -> None:
    cases = tmp_path / "cases"
    _cli(cases, "case", "new", "c1")
    _cli(cases, "evidence", "add", "c1", str(incident_evidence))

    code, out = _cli(cases, "analyze", "c1", "--json")
    assert code == 0, out
    data = json.loads(out)
    assert data["rules_loaded"] >= 25
    assert data["severity_counts"]["critical"] >= 1

    code, out = _cli(cases, "findings", "c1", "--json")
    findings = json.loads(out)
    assert findings and findings[0]["severity"] in ("critical", "high")

    fid = findings[0]["id"]
    code, out = _cli(cases, "findings", "c1", "--accept", str(fid), "--note", "real", "--json")
    assert code == 0 and json.loads(out)["status"] == "accepted"

    code, out = _cli(cases, "findings", "c1", "--show", str(fid))
    assert code == 0 and "Recommendation" in out

    code, out = _cli(cases, "findings", "c1", "--min-severity", "critical", "--json")
    assert all(f["severity"] == "critical" for f in json.loads(out))


def test_cli_rules_list_and_test(tmp_path: Path) -> None:
    code, out = _cli(tmp_path / "c", "rules", "list", "--json")
    assert code == 0
    rows = json.loads(out)
    assert sum(1 for r in rows if r["type"] != "analytic") >= 25
    assert any(r["type"] == "correlation" for r in rows)
    assert any(r["type"] == "analytic" for r in rows)

    log = tmp_path / "auth.log"
    _auth_log(log)
    code, out = _cli(
        tmp_path / "c", "rules", "test", "5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1003", str(log)
    )
    assert code == 0 and "match" in out.lower()

    # A rule that does not match exits 1.
    quiet = tmp_path / "quiet.log"
    quiet.write_text("2024-05-01T00:00:00+00:00 h sshd[1]: Server listening on 0.0.0.0 port 22.\n")
    code, out = _cli(
        tmp_path / "c", "rules", "test", "5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1003", str(quiet)
    )
    assert code == 1
