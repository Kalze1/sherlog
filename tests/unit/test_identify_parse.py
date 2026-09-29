"""Identification, parse service, timeline queries and their CLI commands."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from sherlog.cli import app
from sherlog.core.case import CaseHandle
from sherlog.core.errors import SherlogError
from sherlog.core.models import AuditEntry
from sherlog.core.timeline import TimelineQuery, parse_time, query_events
from sherlog.identify.sample import read_sample
from sherlog.identify.service import identify_case, identify_sample, parse_overrides
from sherlog.intake.service import add_evidence
from sherlog.parsers.service import parse_case
from sherlog.parsers.utmp import LOGIN_PROCESS, USER_PROCESS
from tests.helpers import copy_fixture, lastlog_file, utmp_record

MTIME = datetime(2025, 3, 10, tzinfo=UTC)


@pytest.fixture
def mixed_evidence(tmp_path: Path) -> Path:
    """Fixtures under deliberately meaningless names: identification must use content."""
    root = tmp_path / "collected"
    names = {
        "auth.log": "f01",
        "secure-iso.log": "f02",
        "syslog": "f03",
        "journal.json": "f04",
        "bash_history_ts": "f06",
        "zsh_history": "f07",
        "notes.txt": "f08",
    }
    for src, dst in names.items():
        copy_fixture(src, root / dst, mtime=MTIME)
    copy_fixture("bash_history", root / "home" / "alice" / "f05", mtime=MTIME)
    (root / "f09").write_bytes(
        utmp_record(USER_PROCESS, user="alice", line="pts/0", ip="192.0.2.5")
        + utmp_record(8, line="pts/0", ts=1714558000)
    )
    (root / "f10").write_bytes(utmp_record(LOGIN_PROCESS, user="root", ip="203.0.113.9") * 3)
    lastlog_file(root / "f11", {0: (1714557600, "pts/0", "192.0.2.1")})
    (root / "f12").write_bytes(b"LPKSHHRH" + b"\0" * 512)
    (root / "f13").write_bytes(bytes(range(256)) * 4)  # unknown binary
    (root / "f14").write_bytes(b"")
    return root


EXPECTED_TYPES = {
    "f01": "linux.auth",
    "f02": "linux.auth",
    "f03": "linux.syslog",
    "f04": "journald.json",
    "home/alice/f05": "shell.bash_history",
    "f06": "shell.bash_history",
    "f07": "shell.zsh_history",
    "f08": "unclassified",
    "f09": "utmp.wtmp",
    "f10": "utmp.btmp",
    "f11": "lastlog",
    "f12": "journald.binary",
    "f13": "unclassified",
    "f14": "empty",
}


def test_identify_by_content(case: CaseHandle, mixed_evidence: Path) -> None:
    add_evidence(case, mixed_evidence)
    rows = {r["rel_path"]: r for r in identify_case(case)}
    assert {k: v["artifact_type"] for k, v in rows.items()} == EXPECTED_TYPES
    assert rows["f08"]["status"] == "unclassified"
    assert "Meeting notes" in rows["f08"]["preview"]
    assert rows["f13"]["preview"].startswith("00000000  00 01 02")  # hexdump
    assert rows["f01"]["candidates"]["linux.auth"] > rows["f01"]["candidates"]["linux.syslog"]


def test_identify_override(case: CaseHandle, mixed_evidence: Path) -> None:
    add_evidence(case, mixed_evidence)
    rows = {r["rel_path"]: r for r in identify_case(case, parse_overrides(["f0[3]=linux.auth"]))}
    assert rows["f03"]["artifact_type"] == "linux.auth" and rows["f03"]["overridden"]
    with pytest.raises(SherlogError, match="Unknown artifact type"):
        parse_overrides(["*=nope"])
    with pytest.raises(SherlogError, match="GLOB=TYPE"):
        parse_overrides(["linux.auth"])


def test_identify_sample_threshold(tmp_path: Path) -> None:
    f = tmp_path / "x"
    f.write_text("hello world\n")
    ident = identify_sample(read_sample(f))
    assert ident.artifact_type == "unclassified" and ident.parser is None


def test_parse_case_and_timeline(case: CaseHandle, mixed_evidence: Path) -> None:
    add_evidence(case, mixed_evidence)
    result = parse_case(case)
    files = {f["rel_path"]: f for f in result["files"]}
    assert files["f12"]["status"] == "unsupported"
    assert "journalctl" in files["f12"]["message"]
    assert files["f01"]["status"] == "parsed" and files["f01"]["parse_errors"] == 1
    assert result["total_events"] == sum(f["events"] for f in result["files"])

    events, total = query_events(case, TimelineQuery(limit=None))
    assert total == result["total_events"] == len(events)
    stamps = [e["timestamp_utc"] for e in events]
    dated = [s for s in stamps if s is not None]
    assert dated == sorted(dated)
    assert stamps.index(None) == len(dated)  # undated (plain bash history) last
    assert events[0]["source"]["sha256"]

    logins, _ = query_events(case, TimelineQuery(types=["auth.login"], limit=None))
    assert {e["event_type"] for e in logins} == {"auth.login.success", "auth.login.failure"}

    by_ip, _ = query_events(case, TimelineQuery(ip="203.0.113.50", limit=None))
    assert by_ip and all(e["src_ip"] == "203.0.113.50" for e in by_ip)

    grep, _ = query_events(case, TimelineQuery(grep=r"new USER: name=backdoor", limit=None))
    assert len(grep) == 1  # regex, case-insensitive

    window, _ = query_events(
        case,
        TimelineQuery(
            start=parse_time("2024-05-01T10:00:00"), end=parse_time("2024-05-01T10:00:05")
        ),
    )
    assert window and all("2024-05-01T10:00:0" in e["timestamp_utc"] for e in window)

    page, total2 = query_events(case, TimelineQuery(limit=5, offset=5))
    assert len(page) == 5 and total2 == total

    with pytest.raises(SherlogError, match="regex"):
        query_events(case, TimelineQuery(grep="("))


def test_parse_is_guarded_and_reproducible(case: CaseHandle, mixed_evidence: Path) -> None:
    add_evidence(case, mixed_evidence)
    first = parse_case(case)
    with pytest.raises(SherlogError, match="--force"):
        parse_case(case)
    second = parse_case(case, force=True)
    assert second["discarded_events"] == first["total_events"]
    assert second["files"] == first["files"]
    a, _ = query_events(case, TimelineQuery(limit=None))
    strip = [{k: v for k, v in e.items() if k != "id"} for e in a]
    parse_case(case, force=True)
    b, _ = query_events(case, TimelineQuery(limit=None))
    assert strip == [{k: v for k, v in e.items() if k != "id"} for e in b]
    with case.session() as s:
        actions = [a.action for a in s.scalars(select(AuditEntry))]
    assert actions.count("evidence.parse") == 3


def test_parse_leaves_evidence_untouched(case: CaseHandle, mixed_evidence: Path) -> None:
    add_evidence(case, mixed_evidence)
    parse_case(case)
    from sherlog.intake.service import verify_evidence

    assert verify_evidence(case)["ok"]


def test_invalid_time() -> None:
    with pytest.raises(SherlogError):
        parse_time("yesterday")
    assert parse_time("2024-01-01T03:00:00+03:00") == datetime(2024, 1, 1, tzinfo=UTC)


# --- CLI ------------------------------------------------------------------------------------

runner = CliRunner()


def _cli(cases: Path, *args: str) -> tuple[int, str]:
    r = runner.invoke(app, ["--cases-dir", str(cases), *args])
    return r.exit_code, r.output


def test_cli_identify_parse_timeline(tmp_path: Path, mixed_evidence: Path) -> None:
    cases = tmp_path / "cases"
    _cli(cases, "case", "new", "c1")
    _cli(cases, "evidence", "add", "c1", str(mixed_evidence))

    code, out = _cli(cases, "evidence", "identify", "c1", "--json")
    assert code == 0, out
    assert {r["rel_path"]: r["artifact_type"] for r in json.loads(out)} == EXPECTED_TYPES

    code, out = _cli(cases, "evidence", "identify", "c1")
    assert code == 0 and "unclassified" in out and "Meeting notes" in out

    code, out = _cli(cases, "parse", "c1")
    assert code == 0, out
    assert "events" in out and "journalctl" in out

    code, out = _cli(cases, "parse", "c1")
    assert code == 2 and "--force" in out

    code, out = _cli(cases, "timeline", "c1", "--type", "user.create", "--json")
    data = json.loads(out)
    assert data["total"] == 1 and data["events"][0]["target"] == "backdoor"

    code, out = _cli(cases, "timeline", "c1", "--actor", "deploy", "--limit", "2")
    assert code == 0 and "of" in out and "--offset 2" in out

    code, out = _cli(cases, "timeline", "c1", "--from", "not-a-date")
    assert code == 2

    code, out = _cli(cases, "evidence", "identify", "c1", "--type", "bad")
    assert code == 2 and "GLOB=TYPE" in out


def test_rotated_compressed_logs_parse(case: CaseHandle, tmp_path: Path) -> None:
    import gzip

    root = tmp_path / "rot"
    root.mkdir()
    for i, name in enumerate(["auth.log", "auth.log.1"]):
        copy_fixture("secure-iso.log", root / name, mtime=MTIME)
        os.utime(root / name, (MTIME.timestamp() - i, MTIME.timestamp() - i))
    (root / "auth.log.2.gz").write_bytes(
        gzip.compress(copy_fixture("secure-iso.log", tmp_path / "x").read_bytes())
    )
    add_evidence(case, root)
    result = parse_case(case)
    assert [f["events"] for f in result["files"]] == [4, 4, 4]
