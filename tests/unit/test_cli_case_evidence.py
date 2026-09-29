"""CLI tests for the ``case`` and ``evidence`` command groups."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sherlog.cli import app

runner = CliRunner()


def run(cases_dir: Path, *args: str) -> tuple[int, str]:
    result = runner.invoke(app, ["--cases-dir", str(cases_dir), *args])
    return result.exit_code, result.output


def test_case_lifecycle_json(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    code, out = run(cases, "case", "new", "c1", "--tz", "Africa/Addis_Ababa", "--json")
    assert code == 0, out
    assert json.loads(out)["timezone"] == "Africa/Addis_Ababa"

    code, out = run(cases, "case", "list", "--json")
    assert [c["name"] for c in json.loads(out)] == ["c1"]

    code, out = run(cases, "case", "show", "c1", "--json")
    assert json.loads(out)["name"] == "c1"

    code, out = run(cases, "case", "delete", "c1", "--yes", "--json")
    assert code == 0 and json.loads(out)["deleted"] == "c1"
    assert not (cases / "c1").exists()


def test_errors_are_clean(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    code, out = run(cases, "case", "show", "ghost")
    assert code == 2
    assert "No case named" in out and "Traceback" not in out
    code, out = run(cases, "case", "new", "bad name")
    assert code == 2


def test_delete_requires_confirmation(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    run(cases, "case", "new", "keep")
    result = runner.invoke(app, ["--cases-dir", str(cases), "case", "delete", "keep"], input="n\n")
    assert result.exit_code != 0
    assert (cases / "keep").exists()


def test_evidence_add_list_verify(tmp_path: Path, evidence_tree: Path) -> None:
    cases = tmp_path / "cases"
    run(cases, "case", "new", "c1")
    code, out = run(cases, "evidence", "add", "c1", str(evidence_tree), "--json")
    assert code == 0, out
    assert json.loads(out)["counts"]["file"] == 5

    code, out = run(cases, "evidence", "list", "c1", "--files", "--json")
    assert json.loads(out)[0]["file_count"] == 7

    code, out = run(cases, "evidence", "verify", "c1", "--json")
    assert code == 0 and json.loads(out)["ok"] is True

    (evidence_tree / "var/log/auth.log").write_bytes(b"tampered")
    code, out = run(cases, "evidence", "verify", "c1")
    assert code == 1
    assert "FAILED" in out and "modified" in out


def test_evidence_add_missing_path(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    run(cases, "case", "new", "c1")
    code, out = run(cases, "evidence", "add", "c1", str(tmp_path / "nope"))
    assert code == 2 and "does not exist" in out
