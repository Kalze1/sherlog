"""Tests for case lifecycle and the database layer."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from sherlog.core.case import (
    CaseHandle,
    create_case,
    delete_case,
    list_cases,
    open_case,
    summarize,
)
from sherlog.core.config import Settings, resolve_settings
from sherlog.core.errors import CaseError
from sherlog.core.models import AuditEntry, Case


def test_create_and_summarize(case: CaseHandle) -> None:
    s = summarize(case)
    assert s["name"] == "test-case"
    assert s["investigator"] == "Tester"
    assert s["evidence_items"] == 0
    assert (case.directory / "case.db").is_file()
    with case.session() as sess:
        created = sess.scalars(select(Case)).one().created_at
        assert created.tzinfo is not None
        [entry] = sess.scalars(select(AuditEntry)).all()
        assert entry.action == "case.create"


@pytest.mark.parametrize("name", ["", "bad name", "../escape", ".hidden", "a" * 65, "x/y"])
def test_invalid_names_rejected(settings: Settings, name: str) -> None:
    with pytest.raises(CaseError):
        create_case(settings, name)


def test_invalid_timezone(settings: Settings) -> None:
    with pytest.raises(CaseError, match="timezone"):
        create_case(settings, "c1", timezone="Mars/Olympus")
    assert not (settings.cases_dir / "c1").exists()


def test_duplicate_case(settings: Settings, case: CaseHandle) -> None:
    with pytest.raises(CaseError, match="already exists"):
        create_case(settings, "test-case")


def test_brief_from_file_is_hashed(settings: Settings, tmp_path: Path) -> None:
    brief = tmp_path / "brief.txt"
    brief.write_text("Customer reports defaced site.")
    handle = create_case(settings, "briefed", brief=str(brief))
    try:
        assert summarize(handle)["brief"] == "Customer reports defaced site."
        with handle.session() as s:
            details = s.scalars(select(AuditEntry)).one().details
        assert details["brief_source"] == "file"
        assert details["brief_sha256"] == hashlib.sha256(brief.read_bytes()).hexdigest()
    finally:
        handle.close()


def test_brief_as_text(settings: Settings) -> None:
    handle = create_case(settings, "texty", brief="just some text")
    try:
        assert summarize(handle)["brief"] == "just some text"
    finally:
        handle.close()


def test_open_list_delete(settings: Settings, case: CaseHandle) -> None:
    assert [c["name"] for c in list_cases(settings)] == ["test-case"]
    open_case(settings, "test-case").close()
    with pytest.raises(CaseError, match="No case"):
        open_case(settings, "missing")
    delete_case(settings, "test-case")
    assert list_cases(settings) == []


def test_naive_datetime_rejected(case: CaseHandle) -> None:
    with pytest.raises(Exception, match="naive"), case.session() as s:
        s.add(
            AuditEntry(
                timestamp=datetime(2024, 1, 1),
                actor="x",
                action="y",
                details={},
                sherlog_version="0",
            )
        )


def test_settings_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'cases_dir = "{tmp_path / "from-file"}"\n')
    monkeypatch.setenv("SHERLOG_CONFIG", str(cfg))
    monkeypatch.delenv("SHERLOG_CASES_DIR", raising=False)
    assert resolve_settings().cases_dir == tmp_path / "from-file"
    monkeypatch.setenv("SHERLOG_CASES_DIR", str(tmp_path / "from-env"))
    assert resolve_settings().cases_dir == tmp_path / "from-env"
    assert resolve_settings(tmp_path / "from-cli").cases_dir == tmp_path / "from-cli"
