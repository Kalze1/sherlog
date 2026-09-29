"""Tests for evidence intake, manifest, chain of custody and verification."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from sqlalchemy import select

from sherlog.core.case import CaseHandle
from sherlog.core.errors import EvidenceError
from sherlog.core.models import AuditEntry, CustodyRecord
from sherlog.intake.service import add_evidence, list_evidence, verify_evidence


def _snapshot(root: Path) -> dict[str, tuple[bytes | str, int]]:
    """Content and mtime of every entry, for proving evidence was not modified."""
    out: dict[str, tuple[bytes | str, int]] = {}
    for p in sorted(root.rglob("*")):
        st = os.lstat(p)
        if stat.S_ISREG(st.st_mode):
            out[str(p)] = (p.read_bytes(), st.st_mtime_ns)
        elif stat.S_ISLNK(st.st_mode):
            out[str(p)] = (os.readlink(p), st.st_mtime_ns)
    return out


def _make_read_only(root: Path) -> None:
    for p in sorted(root.rglob("*"), reverse=True):
        if not p.is_symlink() and p.is_file():
            p.chmod(0o444)
    for p in [*root.rglob("*"), root]:
        if p.is_dir() and not p.is_symlink():
            p.chmod(0o555)


def _restore_writable(root: Path) -> None:
    for p in [root, *root.rglob("*")]:
        if p.is_dir() and not p.is_symlink():
            p.chmod(0o755)


def test_add_evidence_records_everything(case: CaseHandle, evidence_tree: Path) -> None:
    result = add_evidence(case, evidence_tree, source_note="collected via scp")
    assert result["counts"] == {"file": 5, "symlink": 1, "special": 1}
    assert result["added_by"] == "Tester"
    assert len(result["item_digest"]) == 64
    [custody] = result["custody"]
    assert custody["action"] == "acquired"
    assert custody["note"] == "collected via scp"
    assert custody["workstation"]

    manifest = json.loads((case.directory / "manifest.json").read_text())
    [item] = manifest["evidence"]
    assert item["source_path"] == str(evidence_tree.resolve())
    files = {f["rel_path"]: f for f in item["files"]}
    assert files["var/log/auth.log.2.gz"]["content_sha256"]
    assert files["var/log/auth.log"]["md5"]

    with case.session() as s:
        actions = [a.action for a in s.scalars(select(AuditEntry))]
    assert actions == ["case.create", "evidence.add"]


def test_evidence_never_modified(case: CaseHandle, evidence_tree: Path) -> None:
    _make_read_only(evidence_tree)
    try:
        before = _snapshot(evidence_tree)
        add_evidence(case, evidence_tree)
        verify_evidence(case)
        assert _snapshot(evidence_tree) == before
    finally:
        _restore_writable(evidence_tree)


def test_duplicate_add_refused(case: CaseHandle, evidence_tree: Path) -> None:
    add_evidence(case, evidence_tree)
    with pytest.raises(EvidenceError, match="already in this case"):
        add_evidence(case, evidence_tree)


def test_missing_path(case: CaseHandle, tmp_path: Path) -> None:
    with pytest.raises(EvidenceError, match="does not exist"):
        add_evidence(case, tmp_path / "nope")


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
def test_unreadable_root_refused(case: CaseHandle, tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o000)
    try:
        with pytest.raises(EvidenceError, match="not readable"):
            add_evidence(case, locked)
    finally:
        locked.chmod(0o755)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
def test_unreadable_file_recorded_not_fatal(case: CaseHandle, evidence_tree: Path) -> None:
    secret = evidence_tree / "var/log/secure"
    secret.write_bytes(b"x")
    secret.chmod(0o000)
    try:
        result = add_evidence(case, evidence_tree)
    finally:
        secret.chmod(0o644)
    assert result["counts"]["unreadable"] == 1
    assert any("secure" in w for w in result["warnings"])


def test_overlap_with_case_dir_refused(case: CaseHandle) -> None:
    with pytest.raises(EvidenceError, match="overlaps"):
        add_evidence(case, case.directory.parent)


def test_verify_detects_changes(case: CaseHandle, evidence_tree: Path) -> None:
    add_evidence(case, evidence_tree)
    assert verify_evidence(case)["ok"] is True

    log = evidence_tree / "var/log"
    (log / "auth.log").write_bytes(b"tampered\n")
    (log / "auth.log.1").unlink()
    (log / "passwd-link").unlink()
    (log / "passwd-link").symlink_to("/etc/shadow")
    (log / "new.log").write_bytes(b"new\n")

    result = verify_evidence(case)
    assert result["ok"] is False
    statuses = {p["rel_path"]: p["status"] for p in result["items"][0]["problems"]}
    assert statuses == {
        "var/log/auth.log": "modified",
        "var/log/auth.log.1": "missing",
        "var/log/passwd-link": "modified",
        "var/log/new.log": "new",
    }
    with case.session() as s:
        actions = [c.action for c in s.scalars(select(CustodyRecord).order_by(CustodyRecord.id))]
    assert actions == ["acquired", "verified", "verification_failed"]


def test_single_file_evidence_and_listing(case: CaseHandle, evidence_tree: Path) -> None:
    add_evidence(case, evidence_tree / "var/log/auth.log", label="auth")
    [item] = list_evidence(case, include_files=True)
    assert item["label"] == "auth"
    assert item["file_count"] == 1
    assert item["files"][0]["rel_path"] == "auth.log"
    assert verify_evidence(case, item_id=item["id"])["ok"]
    with pytest.raises(EvidenceError, match="No evidence item"):
        verify_evidence(case, item_id=999)
