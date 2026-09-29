"""Tests for the evidence walker."""

from __future__ import annotations

from pathlib import Path

import pytest

from sherlog.core.vocab import FileKind
from sherlog.intake.walker import item_digest, parse_rotation, scan


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("auth.log", (None, None)),
        ("auth.log.1", ("auth.log", 1)),
        ("auth.log.2.gz", ("auth.log", 2)),
        ("syslog-20240101.xz", ("syslog", 20240101)),
        ("access.log.gz", ("access.log", 0)),
        ("messages", (None, None)),
    ],
)
def test_parse_rotation(name: str, expected: tuple[str | None, int | None]) -> None:
    assert parse_rotation(name) == expected


def test_scan_records_every_kind(evidence_tree: Path) -> None:
    files = {f.rel_path: f for f in scan(evidence_tree)}
    assert set(files) == {
        "var/log/auth.log",
        "var/log/auth.log.1",
        "var/log/auth.log.2.gz",
        "var/log/syslog.3.bz2",
        "var/log/kern.log.4.xz",
        "var/log/passwd-link",
        "var/log/pipe",
    }
    link = files["var/log/passwd-link"]
    assert link.kind == FileKind.SYMLINK
    assert link.symlink_target == "/etc/passwd"
    assert link.sha256 is None  # not followed
    assert files["var/log/pipe"].kind == FileKind.SPECIAL
    assert files["var/log/auth.log.2.gz"].compression == "gzip"
    assert files["var/log/kern.log.4.xz"].rotation_base == "kern.log"
    assert (files["var/log/auth.log"].mode or "").startswith("-rw")
    assert files["var/log/auth.log"].mtime is not None


def test_scan_is_deterministic(evidence_tree: Path) -> None:
    a, b = scan(evidence_tree), scan(evidence_tree)
    assert [f.rel_path for f in a] == [f.rel_path for f in b]
    assert item_digest(a) == item_digest(b)


def test_digest_changes_with_content(evidence_tree: Path) -> None:
    before = item_digest(scan(evidence_tree))
    (evidence_tree / "var/log/auth.log").write_bytes(b"changed\n")
    assert item_digest(scan(evidence_tree)) != before


def test_scan_single_file(evidence_tree: Path) -> None:
    [only] = scan(evidence_tree / "var/log/auth.log")
    assert only.rel_path == "auth.log"
    assert only.kind == FileKind.FILE and only.sha256
