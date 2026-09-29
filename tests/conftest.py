"""Shared pytest fixtures."""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from sherlog.core.case import CaseHandle, create_case
from sherlog.core.config import Settings

AUTH_LINE = (
    b"Jan  1 00:00:01 web01 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n"
)


@pytest.fixture(autouse=True)
def isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Never read the developer's real config, keys or cache during tests."""
    from sherlog.core.config import KEYS

    for key in KEYS.values():
        for env in key.env:
            monkeypatch.delenv(env, raising=False)
    config = tmp_path / "sherlog-config" / "config.toml"
    monkeypatch.setenv("SHERLOG_CONFIG", str(config))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    return config


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(cases_dir=tmp_path / "cases")


@pytest.fixture
def case(settings: Settings) -> Iterator[CaseHandle]:
    handle = create_case(settings, "test-case", investigator="Tester", timezone="UTC")
    yield handle
    handle.close()


@pytest.fixture
def evidence_tree(tmp_path: Path) -> Path:
    """A small collected-logs tree with rotated, compressed, linked and special files."""
    root = tmp_path / "evidence"
    log = root / "var" / "log"
    log.mkdir(parents=True)
    (log / "auth.log").write_bytes(AUTH_LINE)
    (log / "auth.log.1").write_bytes(AUTH_LINE * 2)
    (log / "auth.log.2.gz").write_bytes(gzip.compress(AUTH_LINE * 3))
    (log / "syslog.3.bz2").write_bytes(bz2.compress(b"bz2 content\n"))
    (log / "kern.log.4.xz").write_bytes(lzma.compress(b"xz content\n"))
    (log / "passwd-link").symlink_to("/etc/passwd")
    os.mkfifo(log / "pipe")
    return root
