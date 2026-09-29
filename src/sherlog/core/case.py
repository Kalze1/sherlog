"""Case lifecycle: create, open, list, summarise and delete cases.

Each case is a directory under the configured cases directory containing
``case.db`` (SQLite) and ``manifest.json``. Deleting a case removes only this
SherLog working data; original evidence is never touched.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from sherlog import __version__
from sherlog.core import audit
from sherlog.core.config import Settings
from sherlog.core.db import DB_FILENAME, SCHEMA_VERSION, make_engine, session_scope
from sherlog.core.errors import CaseError
from sherlog.core.models import Case, CustodyRecord, Event, EvidenceFile, EvidenceItem, Finding
from sherlog.core.timeutil import iso, utcnow

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass
class CaseHandle:
    """An opened case: its directory and database engine."""

    name: str
    directory: Path
    engine: Engine

    @property
    def db_path(self) -> Path:
        return self.directory / DB_FILENAME

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Transactional session on this case's database."""
        with session_scope(self.engine) as s:
            yield s

    def case(self, session: Session) -> Case:
        """Load the case record."""
        case = session.scalars(select(Case)).one_or_none()
        if case is None:
            raise CaseError(f"{self.db_path} has no case record")
        return case

    def close(self) -> None:
        self.engine.dispose()


def validate_name(name: str) -> str:
    """Case names become directory names, so restrict them to a safe charset."""
    if not _NAME_RE.fullmatch(name):
        raise CaseError(
            f"Invalid case name {name!r}: use 1-64 letters, digits, '.', '_' or '-', "
            "starting with a letter or digit."
        )
    return name


def validate_timezone(tz: str) -> str:
    """Ensure ``tz`` is a valid IANA zone name."""
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise CaseError(
            f"Unknown timezone {tz!r}; use an IANA name like 'Africa/Addis_Ababa'"
        ) from exc
    return tz


def _read_brief(brief: str | None) -> tuple[str | None, dict[str, Any]]:
    """Treat ``brief`` as a file path if one exists, otherwise as literal text."""
    if brief is None:
        return None, {"brief_source": None}
    path = Path(brief).expanduser()
    if path.is_file():
        data = path.read_bytes()
        return data.decode("utf-8", errors="replace"), {
            "brief_source": "file",
            "brief_path": str(path.resolve()),
            "brief_sha256": hashlib.sha256(data).hexdigest(),
        }
    return brief, {"brief_source": "text"}


def create_case(
    settings: Settings,
    name: str,
    *,
    brief: str | None = None,
    timezone: str = "UTC",
    investigator: str | None = None,
) -> CaseHandle:
    """Create a new case directory and database."""
    validate_name(name)
    validate_timezone(timezone)
    directory = settings.cases_dir / name
    if directory.exists():
        raise CaseError(f"Case {name!r} already exists at {directory}")
    brief_text, brief_meta = _read_brief(brief)
    investigator = investigator or audit.os_user()

    directory.mkdir(parents=True)
    handle = CaseHandle(name, directory, make_engine(directory / DB_FILENAME))
    with handle.session() as s:
        s.add(
            Case(
                id=str(uuid.uuid4()),
                name=name,
                created_at=utcnow(),
                investigator=investigator,
                timezone=timezone,
                brief=brief_text,
                sherlog_version=__version__,
                schema_version=SCHEMA_VERSION,
            )
        )
        audit.record(
            s,
            "case.create",
            actor=investigator,
            name=name,
            timezone=timezone,
            workstation=audit.workstation(),
            **brief_meta,
        )
    return handle


def open_case(settings: Settings, name: str) -> CaseHandle:
    """Open an existing case by name."""
    validate_name(name)
    directory = settings.cases_dir / name
    if not (directory / DB_FILENAME).is_file():
        raise CaseError(f"No case named {name!r} in {settings.cases_dir}")
    return CaseHandle(name, directory, make_engine(directory / DB_FILENAME))


def summarize(handle: CaseHandle) -> dict[str, Any]:
    """Case metadata plus evidence/event/finding counts."""
    with handle.session() as s:
        case = handle.case(s)

        def count(model: type) -> int:
            return s.scalar(select(func.count()).select_from(model)) or 0

        return {
            "id": case.id,
            "name": case.name,
            "directory": str(handle.directory),
            "created_at": iso(case.created_at),
            "investigator": case.investigator,
            "timezone": case.timezone,
            "brief": case.brief,
            "sherlog_version": case.sherlog_version,
            "schema_version": case.schema_version,
            "evidence_items": count(EvidenceItem),
            "evidence_files": count(EvidenceFile),
            "custody_records": count(CustodyRecord),
            "events": count(Event),
            "findings": count(Finding),
        }


def list_cases(settings: Settings) -> list[dict[str, Any]]:
    """Summaries of every case under the cases directory, sorted by name."""
    if not settings.cases_dir.is_dir():
        return []
    out = []
    for directory in sorted(settings.cases_dir.iterdir()):
        if not (directory / DB_FILENAME).is_file():
            continue
        handle = CaseHandle(directory.name, directory, make_engine(directory / DB_FILENAME))
        try:
            out.append(summarize(handle))
        finally:
            handle.close()
    return out


def delete_case(settings: Settings, name: str) -> Path:
    """Remove a case's working directory. Original evidence is not affected."""
    handle = open_case(settings, name)
    handle.close()
    shutil.rmtree(handle.directory)
    return handle.directory
