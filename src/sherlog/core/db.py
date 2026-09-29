"""Per-case SQLite database: engine/session helpers and shared column types."""

from __future__ import annotations

import functools
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import DateTime, Engine, create_engine, event, inspect, text
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.schema import CreateColumn
from sqlalchemy.types import TypeDecorator

DB_FILENAME = "case.db"
SCHEMA_VERSION = 1


class Base(DeclarativeBase):
    """Declarative base for all SherLog ORM models."""


class UTCDateTime(TypeDecorator[datetime]):
    """Store aware datetimes as naive UTC and return them as aware UTC.

    SQLite has no timezone support, so values are normalised on the way in and
    re-tagged with UTC on the way out. Naive inputs are rejected to avoid silent
    local-time assumptions.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime passed to UTCDateTime; attach a timezone first")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return None if value is None else value.replace(tzinfo=UTC)


def _regexp(pattern: str, value: str | None) -> bool:
    """SQLite REGEXP implementation (used by ``column.regexp_match``)."""
    return value is not None and _compiled(pattern).search(value) is not None


@functools.lru_cache(maxsize=64)
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _on_connect(dbapi_conn: Any, _record: Any) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()
    dbapi_conn.create_function("regexp", 2, _regexp, deterministic=True)


def make_engine(db_path: Path) -> Engine:
    """Create an engine for a case database, creating tables if needed."""
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    event.listen(engine, "connect", _on_connect)
    # Import models so their tables are registered on Base.metadata.
    from sherlog.core import models  # noqa: F401

    Base.metadata.create_all(engine)
    _add_missing_columns(engine)
    return engine


def _add_missing_columns(engine: Engine) -> None:
    """Additive migration: add columns introduced after a case DB was created.

    ``create_all`` creates new tables but never alters existing ones. Only
    nullable columns and columns with a server default are added; anything
    else would need a real migration.
    """
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                if not column.nullable and column.server_default is None:
                    continue
                ddl = CreateColumn(column).compile(dialect=engine.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN {ddl}'))


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    """Transactional session: commit on success, roll back on error."""
    factory = sessionmaker(engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()
