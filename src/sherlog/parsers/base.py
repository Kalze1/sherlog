"""Parser interface and the normalized event produced by parsers."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from pathlib import Path
from typing import Any

from sherlog.core.errors import SherlogError


class UnsupportedArtifact(SherlogError):
    """The artifact was identified but cannot be parsed here; ``str(exc)`` says what to do."""


@dataclass
class Sample:
    """The leading content of an evidence file, used for identification.

    ``head`` is decompressed; ``lines`` are decoded as UTF-8 with replacement.
    Identification must rely on these, never on the file name.
    """

    head: bytes
    lines: list[str]
    size: int
    is_binary: bool


@dataclass
class ParseContext:
    """Information about the file being parsed that is not in its content."""

    path: Path
    case_tz: tzinfo
    # File mtime; the reference point for inferring years missing from syslog timestamps.
    mtime: datetime | None = None


@dataclass
class ParsedEvent:
    """A normalized event before it is stored (see ``sherlog.core.models.Event``)."""

    event_type: str
    raw: str
    line_number: int | None = None
    timestamp_utc: datetime | None = None
    timestamp_raw: str | None = None
    timezone_assumed: bool = False
    host: str | None = None
    actor: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    target: str | None = None
    command: str | None = None
    tags: list[str] = field(default_factory=list)
    extra: dict[str, Any] | None = None


class Parser(ABC):
    """Base class for artifact parsers.

    Subclasses set ``name``, ``artifact_type`` and ``version``, score samples in
    :meth:`can_parse` and yield events from :meth:`parse`. ``parse`` must not
    raise on malformed input; it yields ``parse_error`` events instead.
    """

    name: str
    artifact_type: str
    version: str = "1"
    description: str = ""

    @abstractmethod
    def can_parse(self, sample: Sample) -> float:
        """Confidence in [0, 1] that this parser understands the sampled file."""

    @abstractmethod
    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        """Yield normalized events from the file at ``path`` (opened read-only)."""


def parse_error(raw: str, line_number: int | None, reason: str) -> ParsedEvent:
    """An event recording input the parser could not understand."""
    return ParsedEvent(
        event_type="parse_error", raw=raw, line_number=line_number, tags=[f"error:{reason}"]
    )


_HOME_RE = re.compile(r"/home/(?P<user>[^/]+)/|/(?P<root>root)/")


def user_from_path(path: Path) -> str | None:
    """Owner implied by a home-directory path (e.g. ``/home/bob/.bash_history`` -> bob)."""
    matches = list(_HOME_RE.finditer(path.as_posix()))
    if not matches:
        return None
    last = matches[-1]  # innermost home directory in the path
    return last["user"] or last["root"]
