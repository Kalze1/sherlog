"""Parser registry. Parsers register themselves with :func:`register` on import."""

from __future__ import annotations

import importlib
from typing import TypeVar

from sherlog.parsers.base import Parser

_BUILTIN_MODULES = (
    "sherlog.parsers.syslog",
    "sherlog.parsers.journald",
    "sherlog.parsers.utmp",
    "sherlog.parsers.shell_history",
    "sherlog.parsers.auditd",
    "sherlog.parsers.sudo_log",
    "sherlog.parsers.cron_files",
    "sherlog.parsers.ssh_files",
    "sherlog.parsers.web",
    "sherlog.parsers.packages",
    "sherlog.parsers.kernel",
)

P = TypeVar("P", bound=type[Parser])

_PARSERS: dict[str, Parser] = {}
_loaded = False


def register(cls: P) -> P:
    """Class decorator: instantiate and register a parser."""
    instance = cls()
    if instance.name in _PARSERS:
        raise ValueError(f"duplicate parser name {instance.name!r}")
    _PARSERS[instance.name] = instance
    return cls


def _load_builtins() -> None:
    global _loaded
    if not _loaded:
        for mod in _BUILTIN_MODULES:
            importlib.import_module(mod)
        _loaded = True


def all_parsers() -> list[Parser]:
    """Every registered parser, sorted by name for deterministic scoring order."""
    _load_builtins()
    return [_PARSERS[k] for k in sorted(_PARSERS)]


def by_artifact_type(artifact_type: str) -> Parser | None:
    """The parser handling ``artifact_type``, if any."""
    return next((p for p in all_parsers() if p.artifact_type == artifact_type), None)


def artifact_types() -> list[str]:
    """All artifact types that can be identified."""
    return sorted({p.artifact_type for p in all_parsers()})
