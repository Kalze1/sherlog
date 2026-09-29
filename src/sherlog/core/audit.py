"""Audit logging and analyst/workstation identity."""

from __future__ import annotations

import getpass
import logging
import socket
from typing import Any

from sqlalchemy.orm import Session

from sherlog import __version__
from sherlog.core.models import AuditEntry
from sherlog.core.timeutil import utcnow

log = logging.getLogger(__name__)


def os_user() -> str:
    """Login name of the OS account running SherLog."""
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - no passwd entry / env vars
        return "unknown"


def workstation() -> str:
    """Hostname of the analyst workstation (not the evidence host)."""
    return socket.gethostname()


def record(session: Session, action: str, actor: str | None = None, **details: Any) -> AuditEntry:
    """Append an audit entry to the case database within the caller's transaction."""
    entry = AuditEntry(
        timestamp=utcnow(),
        actor=actor or os_user(),
        action=action,
        details=details,
        sherlog_version=__version__,
    )
    session.add(entry)
    log.debug("audit %s %s", action, details)
    return entry
