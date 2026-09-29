"""Evidence intake and verification (ISO/IEC 27037 acquisition and preservation).

Evidence is referenced in place and only ever opened read-only; SherLog never
copies, moves or writes to it. Every intake and verification appends a chain of
custody record and an audit entry, and regenerates ``manifest.json``.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sqlalchemy import select

from sherlog.core import audit
from sherlog.core.case import CaseHandle
from sherlog.core.errors import EvidenceError
from sherlog.core.models import CustodyRecord, EvidenceFile, EvidenceItem
from sherlog.core.timeutil import utcnow
from sherlog.core.vocab import CustodyAction, FileKind
from sherlog.intake.hashing import hash_file
from sherlog.intake.manifest import item_to_dict, write_manifest
from sherlog.intake.walker import item_digest, list_rel_paths, scan

log = logging.getLogger(__name__)


def _check_readable(root: Path) -> None:
    if not root.exists():
        raise EvidenceError(f"Evidence path does not exist: {root}")
    need = os.R_OK | (os.X_OK if root.is_dir() else 0)
    if not os.access(root, need):
        raise EvidenceError(f"Evidence path is not readable: {root}")


def _is_within(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def add_evidence(
    handle: CaseHandle,
    path: str | Path,
    *,
    label: str | None = None,
    actor: str | None = None,
    source_note: str | None = None,
) -> dict[str, Any]:
    """Hash and record every file under ``path`` as a new evidence item."""
    root = Path(path).expanduser().resolve()
    _check_readable(root)
    case_dir = handle.directory.resolve()
    if _is_within(case_dir, root) or _is_within(root, case_dir):
        raise EvidenceError(f"Evidence path {root} overlaps the case directory {case_dir}")

    with handle.session() as s:
        if s.scalars(select(EvidenceItem).where(EvidenceItem.source_path == str(root))).first():
            raise EvidenceError(
                f"{root} is already in this case; use 'sherlog evidence verify' to re-check it"
            )
        actor = actor or handle.case(s).investigator

    log.info("scanning %s", root)
    scanned = scan(root)
    digest = item_digest(scanned)
    now = utcnow()
    item = EvidenceItem(
        label=label or root.name,
        source_path=str(root),
        added_at=now,
        added_by=actor,
        source_note=source_note,
        item_digest=digest,
        files=[EvidenceFile(**asdict(f)) for f in scanned],
    )
    item.custody.append(
        CustodyRecord(
            action=CustodyAction.ACQUIRED,
            timestamp=now,
            actor=actor,
            os_user=audit.os_user(),
            workstation=audit.workstation(),
            source_path=str(root),
            item_digest=digest,
            note=source_note,
        )
    )
    kinds = Counter(str(f.kind) for f in scanned)
    warnings = [f"{f.rel_path}: {f.note}" for f in scanned if f.note]

    with handle.session() as s:
        s.add(item)
        s.flush()
        manifest_sha = write_manifest(s, handle.directory)
        audit.record(
            s,
            "evidence.add",
            actor=actor,
            item_id=item.id,
            source_path=str(root),
            item_digest=digest,
            counts=dict(kinds),
            manifest_sha256=manifest_sha,
        )
        result = item_to_dict(item, include_files=False)
    result.update(counts=dict(kinds), warnings=warnings, manifest_sha256=manifest_sha)
    return result


def _verify_file(f: EvidenceFile) -> tuple[str, str | None]:
    """Return (status, detail) for one recorded file: ok, modified, missing or unreadable."""
    path = Path(f.path)
    if f.kind == FileKind.SYMLINK:
        if not path.is_symlink():
            return "missing", "symlink no longer present"
        target = os.readlink(path)
        return ("ok", None) if target == f.symlink_target else ("modified", f"target now {target}")
    if f.kind != FileKind.FILE:
        # Special/unreadable entries were never hashed; just report presence.
        return ("ok", None) if os.path.lexists(path) else ("missing", None)
    if not os.path.lexists(path):
        return "missing", None
    try:
        h = hash_file(path)
    except OSError as exc:
        return "unreadable", exc.strerror
    if (h.sha256, h.md5, h.size) != (f.sha256, f.md5, f.size):
        return "modified", f"sha256 now {h.sha256}"
    return "ok", None


def verify_evidence(
    handle: CaseHandle, *, item_id: int | None = None, actor: str | None = None
) -> dict[str, Any]:
    """Re-hash recorded evidence and report any change since intake.

    Files that appeared under a directory item after intake are reported as
    ``new``. A custody record is appended per item with the outcome.
    """
    with handle.session() as s:
        actor = actor or handle.case(s).investigator
        query = select(EvidenceItem).order_by(EvidenceItem.id)
        if item_id is not None:
            query = query.where(EvidenceItem.id == item_id)
        items = s.scalars(query).all()
        if item_id is not None and not items:
            raise EvidenceError(f"No evidence item with id {item_id}")

        report: list[dict[str, Any]] = []
        for item in items:
            problems = []
            for f in item.files:
                status, detail = _verify_file(f)
                if status != "ok":
                    problems.append({"rel_path": f.rel_path, "status": status, "detail": detail})
            root = Path(item.source_path)
            if root.is_dir():
                known = {f.rel_path for f in item.files}
                for rel in list_rel_paths(root):
                    if rel not in known:
                        problems.append({"rel_path": rel, "status": "new", "detail": None})

            ok = not problems
            item.custody.append(
                CustodyRecord(
                    action=CustodyAction.VERIFIED if ok else CustodyAction.VERIFICATION_FAILED,
                    timestamp=utcnow(),
                    actor=actor,
                    os_user=audit.os_user(),
                    workstation=audit.workstation(),
                    source_path=item.source_path,
                    item_digest=item.item_digest,
                    note=None if ok else f"{len(problems)} problem(s)",
                )
            )
            report.append(
                {
                    "item_id": item.id,
                    "label": item.label,
                    "source_path": item.source_path,
                    "files_checked": len(item.files),
                    "ok": ok,
                    "problems": problems,
                }
            )

        s.flush()
        manifest_sha = write_manifest(s, handle.directory)
        all_ok = all(r["ok"] for r in report)
        audit.record(
            s,
            "evidence.verify",
            actor=actor,
            item_id=item_id,
            ok=all_ok,
            problems={r["item_id"]: r["problems"] for r in report if not r["ok"]},
            manifest_sha256=manifest_sha,
        )
    return {"ok": all_ok, "items": report}


def list_evidence(handle: CaseHandle, *, include_files: bool = False) -> list[dict[str, Any]]:
    """Evidence items (and optionally their files) recorded in the case."""
    with handle.session() as s:
        items = s.scalars(select(EvidenceItem).order_by(EvidenceItem.id)).all()
        return [item_to_dict(i, include_files=include_files) for i in items]
