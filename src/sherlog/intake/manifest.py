"""``manifest.json``: a human-readable export of the evidence inventory and custody chain.

The database is authoritative; the manifest is regenerated from it after every
intake or verification so it can be archived alongside the report.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sherlog import __version__
from sherlog.core.models import Case, CustodyRecord, EvidenceFile, EvidenceItem
from sherlog.core.timeutil import iso, utcnow

MANIFEST_FILENAME = "manifest.json"


def file_to_dict(f: EvidenceFile) -> dict[str, Any]:
    """Serialize an evidence file row."""
    return {
        "path": f.path,
        "rel_path": f.rel_path,
        "kind": str(f.kind),
        "size": f.size,
        "sha256": f.sha256,
        "md5": f.md5,
        "mtime": iso(f.mtime),
        "atime": iso(f.atime),
        "ctime": iso(f.ctime),
        "uid": f.uid,
        "gid": f.gid,
        "mode": f.mode,
        "inode": f.inode,
        "symlink_target": f.symlink_target,
        "compression": f.compression,
        "content_sha256": f.content_sha256,
        "content_size": f.content_size,
        "rotation_base": f.rotation_base,
        "rotation_index": f.rotation_index,
        "note": f.note,
    }


def custody_to_dict(c: CustodyRecord) -> dict[str, Any]:
    """Serialize a chain-of-custody record."""
    return {
        "action": str(c.action),
        "timestamp": iso(c.timestamp),
        "actor": c.actor,
        "os_user": c.os_user,
        "workstation": c.workstation,
        "source_path": c.source_path,
        "item_digest": c.item_digest,
        "note": c.note,
    }


def item_to_dict(item: EvidenceItem, *, include_files: bool = True) -> dict[str, Any]:
    """Serialize an evidence item with its custody chain (and optionally files)."""
    out: dict[str, Any] = {
        "id": item.id,
        "label": item.label,
        "source_path": item.source_path,
        "added_at": iso(item.added_at),
        "added_by": item.added_by,
        "source_note": item.source_note,
        "item_digest": item.item_digest,
        "file_count": len(item.files),
        "total_bytes": sum(f.size or 0 for f in item.files if f.sha256),
        "custody": [custody_to_dict(c) for c in item.custody],
    }
    if include_files:
        out["files"] = [file_to_dict(f) for f in item.files]
    return out


def build_manifest(session: Session) -> dict[str, Any]:
    """Assemble the manifest document from the database."""
    case = session.scalars(select(Case)).one()
    items = session.scalars(select(EvidenceItem).order_by(EvidenceItem.id)).all()
    return {
        "manifest_version": 1,
        "generated_at": iso(utcnow()),
        "generator": f"sherlog {__version__}",
        "case": {
            "id": case.id,
            "name": case.name,
            "investigator": case.investigator,
            "timezone": case.timezone,
            "created_at": iso(case.created_at),
        },
        "evidence": [item_to_dict(i) for i in items],
    }


def write_manifest(session: Session, case_dir: Path) -> str:
    """Write ``manifest.json`` atomically and return its SHA-256."""
    data = json.dumps(build_manifest(session), indent=2, sort_keys=True).encode() + b"\n"
    target = case_dir / MANIFEST_FILENAME
    tmp = target.with_suffix(".json.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, target)
    return hashlib.sha256(data).hexdigest()
