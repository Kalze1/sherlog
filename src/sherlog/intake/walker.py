"""Walk an evidence path and collect metadata and hashes for every entry.

Symlinks are recorded with their target but never followed (on a mounted image
an absolute link would point into the analyst's own system). FIFOs, sockets and
devices are recorded but never opened. Traversal order is sorted so that
repeated runs produce identical manifests.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import stat
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sherlog.core.timeutil import from_epoch_ns
from sherlog.core.vocab import FileKind
from sherlog.intake.hashing import hash_file

log = logging.getLogger(__name__)

# auth.log.1, auth.log.2.gz, syslog-20240101.xz, access.log.10.bz2
_ROTATION_RE = re.compile(
    r"^(?P<base>.+?)(?:[.-](?P<index>\d{1,3}|\d{8}))?(?P<ext>\.(?:gz|bz2|xz))?$"
)


@dataclass
class ScannedFile:
    """Metadata and hashes for one path found during an evidence walk."""

    path: str
    rel_path: str
    kind: FileKind
    size: int | None = None
    sha256: str | None = None
    md5: str | None = None
    mtime: datetime | None = None
    atime: datetime | None = None
    ctime: datetime | None = None
    uid: int | None = None
    gid: int | None = None
    mode: str | None = None
    inode: int | None = None
    symlink_target: str | None = None
    compression: str | None = None
    content_sha256: str | None = None
    content_size: int | None = None
    rotation_base: str | None = None
    rotation_index: int | None = None
    note: str | None = None


def parse_rotation(name: str) -> tuple[str | None, int | None]:
    """Return (base name, rotation index) for rotated/compressed log names, else (None, None)."""
    m = _ROTATION_RE.fullmatch(name)
    if not m or not (m["index"] or m["ext"]):
        return None, None
    return m["base"], int(m["index"]) if m["index"] else 0


def _iter_paths(root: Path) -> Iterator[tuple[Path, str | None]]:
    """Yield (path, error) for every entry under ``root`` in sorted order, not following links.

    ``root`` itself must already be resolved; links *inside* it are never followed.
    """
    if not root.is_dir():
        yield root, None
        return
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError as exc:
            yield directory, f"cannot list directory: {exc.strerror}"
            continue
        subdirs = []
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                subdirs.append(Path(entry.path))
            else:
                yield Path(entry.path), None
        stack.extend(reversed(subdirs))


def scan_entry(path: Path, rel_path: str) -> ScannedFile:
    """Stat (without following links) and, for regular files, hash one path."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        return ScannedFile(str(path), rel_path, FileKind.UNREADABLE, note=f"lstat: {exc.strerror}")

    rec = ScannedFile(
        path=str(path),
        rel_path=rel_path,
        kind=FileKind.FILE,
        size=st.st_size,
        mtime=from_epoch_ns(st.st_mtime_ns),
        atime=from_epoch_ns(st.st_atime_ns),
        ctime=from_epoch_ns(st.st_ctime_ns),
        uid=st.st_uid,
        gid=st.st_gid,
        mode=stat.filemode(st.st_mode),
        inode=st.st_ino,
    )
    rec.rotation_base, rec.rotation_index = parse_rotation(path.name)

    if stat.S_ISLNK(st.st_mode):
        rec.kind = FileKind.SYMLINK
        rec.symlink_target = os.readlink(path)
        return rec
    if not stat.S_ISREG(st.st_mode):
        rec.kind = FileKind.SPECIAL
        rec.note = "special file (not read)"
        return rec

    try:
        hashes = hash_file(path)
    except OSError as exc:
        rec.kind = FileKind.UNREADABLE
        rec.note = f"read: {exc.strerror}"
        return rec

    rec.sha256, rec.md5, rec.size = hashes.sha256, hashes.md5, hashes.size
    rec.compression = hashes.compression
    rec.content_sha256, rec.content_size = hashes.content_sha256, hashes.content_size
    notes = []
    if hashes.content_error:
        notes.append(f"decompression failed: {hashes.content_error}")
    if hashes.changed_during_read:
        notes.append("file changed while being hashed; source may be live")
    rec.note = "; ".join(notes) or None
    return rec


def scan(root: Path) -> list[ScannedFile]:
    """Scan every entry under ``root`` (or ``root`` itself if it is not a directory).

    ``root`` should be an absolute, resolved path.
    """
    base = root if root.is_dir() else root.parent
    results = []
    for path, error in _iter_paths(root):
        rel = path.relative_to(base).as_posix() if path != base else "."
        if error:
            results.append(ScannedFile(str(path), rel, FileKind.UNREADABLE, note=error))
            continue
        rec = scan_entry(path, rel)
        log.debug("scanned %s (%s)", rel, rec.kind)
        results.append(rec)
    return results


def list_rel_paths(root: Path) -> list[str]:
    """Relative paths under ``root`` without statting or hashing (cheap presence check)."""
    base = root if root.is_dir() else root.parent
    return [p.relative_to(base).as_posix() if p != base else "." for p, _ in _iter_paths(root)]


def item_digest(files: Iterable[ScannedFile]) -> str:
    """Digest over sorted (rel_path, kind, sha256/target) so any change is detectable."""
    h = hashlib.sha256()
    for f in sorted(files, key=lambda f: f.rel_path):
        marker = f.sha256 or f.symlink_target or ""
        h.update(f"{f.rel_path}\t{f.kind}\t{marker}\n".encode())
    return h.hexdigest()
