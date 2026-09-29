"""Streaming SHA-256/MD5 hashing of evidence files."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from sherlog.intake.readonly import detect_compression, open_evidence, open_raw

CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class FileHashes:
    """Hashes of a file as stored and, if compressed, of its decompressed content."""

    sha256: str
    md5: str
    size: int
    compression: str | None = None
    content_sha256: str | None = None
    content_size: int | None = None
    # Set when the decompressed stream could not be read (corrupt/truncated archive).
    content_error: str | None = None
    # Set when size/mtime changed between the start and end of hashing.
    changed_during_read: bool = False


def hash_stream(fh: BinaryIO) -> tuple[str, str, int]:
    """Return (sha256, md5, byte count) for everything readable from ``fh``."""
    sha, md5, size = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
    while chunk := fh.read(CHUNK_SIZE):
        sha.update(chunk)
        md5.update(chunk)
        size += len(chunk)
    return sha.hexdigest(), md5.hexdigest(), size


def hash_file(path: str | Path) -> FileHashes:
    """Hash a regular file read-only; also hash decompressed content for gzip/bzip2/xz."""
    with open_raw(path) as fh:
        before = os.fstat(fh.fileno())
        compression = detect_compression(fh.read(8))
        fh.seek(0)
        sha256, md5, size = hash_stream(fh)
        after = os.fstat(fh.fileno())
    changed = (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)

    content_sha256 = content_size = content_error = None
    if compression:
        try:
            with open_evidence(path) as dfh:
                content_sha256, _, content_size = hash_stream(dfh)
        except (OSError, EOFError, ValueError) as exc:
            content_error = f"{type(exc).__name__}: {exc}"

    return FileHashes(
        sha256=sha256,
        md5=md5,
        size=size,
        compression=compression,
        content_sha256=content_sha256,
        content_size=content_size,
        content_error=content_error,
        changed_during_read=changed,
    )
