"""Read-only access to evidence files.

Every evidence read in SherLog goes through :func:`open_raw` or
:func:`open_evidence`. Files are opened with ``O_RDONLY | O_NOFOLLOW`` and, when
the kernel permits it (the caller owns the file or has CAP_FOWNER),
``O_NOATIME`` so that reading does not update the access time.
"""

from __future__ import annotations

import bz2
import errno
import gzip
import logging
import lzma
import os
from pathlib import Path
from typing import BinaryIO

log = logging.getLogger(__name__)

_O_NOATIME = getattr(os, "O_NOATIME", 0)
_BASE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)

# Magic bytes, checked on content rather than file extension.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
)


def open_raw(path: str | Path) -> BinaryIO:
    """Open an evidence file read-only, without following symlinks or touching atime."""
    try:
        fd = os.open(path, _BASE_FLAGS | _O_NOATIME)
    except OSError as exc:
        if _O_NOATIME and exc.errno == errno.EPERM:
            log.debug("O_NOATIME not permitted for %s; atime may be updated", path)
            fd = os.open(path, _BASE_FLAGS)
        else:
            raise
    return os.fdopen(fd, "rb")


def detect_compression(head: bytes) -> str | None:
    """Return ``gzip``, ``bzip2``, ``xz`` or ``None`` from a file's leading bytes."""
    for magic, name in _MAGIC:
        if head.startswith(magic):
            return name
    return None


def sniff_compression(path: str | Path) -> str | None:
    """Detect compression of the file at ``path`` from its content."""
    with open_raw(path) as fh:
        return detect_compression(fh.read(8))


def open_evidence(path: str | Path) -> BinaryIO:
    """Open an evidence file read-only, transparently decompressing gzip/bzip2/xz."""
    raw = open_raw(path)
    kind = detect_compression(raw.read(8))
    raw.seek(0)
    if kind == "gzip":
        return gzip.GzipFile(fileobj=raw, mode="rb")  # type: ignore[return-value]
    if kind == "bzip2":
        return bz2.BZ2File(raw, mode="rb")  # type: ignore[return-value]
    if kind == "xz":
        return lzma.LZMAFile(raw, mode="rb")  # type: ignore[return-value]
    return raw
