"""Tests for read-only access and hashing."""

from __future__ import annotations

import bz2
import errno
import gzip
import hashlib
import lzma
import os
from pathlib import Path

import pytest

from sherlog.intake.hashing import hash_file
from sherlog.intake.readonly import detect_compression, open_evidence, open_raw

ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
ABC_MD5 = "900150983cd24fb0d6963f7d28e17f72"


def test_hash_known_vector(tmp_path: Path) -> None:
    f = tmp_path / "abc"
    f.write_bytes(b"abc")
    h = hash_file(f)
    assert (h.sha256, h.md5, h.size) == (ABC_SHA256, ABC_MD5, 3)
    assert h.compression is None and h.content_sha256 is None


def test_hash_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "empty"
    f.write_bytes(b"")
    assert hash_file(f).sha256 == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize(
    ("compress", "name"),
    [(gzip.compress, "gzip"), (bz2.compress, "bzip2"), (lzma.compress, "xz")],
)
def test_compressed_content_hash(tmp_path: Path, compress, name: str) -> None:  # type: ignore[no-untyped-def]
    payload = b"line one\nline two\n" * 100
    f = tmp_path / "log.bin"  # extension deliberately uninformative
    f.write_bytes(compress(payload))
    h = hash_file(f)
    assert h.compression == name
    assert h.sha256 == hashlib.sha256(f.read_bytes()).hexdigest()
    assert h.content_sha256 == hashlib.sha256(payload).hexdigest()
    assert h.content_size == len(payload)
    with open_evidence(f) as fh:
        assert fh.read() == payload


def test_detect_compression_ignores_extension() -> None:
    assert detect_compression(b"plain text") is None
    assert detect_compression(b"\x1f\x8b\x08") == "gzip"


def test_corrupt_gzip_records_error(tmp_path: Path) -> None:
    f = tmp_path / "broken.gz"
    f.write_bytes(gzip.compress(b"x" * 1000)[:20])
    h = hash_file(f)
    assert h.compression == "gzip"
    assert h.content_sha256 is None
    assert h.content_error


def test_open_raw_refuses_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError) as exc:
        open_raw(link)
    assert exc.value.errno == errno.ELOOP


def test_open_raw_is_read_only(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_bytes(b"data")
    with open_raw(f) as fh, pytest.raises(OSError):
        fh.write(b"nope")  # type: ignore[call-overload]
    assert f.read_bytes() == b"data"


def test_hashing_preserves_atime_when_owner(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_bytes(b"data")
    st = os.stat(f)
    old_atime_ns = st.st_mtime_ns - 10**12  # older than mtime: relatime would update it
    os.utime(f, ns=(old_atime_ns, st.st_mtime_ns))
    hash_file(f)
    assert os.stat(f).st_atime_ns == old_atime_ns
