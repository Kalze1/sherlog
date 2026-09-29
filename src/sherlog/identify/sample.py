"""Read a content sample from an evidence file for identification."""

from __future__ import annotations

from pathlib import Path

from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import Sample

SAMPLE_BYTES = 64 * 1024
SAMPLE_LINES = 200


def looks_binary(head: bytes) -> bool:
    """NUL bytes, or more than 30% non-text bytes, in the sample."""
    if not head:
        return False
    if b"\0" in head:
        return True
    text = bytes(range(32, 127)) + b"\n\r\t\f\b\x1b"
    nontext = sum(1 for b in head if b not in text and b < 128)
    return nontext / len(head) > 0.3


def read_sample(path: Path, size: int | None = None) -> Sample:
    """Sample the (decompressed) start of a file.

    ``size`` is the logical (decompressed) size recorded at intake; binary
    formats with fixed-size records use it to check alignment.
    """
    with open_evidence(path) as fh:
        head = fh.read(SAMPLE_BYTES)
    binary = looks_binary(head)
    lines: list[str] = []
    if not binary:
        text = head.decode("utf-8", errors="replace")
        # Drop a possibly truncated final line when the sample was cut short.
        parts = text.splitlines()
        if len(head) == SAMPLE_BYTES and parts:
            parts = parts[:-1]
        lines = parts[:SAMPLE_LINES]
    return Sample(
        head=head, lines=lines, size=len(head) if size is None else size, is_binary=binary
    )


def preview(sample: Sample, max_lines: int = 10, max_bytes: int = 256) -> str:
    """Human-readable preview: first lines of text, or a hexdump of binary content."""
    if not sample.is_binary:
        return "\n".join(line[:200] for line in sample.lines[:max_lines])
    out = []
    data = sample.head[:max_bytes]
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{off:08x}  {hexpart:<47}  {asc}")
    return "\n".join(out)
