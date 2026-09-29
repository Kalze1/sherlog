"""Shell history: bash (with or without HISTTIMEFORMAT epochs) and zsh extended history.

Plain bash history has no timestamps; those events have ``timestamp_utc = None``
and appear at the end of the timeline. The owning user is taken from the
evidence path (``/home/<user>/...`` or ``/root/...``) when available, since the
file content does not record it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import ParseContext, ParsedEvent, Parser, Sample, user_from_path
from sherlog.parsers.registry import register
from sherlog.parsers.syslog import split_header

_BASH_TS = re.compile(r"^#(?P<epoch>\d{9,11})$")
_ZSH_EXT = re.compile(r"^: (?P<epoch>\d{9,11}):(?P<dur>\d+);(?P<cmd>.*)$")

# First words that are common at an interactive prompt.
COMMON_COMMANDS = frozenset(
    [
        "ls",
        "cd",
        "cat",
        "less",
        "more",
        "vi",
        "vim",
        "nano",
        "grep",
        "find",
        "sudo",
        "su",
        "ps",
        "top",
        "htop",
        "kill",
        "pkill",
        "df",
        "du",
        "free",
        "mkdir",
        "rm",
        "rmdir",
        "cp",
        "mv",
        "touch",
        "chmod",
        "chown",
        "chattr",
        "ln",
        "echo",
        "export",
        "history",
        "clear",
        "exit",
        "whoami",
        "id",
        "uname",
        "hostname",
        "ip",
        "ifconfig",
        "netstat",
        "ss",
        "ping",
        "curl",
        "wget",
        "scp",
        "ssh",
        "sftp",
        "rsync",
        "tar",
        "gzip",
        "gunzip",
        "unzip",
        "zip",
        "apt",
        "apt-get",
        "yum",
        "dnf",
        "rpm",
        "dpkg",
        "pip",
        "pip3",
        "python",
        "python3",
        "perl",
        "php",
        "bash",
        "sh",
        "zsh",
        "nc",
        "ncat",
        "socat",
        "systemctl",
        "service",
        "journalctl",
        "crontab",
        "git",
        "docker",
        "kubectl",
        "make",
        "gcc",
        "base64",
        "openssl",
        "awk",
        "sed",
        "tail",
        "head",
        "passwd",
        "useradd",
        "usermod",
        "userdel",
        "w",
        "who",
        "last",
        "mount",
        "umount",
        "nohup",
        "screen",
        "tmux",
    ]
)


def _first_word(line: str) -> str:
    word = line.strip().split(maxsplit=1)[0] if line.strip() else ""
    return word.rsplit("/", 1)[-1]


def _epoch(value: str) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), UTC)
    except (ValueError, OverflowError, OSError):
        return None


def _lines(path: Path) -> Iterator[tuple[int, str]]:
    with open_evidence(path) as fh:
        for n, raw in enumerate(fh, 1):
            yield n, raw.decode("utf-8", errors="replace").rstrip("\r\n")


def _text_lines(sample: Sample) -> list[str]:
    return [] if sample.is_binary else [line for line in sample.lines if line.strip()]


@register
class BashHistoryParser(Parser):
    name = "bash_history"
    artifact_type = "shell.bash_history"
    description = "bash history, optionally with #<epoch> timestamp lines"

    def can_parse(self, sample: Sample) -> float:
        lines = _text_lines(sample)
        if not lines:
            return 0.0
        if sum(1 for line in lines if split_header(line)) > len(lines) * 0.3:
            return 0.0
        ts = sum(1 for line in lines if _BASH_TS.match(line))
        if ts and ts >= len(lines) * 0.3:
            return 0.95
        common = sum(1 for line in lines if _first_word(line) in COMMON_COMMANDS)
        ratio = common / len(lines)
        return 0.0 if ratio < 0.2 else round(min(0.85, 0.4 + 0.5 * ratio), 3)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        user = user_from_path(ctx.path)
        pending: tuple[int, str] | None = None  # (line number, "#epoch" line)
        for n, line in _lines(path):
            if _BASH_TS.match(line):
                pending = (n, line)
                continue
            if not line.strip():
                continue
            ts = _epoch(pending[1][1:]) if pending else None
            yield ParsedEvent(
                event_type="shell.command",
                raw=f"{pending[1]}\n{line}" if pending else line,
                line_number=n,
                timestamp_utc=ts,
                timestamp_raw=pending[1] if pending else None,
                actor=user,
                command=line,
                tags=["bash"] + ([] if ts else ["no_timestamp"]),
            )
            pending = None


@register
class ZshHistoryParser(Parser):
    name = "zsh_history"
    artifact_type = "shell.zsh_history"
    description = "zsh extended history (': <epoch>:<duration>;<command>')"

    def can_parse(self, sample: Sample) -> float:
        lines = _text_lines(sample)
        if not lines:
            return 0.0
        hits = sum(1 for line in lines if _ZSH_EXT.match(line))
        return 0.95 if hits >= len(lines) * 0.5 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        user = user_from_path(ctx.path)
        for n, line in _lines(path):
            if not line.strip():
                continue
            m = _ZSH_EXT.match(line)
            cmd = m["cmd"] if m else line  # continuation of a multi-line command
            ts = _epoch(m["epoch"]) if m else None
            yield ParsedEvent(
                event_type="shell.command",
                raw=line,
                line_number=n,
                timestamp_utc=ts,
                timestamp_raw=m["epoch"] if m else None,
                actor=user,
                command=cmd,
                tags=["zsh"] + ([f"duration:{m['dur']}"] if m else ["no_timestamp"]),
            )
