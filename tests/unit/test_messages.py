"""Tests for the Linux message classifier."""

from __future__ import annotations

import pytest

from sherlog.parsers.linux_messages import classify

CASES = [
    # (program, message, event_type, actor, src_ip, target, command)
    (
        "sshd",
        "Accepted password for bob from 10.0.0.1 port 22 ssh2",
        "auth.login.success",
        "bob",
        "10.0.0.1",
        None,
        None,
    ),
    (
        "sshd",
        "Failed password for invalid user oracle from 10.0.0.2 port 5 ssh2",
        "auth.login.failure",
        "oracle",
        "10.0.0.2",
        None,
        None,
    ),
    (
        "sshd",
        "Failed none for invalid user  from 10.0.0.2 port 5 ssh2",
        "auth.login.failure",
        None,
        "10.0.0.2",
        None,
        None,
    ),
    ("sshd", "Invalid user test from 10.0.0.3 port 9", "other", "test", "10.0.0.3", None, None),
    (
        "sshd",
        "error: maximum authentication attempts exceeded for root from 10.0.0.4 port 1 ssh2",
        "auth.login.failure",
        "root",
        "10.0.0.4",
        None,
        None,
    ),
    (
        "sshd-session",
        "Accepted publickey for ops from 2001:db8::1 port 22 ssh2: RSA SHA256:abc",
        "auth.login.success",
        "ops",
        "2001:db8::1",
        None,
        None,
    ),
    (
        "sshd",
        "Disconnected from user bob 10.0.0.1 port 22",
        "auth.logout",
        "bob",
        "10.0.0.1",
        None,
        None,
    ),
    (
        "sshd",
        "Connection closed by authenticating user root 10.0.0.9 port 4 [preauth]",
        "other",
        "root",
        "10.0.0.9",
        None,
        None,
    ),
    (
        "sudo",
        "  bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls /root",
        "auth.sudo",
        "bob",
        None,
        "root",
        "/bin/ls /root",
    ),
    (
        "sudo",
        "bob : TTY=pts/0 ; PWD=/tmp ; USER=root ; ENV=A=b ; COMMAND=/usr/bin/env",
        "auth.sudo",
        "bob",
        None,
        "root",
        "/usr/bin/env",
    ),
    (
        "su",
        "pam_unix(su:session): session opened for user root(uid=0) by bob(uid=1000)",
        "auth.su",
        "bob",
        None,
        "root",
        None,
    ),
    ("su", "(to root) bob on pts/1", "auth.su", "bob", None, "root", None),
    (
        "useradd",
        "new user: name=eve, UID=0, GID=0, home=/root, shell=/bin/bash, from=none",
        "user.create",
        None,
        None,
        "eve",
        None,
    ),
    ("usermod", "add 'eve' to group 'wheel'", "group.modify", None, None, "eve", None),
    ("usermod", "change user 'eve' password", "password.change", None, None, "eve", None),
    (
        "usermod",
        "change user 'eve' shell from '/bin/sh' to '/bin/bash'",
        "user.modify",
        None,
        None,
        "eve",
        None,
    ),
    ("userdel", "delete user 'eve'", "user.delete", None, None, "eve", None),
    (
        "gpasswd",
        "user eve added by root to group sudo",
        "group.modify",
        "root",
        None,
        "eve",
        None,
    ),
    (
        "chpasswd",
        "pam_unix(chpasswd:chauthtok): password changed for root",
        "password.change",
        None,
        None,
        "root",
        None,
    ),
    (
        "CRON",
        "(root) CMD (run-parts /etc/cron.hourly)",
        "cron.exec",
        "root",
        None,
        None,
        "run-parts /etc/cron.hourly",
    ),
    ("crontab", "(bob) REPLACE (bob)", "cron.modify", "bob", None, "bob", None),
    (
        "systemd",
        "Started Session 3 of User bob.",
        "service.start",
        None,
        None,
        "Session 3 of User bob",
        None,
    ),
    ("systemd-logind", "New session 3 of user bob.", "auth.session.open", "bob", None, None, None),
    ("kernel", "[ 0.0] Linux version 6.1.0 (gcc)", "system.boot", None, None, "6.1.0", None),
    ("kernel", "[ 5.0] usb 1-1: new device", "kernel.message", None, None, None, None),
    ("nginx", "whatever", "other", None, None, None, None),
    (None, "-- MARK --", "other", None, None, None, None),
]


@pytest.mark.parametrize(
    ("program", "message", "etype", "actor", "src_ip", "target", "command"), CASES
)
def test_classify(
    program: str | None,
    message: str,
    etype: str,
    actor: str | None,
    src_ip: str | None,
    target: str | None,
    command: str | None,
) -> None:
    c = classify(program, message)
    assert (c.event_type, c.actor, c.src_ip, c.target, c.command) == (
        etype,
        actor,
        src_ip,
        target,
        command,
    )


def test_sudo_failure_tagged() -> None:
    c = classify(
        "sudo",
        "bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
    )
    assert c.event_type == "auth.sudo"
    assert "sudo_failed" in c.tags


def test_publickey_fingerprint_tag() -> None:
    c = classify("sshd", "Accepted publickey for a from 1.2.3.4 port 1 ssh2: ED25519 SHA256:xyz+/=")
    assert "key:SHA256:xyz+/=" in c.tags
