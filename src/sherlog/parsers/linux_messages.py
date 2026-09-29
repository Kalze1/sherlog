"""Classify Linux daemon messages (sshd, sudo, su, shadow-utils, cron, systemd, ...).

Shared by the syslog/auth.log and journald parsers: given a program name and
message text, return normalized fields. Unrecognised messages become ``other``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

AUTH_PROGRAMS = frozenset(
    {
        "sshd",
        "sshd-session",
        "sudo",
        "su",
        "useradd",
        "userdel",
        "usermod",
        "groupadd",
        "groupdel",
        "groupmod",
        "gpasswd",
        "passwd",
        "chpasswd",
        "chage",
        "login",
        "systemd-logind",
        "polkitd",
        "pkexec",
        "unix_chkpwd",
    }
)


@dataclass
class Classified:
    """Normalized fields extracted from a message."""

    event_type: str = "other"
    actor: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    target: str | None = None
    command: str | None = None
    tags: list[str] = field(default_factory=list)


Handler = Callable[[re.Match[str]], Classified]
_RULES: dict[str, list[tuple[re.Pattern[str], Handler]]] = {}


def _on(programs: str, pattern: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        for prog in programs.split():
            _RULES.setdefault(prog, []).append((re.compile(pattern), fn))
        return fn

    return deco


# --- sshd ---------------------------------------------------------------------------------
_SSHD = "sshd sshd-session"
_KEY_FP = re.compile(r"\b(SHA256:[A-Za-z0-9+/=]+)")


@_on(_SSHD, r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
def _ssh_accepted(m: re.Match[str]) -> Classified:
    tags = ["ssh", f"method:{m['method']}"]
    if fp := _KEY_FP.search(m.string):
        tags.append(f"key:{fp[1]}")
    return Classified("auth.login.success", actor=m["user"], src_ip=m["ip"], tags=tags)


@_on(
    _SSHD,
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) "
    r"from (?P<ip>\S+) port (?P<port>\d+)",
)
def _ssh_failed(m: re.Match[str]) -> Classified:
    tags = ["ssh", f"method:{m['method']}"]
    if m["invalid"]:
        tags.append("invalid_user")
    return Classified("auth.login.failure", actor=m["user"] or None, src_ip=m["ip"], tags=tags)


@_on(_SSHD, r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)")
def _ssh_invalid(m: re.Match[str]) -> Classified:
    # Precedes the "Failed ... invalid user" line; kept as context, not counted as a failure.
    return Classified(actor=m["user"] or None, src_ip=m["ip"], tags=["ssh", "invalid_user"])


@_on(
    _SSHD,
    r"^error: maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
    r"(?P<user>\S*) from (?P<ip>\S+)",
)
def _ssh_max(m: re.Match[str]) -> Classified:
    return Classified(
        "auth.login.failure", actor=m["user"] or None, src_ip=m["ip"], tags=["ssh", "max_attempts"]
    )


@_on(
    _SSHD,
    r"^Disconnected from (?:(?P<pre>authenticating|invalid) user (?P<u1>\S+) |user (?P<u2>\S+) )?"
    r"(?P<ip>\S+) port \d+",
)
def _ssh_disconnect(m: re.Match[str]) -> Classified:
    if m["u2"]:
        return Classified("auth.logout", actor=m["u2"], src_ip=m["ip"], tags=["ssh"])
    return Classified(actor=m["u1"], src_ip=m["ip"], tags=["ssh", "disconnect"])


@_on(
    _SSHD,
    r"^(?:Connection closed|Connection reset|Received disconnect) (?:by|from) "
    r"(?:(?:authenticating|invalid) user (?P<user>\S+) )?(?P<ip>[0-9A-Fa-f:.]+)",
)
def _ssh_closed(m: re.Match[str]) -> Classified:
    return Classified(actor=m["user"], src_ip=m["ip"], tags=["ssh", "disconnect"])


@_on(_SSHD, r"^Server listening on")
def _ssh_listen(m: re.Match[str]) -> Classified:
    return Classified("service.start", target="sshd", tags=["ssh"])


# LogLevel VERBOSE messages.
@_on(_SSHD, r"^Connection from (?P<src>\S+) port \d+ on (?P<dst>\S+) port (?P<dport>\d+)")
def _ssh_connection(m: re.Match[str]) -> Classified:
    return Classified(src_ip=m["src"], dst_ip=m["dst"], tags=["ssh", "connection"])


@_on(_SSHD, r"^Accepted key (?P<ktype>\S+) (?P<fp>SHA256:\S+) found at (?P<file>\S+?):(?P<ln>\d+)")
def _ssh_key_found(m: re.Match[str]) -> Classified:
    return Classified(
        target=m["file"],
        tags=["ssh", f"key:{m['fp']}", f"key_type:{m['ktype']}", f"key_line:{m['ln']}"],
    )


# --- PAM (any program) ----------------------------------------------------------------------
_PAM_SESSION = (
    r"pam_unix\((?P<svc>[\w-]+):session\): session (?P<state>opened|closed) for user "
    r"(?P<user>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<by>[^\s(]*)(?:\(uid=\d+\))?)?"
)
_PAM_AUTHFAIL = r"pam_unix\((?P<svc>[\w-]+):auth\): authentication failure;.*"
_PAM_PASSWD = r"pam_unix\((?P<svc>[\w-]+):chauthtok\): password changed for (?P<user>\S+)"


def _pam_session(m: re.Match[str]) -> Classified:
    svc, user, by = m["svc"], m["user"], m["by"] or None
    tags = [f"service:{svc}"]
    if svc in ("su", "su-l") and m["state"] == "opened":
        return Classified("auth.su", actor=by, target=user, tags=tags)
    etype = "auth.session.open" if m["state"] == "opened" else "auth.session.close"
    return Classified(etype, actor=user, target=user, tags=tags if not by else [*tags, f"by:{by}"])


_RHOST = re.compile(r"\brhost=(?P<ip>\S+)")
_PAM_USER = re.compile(r"\buser=(?P<user>\S+)")


def _pam_authfail(m: re.Match[str]) -> Classified:
    # Summarised elsewhere (e.g. sshd "Failed password"); context only to avoid double counting.
    ip = _RHOST.search(m.string)
    user = _PAM_USER.search(m.string)
    return Classified(
        actor=user["user"] if user else None,
        src_ip=ip["ip"] if ip else None,
        tags=[f"service:{m['svc']}", "pam_auth_failure"],
    )


def _pam_passwd(m: re.Match[str]) -> Classified:
    return Classified("password.change", target=m["user"], tags=[f"service:{m['svc']}"])


# --- sudo / su ------------------------------------------------------------------------------
@_on(
    "sudo",
    r"^\s*(?P<user>[^\s:]+) : (?:(?P<fail>[^;]+?) ; )?TTY=(?P<tty>[^;]*?) ; PWD=(?P<pwd>[^;]*?) ; "
    r"USER=(?P<target>[^;]*?) ; (?:[A-Z]+=[^;]*? ; )*COMMAND=(?P<cmd>.*)$",
)
def _sudo(m: re.Match[str]) -> Classified:
    tags = [f"tty:{m['tty']}", f"pwd:{m['pwd']}"]
    if m["fail"]:
        tags += ["sudo_failed", f"reason:{m['fail'].strip()}"]
    return Classified("auth.sudo", actor=m["user"], target=m["target"], command=m["cmd"], tags=tags)


@_on("su", r"^(?P<failed>FAILED SU )?\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")
def _su_legacy(m: re.Match[str]) -> Classified:
    tags = [f"tty:{m['tty']}"] + (["su_failed"] if m["failed"] else [])
    return Classified("auth.su", actor=m["user"], target=m["target"], tags=tags)


# --- shadow-utils ---------------------------------------------------------------------------
@_on(
    "useradd",
    r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), "
    r"home=(?P<home>[^,]+), shell=(?P<shell>[^,\s]+)",
)
def _useradd(m: re.Match[str]) -> Classified:
    return Classified(
        "user.create",
        target=m["user"],
        tags=[f"uid:{m['uid']}", f"gid:{m['gid']}", f"home:{m['home']}", f"shell:{m['shell']}"],
    )


@_on("useradd groupadd", r"^(?:new group|group added to \S+): name=(?P<group>[^,]+)")
def _groupadd(m: re.Match[str]) -> Classified:
    return Classified("group.modify", target=m["group"], tags=["group_create"])


@_on("useradd usermod", r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
def _add_to_group(m: re.Match[str]) -> Classified:
    return Classified("group.modify", target=m["user"], tags=[f"group:{m['group']}"])


@_on("gpasswd", r"^user (?P<user>\S+) added by (?P<by>\S+) to group (?P<group>\S+)")
def _gpasswd_add(m: re.Match[str]) -> Classified:
    return Classified("group.modify", actor=m["by"], target=m["user"], tags=[f"group:{m['group']}"])


@_on("usermod", r"^change user '(?P<user>[^']+)' password")
def _usermod_pw(m: re.Match[str]) -> Classified:
    return Classified("password.change", target=m["user"])


@_on("usermod chage", r"user '(?P<user>[^']+)'")
def _usermod_other(m: re.Match[str]) -> Classified:
    return Classified("user.modify", target=m["user"])


@_on("userdel", r"^delete user '(?P<user>[^']+)'")
def _userdel(m: re.Match[str]) -> Classified:
    return Classified("user.delete", target=m["user"])


# --- cron -----------------------------------------------------------------------------------
_CRON = "CRON CROND cron crond crontab"
CRON_PROGRAMS = frozenset({*_CRON.split(), "anacron", "run-parts"})


@_on(_CRON, r"^\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)\s*$")
def _cron_cmd(m: re.Match[str]) -> Classified:
    return Classified("cron.exec", actor=m["user"], command=m["cmd"].strip())


@_on(_CRON, r"^\((?P<user>[^)]+)\) (?P<action>REPLACE|END EDIT|DELETE) \((?P<owner>[^)]*)\)")
def _cron_modify(m: re.Match[str]) -> Classified:
    return Classified(
        "cron.modify", actor=m["user"], target=m["owner"], tags=[f"action:{m['action']}"]
    )


@_on("anacron", r"^Job `(?P<job>[^']+)' started")
def _anacron_job(m: re.Match[str]) -> Classified:
    return Classified("cron.exec", target=m["job"], tags=["anacron"])


@_on("run-parts", r"^starting (?P<script>\S+)")
def _run_parts(m: re.Match[str]) -> Classified:
    return Classified("cron.exec", command=m["script"], tags=["run-parts"])


# --- systemd / logind / journald / rsyslog / kernel -----------------------------------------
@_on("systemd", r"^(?P<verb>Started|Stopped|Failed to start) (?P<unit>.+?)\.?$")
def _systemd_unit(m: re.Match[str]) -> Classified:
    etype = {"Started": "service.start", "Stopped": "service.stop"}.get(m["verb"], "other")
    tags = ["service_failed"] if m["verb"] == "Failed to start" else []
    return Classified(etype, target=m["unit"], tags=tags)


@_on("systemd-logind", r"^New session (?P<sid>\S+) of user (?P<user>[^\s.]+)")
def _logind_new(m: re.Match[str]) -> Classified:
    return Classified("auth.session.open", actor=m["user"], tags=["logind", f"session:{m['sid']}"])


@_on("systemd-logind", r"^Removed session (?P<sid>[^\s.]+)")
def _logind_removed(m: re.Match[str]) -> Classified:
    return Classified("auth.session.close", tags=["logind", f"session:{m['sid']}"])


@_on("systemd-logind", r"^System is (?:powering down|rebooting|halting)")
def _logind_shutdown(m: re.Match[str]) -> Classified:
    return Classified("system.shutdown")


@_on("systemd-journald", r"^Journal (?P<state>started|stopped)")
def _journald(m: re.Match[str]) -> Classified:
    etype = "service.start" if m["state"] == "started" else "service.stop"
    return Classified(etype, target="systemd-journald", tags=["logging"])


@_on("rsyslogd", r"\] start$")
def _rsyslog_start(m: re.Match[str]) -> Classified:
    return Classified("service.start", target="rsyslogd", tags=["logging"])


@_on("rsyslogd", r"exiting on signal (?P<sig>\d+)")
def _rsyslog_stop(m: re.Match[str]) -> Classified:
    return Classified("service.stop", target="rsyslogd", tags=["logging", f"signal:{m['sig']}"])


@_on("kernel", r"Linux version (?P<ver>\S+)")
def _kernel_boot(m: re.Match[str]) -> Classified:
    return Classified("system.boot", target=m["ver"], tags=["kernel"])


@_on(
    "kernel",
    r"\[(?P<fw>UFW \w+|[\w-]*(?:DROP|REJECT|BLOCK)[\w-]*)\].*?SRC=(?P<src>\S+) DST=(?P<dst>\S+)"
    r"(?:.*?PROTO=(?P<proto>\S+))?(?:.*?DPT=(?P<dpt>\d+))?",
)
def _kernel_firewall(m: re.Match[str]) -> Classified:
    tags = ["kernel", "firewall", f"fw:{m['fw']}"]
    tags += [f"proto:{m['proto']}"] if m["proto"] else []
    tags += [f"dport:{m['dpt']}"] if m["dpt"] else []
    return Classified("kernel.message", src_ip=m["src"], dst_ip=m["dst"], tags=tags)


# (pattern, tag) pairs for security-relevant kernel messages; first match wins.
_KERNEL_TAGS = (
    (re.compile(r"\bsegfault at\b|general protection fault|traps: \S+ trap"), "crash"),
    (re.compile(r"Out of memory: Kill(?:ed)? process|oom-kill"), "oom"),
    (re.compile(r"taints kernel|module verification failed|loading out-of-tree module"), "taint"),
    (re.compile(r"entered promiscuous mode"), "promiscuous"),
    (re.compile(r"\busb \S+: new .*device"), "usb"),
    (re.compile(r"^audit: |\baudit\(\d"), "audit"),
    (re.compile(r"\bEXT4-fs error|I/O error|Buffer I/O error"), "io_error"),
)


def _kernel_other(message: str) -> Classified:
    for pattern, tag in _KERNEL_TAGS:
        if pattern.search(message):
            return Classified("kernel.message", tags=["kernel", tag])
    return Classified("kernel.message", tags=["kernel"])


def normalize_program(program: str | None) -> str:
    """``run-parts(/etc/cron.daily)`` -> ``run-parts``; ``None`` -> ``''``."""
    return (program or "").split("(", 1)[0]


def classify(program: str | None, message: str) -> Classified:
    """Classify ``message`` from ``program`` into normalized fields."""
    prog = normalize_program(program)
    for pattern, handler in _RULES.get(prog, ()):
        if m := pattern.search(message):
            return handler(m)
    # PAM lines can come from any service binary.
    if "pam_unix(" in message:
        for pat, pam_handler in (
            (_PAM_SESSION, _pam_session),
            (_PAM_PASSWD, _pam_passwd),
            (_PAM_AUTHFAIL, _pam_authfail),
        ):
            if m := re.search(pat, message):
                return pam_handler(m)
    if prog == "kernel":
        return _kernel_other(message)
    return Classified()
