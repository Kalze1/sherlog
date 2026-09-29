# SherLog

[![CI](https://github.com/Kalze1/sherlog/actions/workflows/ci.yml/badge.svg)](https://github.com/Kalze1/sherlog/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**AI-assisted Linux log forensics and incident response.**

> **Status: pre-alpha (Phase 7 — AI investigation assistant).** Sample evidence sets and the
> web UI come next. This README describes the intended design and
> will grow with each phase.

SherLog investigates a folder of collected Linux logs (or a mounted disk image). It:

1. preserves evidence integrity — SHA-256/MD5 hashing at intake and re-verification at report
   time, chain of custody, read-only handling;
2. identifies log artifacts by content, not filename;
3. parses them into a normalized event timeline;
4. runs deterministic Sigma detection rules;
5. uses an LLM as a *constrained* investigation assistant that proposes pivots and hypotheses,
   which the engine then verifies against the evidence;
6. enriches IOCs via AbuseIPDB and VirusTotal (with a fully offline mode);
7. maps findings to MITRE ATT&CK and, only where evidence supports it, to CVEs;
8. produces a standards-aligned report (Markdown, HTML, PDF, JSON, STIX 2.1);
9. is usable from both a CLI and a web UI sharing one core library.

Target users: CERT/CSIRT analysts, SOC responders and students.

## Install (development)

Requires Python 3.11+ on Linux.

```bash
git clone git@github.com:Kalze1/sherlog.git
cd sherlog
uv sync                 # creates .venv with runtime + dev dependencies from uv.lock
uv run sherlog --version
uv run pre-commit install
```

Without uv: `python -m venv .venv && . .venv/bin/activate && pip install -e .`

## Usage (so far)

```bash
sherlog case new web01-incident --tz Africa/Addis_Ababa --brief brief.txt --investigator "A. Analyst"
sherlog evidence add web01-incident /mnt/evidence/web01/var/log --note "scp from web01 by A. Analyst"
sherlog evidence list web01-incident --files
sherlog evidence verify web01-incident      # exits 1 if anything changed since intake
sherlog evidence identify web01-incident    # artifact type per file, by content
sherlog parse web01-incident                # normalized events into the case DB
sherlog timeline web01-incident --type auth.login --ip 203.0.113.50
sherlog timeline web01-incident --from 2024-12-31T23:00 --grep 'useradd|usermod' --json
sherlog analyze web01-incident              # run detection rules -> findings
sherlog findings web01-incident             # review findings (highest severity first)
sherlog findings web01-incident --show 12   # one finding with its linked evidence
sherlog findings web01-incident --accept 12 --note "confirmed"   # or --reject
sherlog rules list                          # bundled Sigma rules + analytics
sherlog rules test <rule-id> /path/to/auth.log   # test a rule against one file
sherlog iocs web01-incident                 # IOCs linked to findings (--all for every one)
sherlog config set enrichment.virustotal_key <key>   # or VT_API_KEY / ABUSEIPDB_API_KEY env
sherlog enrich web01-incident               # AbuseIPDB + VirusTotal lookups (opt-in)
sherlog config set ai.provider anthropic     # opt in to the AI assistant (see below)
sherlog investigate web01-incident -q "How did the attacker get in?"
sherlog ai draft web01-incident --accept     # review the AI-drafted summary
sherlog report web01-incident               # re-verify evidence, write the report
sherlog report web01-incident -f md -o ./out     # just Markdown, elsewhere
sherlog case show web01-incident --json     # every command supports --json
```

Cases are stored in `~/.local/share/sherlog/cases/<name>/` (`case.db` + `manifest.json`).
Override with `--cases-dir`, `SHERLOG_CASES_DIR`, or `cases_dir` in
`~/.config/sherlog/config.toml` (precedence in that order).

Intake references evidence in place and never writes to it: files are opened with
`O_RDONLY|O_NOFOLLOW` (plus `O_NOATIME` where permitted), symlinks are recorded but not
followed, FIFOs/devices are recorded but never opened, and gzip/bzip2/xz files (detected by
magic bytes) get both an on-disk hash and a decompressed-content hash.

### Supported artifacts

| Artifact type | What | Notes |
| --- | --- | --- |
| `linux.auth` | auth.log / secure | sshd, sudo, su, PAM, useradd/usermod/passwd, logind |
| `linux.syslog` | syslog / messages | cron, systemd units, rsyslog, kernel boot |
| `linux.cron` | /var/log/cron | CROND, crontab edits, anacron, run-parts |
| `linux.kernel` | kern.log | firewall drops (src/dst IPs), segfaults, taint, promiscuous mode, USB |
| `linux.dmesg` | `dmesg` / `dmesg -T` output | uptime-only lines are undated |
| `linux.audit` | audit.log (auditd) | logins, sudo, EXECVE command lines, account changes, auditd stop/disable; hex fields decoded |
| `sudo.log` | sudo `logfile` | wrapped lines joined; year inferred |
| `cron.crontab` | user and system crontabs | `cron.entry` state events with file mtime |
| `ssh.authorized_keys` | authorized_keys | `ssh-keygen`-compatible fingerprints, forced commands and `from=` flagged |
| `ssh.sshd_config` | sshd_config | risky settings tagged (`PermitRootLogin yes`, ...) |
| `web.access` | Apache/Nginx access logs | common, combined, vhost_combined, trailing X-Forwarded-For; HTTP fields in `extra` |
| `web.apache_error` / `web.nginx_error` | error logs | client IP and request extracted |
| `pkg.dpkg` / `pkg.apt_history` | dpkg.log, apt history.log | apt blocks record who ran which command |
| `pkg.yum` / `pkg.dnf_rpm` | yum.log, dnf.rpm.log | |
| `journald.json` | `journalctl -o json` export | exact UTC timestamps |
| `journald.binary` | `*.journal` files | parsed only with `python3-systemd`; otherwise reported with export steps |
| `utmp.wtmp` / `utmp.btmp` | login records / failed logins | glibc 64-bit struct layout |
| `lastlog` | last login per UID | |
| `shell.bash_history` / `shell.zsh_history` | shell history | `HISTTIMEFORMAT` epochs and zsh extended history |

Files are identified by sampling content, never by name; anything below the confidence
threshold is listed as `unclassified` with a preview. Override with
`--type 'GLOB=TYPE'`. Syslog timestamps without a year are dated from the file's mtime
(tracking December→January rollovers) and tagged `year_inferred`; timestamps without a
zone use the case `--tz` and are flagged `timezone_assumed`.

## Detection

`sherlog analyze` runs three kinds of deterministic detection over the timeline and writes
**findings**, then groups matches so one finding describes one entity's activity (e.g. "SSH
brute force from 203.0.113.50: 14 failures") rather than one row per log line.

- **Sigma rules** (`rules/*.yml`) — a self-contained matcher supporting selection/condition
  with `contains`/`startswith`/`endswith`/`re`/`cidr`/numeric/`exists`/`fieldref` modifiers,
  `and`/`or`/`not`, `1 of`/`all of`, and Sigma v2 correlations (`event_count`, `value_count`,
  `temporal`, `temporal_ordered`). Fields are SherLog's normalized event fields plus
  `extra.<key>` and derived `hour_local`/`weekday_local`.
- **Built-in analytics** for things rules cannot express: log gaps, wtmp/btmp truncation,
  one-off login source IPs, logging restarts outside a boot, and publickey logins whose
  fingerprint is absent from collected `authorized_keys`.

Every finding records `verified_by` (`rule`, `analyst` or `ai_proposed`), links the exact
events (with source file and SHA-256) that support it, and carries an ATT&CK technique list and
a recommendation. Re-running `analyze` is idempotent: an analyst's accept/reject and notes
survive via a stable fingerprint, and open findings that no longer match are removed. Write your
own rules and point at them with `--rules DIR` (add `--no-bundled-rules` to use only yours).

The shipped rule set covers SSH brute force / spraying / success-after-failures, root and
off-hours logins, account and privilege changes (new user, UID-0 backdoor, sudo group, sudoers,
foreign password reset), persistence (cron, systemd units, authorized_keys, shell rc files,
/tmp execution, kernel taint), web attacks (SQLi, LFI, RCE, web shells, scanners), shell
anti-forensics (reverse shells, curl|bash, base64|sh, history/log clearing, timestomping,
auditd disable) and credential access. ATT&CK data is a curated Linux subset bundled at
`src/sherlog/data/attack_linux.json`.

## IOCs and enrichment

`sherlog analyze` extracts indicators locally — IPs, domains, URLs, hashes, files staged in
`/tmp`-like directories and attacker-created or newly privileged usernames — and links each
to the findings its events support. Extraction favours precision: hashes only from command
lines, domains only from URLs or commands with common TLDs, loopback addresses dropped and
non-global addresses tagged private.

`sherlog enrich` is the explicit opt-in for external lookups (AbuseIPDB `/check`, VirusTotal
v3 IPs, domains and files). By default only finding-linked IOCs are enriched (`--all` for
every one). Before any request the egress policy applies:

- usernames, paths and full URLs are **never** sent (a URL's host is looked up as a domain);
- private/reserved addresses are sent only with `--enrich-private`;
- internal domains (single-label names, `.local`/`.corp`/..., and `enrichment.internal_domains`)
  are never sent.

Responses are cached in `~/.cache/sherlog/enrichment.db` (TTL `enrichment.cache_ttl_hours`,
default 24 h) and shared across cases; rate limits default to the free tiers (VirusTotal
4/min and 500/day, AbuseIPDB 1000/day) and are enforced across runs. HTTP 401/403/429 stop a
provider for the run. Each IOC keeps a verdict (malicious / suspicious / clean / unknown) with
the provider summary **and** the raw response; thresholds are in
`src/sherlog/enrichment/providers.py`. `--offline` (or `offline = true`) uses only the cache
and local GeoIP (a MaxMind `.mmdb` set via `enrichment.geoip_db`, with
`pip install 'sherlog[geoip]'`). Every lookup decision is written to the audit log.

API keys come from `SHERLOG_VIRUSTOTAL_KEY`/`VT_API_KEY`, `SHERLOG_ABUSEIPDB_KEY`/
`ABUSEIPDB_API_KEY`, or `sherlog config set` (stored with mode 0600; `config show` masks them).

## AI investigation assistant

The assistant is **off until you configure a provider** and never runs with `--offline`/`--no-ai`:

```bash
sherlog config set ai.provider anthropic      # default model claude-sonnet-4-6 (ai.model to change)
export ANTHROPIC_API_KEY=...                  # or `ant auth login`, or ai.anthropic_key
pip install 'sherlog[ai]'                     # the Anthropic SDK
# alternatives: ai.provider openai (+ ai.openai_base_url, ai.model) or ollama (+ ai.model)
```

`sherlog analyze` runs it after the rules when configured; `sherlog investigate` runs it on its
own. How it is constrained:

- **Tools, not access.** The model can only call eight tools — `search_events`,
  `pivot_on_ioc`, `get_timeline_window`, `list_artifacts`, `run_rule`, `propose_finding`,
  `propose_hypothesis`, `request_enrichment`. No shell, files or internet.
- **Facts vs. hypotheses.** `propose_finding` must cite event ids that exist (otherwise it is
  rejected and the model is told why) and creates an **AI-proposed** finding the analyst accepts
  or rejects (`sherlog findings --accept/--reject`). Hypotheses are stored separately and are
  never findings.
- **Redaction on by default.** Host names, internal (RFC 1918/ULA) addresses, usernames
  (except generic system accounts), e-mail addresses and internal domains are replaced with
  stable HMAC pseudonyms before anything is sent; the model's tool arguments are mapped back
  locally. `--no-redact` disables it and is recorded in the report.
- **Limits.** At most `ai.max_iterations` (15) tool rounds and `ai.token_budget` tokens per run.
- **Draft from confirmed findings only.** A final, tool-less request drafts the executive
  summary and narrative from rule/analyst findings; it is used in the report only after
  `sherlog ai draft --accept` (or `--write`/`--edit` to revise it first).
- **Reproducible.** Every exchange is stored exactly as sent (`sherlog ai show`); a run can be
  exported and replayed (`sherlog ai export` / `sherlog investigate --replay`) to reproduce the
  same proposals without calling a model. Prompts live in `src/sherlog/ai/prompts.py`.

## Sample cases

`samples/generate/` holds deterministic generators for sample evidence sets with answer keys:

```bash
python -m samples.generate --out samples/out        # writes <scenario>/evidence and answer_key.json
sherlog case new demo && sherlog evidence add demo samples/out/a-ssh-bruteforce-cron/evidence
sherlog analyze demo --no-ai && sherlog report demo
```

| Scenario | Status |
| --- | --- |
| a — SSH brute force → privileged backdoor account → cron persistence | available |
| b — web application exploitation → web shell → privilege escalation | planned |
| c — insider misuse with log tampering | planned |

`tests/e2e/test_samples.py` runs the whole pipeline on every registered scenario and checks
its answer key: expected findings, no unexpected high-severity findings, ATT&CK techniques,
IOCs, exact UTC times of key events, report outputs and limitations, and byte-identical
regeneration.

## Reporting

`sherlog report <case>` first re-hashes all evidence and compares it with intake (recording a
custody entry), then writes to `<case>/report/`:

| File | Content |
| --- | --- |
| `report.md`, `report.html` | Full report: case metadata, executive summary, scope and evidence with hashes and chain of custody, methodology and standards mapping, key-event timeline, findings by severity with provenance badges, IOCs, ATT&CK coverage, recommendations (containment / eradication / recovery / long-term), limitations and assumptions, and appendices (audit log, rules applied, AI use, dismissed findings) |
| `report.pdf` | Rendered from the HTML when WeasyPrint is installed (`pip install 'sherlog[pdf]'`); otherwise skipped with a notice |
| `findings.json` | Every finding with its linked events |
| `events.jsonl` | The complete normalized timeline |
| `iocs.stix.json` | STIX 2.1 bundle (identity, ATT&CK attack-patterns, indicators, report) with deterministic ids |
| `SHA256SUMS` | Hashes of the outputs, also recorded in the audit log |

The executive summary is generated only from findings and states so. Limitations are computed
from the case: assumed timezones, inferred years, undated and unparseable events, unanalyzed
files, log gaps, and an explicit "no CVE could be attributed" when none is tied to evidence.

## Principles

- **Evidence is never modified.** Work happens on read-only handles; every input is hashed at
  intake and re-verified at report time.
- **Facts vs. hypotheses.** Every finding records `verified_by`: `rule`, `analyst` or
  `ai_proposed`. The LLM never writes findings directly.
- **Reproducible.** Every command, query, rule match and enrichment call goes to an audit log.
- **Private and offline-capable.** `--offline` disables all AI and enrichment. External calls go
  through a redaction layer by default.
- **Honest about limits.** No CVE is attributed without concrete evidence; timezone assumptions,
  missing syslog years and log gaps are reported as limitations.

## Standards alignment

| Area | Standards |
| --- | --- |
| Identification, collection, acquisition, preservation | ISO/IEC 27037, RFC 3227 |
| Analysis and investigation process | ISO/IEC 27042, ISO/IEC 27043, NIST SP 800-86 |
| Incident handling and recommendations | NIST SP 800-61r3 |

Details of how each phase and report section maps to these standards will be documented as the
corresponding components are built.

## Roadmap

v0.1 is built in phases: skeleton → intake → identification and parsers → detection → reporting →
enrichment → AI orchestrator → sample cases → web UI → polish and release.

Planned for v2: Windows EVTX, memory analysis via Volatility 3, live host collection.

## License

[Apache-2.0](LICENSE)
