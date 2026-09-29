"""Threat-intelligence providers: AbuseIPDB and VirusTotal v3.

Each provider builds a request for an IOC and summarizes the response into a
verdict (malicious / suspicious / clean / unknown). Thresholds are explicit
here so a report reader can see how a verdict was reached; the raw response is
always kept alongside the summary.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, ClassVar

from sherlog import __version__
from sherlog.core.errors import SherlogError
from sherlog.core.vocab import IOCType, Verdict

# (url, headers, timeout) -> (HTTP status, parsed JSON body or None)
HttpGet = Callable[[str, dict[str, str], float], tuple[int, Any]]
USER_AGENT = f"SherLog/{__version__} (+https://github.com/Kalze1/sherlog)"
TIMEOUT = 20.0


class NetworkError(SherlogError):
    """The provider could not be reached."""


def urllib_get(url: str, headers: dict[str, str], timeout: float) -> tuple[int, Any]:
    """Default HTTP client (stdlib only)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read() or b"null")
        except ValueError:
            body = None
        return exc.code, body
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NetworkError(f"network error: {exc}") from exc


class Provider(ABC):
    name: str
    types: frozenset[IOCType]

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def supports(self, kind: IOCType) -> bool:
        return kind in self.types

    @abstractmethod
    def request(self, kind: IOCType, value: str) -> tuple[str, dict[str, str]]:
        """(url, headers) for looking up one IOC."""

    @abstractmethod
    def summarize(self, body: Any) -> tuple[Verdict, dict[str, Any]]:
        """Verdict and key facts from a successful (200) response."""


class AbuseIPDB(Provider):
    name = "abuseipdb"
    types = frozenset({IOCType.IPV4, IOCType.IPV6})
    BASE = "https://api.abuseipdb.com/api/v2/check"

    def request(self, kind: IOCType, value: str) -> tuple[str, dict[str, str]]:
        query = urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90})
        return f"{self.BASE}?{query}", {"Key": self.api_key, "Accept": "application/json"}

    def summarize(self, body: Any) -> tuple[Verdict, dict[str, Any]]:
        data = (body or {}).get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        summary = {
            "abuse_confidence_score": score,
            "total_reports": reports,
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
            "last_reported_at": data.get("lastReportedAt"),
        }
        if score >= 75:
            verdict = Verdict.MALICIOUS
        elif score >= 25:
            verdict = Verdict.SUSPICIOUS
        elif reports == 0:
            verdict = Verdict.UNKNOWN  # no reports is not evidence of being clean
        else:
            verdict = Verdict.CLEAN
        return verdict, summary


class VirusTotal(Provider):
    name = "virustotal"
    types = frozenset({IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.SHA256, IOCType.MD5})
    BASE = "https://www.virustotal.com/api/v3"
    _PATHS: ClassVar[dict[IOCType, str]] = {
        IOCType.IPV4: "ip_addresses",
        IOCType.IPV6: "ip_addresses",
        IOCType.DOMAIN: "domains",
        IOCType.SHA256: "files",
        IOCType.MD5: "files",
    }

    def request(self, kind: IOCType, value: str) -> tuple[str, dict[str, str]]:
        path = self._PATHS[kind]
        url = f"{self.BASE}/{path}/{urllib.parse.quote(value, safe='')}"
        return url, {"x-apikey": self.api_key}

    def summarize(self, body: Any) -> tuple[Verdict, dict[str, Any]]:
        attrs = ((body or {}).get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious") or 0)
        sus = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        summary = {
            "malicious": mal,
            "suspicious": sus,
            "harmless": harmless,
            "undetected": undetected,
            "reputation": attrs.get("reputation"),
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
            "type_description": attrs.get("type_description"),
            "meaningful_name": attrs.get("meaningful_name"),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }
        if mal >= 3:
            verdict = Verdict.MALICIOUS
        elif mal >= 1 or sus >= 2:
            verdict = Verdict.SUSPICIOUS
        elif harmless + undetected > 0:
            verdict = Verdict.CLEAN
        else:
            verdict = Verdict.UNKNOWN
        return verdict, summary


PROVIDERS: dict[str, type[Provider]] = {p.name: p for p in (AbuseIPDB, VirusTotal)}
_RANK = {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3}


def combine_verdicts(verdicts: list[Verdict]) -> Verdict:
    """Most severe verdict wins; any evidence beats 'unknown'."""
    return max(verdicts, key=lambda v: _RANK[v], default=Verdict.UNKNOWN)
