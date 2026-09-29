"""Offline GeoIP/ASN lookups from a local MaxMind database, if one is configured.

Needs the optional ``maxminddb`` package (``pip install 'sherlog[geoip]'``) and a
GeoLite2/GeoIP2 ``.mmdb`` file; nothing is ever fetched from the network.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class GeoIP:
    """Lookups against one .mmdb file (City, Country or ASN editions)."""

    def __init__(self, path: Path) -> None:
        import maxminddb  # type: ignore[import-not-found,unused-ignore]

        self.path = path
        self._reader = maxminddb.open_database(str(path))

    def lookup(self, ip: str) -> dict[str, Any] | None:
        try:
            if not ipaddress.ip_address(ip).is_global:
                return None
        except ValueError:
            return None
        rec = self._reader.get(ip)
        if not isinstance(rec, dict):
            return None
        out = {
            "country": (rec.get("country") or {}).get("iso_code"),
            "city": ((rec.get("city") or {}).get("names") or {}).get("en"),
            "asn": rec.get("autonomous_system_number"),
            "as_org": rec.get("autonomous_system_organization"),
        }
        return {k: v for k, v in out.items() if v is not None} or None

    def close(self) -> None:
        self._reader.close()


def open_geoip(path: str | None) -> tuple[GeoIP | None, str | None]:
    """(reader, reason-if-unavailable)."""
    if not path:
        return None, "no GeoIP database configured (enrichment.geoip_db)"
    p = Path(path).expanduser()
    if not p.is_file():
        return None, f"GeoIP database not found: {p}"
    try:
        return GeoIP(p), None
    except ImportError:
        return None, "maxminddb is not installed (pip install 'sherlog[geoip]')"
    except Exception as exc:  # corrupt/unsupported database
        return None, f"cannot open GeoIP database: {exc}"
