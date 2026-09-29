"""Web server logs: Apache/Nginx access logs, Apache error log, Nginx error log.

Access logs in Common, Combined and ``vhost_combined`` formats are handled by
one parser (Apache's and Nginx's default ``combined`` formats are identical).
A trailing quoted field, as in Nginx's common ``"$http_x_forwarded_for"``
extension, is kept as ``x_forwarded_for``. HTTP details go to ``extra`` so
detection rules can match on them.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sherlog.intake.readonly import open_evidence
from sherlog.parsers.base import ParseContext, ParsedEvent, Parser, Sample, parse_error
from sherlog.parsers.registry import register

_Q = r'"(?P<{}>(?:[^"\\]|\\.)*)"'
_ACCESS = re.compile(
    r"^(?:(?P<vhost>[\w.-]+:\d+) )?(?P<client>\S+) (?P<ident>\S+) (?P<user>\S+) "
    r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "
    + _Q.format("request")
    + r" (?P<status>\d{3}) (?P<bytes>\d+|-)"
    + r"(?: "
    + _Q.format("referer")
    + " "
    + _Q.format("ua")
    + r")?(?: "
    + _Q.format("xff")
    + r")?(?P<trailing>.*)$"
)
_REQUEST = re.compile(r"^(?P<method>[A-Z][A-Z_-]*) (?P<url>\S+)(?: (?P<proto>HTTP/[\d.]+))?$")
_APACHE_ERROR = re.compile(
    r"^\[(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] "
    r"\[(?:(?P<module>[^:\]]+):)?(?P<level>[^\]]+)\]"
    r"(?: \[pid (?P<pid>\d+)(?::tid \d+)?\])?(?: \[client (?P<client>[^\]]+)\])? ?(?P<msg>.*)$"
)
_NGINX_ERROR = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] "
    r"(?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<cid>\d+) )?(?P<msg>.*)$"
)
_NGINX_CLIENT = re.compile(r", client: (?P<client>[^,]+)")
_NGINX_REQUEST = re.compile(r', request: "(?P<request>(?:[^"\\]|\\.)*)"')
_NGINX_SERVER = re.compile(r", server: (?P<server>[^,]+)")


def _unescape(value: str | None) -> str | None:
    if value is None or value == "-":
        return None
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    # Strip ports: "1.2.3.4:5678" and "[2001:db8::1]:443".
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _text_lines(path: Path) -> Iterator[tuple[int, str]]:
    with open_evidence(path) as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.strip():
                yield n, line


def _ratio(sample: Sample, pattern: re.Pattern[str]) -> float:
    lines = [line for line in sample.lines if line.strip()]
    if sample.is_binary or not lines:
        return 0.0
    return sum(1 for line in lines if pattern.match(line)) / len(lines)


@register
class WebAccessParser(Parser):
    name = "web_access"
    artifact_type = "web.access"
    description = "Apache/Nginx access log (common, combined, vhost_combined)"

    def can_parse(self, sample: Sample) -> float:
        ratio = _ratio(sample, _ACCESS)
        return round(0.5 + 0.45 * ratio, 3) if ratio >= 0.6 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        for n, line in _text_lines(path):
            m = _ACCESS.match(line)
            if m is None:
                yield parse_error(line, n, "not_an_access_log_line")
                continue
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
            request = _unescape(m["request"]) or ""
            req = _REQUEST.match(request)
            extra: dict[str, Any] = {
                "method": req["method"] if req else None,
                "url": req["url"] if req else None,
                "protocol": req["proto"] if req else None,
                "request": request,
                "status": int(m["status"]),
                "bytes": int(m["bytes"]) if m["bytes"] != "-" else None,
                "referer": _unescape(m["referer"]),
                "user_agent": _unescape(m["ua"]),
                "x_forwarded_for": _unescape(m["xff"]),
                "vhost": m["vhost"],
                "client": m["client"],
            }
            tags = ["web", f"status:{m['status']}"]
            if req:
                tags.append(f"method:{req['method']}")
            elif request:
                tags.append("malformed_request")
            if m["xff"] is not None:
                tags.append("format:with_xff")
            yield ParsedEvent(
                event_type="web.request",
                raw=line,
                line_number=n,
                timestamp_utc=ts,
                timestamp_raw=m["ts"],
                host=m["vhost"].rsplit(":", 1)[0] if m["vhost"] else None,
                actor=None if m["user"] == "-" else m["user"],
                src_ip=_ip(m["client"]),
                target=req["url"] if req else request or None,
                tags=tags,
                extra=extra,
            )


@register
class ApacheErrorParser(Parser):
    name = "apache_error"
    artifact_type = "web.apache_error"
    description = "Apache httpd error log"

    def can_parse(self, sample: Sample) -> float:
        ratio = _ratio(sample, _APACHE_ERROR)
        return round(0.5 + 0.45 * ratio, 3) if ratio >= 0.6 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        for n, line in _text_lines(path):
            m = _APACHE_ERROR.match(line)
            if m is None:
                yield parse_error(line, n, "not_an_apache_error_line")
                continue
            fmt = "%a %b %d %H:%M:%S.%f %Y" if "." in m["ts"] else "%a %b %d %H:%M:%S %Y"
            try:
                ts = (
                    datetime.strptime(" ".join(m["ts"].split()), fmt)
                    .replace(tzinfo=ctx.case_tz)
                    .astimezone(UTC)
                )
            except ValueError:
                ts = None
            yield ParsedEvent(
                event_type="web.error",
                raw=line,
                line_number=n,
                timestamp_utc=ts,
                timestamp_raw=m["ts"],
                timezone_assumed=True,
                src_ip=_ip(m["client"]),
                tags=["web", f"level:{m['level']}"]
                + ([f"module:{m['module']}"] if m["module"] else []),
                extra={"level": m["level"], "module": m["module"], "message": m["msg"]},
            )


@register
class NginxErrorParser(Parser):
    name = "nginx_error"
    artifact_type = "web.nginx_error"
    description = "Nginx error log"

    def can_parse(self, sample: Sample) -> float:
        ratio = _ratio(sample, _NGINX_ERROR)
        return round(0.5 + 0.45 * ratio, 3) if ratio >= 0.6 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[ParsedEvent]:
        for n, line in _text_lines(path):
            m = _NGINX_ERROR.match(line)
            if m is None:
                yield parse_error(line, n, "not_an_nginx_error_line")
                continue
            ts = (
                datetime.strptime(m["ts"], "%Y/%m/%d %H:%M:%S")
                .replace(tzinfo=ctx.case_tz)
                .astimezone(UTC)
            )
            msg = m["msg"]
            client = _NGINX_CLIENT.search(msg)
            request = _NGINX_REQUEST.search(msg)
            server = _NGINX_SERVER.search(msg)
            req = _REQUEST.match(request["request"]) if request else None
            yield ParsedEvent(
                event_type="web.error",
                raw=line,
                line_number=n,
                timestamp_utc=ts,
                timestamp_raw=m["ts"],
                timezone_assumed=True,
                host=server["server"] if server else None,
                src_ip=_ip(client["client"]) if client else None,
                target=req["url"] if req else None,
                tags=["web", f"level:{m['level']}"],
                extra={
                    "level": m["level"],
                    "message": msg,
                    "request": request["request"] if request else None,
                },
            )
