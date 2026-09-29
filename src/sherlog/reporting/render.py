"""Render the report context to Markdown, HTML and (optionally) PDF."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import jinja2

log = logging.getLogger(__name__)

_MD_BADGES = {"rule": "**[RULE]**", "analyst": "**[ANALYST]**", "ai_proposed": "**[AI-PROPOSED]**"}


def _cell(value: Any) -> str:
    """Make a value safe inside a Markdown table cell."""
    if value is None:
        return ""
    return (
        str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    )


def _code(value: Any) -> str:
    """Make a value safe inside inline Markdown code (no backticks)."""
    return "" if value is None else str(value).replace("`", "'")


def _bytes(n: Any) -> str:
    size = float(n or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"  # pragma: no cover


def _tojson_compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _env(autoescape: bool) -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("sherlog.reporting", "templates"),
        autoescape=autoescape,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined,
    )
    env.filters["cell"] = _cell
    env.filters["code"] = _code
    env.filters["bytes"] = _bytes
    env.filters["badge"] = lambda v: _MD_BADGES.get(str(v), str(v))
    env.filters["tojson_compact"] = _tojson_compact
    return env


def render_markdown(context: dict[str, Any]) -> str:
    return _env(autoescape=False).get_template("report.md.j2").render(**context)


def render_html(context: dict[str, Any]) -> str:
    return _env(autoescape=True).get_template("report.html.j2").render(**context)


def pdf_available() -> bool:
    try:
        import weasyprint  # type: ignore[import-not-found,unused-ignore]  # noqa: F401
    except Exception:  # ImportError, or OSError when Pango is missing
        return False
    return True


def render_pdf(html: str, target: Path) -> bool:
    """Write a PDF from the HTML report; returns False if WeasyPrint is unavailable."""
    try:
        import weasyprint  # type: ignore[import-not-found,unused-ignore]
    except Exception as exc:
        log.info("PDF skipped: WeasyPrint unavailable (%s)", exc)
        return False
    weasyprint.HTML(string=html).write_pdf(str(target))
    return True
