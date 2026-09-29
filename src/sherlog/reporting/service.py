"""Generate a report and its exports into an output directory."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from sherlog.core import audit
from sherlog.core.case import CaseHandle
from sherlog.core.errors import SherlogError
from sherlog.reporting.context import build_context
from sherlog.reporting.exports import findings_document, iter_events_jsonl, stix_bundle, write_json
from sherlog.reporting.render import render_html, render_markdown, render_pdf

log = logging.getLogger(__name__)

FORMATS = ("md", "html", "pdf", "json", "stix", "events")
DEFAULT_FORMATS = FORMATS


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def generate_report(
    handle: CaseHandle,
    out_dir: Path | None = None,
    *,
    formats: tuple[str, ...] = DEFAULT_FORMATS,
    verify: bool = True,
    include_rejected: bool = False,
) -> dict[str, Any]:
    """Build the report context once and write every requested output format.

    Returns the output directory, written files with SHA-256, skipped formats and
    the verification outcome. Writes ``SHA256SUMS`` alongside the outputs.
    """
    unknown = set(formats) - set(FORMATS)
    if unknown:
        raise SherlogError(f"Unknown report format(s): {', '.join(sorted(unknown))}")
    out = (out_dir or handle.directory / "report").expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    context = build_context(handle, verify=verify, include_rejected=include_rejected)
    written: dict[str, Path] = {}
    skipped: dict[str, str] = {}

    html: str | None = None
    if "md" in formats:
        written["md"] = out / "report.md"
        written["md"].write_text(render_markdown(context), encoding="utf-8")
    if "html" in formats or "pdf" in formats:
        html = render_html(context)
    if "html" in formats and html is not None:
        written["html"] = out / "report.html"
        written["html"].write_text(html, encoding="utf-8")
    if "pdf" in formats and html is not None:
        target = out / "report.pdf"
        if render_pdf(html, target):
            written["pdf"] = target
        else:
            skipped["pdf"] = "WeasyPrint is not installed (pip install 'sherlog[pdf]')"
    if "json" in formats:
        written["json"] = out / "findings.json"
        write_json(
            written["json"], findings_document(handle, context, include_rejected=include_rejected)
        )
    if "events" in formats:
        written["events"] = out / "events.jsonl"
        with written["events"].open("w", encoding="utf-8") as fh:
            for line in iter_events_jsonl(handle):
                fh.write(line + "\n")
    if "stix" in formats:
        written["stix"] = out / "iocs.stix.json"
        written["stix"].write_text(
            stix_bundle(handle, context).serialize(pretty=True) + "\n", encoding="utf-8"
        )

    hashes = {name: _sha256(path) for name, path in written.items()}
    sums = "".join(
        f"{hashes[n]}  {written[n].name}\n" for n in sorted(written, key=lambda n: written[n].name)
    )
    (out / "SHA256SUMS").write_text(sums, encoding="utf-8")

    with handle.session() as s:
        audit.record(
            s,
            "report.generate",
            out_dir=str(out),
            files={written[n].name: hashes[n] for n in written},
            skipped=skipped,
            evidence_verified=None
            if context["verification"] is None
            else context["verification"]["ok"],
            findings=len(context["findings"]),
        )
    return {
        "out_dir": str(out),
        "files": {n: {"path": str(p), "sha256": hashes[n]} for n, p in written.items()},
        "skipped": skipped,
        "evidence_verified": None
        if context["verification"] is None
        else context["verification"]["ok"],
        "findings": len(context["findings"]),
        "severity_counts": context["severity_counts"],
    }
