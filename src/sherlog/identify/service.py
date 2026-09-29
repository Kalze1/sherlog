"""Identify the artifact type of every evidence file by content.

Each registered parser scores a content sample; the best score wins if it
reaches :data:`THRESHOLD`. Files below it are recorded as ``unclassified`` with
a preview so nothing is silently dropped. Analysts can override the type per
file with glob patterns on the evidence-relative path.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select

from sherlog.core import audit
from sherlog.core.case import CaseHandle
from sherlog.core.errors import SherlogError
from sherlog.core.models import Artifact, EvidenceFile
from sherlog.core.vocab import FileKind
from sherlog.identify.sample import preview, read_sample
from sherlog.parsers.base import Parser, Sample
from sherlog.parsers.registry import all_parsers, artifact_types, by_artifact_type

log = logging.getLogger(__name__)

THRESHOLD = 0.5
UNCLASSIFIED = "unclassified"
EMPTY = "empty"


@dataclass(frozen=True)
class Identification:
    """Result of scoring one sample against every parser."""

    artifact_type: str
    parser: Parser | None
    confidence: float
    candidates: dict[str, float]


def identify_sample(sample: Sample) -> Identification:
    """Score ``sample`` with every parser and pick the best one above the threshold."""
    scores: dict[str, tuple[float, Parser]] = {}
    for parser in all_parsers():
        try:
            score = max(0.0, min(1.0, parser.can_parse(sample)))
        except Exception:  # a buggy scorer must not break identification
            log.exception("parser %s failed while scoring", parser.name)
            continue
        if score > 0:
            scores[parser.artifact_type] = (score, parser)
    candidates = {k: v[0] for k, v in sorted(scores.items(), key=lambda kv: -kv[1][0])}
    if not scores:
        return Identification(UNCLASSIFIED, None, 0.0, {})
    best_type, (best_score, best_parser) = max(scores.items(), key=lambda kv: (kv[1][0], kv[0]))
    if best_score < THRESHOLD:
        return Identification(UNCLASSIFIED, None, best_score, candidates)
    return Identification(best_type, best_parser, best_score, candidates)


def parse_overrides(specs: list[str]) -> list[tuple[str, str]]:
    """Parse ``GLOB=TYPE`` strings, validating the artifact type."""
    known = artifact_types()
    out = []
    for spec in specs:
        pattern, sep, atype = spec.rpartition("=")
        if not sep or not pattern or not atype:
            raise SherlogError(
                f"Invalid --type {spec!r}; expected GLOB=TYPE, e.g. '*secure*=linux.auth'"
            )
        if atype not in known:
            raise SherlogError(f"Unknown artifact type {atype!r}; known types: {', '.join(known)}")
        out.append((pattern, atype))
    return out


def _override_for(rel_path: str, overrides: list[tuple[str, str]]) -> str | None:
    for pattern, atype in reversed(overrides):  # last match wins
        if fnmatch.fnmatch(rel_path, pattern):
            return atype
    return None


def _identify_file(f: EvidenceFile, overrides: list[tuple[str, str]]) -> dict[str, Any]:
    logical_size = f.content_size if f.compression else f.size
    if logical_size == 0:
        return {"artifact_type": EMPTY, "status": "empty", "confidence": 1.0}
    try:
        sample = read_sample(Path(f.path), logical_size)
    except (OSError, EOFError, ValueError) as exc:
        return {
            "artifact_type": UNCLASSIFIED,
            "status": "error",
            "confidence": 0.0,
            "message": f"cannot read sample: {exc}",
        }
    ident = identify_sample(sample)
    result: dict[str, Any] = {
        "artifact_type": ident.artifact_type,
        "confidence": ident.confidence,
        "candidates": ident.candidates,
        "parser": ident.parser,
        "status": "identified" if ident.parser else "unclassified",
    }
    if forced := _override_for(f.rel_path, overrides):
        result.update(
            artifact_type=forced,
            parser=by_artifact_type(forced),
            status="identified",
            overridden=True,
        )
    if result["status"] == "unclassified":
        result["preview"] = preview(sample)
    return result


def identify_case(
    handle: CaseHandle, overrides: list[tuple[str, str]] | None = None
) -> list[dict[str, Any]]:
    """(Re)identify every regular evidence file in the case and store the results."""
    overrides = overrides or []
    summary: list[dict[str, Any]] = []
    with handle.session() as s:
        files = s.scalars(
            select(EvidenceFile).where(EvidenceFile.kind == FileKind.FILE).order_by(EvidenceFile.id)
        ).all()
        existing = {a.file_id: a for a in s.scalars(select(Artifact))}
        for f in files:
            r = _identify_file(f, overrides)
            parser: Parser | None = r.get("parser")
            art = existing.get(f.id) or Artifact(file_id=f.id)
            art.artifact_type = r["artifact_type"]
            art.parser = parser.name if parser else None
            art.parser_version = parser.version if parser else None
            art.confidence = r["confidence"]
            art.overridden = r.get("overridden", False)
            art.candidates = r.get("candidates", {})
            art.status = r["status"]
            art.preview = r.get("preview")
            art.message = r.get("message")
            art.event_count = art.parse_error_count = 0
            s.add(art)
            summary.append(artifact_to_dict(art, f))
        audit.record(
            s,
            "evidence.identify",
            overrides=[f"{p}={t}" for p, t in overrides],
            results={d["rel_path"]: d["artifact_type"] for d in summary},
        )
    return summary


def artifact_to_dict(art: Artifact, f: EvidenceFile) -> dict[str, Any]:
    """Serialize an artifact row with its file identity."""
    return {
        "file_id": f.id,
        "item_id": f.item_id,
        "path": f.path,
        "rel_path": f.rel_path,
        "sha256": f.sha256,
        "artifact_type": art.artifact_type,
        "parser": art.parser,
        "parser_version": art.parser_version,
        "confidence": art.confidence,
        "overridden": art.overridden,
        "candidates": art.candidates,
        "status": art.status,
        "event_count": art.event_count,
        "parse_error_count": art.parse_error_count,
        "preview": art.preview,
        "message": art.message,
    }


def list_artifacts(handle: CaseHandle) -> list[dict[str, Any]]:
    """Stored identification results for every file."""
    with handle.session() as s:
        rows = s.execute(
            select(Artifact, EvidenceFile)
            .join(EvidenceFile, Artifact.file_id == EvidenceFile.id)
            .order_by(EvidenceFile.id)
        ).all()
        return [artifact_to_dict(a, f) for a, f in rows]
