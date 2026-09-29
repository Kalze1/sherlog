"""MITRE ATT&CK lookups over the bundled, curated Linux technique list."""

from __future__ import annotations

import functools
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TAG_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"

    @property
    def parent_id(self) -> str:
        return self.id.split(".", 1)[0]


@dataclass(frozen=True)
class AttackBundle:
    techniques: dict[str, Technique]
    tactics: dict[str, str]  # sigma-style key -> display name
    source: str
    note: str

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id.upper())

    def tactic_name(self, key: str) -> str:
        return self.tactics.get(key, key.replace("_", " ").title())

    def coverage(self, technique_ids: Iterable[str]) -> dict[str, list[Technique]]:
        """Techniques grouped by tactic, in canonical tactic order (for the report matrix)."""
        seen: dict[str, Technique] = {}
        for tid in technique_ids:
            if t := self.get(tid):
                seen[t.id] = t
        out: dict[str, list[Technique]] = {key: [] for key in self.tactics}
        for t in sorted(seen.values(), key=lambda t: t.id):
            for tactic in t.tactics:
                out.setdefault(tactic, []).append(t)
        return {k: v for k, v in out.items() if v}


@functools.lru_cache(maxsize=1)
def load_bundle() -> AttackBundle:
    """Load the bundled ATT&CK data (cached)."""
    data = json.loads(
        resources.files("sherlog.data").joinpath("attack_linux.json").read_text(encoding="utf-8")
    )
    techniques = {
        t["id"]: Technique(t["id"], t["name"], tuple(t["tactics"])) for t in data["techniques"]
    }
    return AttackBundle(techniques, dict(data["tactics"]), data["source"], data["note"])


def techniques_from_tags(tags: Iterable[str]) -> list[str]:
    """``attack.t1110.001`` -> ``T1110.001``; other tags are ignored."""
    out = []
    for tag in tags:
        if m := TAG_TECHNIQUE_RE.match(tag):
            out.append(m[1].upper())
    return out


def tactics_from_tags(tags: Iterable[str]) -> list[str]:
    """``attack.credential_access`` -> ``credential_access`` (only known tactics)."""
    known = load_bundle().tactics
    return [t[7:] for t in tags if t.startswith("attack.") and t[7:] in known]
