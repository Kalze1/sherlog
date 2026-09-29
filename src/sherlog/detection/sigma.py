"""Sigma rule loading and matching (a small, self-contained subset of the Sigma spec).

Supported:

* ``detection`` with named selections (maps = AND of fields, list of maps = OR,
  list of strings = keyword search) and a ``condition`` using ``and``/``or``/
  ``not``, parentheses, ``1 of x*``/``all of x*`` and ``1 of them``/``all of them``.
* Field modifiers ``contains``, ``startswith``, ``endswith``, ``re`` (``re|i`` for
  case-insensitive), ``all``, ``gt``/``gte``/``lt``/``lte``, ``cidr`` and ``exists``.
  Plain values match case-insensitively with ``*``/``?`` wildcards; ``null``
  matches an absent field. Lists of values are OR-ed unless ``|all`` is given.
* Sigma v2 correlation rules (``event_count``, ``value_count``, ``temporal``,
  ``temporal_ordered``) referencing base rules by ``name``.

Fields are SherLog's normalized event fields (``event_type``, ``actor``,
``src_ip``, ``command``, ``tags`` ...) plus ``extra.<key>`` (or just ``<key>``)
for artifact-specific data and the derived ``hour_local``/``weekday_local``.
A ``tags`` (list) field matches when any element matches.

SherLog-specific settings live under ``x-sherlog``: ``recommendation`` (required),
``confidence`` (0-1), ``group_by`` and ``cluster_gap`` (how matches are grouped
into findings).
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import re
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from sherlog.core.errors import SherlogError
from sherlog.core.vocab import Severity
from sherlog.detection.attack import load_bundle, tactics_from_tags, techniques_from_tags

Record = dict[str, Any]
Predicate = Callable[[Record], bool]

LEVELS = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
CORRELATION_TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")
_TIMESPAN_RE = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class RuleError(SherlogError):
    """A rule file is malformed."""


# --- field access -----------------------------------------------------------------------------


def get_field(record: Record, name: str) -> Any:
    """Resolve a Sigma field name against a record (columns first, then ``extra``)."""
    if name in record:
        return record[name]
    extra = record.get("extra") or {}
    if name.startswith("extra."):
        return extra.get(name[6:])
    return extra.get(name)


# --- value matchers ---------------------------------------------------------------------------


def _wildcard_regex(value: str, mode: str) -> re.Pattern[str]:
    """Translate a Sigma wildcard string into a case-insensitive regex."""
    parts = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            parts.append(re.escape(value[i + 1]))
            i += 2
            continue
        parts.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    body = "".join(parts)
    if mode == "equals":
        pattern = f"^{body}$"
    elif mode == "startswith":
        pattern = f"^{body}"
    elif mode == "endswith":
        pattern = f"{body}$"
    else:  # contains
        pattern = body
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


def _to_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _to_number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _scalar_matcher(value: Any, modifiers: list[str]) -> Callable[[Any], bool]:
    """Build a matcher for one Sigma value under the given modifiers (``all`` excluded)."""
    mods = [m for m in modifiers if m != "all"]
    if "re" in mods:
        flags = re.IGNORECASE if "i" in mods else 0
        try:
            rx = re.compile(str(value), flags)
        except re.error as exc:
            raise RuleError(f"invalid regex {value!r}: {exc}") from exc
        return lambda v: (t := _to_text(v)) is not None and rx.search(t) is not None
    if "cidr" in mods:
        net = ipaddress.ip_network(str(value), strict=False)

        def in_net(v: Any) -> bool:
            try:
                return ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False

        return in_net
    for cmp in ("gt", "gte", "lt", "lte"):
        if cmp in mods:
            limit = _to_number(value)
            if limit is None:
                raise RuleError(f"numeric modifier {cmp} needs a number, got {value!r}")
            ops: dict[str, Callable[[float, float], bool]] = {
                "gt": lambda a, b: a > b,
                "gte": lambda a, b: a >= b,
                "lt": lambda a, b: a < b,
                "lte": lambda a, b: a <= b,
            }
            op = ops[cmp]
            return lambda v: (n := _to_number(v)) is not None and op(n, limit)
    if "exists" in mods:
        want = bool(value)
        return lambda v: (v is not None) == want
    if value is None:
        return lambda v: v is None
    if isinstance(value, bool):
        return lambda v: v is value or _to_text(v) == _to_text(value)
    if isinstance(value, int | float):
        num = float(value)
        return lambda v: (n := _to_number(v)) is not None and n == num
    mode = next((m for m in ("contains", "startswith", "endswith") if m in mods), "equals")
    rx_w = _wildcard_regex(str(value), mode)
    return lambda v: (t := _to_text(v)) is not None and rx_w.search(t) is not None


def _lift(matcher: Callable[[Any], bool]) -> Callable[[Any], bool]:
    """Apply a scalar matcher to list-valued fields (any element)."""

    def apply(v: Any) -> bool:
        if isinstance(v, list | tuple | set):
            return any(matcher(x) for x in v)
        return matcher(v)

    return apply


def compile_field(spec: str, value: Any) -> Predicate:
    """``field|mod1|mod2: value`` -> predicate over a record."""
    name, *modifiers = spec.split("|")
    unknown = set(modifiers) - {
        "contains", "startswith", "endswith", "re", "i", "all", "gt", "gte", "lt", "lte",
        "cidr", "exists", "fieldref",
    }  # fmt: skip
    if unknown:
        raise RuleError(f"unsupported modifier(s) {sorted(unknown)} on field {name!r}")
    if "fieldref" in modifiers:
        # Compare this field to another field named by the value (case-insensitive text).
        if not isinstance(value, str):
            raise RuleError(f"field {name!r}: fieldref needs a single field name")
        other = value

        def fieldref(r: Record) -> bool:
            a, b = _to_text(get_field(r, name)), _to_text(get_field(r, other))
            return a is not None and b is not None and a.casefold() == b.casefold()

        return fieldref
    values: list[Any] = value if isinstance(value, list) else [value]
    if not values:
        raise RuleError(f"field {name!r} has an empty value list")
    if "exists" in modifiers and (value is None or isinstance(value, list)):
        raise RuleError(f"field {name!r}: exists needs true/false")
    matchers = [_lift(_scalar_matcher(v, modifiers)) for v in values]
    if "all" in modifiers:
        return lambda r: all(m(get_field(r, name)) for m in matchers)
    return lambda r: any(m(get_field(r, name)) for m in matchers)


_KEYWORD_FIELDS = ("raw", "command", "target", "actor", "host")


def compile_selection(definition: Any) -> Predicate:
    """Compile one named selection."""
    if isinstance(definition, dict):
        if not definition:
            raise RuleError("empty selection")
        preds = [compile_field(k, v) for k, v in definition.items()]
        return lambda r: all(p(r) for p in preds)
    if isinstance(definition, list):
        if not definition:
            raise RuleError("empty selection list")
        if all(isinstance(d, dict) for d in definition):
            alts = [compile_selection(d) for d in definition]
            return lambda r: any(p(r) for p in alts)
        if all(isinstance(d, str | int | float) for d in definition):
            kws = [_wildcard_regex(str(d), "contains") for d in definition]

            def keywords(r: Record) -> bool:
                texts = [t for f in _KEYWORD_FIELDS if (t := _to_text(r.get(f)))]
                return any(rx.search(t) for rx in kws for t in texts)

            return keywords
        raise RuleError("selection list must be all maps or all keywords")
    raise RuleError(f"selection must be a map or list, got {type(definition).__name__}")


# --- condition grammar ------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[()]|[^()\s]+")


class _ConditionParser:
    """Recursive-descent parser for Sigma conditions (no aggregation pipe)."""

    def __init__(self, text: str, selections: dict[str, Predicate]) -> None:
        if "|" in text:
            raise RuleError(
                "aggregation conditions ('| count() ...') are not supported; "
                "use a correlation rule instead"
            )
        self.tokens = _TOKEN_RE.findall(text)
        self.pos = 0
        self.selections = selections

    def parse(self) -> Predicate:
        if not self.tokens:
            raise RuleError("empty condition")
        expr = self._or()
        if self.pos != len(self.tokens):
            raise RuleError(f"unexpected token {self.tokens[self.pos]!r} in condition")
        return expr

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            raise RuleError("unexpected end of condition")
        self.pos += 1
        return tok

    def _or(self) -> Predicate:
        left = self._and()
        while self._peek() == "or":
            self._next()
            right = self._and()
            left = (lambda a, b: lambda r: a(r) or b(r))(left, right)
        return left

    def _and(self) -> Predicate:
        left = self._not()
        while self._peek() == "and":
            self._next()
            right = self._not()
            left = (lambda a, b: lambda r: a(r) and b(r))(left, right)
        return left

    def _not(self) -> Predicate:
        if self._peek() == "not":
            self._next()
            inner = self._not()
            return lambda r: not inner(r)
        return self._atom()

    def _atom(self) -> Predicate:
        tok = self._next()
        if tok == "(":
            inner = self._or()
            if self._next() != ")":
                raise RuleError("missing ')' in condition")
            return inner
        if tok in ("1", "all") and self._peek() == "of":
            self._next()
            pattern = self._next()
            names = (
                list(self.selections)
                if pattern == "them"
                else [n for n in self.selections if fnmatch.fnmatchcase(n, pattern)]
            )
            if not names:
                raise RuleError(f"'{tok} of {pattern}' matches no selection")
            preds = [self.selections[n] for n in names]
            if tok == "all":
                return lambda r: all(p(r) for p in preds)
            return lambda r: any(p(r) for p in preds)
        if tok in self.selections:
            return self.selections[tok]
        raise RuleError(f"unknown selection {tok!r} in condition")


def compile_detection(detection: dict[str, Any]) -> Predicate:
    """Compile a Sigma ``detection`` block into a predicate."""
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleError("detection must be a map with a 'condition'")
    condition = detection["condition"]
    if isinstance(condition, list):  # Sigma allows a list = OR of conditions
        condition = " or ".join(f"({c})" for c in condition)
    selections = {k: compile_selection(v) for k, v in detection.items() if k != "condition"}
    if not selections:
        raise RuleError("detection has no selections")
    return _ConditionParser(str(condition), selections).parse()


# --- rules ------------------------------------------------------------------------------------


def parse_timespan(value: str) -> timedelta:
    m = _TIMESPAN_RE.match(str(value).strip())
    if not m:
        raise RuleError(f"invalid timespan {value!r}; use e.g. 10m, 1h, 2d")
    return timedelta(seconds=int(m[1]) * _UNITS[m[2]])


@dataclass(frozen=True)
class Correlation:
    type: str
    rules: tuple[str, ...]  # names of referenced rules
    group_by: tuple[str, ...]
    timespan: timedelta
    condition: dict[str, int]  # e.g. {"gte": 10}
    field: str | None = None  # value_count
    generate: bool = False


@dataclass
class Rule:
    """A loaded Sigma rule (base detection or correlation)."""

    id: str
    title: str
    name: str | None
    description: str
    level: Severity
    tags: tuple[str, ...]
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    recommendation: str
    confidence: float
    group_by: tuple[str, ...]
    cluster_gap: timedelta
    falsepositives: tuple[str, ...]
    references: tuple[str, ...]
    status: str
    author: str
    logsource: dict[str, str]
    path: Path | None
    sha256: str
    predicate: Predicate | None = None
    correlation: Correlation | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def is_correlation(self) -> bool:
        return self.correlation is not None

    @property
    def key(self) -> str:
        """Identifier other rules use to reference this one."""
        return self.name or self.id

    def matches(self, record: Record) -> bool:
        return self.predicate is not None and self.predicate(record)


def _require(doc: dict[str, Any], key: str, where: str) -> Any:
    if key not in doc or doc[key] in (None, ""):
        raise RuleError(f"{where}: missing required field {key!r}")
    return doc[key]


def _str_list(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def rule_from_dict(doc: dict[str, Any], path: Path | None = None, raw: bytes = b"") -> Rule:
    """Validate and compile one rule document."""
    where = str(path) if path else "<rule>"
    if not isinstance(doc, dict):
        raise RuleError(f"{where}: rule must be a map")
    title = str(_require(doc, "title", where))
    rid = str(_require(doc, "id", where))
    try:
        uuid.UUID(rid)
    except ValueError as exc:
        raise RuleError(f"{where}: id must be a UUID") from exc
    level_key = str(doc.get("level", "medium")).lower()
    if level_key not in LEVELS:
        raise RuleError(f"{where}: level must be one of {', '.join(LEVELS)}")
    tags = _str_list(doc.get("tags"))
    ext = doc.get("x-sherlog") or {}
    if not isinstance(ext, dict):
        raise RuleError(f"{where}: x-sherlog must be a map")
    recommendation = ext.get("recommendation")
    if not recommendation:
        raise RuleError(f"{where}: x-sherlog.recommendation is required")
    confidence = float(ext.get("confidence", 0.7))
    if not 0 <= confidence <= 1:
        raise RuleError(f"{where}: x-sherlog.confidence must be between 0 and 1")

    warnings = []
    bundle = load_bundle()
    techniques = techniques_from_tags(tags)
    for t in techniques:
        if bundle.get(t) is None:
            warnings.append(f"technique {t} not in bundled ATT&CK data")
    if not techniques:
        warnings.append("no attack.tXXXX tag")

    predicate = correlation = None
    if "correlation" in doc:
        c = doc["correlation"]
        if not isinstance(c, dict):
            raise RuleError(f"{where}: correlation must be a map")
        ctype = str(_require(c, "type", where))
        if ctype not in CORRELATION_TYPES:
            raise RuleError(f"{where}: correlation type must be one of {CORRELATION_TYPES}")
        rules = _str_list(_require(c, "rules", where))
        if ctype in ("temporal", "temporal_ordered") and len(rules) < 2:
            raise RuleError(f"{where}: temporal correlations need at least two rules")
        cond = c.get("condition") or {}
        if ctype in ("event_count", "value_count"):
            if not cond or not all(k in ("gt", "gte", "lt", "lte", "eq") for k in cond):
                raise RuleError(f"{where}: {ctype} needs a condition like {{gte: 10}}")
            cond = {k: int(v) for k, v in cond.items()}
        fld = c.get("field")
        if ctype == "value_count" and not fld:
            raise RuleError(f"{where}: value_count needs a field")
        correlation = Correlation(
            type=ctype,
            rules=rules,
            group_by=_str_list(c.get("group-by") or c.get("group_by")),
            timespan=parse_timespan(_require(c, "timespan", where)),
            condition=dict(cond),
            field=str(fld) if fld else None,
            generate=bool(c.get("generate", False)),
        )
    elif "detection" in doc:
        try:
            predicate = compile_detection(doc["detection"])
        except RuleError as exc:
            raise RuleError(f"{where}: {exc}") from exc
    else:
        raise RuleError(f"{where}: rule needs 'detection' or 'correlation'")

    logsource = {str(k): str(v) for k, v in (doc.get("logsource") or {}).items()}
    if predicate is not None and logsource.get("product", "linux") != "linux":
        warnings.append(f"logsource.product is {logsource.get('product')!r}, expected 'linux'")

    return Rule(
        id=rid,
        title=title,
        name=str(doc["name"]) if doc.get("name") else None,
        description=str(doc.get("description", "")).strip(),
        level=LEVELS[level_key],
        tags=tags,
        techniques=tuple(techniques),
        tactics=tuple(tactics_from_tags(tags)),
        recommendation=str(recommendation).strip(),
        confidence=confidence,
        group_by=_str_list(ext.get("group_by")) or ("src_ip", "actor"),
        cluster_gap=parse_timespan(ext.get("cluster_gap", "1h")),
        falsepositives=_str_list(doc.get("falsepositives")),
        references=_str_list(doc.get("references")),
        status=str(doc.get("status", "experimental")),
        author=str(doc.get("author", "")),
        logsource=logsource,
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        predicate=predicate,
        correlation=correlation,
        warnings=warnings,
    )


def load_rule_file(path: Path) -> list[Rule]:
    """Load every YAML document in a rule file."""
    raw = path.read_bytes()
    try:
        docs = [d for d in yaml.safe_load_all(raw) if d is not None]
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc
    return [rule_from_dict(d, path, raw) for d in docs]


def iter_rule_files(directory: Path) -> Iterator[Path]:
    yield from sorted(p for p in directory.rglob("*.y*ml") if p.is_file())


@dataclass
class RuleSet:
    """Loaded rules with correlation references resolved."""

    rules: list[Rule]
    by_key: dict[str, Rule]
    suppressed: frozenset[str]  # keys of rules consumed by a correlation with generate=false

    @property
    def base_rules(self) -> list[Rule]:
        return [r for r in self.rules if not r.is_correlation]

    @property
    def correlations(self) -> list[Rule]:
        """Correlation rules in dependency order (referenced correlations first)."""
        ordered: list[Rule] = []
        seen: set[str] = set()

        def visit(rule: Rule, stack: tuple[str, ...]) -> None:
            if rule.key in seen:
                return
            if rule.key in stack:
                raise RuleError(f"correlation cycle: {' -> '.join((*stack, rule.key))}")
            assert rule.correlation is not None
            for ref in rule.correlation.rules:
                dep = self.by_key[ref]
                if dep.is_correlation:
                    visit(dep, (*stack, rule.key))
            seen.add(rule.key)
            ordered.append(rule)

        for rule in self.rules:
            if rule.is_correlation:
                visit(rule, ())
        return ordered

    def get(self, key: str) -> Rule | None:
        return self.by_key.get(key)


def build_ruleset(rules: Sequence[Rule]) -> RuleSet:
    """Index rules, check uniqueness and resolve correlation references."""
    by_key: dict[str, Rule] = {}
    ids: set[str] = set()
    for rule in rules:
        if rule.id in ids:
            raise RuleError(f"duplicate rule id {rule.id} ({rule.path})")
        ids.add(rule.id)
        for key in {rule.id, rule.key}:
            if key in by_key and by_key[key] is not rule:
                raise RuleError(f"duplicate rule name/id {key!r} ({rule.path})")
            by_key[key] = rule
    suppressed: set[str] = set()
    for rule in rules:
        if rule.correlation is None:
            continue
        for ref in rule.correlation.rules:
            if ref not in by_key:
                raise RuleError(f"{rule.path}: correlation references unknown rule {ref!r}")
            if not rule.correlation.generate:
                suppressed.add(by_key[ref].key)
    ordered = sorted(rules, key=lambda r: (r.is_correlation, r.key))
    rs = RuleSet(ordered, by_key, frozenset(suppressed))
    _ = rs.correlations  # force resolution; raises on cycles
    return rs


def default_rules_dir() -> Path:
    """The rule directory shipped with SherLog (wheel) or in the source checkout."""
    from importlib import resources

    packaged = Path(str(resources.files("sherlog"))) / "rules"
    if packaged.is_dir():
        return packaged
    checkout = Path(__file__).resolve().parents[3] / "rules"
    if checkout.is_dir():
        return checkout
    raise SherlogError("bundled rules directory not found; pass --rules DIR")


def load_rules(directories: Sequence[Path] | None = None) -> RuleSet:
    """Load rules from the given directories (default: the bundled set)."""
    dirs = list(directories) if directories else [default_rules_dir()]
    rules: list[Rule] = []
    for directory in dirs:
        if not directory.is_dir():
            raise SherlogError(f"rules directory not found: {directory}")
        for path in iter_rule_files(directory):
            rules.extend(load_rule_file(path))
    if not rules:
        raise SherlogError(f"no rules found in {', '.join(map(str, dirs))}")
    return build_ruleset(rules)
