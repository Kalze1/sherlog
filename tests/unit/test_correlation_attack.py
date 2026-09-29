"""Tests for the correlation runtime and the ATT&CK bundle."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sherlog.core.vocab import Severity
from sherlog.detection.attack import (
    load_bundle,
    tactics_from_tags,
    techniques_from_tags,
)
from sherlog.detection.correlation import Match, run_correlation
from sherlog.detection.sigma import Correlation, Rule


def _match(rule_key: str, second: int, **fields: object) -> Match:
    ts = datetime(2024, 5, 1, 10, 0, 0, tzinfo=UTC) + timedelta(seconds=second)
    return Match(rule_key, ts, (second,), {"src_ip": "203.0.113.9", **fields})


def _rule(corr: Correlation) -> Rule:
    return Rule(
        id="00000000-0000-0000-0000-000000000000",
        title="c",
        name=None,
        description="",
        level=Severity.HIGH,
        tags=(),
        techniques=(),
        tactics=(),
        recommendation="r",
        confidence=0.8,
        group_by=("src_ip",),
        cluster_gap=timedelta(hours=1),
        falsepositives=(),
        references=(),
        status="stable",
        author="",
        logsource={},
        path=None,
        sha256="",
        correlation=corr,
    )


# --- ATT&CK bundle ----------------------------------------------------------------------------


def test_attack_lookup_and_url() -> None:
    b = load_bundle()
    t = b.get("t1110.001")  # case-insensitive
    assert t and t.name == "Brute Force: Password Guessing"
    assert t.url == "https://attack.mitre.org/techniques/T1110/001/"
    assert b.get("T1110").url == "https://attack.mitre.org/techniques/T1110/"
    assert b.get("T9999") is None


def test_tags_helpers() -> None:
    tags = ["attack.credential_access", "attack.t1110.001", "misc", "attack.t1078"]
    assert techniques_from_tags(tags) == ["T1110.001", "T1078"]
    assert tactics_from_tags(tags) == ["credential_access"]


def test_coverage_grouped_by_tactic() -> None:
    cov = load_bundle().coverage(["T1110.001", "T1078", "T9999"])
    assert "credential_access" in cov
    assert any(t.id == "T1078" for ts in cov.values() for t in ts)


# --- event_count ------------------------------------------------------------------------------


def test_event_count_threshold_and_window() -> None:
    corr = Correlation("event_count", ("base",), ("src_ip",), timedelta(minutes=5), {"gte": 10})
    rule = _rule(corr)
    # 10 distinct failures within 5 minutes -> one match.
    matches = {
        "base": [
            _match("base", s, actor=f"u{s}", event_type="auth.login.failure")
            for s in range(0, 300, 30)
        ]
    }
    assert len(matches["base"]) == 10
    out = run_correlation(rule, matches)
    assert len(out) == 1 and out[0].fields["count"] == 10

    # Nine distinct -> below threshold.
    matches["base"] = matches["base"][:9]
    assert run_correlation(rule, matches) == []


def test_event_count_deduplicates_same_occurrence() -> None:
    corr = Correlation("event_count", ("base",), ("src_ip",), timedelta(minutes=5), {"gte": 10})
    # Same failure recorded twice (auth.log + journal): 10 rows but 5 distinct occurrences.
    rows = []
    for s in range(0, 150, 30):
        rows.append(_match("base", s, actor="root", event_type="auth.login.failure"))
        rows.append(Match("base", rows[-1].timestamp, (1000 + s,), dict(rows[-1].fields)))
    out = run_correlation(_rule(corr), {"base": rows})
    assert out == []  # 5 distinct < 10


def test_value_count() -> None:
    corr = Correlation(
        "value_count", ("base",), ("src_ip",), timedelta(minutes=30), {"gte": 5}, field="actor"
    )
    rows = [
        _match("base", s * 60, actor=f"user{s}", event_type="auth.login.failure") for s in range(5)
    ]
    out = run_correlation(_rule(corr), {"base": rows})
    assert len(out) == 1
    assert sorted(out[0].fields["distinct_actor"]) == [f"user{s}" for s in range(5)]


# --- temporal ---------------------------------------------------------------------------------


def test_temporal_ordered_requires_order() -> None:
    corr = Correlation(
        "temporal_ordered", ("fail", "success"), ("src_ip",), timedelta(minutes=10), {"gte": 1}
    )
    rule = _rule(corr)
    fail = _match("fail", 0, event_type="auth.login.failure")
    success = _match("success", 60, event_type="auth.login.success")
    assert len(run_correlation(rule, {"fail": [fail], "success": [success]})) == 1
    # Success before failure -> no match.
    early_success = _match("success", 0, event_type="auth.login.success")
    late_fail = _match("fail", 60, event_type="auth.login.failure")
    assert run_correlation(rule, {"fail": [late_fail], "success": [early_success]}) == []


def test_temporal_needs_all_rules_in_window() -> None:
    corr = Correlation("temporal", ("a", "b"), ("src_ip",), timedelta(minutes=5), {"gte": 1})
    only_a = {"a": [_match("a", 0)], "b": []}
    assert run_correlation(_rule(corr), only_a) == []


def test_group_by_missing_field_skipped() -> None:
    corr = Correlation("event_count", ("base",), ("src_ip",), timedelta(minutes=5), {"gte": 2})
    rows = [Match("base", datetime(2024, 5, 1, tzinfo=UTC), (1,), {})]  # no src_ip
    assert run_correlation(_rule(corr), {"base": rows}) == []
