"""求值器：继承求值、冲突确定性、属性缺失 fail-closed、重复求值一致。"""
from __future__ import annotations

from app.matcher import Matcher
from app.models import DecisionRequest
from app.parser import parse_bundle
from app.validator import validate_bundle

from .conftest import log_decision


def make_matcher(bundle_json: str) -> Matcher:
    bundle = parse_bundle(bundle_json)
    validate_bundle(bundle)
    return Matcher(bundle)


def evaluate_and_log(matcher: Matcher, request: DecisionRequest):
    result = matcher.evaluate(request)
    log_decision(request, result)
    return result


def test_inheritance_chain_matches_parent_rule():
    m = make_matcher(
        '{"version":"v","subjects":{'
        '"alice":{"inherits":["dev"]},"dev":{"inherits":["eng"]},"eng":{}},'
        '"resources":{"doc1":{"inherits":["docs"]},"docs":{}},'
        '"rules":[{"id":"eng-read-docs","effect":"allow","priority":1,'
        '"subjects":["eng"],"actions":["read"],"resources":["docs"]}]}'
    )
    r = evaluate_and_log(m, DecisionRequest("alice", "read", "doc1"))
    assert r.decision == "allow"
    assert r.winning_rule == "eng-read-docs"
    assert "alice" in r.trace[1] and "eng" in r.trace[1]


def test_missing_attribute_is_fail_closed():
    m = make_matcher(
        '{"version":"v","subjects":{"alice":{}},"resources":{"doc1":{}},'
        '"rules":[{"id":"need-team","effect":"allow","priority":1,'
        '"subjects":["alice"],"actions":["read"],"resources":["doc1"],'
        '"conditions":[{"key":"subject.team","op":"eq","value":"payments"}]}]}'
    )
    r = evaluate_and_log(m, DecisionRequest("alice", "read", "doc1"))
    assert r.decision == "deny"
    assert "属性缺失" in r.reason
    assert "subject.team" in r.reason


def test_unknown_subject_and_resource_denied():
    m = make_matcher('{"version":"v","subjects":{"alice":{}},"resources":{"d":{}}}')
    r1 = evaluate_and_log(m, DecisionRequest("mallory", "read", "d"))
    r2 = evaluate_and_log(m, DecisionRequest("alice", "read", "ghost"))
    assert r1.decision == "deny" and "未在策略包" in r1.reason
    assert r2.decision == "deny" and "未在策略包" in r2.reason


def test_no_rule_matched_defaults_to_deny():
    m = make_matcher(
        '{"version":"v","subjects":{"alice":{}},"resources":{"d":{}},'
        '"rules":[{"id":"r1","effect":"allow","priority":1,'
        '"subjects":["alice"],"actions":["read"],"resources":["d"]}]}'
    )
    r = evaluate_and_log(m, DecisionRequest("alice", "delete", "d"))
    assert r.decision == "deny"
    assert "默认拒绝" in r.reason


def test_conflict_same_priority_deny_wins_and_all_matched_reported():
    m = make_matcher(
        '{"version":"v","subjects":{"alice":{}},"resources":{"d":{}},'
        '"rules":['
        '{"id":"z-allow","effect":"allow","priority":10,"subjects":["alice"],"actions":["read"],"resources":["d"]},'
        '{"id":"a-deny","effect":"deny","priority":10,"subjects":["*"],"actions":["read"],"resources":["d"]}]}'
    )
    r = evaluate_and_log(m, DecisionRequest("alice", "read", "d"))
    assert r.decision == "deny"
    assert r.winning_rule == "a-deny"
    # 被命中的规则全部记录，不静默跳过
    assert {m.rule_id for m in r.matched_rules} == {"z-allow", "a-deny"}


def test_conflict_same_priority_same_effect_tiebreak_by_rule_id():
    m = make_matcher(
        '{"version":"v","subjects":{"alice":{}},"resources":{"d":{}},'
        '"rules":['
        '{"id":"r-b","effect":"allow","priority":10,"subjects":["alice"],"actions":["read"],"resources":["d"]},'
        '{"id":"r-a","effect":"allow","priority":10,"subjects":["*"],"actions":["read"],"resources":["d"]}]}'
    )
    r = evaluate_and_log(m, DecisionRequest("alice", "read", "d"))
    assert r.decision == "allow"
    assert r.winning_rule == "r-a"  # 字典序确定性裁决


def test_higher_priority_beats_deny_preference():
    m = make_matcher(
        '{"version":"v","subjects":{"alice":{}},"resources":{"d":{}},'
        '"rules":['
        '{"id":"low-deny","effect":"deny","priority":1,"subjects":["alice"],"actions":["read"],"resources":["d"]},'
        '{"id":"high-allow","effect":"allow","priority":99,"subjects":["alice"],"actions":["read"],"resources":["d"]}]}'
    )
    r = evaluate_and_log(m, DecisionRequest("alice", "read", "d"))
    assert r.decision == "allow"
    assert r.winning_rule == "high-allow"


def test_repeated_evaluation_is_identical():
    m = make_matcher(
        '{"version":"v","subjects":{"alice":{"inherits":["eng"]},"eng":{}},'
        '"resources":{"d":{"inherits":["docs"]},"docs":{}},'
        '"rules":['
        '{"id":"r1","effect":"allow","priority":10,"subjects":["eng"],"actions":["read"],"resources":["docs"]},'
        '{"id":"r2","effect":"deny","priority":10,"subjects":["*"],"actions":["read"],"resources":["d"]}]}'
    )
    request = DecisionRequest("alice", "read", "d")
    results = [m.evaluate(request) for _ in range(50)]
    log_decision(request, results[0])
    assert all(r == results[0] for r in results)
    assert results[0].decision == "deny"


def test_inherited_attributes_merge_child_overrides_parent():
    m = make_matcher(
        '{"version":"v",'
        '"subjects":{"alice":{"inherits":["eng"],"attributes":{"level":"senior"}},'
        '"eng":{"attributes":{"level":"junior","type":"employee"}}},'
        '"resources":{"d":{}},'
        '"rules":[{"id":"senior-only","effect":"allow","priority":1,'
        '"subjects":["alice"],"actions":["read"],"resources":["d"],'
        '"conditions":[{"key":"subject.level","op":"eq","value":"senior"}]}]}'
    )
    r = evaluate_and_log(m, DecisionRequest("alice", "read", "d"))
    assert r.decision == "allow"  # 子节点属性覆盖父节点
