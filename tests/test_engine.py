"""继承求值、属性缺失与规则冲突：结论确定、可解释、可复现。"""
import logging

import pytest

from policy_service.engine import evaluate
from policy_service.loader import parse_policy_package
from policy_service.models import DecisionOutcome, DecisionRequest

logger = logging.getLogger("policy-test")

PKG = parse_policy_package(
    """{
      "version": "v1",
      "subjects": {"alice": ["employee"], "employee": ["user"]},
      "resources": {"doc-1": ["folder-a"], "folder-a": ["root"]},
      "rules": [
        {"id": "allow-employee-read", "effect": "allow", "priority": 10,
         "subjects": ["employee"], "actions": ["read"], "resources": ["folder-a"]},
        {"id": "deny-doc-1", "effect": "deny", "priority": 20,
         "resources": ["doc-1"]},
        {"id": "allow-prod-write", "effect": "allow", "priority": 30,
         "subjects": ["user"], "actions": ["write"],
         "condition": {"env": "prod"}}
      ]
    }"""
)


def test_inherited_subject_and_resource_allow(log_decision):
    req = DecisionRequest("alice", "read", "doc-1")
    d = log_decision(req, evaluate(PKG, req))
    # deny-doc-1 优先级更高，结论应为 deny，且两条命中规则都被记录
    assert d.outcome == DecisionOutcome.DENY
    assert [m.rule_id for m in d.matched_rules] == ["deny-doc-1", "allow-employee-read"]
    paths = {m.rule_id: m.subject_path for m in d.matched_rules}
    assert paths["allow-employee-read"] == ("alice", "employee")


def test_missing_attribute_never_defaults_to_allow(log_decision):
    req = DecisionRequest("alice", "write", "doc-1")  # 缺少 env 上下文
    d = log_decision(req, evaluate(PKG, req))
    assert d.outcome == DecisionOutcome.DENY
    assert "allow-prod-write" not in [m.rule_id for m in d.matched_rules]


def test_condition_satisfied_allows(log_decision):
    req = DecisionRequest("alice", "write", "doc-1", {"env": "prod"})
    d = log_decision(req, evaluate(PKG, req))
    assert d.outcome == DecisionOutcome.ALLOW
    assert d.matched_rules[0].rule_id == "allow-prod-write"


def test_no_match_defaults_to_deny_with_reason(log_decision):
    req = DecisionRequest("stranger", "read", "unknown-doc")
    d = log_decision(req, evaluate(PKG, req))
    assert d.outcome == DecisionOutcome.DENY
    assert "默认拒绝" in d.reason
    assert d.matched_rules == ()


def test_same_priority_deny_overrides_allow(log_decision):
    pkg = parse_policy_package(
        '{"version":"v2","rules":['
        '{"id":"a","effect":"allow","priority":5,"subjects":["s"]},'
        '{"id":"b","effect":"deny","priority":5,"actions":["x"]}]}'
    )
    req = DecisionRequest("s", "x", "r")
    d = log_decision(req, evaluate(pkg, req))
    assert d.outcome == DecisionOutcome.DENY
    assert [m.rule_id for m in d.matched_rules] == ["a", "b"]  # 稳定排序，不跳过
    assert "deny 优先" in d.reason


@pytest.mark.parametrize("i", range(50))
def test_repeated_evaluation_is_deterministic(i, log_decision):
    req = DecisionRequest("alice", "read", "doc-1")
    d = log_decision(req, evaluate(PKG, req))
    assert d == evaluate(PKG, req)
