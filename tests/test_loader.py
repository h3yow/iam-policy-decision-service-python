"""畸形策略与继承冲突：失败原因必须可区分。"""
import logging

import pytest

from policy_service.errors import (
    PolicySemanticError,
    PolicySyntaxError,
)
from policy_service.loader import parse_policy_package

logger = logging.getLogger("policy-test")


def test_valid_package_loads():
    pkg = parse_policy_package(
        '{"version":"v1","subjects":{"a":["b"]},'
        '"rules":[{"id":"r","effect":"allow","priority":1}]}'
    )
    assert pkg.version == "v1"
    assert pkg.rules[0].rule_id == "r"


@pytest.mark.parametrize(
    "raw",
    [
        "{not json",
        "[]",
        '{"version": 1}',
        '{"version": ""}',
        '{"version": "v1", "rules": [{"effect": "allow", "priority": 1}]}',
        '{"version": "v1", "rules": [{"id": "r", "effect": "maybe", "priority": 1}]}',
        '{"version": "v1", "rules": [{"id": "r", "effect": "allow", "priority": "high"}]}',
        '{"version": "v1", "subjects": {"a": "b"}}',
    ],
    ids=["bad-json", "not-object", "version-not-str", "version-empty",
         "rule-missing-id", "bad-effect", "priority-not-int", "hierarchy-not-list"],
)
def test_syntax_errors_are_distinguishable(raw):
    with pytest.raises(PolicySyntaxError) as exc_info:
        parse_policy_package(raw)
    logger.info("语法拒绝 raw=%r 原因=%s", raw, exc_info.value)


def test_subject_hierarchy_cycle_rejected():
    raw = '{"version":"v1","subjects":{"a":["b"],"b":["a"]}}'
    with pytest.raises(PolicySemanticError, match="继承环"):
        parse_policy_package(raw)


def test_resource_hierarchy_cycle_rejected():
    raw = '{"version":"v1","resources":{"x":["y"],"y":["z"],"z":["x"]}}'
    with pytest.raises(PolicySemanticError, match="继承环"):
        parse_policy_package(raw)


def test_duplicate_rule_id_rejected():
    raw = ('{"version":"v1","rules":['
           '{"id":"r","effect":"allow","priority":1},'
           '{"id":"r","effect":"deny","priority":2}]}')
    with pytest.raises(PolicySemanticError, match="规则 ID 重复"):
        parse_policy_package(raw)


def test_contradictory_rules_rejected():
    raw = ('{"version":"v1","rules":['
           '{"id":"a","effect":"allow","priority":5,"subjects":["s"]},'
           '{"id":"b","effect":"deny","priority":5,"subjects":["s"]}]}')
    with pytest.raises(PolicySemanticError, match="结论相反"):
        parse_policy_package(raw)
