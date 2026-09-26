"""畸形策略：三类拒绝原因必须可区分。"""
from __future__ import annotations

import pytest

from app.models import PolicyRejectError, RejectReason
from app.parser import parse_bundle
from app.validator import validate_bundle


def test_malformed_json_and_yaml_rejected_as_syntax():
    with pytest.raises(PolicyRejectError) as exc:
        parse_bundle("{not json, also: not: yaml: [")
    assert exc.value.reason is RejectReason.SYNTAX_ERROR
    assert exc.value.details  # 附带解析器原始错误


@pytest.mark.parametrize(
    "raw",
    [
        '{"version":"v","rules":[{"id":"r1","effect":"maybe","priority":1,'
        '"subjects":["*"],"actions":["*"],"resources":["*"]}]}',
        '{"version":"v","rules":[{"id":"r1","effect":"allow","priority":"high",'
        '"subjects":["*"],"actions":["*"],"resources":["*"]}]}',
        '{"version":"v","rules":[{"id":"r1","effect":"allow","priority":1,'
        '"subjects":[],"actions":["*"],"resources":["*"]}]}',
        '{"rules":[]}',
    ],
)
def test_bad_field_types_rejected_as_syntax(raw):
    with pytest.raises(PolicyRejectError) as exc:
        parse_bundle(raw)
    assert exc.value.reason is RejectReason.SYNTAX_ERROR


def test_duplicate_rule_id_is_semantic():
    bundle = parse_bundle(
        '{"version":"v","rules":['
        '{"id":"r1","effect":"allow","priority":1,"subjects":["*"],"actions":["a"],"resources":["*"]},'
        '{"id":"r1","effect":"allow","priority":2,"subjects":["*"],"actions":["b"],"resources":["*"]}]}'
    )
    with pytest.raises(PolicyRejectError) as exc:
        validate_bundle(bundle)
    assert exc.value.reason is RejectReason.SEMANTIC_ERROR
    assert any("规则 id 重复" in d for d in exc.value.details)


def test_subject_inheritance_cycle_is_semantic():
    bundle = parse_bundle(
        '{"version":"v","subjects":{'
        '"a":{"inherits":["b"]},"b":{"inherits":["c"]},"c":{"inherits":["a"]}}}'
    )
    with pytest.raises(PolicyRejectError) as exc:
        validate_bundle(bundle)
    assert exc.value.reason is RejectReason.SEMANTIC_ERROR
    assert any("继承链存在环" in d for d in exc.value.details)


def test_unknown_inheritance_and_rule_refs_collected_together():
    bundle = parse_bundle(
        '{"version":"v","subjects":{"a":{"inherits":["ghost"]}},'
        '"rules":[{"id":"r1","effect":"allow","priority":1,'
        '"subjects":["nope"],"actions":["read"],"resources":["missing"]}]}'
    )
    with pytest.raises(PolicyRejectError) as exc:
        validate_bundle(bundle)
    details = exc.value.details
    assert any("继承了未定义" in d for d in details)
    assert any("未定义的主体" in d for d in details)
    assert any("未定义的资源" in d for d in details)


def test_contradictory_rules_same_scope_priority_rejected():
    bundle = parse_bundle(
        '{"version":"v","subjects":{"a":{}},"resources":{"d":{}},"rules":['
        '{"id":"r-allow","effect":"allow","priority":5,"subjects":["a"],"actions":["x"],"resources":["d"]},'
        '{"id":"r-deny","effect":"deny","priority":5,"subjects":["a"],"actions":["x"],"resources":["d"]}]}'
    )
    with pytest.raises(PolicyRejectError) as exc:
        validate_bundle(bundle)
    assert any("规则矛盾" in d for d in exc.value.details)
