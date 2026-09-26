"""测试公共夹具与日志：单测日志中打印请求输入与判定依据。"""
from __future__ import annotations

import logging
import sys

import pytest

from app.models import DecisionRequest, DecisionResult

# 确保判定日志输出到 stdout（pytest -s 可见）
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
decision_log = logging.getLogger("pdp.test.decisions")
decision_log.setLevel(logging.INFO)
if not any(isinstance(h, logging.StreamHandler) for h in decision_log.handlers):
    decision_log.addHandler(_handler)
decision_log.propagate = True


def log_decision(request: DecisionRequest, result: DecisionResult) -> None:
    """打印请求输入、命中规则、裁决规则与完整判定依据。"""
    decision_log.info(
        "请求输入: subject=%r action=%r resource=%r | 生效版本=%s",
        request.subject, request.action, request.resource, result.version,
    )
    decision_log.info(
        "判定结论: %s | 裁决规则=%s | 命中规则=%s",
        result.decision,
        result.winning_rule,
        [f"{m.rule_id}({m.effect},p={m.priority})" for m in result.matched_rules],
    )
    decision_log.info("判定原因: %s", result.reason)
    for line in result.trace:
        decision_log.info("  trace: %s", line)


@pytest.fixture
def service_with_v1_v2(tmp_path):
    """带 v1/v2 两个有效版本的服务，v1 已生效。"""
    from app.service import PolicyDecisionService

    svc = PolicyDecisionService()
    v1 = tmp_path / "v1.json"
    v1.write_text(
        '{"version":"v1",'
        '"subjects":{'
        '"alice":{"inherits":["eng"],"attributes":{"team":"payments"}},'
        '"bob":{"inherits":["contractors"]},'
        '"eng":{"attributes":{"type":"employee"}},'
        '"contractors":{"attributes":{"type":"external"}}},'
        '"resources":{'
        '"doc1":{"inherits":["docs"]},"docs":{"attributes":{"classification":"internal"}}},'
        '"rules":['
        '{"id":"allow-eng-read","effect":"allow","priority":10,'
        '"subjects":["eng"],"actions":["read"],"resources":["docs"],'
        '"conditions":[{"key":"resource.classification","op":"eq","value":"internal"}]},'
        '{"id":"deny-contractors","effect":"deny","priority":10,'
        '"subjects":["contractors"],"actions":["*"],"resources":["*"]}]}'
    )
    v2 = tmp_path / "v2.json"
    v2.write_text(
        '{"version":"v2",'
        '"subjects":{'
        '"alice":{"inherits":["eng"],"attributes":{"team":"payments"}},'
        '"bob":{"inherits":["contractors"]},'
        '"eng":{"attributes":{"type":"employee"}},'
        '"contractors":{"attributes":{"type":"external"}}},'
        '"resources":{'
        '"doc1":{"inherits":["docs"]},"docs":{"attributes":{"classification":"internal"}}},'
        '"rules":['
        '{"id":"allow-eng-read","effect":"allow","priority":10,'
        '"subjects":["eng"],"actions":["read"],"resources":["docs"],'
        '"conditions":[{"key":"resource.classification","op":"eq","value":"internal"}]},'
        '{"id":"allow-eng-write","effect":"allow","priority":20,'
        '"subjects":["eng"],"actions":["write"],"resources":["doc1"]},'
        '{"id":"deny-contractors","effect":"deny","priority":10,'
        '"subjects":["contractors"],"actions":["*"],"resources":["*"]}]}'
    )
    svc.load_version(v1.read_text())
    svc.load_version(v2.read_text())
    svc.activate("v1")
    return svc
