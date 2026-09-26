import logging

import pytest

logger = logging.getLogger("policy-test")


@pytest.fixture
def log_decision():
    """打印请求输入与判定依据，便于从单测日志追溯结论。"""

    def _log(request, decision):
        logger.info(
            "请求输入 subject=%s action=%s resource=%s context=%s | "
            "判定 outcome=%s version=%s reason=%s matched=%s",
            request.subject, request.action, request.resource, request.context,
            decision.outcome.value, decision.policy_version, decision.reason,
            [(m.rule_id, m.effect.value, m.priority) for m in decision.matched_rules],
        )
        return decision

    return _log
