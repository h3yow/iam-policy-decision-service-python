"""并发请求下的策略切换与回滚：结论必须稳定且与所报版本一致。"""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.models import DecisionRequest, PolicyRejectError, RejectReason

from .conftest import log_decision

WRITE_REQ = DecisionRequest("alice", "write", "doc1")   # v1: deny(无规则), v2: allow
READ_REQ = DecisionRequest("alice", "read", "doc1")     # v1/v2 均 allow


def test_concurrent_evaluation_during_switch_and_rollback(service_with_v1_v2):
    svc = service_with_v1_v2
    errors: list[BaseException] = []
    violations: list[str] = []
    stop = threading.Event()

    def switcher():
        try:
            while not stop.is_set():
                svc.activate("v2")
                try:
                    svc.rollback()  # 回到 v1
                except RuntimeError as exc:
                    # 多个切换线程交错时，"无历史可回滚"是合法结果
                    assert "没有可回滚" in str(exc)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def evaluator():
        try:
            while not stop.is_set():
                r = svc.evaluate(WRITE_REQ)
                # 不变式：结论必须与其所报版本一致
                if r.version == "v1" and r.decision != "deny":
                    violations.append(f"v1 下 write 应为 deny，得到 {r.decision}")
                if r.version == "v2" and r.decision != "allow":
                    violations.append(f"v2 下 write 应为 allow，得到 {r.decision}")
                if r.version not in ("v1", "v2"):
                    violations.append(f"出现未知版本 {r.version}")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=switcher) for _ in range(2)]
    threads += [threading.Thread(target=evaluator) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads[2:]:
        t.join(timeout=0.5)  # 让求值线程跑一会儿
    import time
    time.sleep(0.5)
    stop.set()
    for t in threads:
        t.join(timeout=5)

    assert not errors, f"并发期间出现异常: {errors}"
    assert not violations, f"结论与版本不一致: {violations[:5]}"

    # 切换结束后，生效版本确定，结论确定
    final = svc.evaluate(WRITE_REQ)
    log_decision(WRITE_REQ, final)
    assert svc.active_version == "v1"
    assert final.decision == "deny"


def test_concurrent_evaluation_same_version_is_identical(service_with_v1_v2):
    svc = service_with_v1_v2
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: svc.evaluate(READ_REQ), range(200)))
    log_decision(READ_REQ, results[0])
    assert all(r == results[0] for r in results)
    assert results[0].decision == "allow"


def test_failed_loads_never_affect_active_decisions(service_with_v1_v2):
    svc = service_with_v1_v2
    bad_bundles = [
        "{broken json",                                                            # syntax
        json.dumps({"version": "v-bad-cycle", "subjects": {
            "a": {"inherits": ["b"]}, "b": {"inherits": ["a"]}}}),                 # semantic: 环
        json.dumps({"version": "v-bad-ref", "rules": [{
            "id": "r", "effect": "allow", "priority": 1,
            "subjects": ["ghost"], "actions": ["x"], "resources": ["y"]}]}),       # semantic: 引用
        json.dumps({"version": "v1", "rules": []}),                                # duplicate
    ]
    expected_reasons = [
        RejectReason.SYNTAX_ERROR, RejectReason.SEMANTIC_ERROR,
        RejectReason.SEMANTIC_ERROR, RejectReason.DUPLICATE_VERSION,
    ]
    seen_reasons: list[RejectReason] = []
    decisions: list[str] = []
    stop = threading.Event()

    def loader():
        while not stop.is_set():
            for text, expected in zip(bad_bundles, expected_reasons):
                try:
                    svc.load_version(text)
                except PolicyRejectError as exc:
                    assert exc.reason is expected
                    seen_reasons.append(exc.reason)

    def evaluator():
        while not stop.is_set():
            decisions.append(svc.evaluate(READ_REQ).decision)

    threads = [threading.Thread(target=loader) for _ in range(2)]
    threads += [threading.Thread(target=evaluator) for _ in range(4)]
    for t in threads:
        t.start()
    import time
    time.sleep(0.5)
    stop.set()
    for t in threads:
        t.join(timeout=5)

    # 失败原因可区分，且生效版本的判定全程不受影响
    assert set(seen_reasons) == set(expected_reasons)
    assert decisions and all(d == "allow" for d in decisions)
    assert svc.active_version == "v1"


def test_rollback_restores_previous_version(service_with_v1_v2):
    svc = service_with_v1_v2
    svc.activate("v2")
    assert svc.evaluate(WRITE_REQ).decision == "allow"
    assert svc.rollback() == "v1"
    r = svc.evaluate(WRITE_REQ)
    log_decision(WRITE_REQ, r)
    assert r.decision == "deny"
    with pytest.raises(RuntimeError):
        svc.rollback()  # 没有更多历史


def test_evaluate_without_active_version_raises():
    from app.service import PolicyDecisionService

    svc = PolicyDecisionService()
    with pytest.raises(RuntimeError, match="没有生效"):
        svc.evaluate(READ_REQ)
