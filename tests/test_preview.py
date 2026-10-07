"""变更预演：翻转识别、校验失败隔离、并发自洽、畸形请求隔离、可复现。"""
import json
import logging
import threading

import pytest
from fastapi.testclient import TestClient

from main import app, store
from policy_service.errors import (
    DuplicateVersionError,
    PolicyError,
    PolicySemanticError,
    PolicySyntaxError,
)
from policy_service.models import DecisionOutcome
from policy_service.preview import run_preview
from policy_service.store import PolicyStore

logger = logging.getLogger("policy-test")

V1 = {
    "version": "v1",
    "subjects": {"alice": ["employee"]},
    "rules": [{"id": "allow-read", "effect": "allow", "priority": 10,
               "subjects": ["employee"], "actions": ["read"], "resources": ["doc"]}],
}
V2 = {
    "version": "v2",
    "subjects": {"alice": ["employee"]},
    "rules": [{"id": "deny-read", "effect": "deny", "priority": 10,
               "subjects": ["employee"], "actions": ["read"], "resources": ["doc"]}],
}
REQ = {"subject": "alice", "action": "read", "resource": "doc"}


@pytest.fixture(autouse=True)
def fresh_store():
    store._versions.clear()
    store._active_version = None
    yield


@pytest.fixture
def client():
    return TestClient(app)


def _local_store() -> PolicyStore:
    """只登记并激活 v1；v2 作为未登记的候选包参与预演。"""
    local = PolicyStore()
    local.load(json.dumps(V1))
    local.activate("v1")
    return local


def _log_item(item):
    if item.status != "ok":
        logger.info("预演条目[%d] 失败: %s", item.index, item.error)
        return
    a, c = item.active_decision, item.candidate_decision
    logger.info(
        "预演条目[%d] 请求输入=%s | 生效侧[%s]=%s 依据=%s 命中=%s | "
        "候选侧[%s]=%s 依据=%s 命中=%s | 翻转=%s",
        item.index, item.request,
        a.policy_version, a.outcome.value, a.reason,
        [(m.rule_id, m.effect.value) for m in a.matched_rules],
        c.policy_version, c.outcome.value, c.reason,
        [(m.rule_id, m.effect.value) for m in c.matched_rules],
        item.flipped,
    )


def test_preview_detects_flips_and_unchanged():
    local = _local_store()
    candidate = local.check_candidate(json.dumps(V2))
    requests = [
        REQ,                                                    # allow -> deny，翻转
        {"subject": "alice", "action": "write", "resource": "doc"},  # 两侧均默认拒绝
    ]
    report = run_preview(local.active(), candidate, requests)
    for item in report.items:
        _log_item(item)
    assert report.active_version == "v1" and report.candidate_version == "v2"
    assert report.total == 2 and report.ok_count == 2 and report.error_count == 0
    assert report.flipped_count == 1
    first, second = report.items
    assert first.flipped is True
    assert first.active_decision.outcome == DecisionOutcome.ALLOW
    assert first.candidate_decision.outcome == DecisionOutcome.DENY
    # 未翻转的条目也能看出两个版本结论一致
    assert second.flipped is False
    assert second.active_decision.outcome == second.candidate_decision.outcome == DecisionOutcome.DENY
    # 报告可追溯到命中规则
    assert first.active_decision.matched_rules[0].rule_id == "allow-read"
    assert first.candidate_decision.matched_rules[0].rule_id == "deny-read"
    # 预演结束后生效版本与开始时一致，候选包未被登记
    assert local.active_version() == "v1"
    assert local.versions() == ["v1"]  # 候选包未被预演登记


def test_preview_candidate_validation_failure_keeps_active_untouched():
    local = PolicyStore()
    local.load(json.dumps(V1))
    local.activate("v1")
    before_versions = local.versions()

    with pytest.raises(PolicySyntaxError):
        local.check_candidate(json.dumps({"version": "bad", "rules": [{"id": "r"}]}))
    with pytest.raises(PolicySemanticError):
        local.check_candidate(json.dumps({"version": "bad2", "subjects": {"a": ["a"]}}))
    with pytest.raises(DuplicateVersionError):
        local.check_candidate(json.dumps(V1))
    logger.info("候选包三类校验失败原因均可区分: syntax / semantic / duplicate_version")

    # 当前生效版本与登记列表均未受影响
    assert local.active_version() == "v1"
    assert local.versions() == before_versions


def test_preview_via_http_candidate_not_registered(client):
    assert client.post("/policies", json=V1).status_code == 201
    assert client.post("/policies/v1/activate").status_code == 200
    r = client.post("/policies/preview", json={"candidate": V2, "requests": [REQ]})
    assert r.status_code == 200
    body = r.json()
    logger.info("HTTP 预演报告=%s", body)
    assert body["flipped_count"] == 1
    item = body["items"][0]
    assert item["active_decision"]["outcome"] == "allow"
    assert item["candidate_decision"]["outcome"] == "deny"
    assert item["active_decision"]["policy_version"] == "v1"
    assert item["candidate_decision"]["policy_version"] == "v2"
    # 候选包未被登记、生效版本未变
    assert client.get("/policies").json() == {"active": "v1", "versions": ["v1"]}
    # 预演后 /decide 行为不变
    r = client.post("/decide", json=REQ)
    assert r.json()["outcome"] == "allow" and r.json()["policy_version"] == "v1"


def test_preview_http_validation_errors_distinguishable(client):
    client.post("/policies", json=V1)
    client.post("/policies/v1/activate")
    r = client.post("/policies/preview", json={"candidate": {"version": 1}, "requests": []})
    assert r.status_code == 422 and r.json()["error"] == "syntax"
    r = client.post("/policies/preview",
                    json={"candidate": {"version": "v9", "subjects": {"a": ["a"]}}, "requests": []})
    assert r.status_code == 422 and r.json()["error"] == "semantic"
    r = client.post("/policies/preview", json={"candidate": V1, "requests": []})
    assert r.status_code == 409 and r.json()["error"] == "duplicate_version"
    assert client.get("/policies").json() == {"active": "v1", "versions": ["v1"]}


def test_preview_without_active_version_fails_closed():
    local = PolicyStore()
    candidate = local.check_candidate(json.dumps(V2))
    with pytest.raises(PolicyError):
        local.active()  # 无生效版本时连快照都取不到，预演无法开始
    assert local.active_version() is None
    assert candidate.version == "v2"


def test_preview_isolates_malformed_requests():
    local = _local_store()
    candidate = local.check_candidate(json.dumps(V2))
    requests = [
        REQ,
        {"action": "read", "resource": "doc"},                 # 缺 subject
        {"subject": "alice", "action": "read", "resource": 1},  # 类型错误
        "not-a-dict",                                           # 非对象
        {"subject": "alice", "action": "read", "resource": "doc",
         "context": {"env": "prod"}},                           # 正常
    ]
    report = run_preview(local.active(), candidate, requests)
    for item in report.items:
        _log_item(item)
    assert report.total == 5 and report.ok_count == 2 and report.error_count == 3
    # 畸形条目只标记自身，正常条目结论正确
    assert [i.status for i in report.items] == ["ok", "error", "error", "error", "ok"]
    assert report.items[0].flipped is True
    assert report.items[4].flipped is True
    for i in (1, 2, 3):
        assert report.items[i].error is not None
        assert report.items[i].active_decision is None
        assert report.items[i].candidate_decision is None


def test_preview_is_deterministic_and_scales():
    local = _local_store()
    candidate = local.check_candidate(json.dumps(V2))
    requests = [
        {"subject": "alice", "action": a, "resource": "doc"}
        for a in (["read", "write"] * 1500)  # 3000 条
    ]
    report1 = run_preview(local.active(), candidate, requests)
    report2 = run_preview(local.active(), candidate, requests)
    assert report1.total == 3000 and report1.ok_count == 3000
    assert report1.flipped_count == 1500
    # 同一批输入重复预演，结果完全一致
    assert report1 == report2
    logger.info("3000 条请求两次预演结果完全一致，翻转 %d 条", report1.flipped_count)


def test_preview_consistent_snapshot_under_concurrent_switch():
    """预演与激活/回滚并发交错：报告内每条生效侧结论都依据同一快照版本。"""
    local = _local_store()
    local.load(json.dumps(V2))  # 登记 v2 供并发切换/回滚
    v3 = dict(V2, version="v3")
    candidate = local.check_candidate(json.dumps(v3))
    expected = {"v1": DecisionOutcome.ALLOW, "v2": DecisionOutcome.DENY}
    requests = [REQ] * 200
    errors: list[str] = []
    stop = threading.Event()

    def switcher():
        while not stop.is_set():
            local.activate("v2")
            local.activate("v1")  # 回滚

    def previewer():
        for _ in range(50):
            snapshot = local.active()
            report = run_preview(snapshot, candidate, requests)
            _log_item(report.items[0])  # 抽样记录，完整校验在下面逐条进行
            for item in report.items:
                a = item.active_decision
                # 报告内所有生效侧结论必须来自开始时取定的那个快照版本
                if a.policy_version != snapshot.version:
                    errors.append(
                        f"快照 {snapshot.version} 的报告混入版本 {a.policy_version}")
                if a.outcome != expected[a.policy_version]:
                    errors.append(f"版本 {a.policy_version} 得出矛盾结论 {a.outcome}")
                if item.candidate_decision.policy_version != "v3":
                    errors.append("候选侧结论未依据候选版本")

    threads = [threading.Thread(target=switcher) for _ in range(2)]
    threads += [threading.Thread(target=previewer) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads[2:]:
        t.join()
    stop.set()
    for t in threads[:2]:
        t.join()
    assert not errors, errors
