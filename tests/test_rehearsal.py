"""变更预演：翻转识别、校验失败隔离、并发自洽、畸形请求隔离、确定性。"""
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
from policy_service.rehearsal import rehearse
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
# 候选包：把 read 翻转为 deny，同时新增一条 write 放行规则
CANDIDATE = {
    "version": "v3-candidate",
    "subjects": {"alice": ["employee"]},
    "rules": [
        {"id": "deny-read", "effect": "deny", "priority": 10,
         "subjects": ["employee"], "actions": ["read"], "resources": ["doc"]},
        {"id": "allow-write", "effect": "allow", "priority": 5,
         "subjects": ["employee"], "actions": ["write"], "resources": ["doc"]},
    ],
}

REQ_READ = {"subject": "alice", "action": "read", "resource": "doc"}
REQ_WRITE = {"subject": "alice", "action": "write", "resource": "doc"}
REQ_UNKNOWN = {"subject": "nobody", "action": "read", "resource": "doc"}


@pytest.fixture(autouse=True)
def fresh_store():
    store._versions.clear()
    store._active_version = None
    yield


@pytest.fixture
def client():
    return TestClient(app)


def _local_store_with_v1() -> PolicyStore:
    local = PolicyStore()
    local.load(json.dumps(V1))
    local.activate("v1")
    return local


def _log_report(report):
    for item in report.items:
        if item.error:
            logger.info("第 %d 条请求畸形已隔离: %s", item.index, item.error)
        else:
            logger.info(
                "请求输入=%s | %s 下 %s(%s) | %s 下 %s(%s) | 翻转=%s",
                item.request,
                item.baseline.policy_version, item.baseline.outcome.value, item.baseline.reason,
                item.candidate.policy_version, item.candidate.outcome.value, item.candidate.reason,
                item.flipped,
            )


def test_flip_detection_and_consistent_items():
    """翻转识别：read 由 allow 翻为 deny，write 由默认拒绝翻为 allow，未知主体两版一致。"""
    local = _local_store_with_v1()
    report = rehearse(local, json.dumps(CANDIDATE), [REQ_READ, REQ_WRITE, REQ_UNKNOWN])
    _log_report(report)

    assert report.baseline_version == "v1"
    assert report.candidate_version == "v3-candidate"
    assert report.total == 3 and report.failed == 0 and report.flipped == 2

    read_item, write_item, unknown_item = report.items
    assert read_item.flipped is True
    assert read_item.baseline.outcome.value == "allow"
    assert read_item.candidate.outcome.value == "deny"
    assert write_item.flipped is True
    assert write_item.baseline.outcome.value == "deny"
    assert write_item.candidate.outcome.value == "allow"
    # 未翻转的条目也能看出两个版本结论一致
    assert unknown_item.flipped is False
    assert unknown_item.baseline.outcome == unknown_item.candidate.outcome
    # 报告可追溯到版本与命中规则
    assert read_item.baseline.policy_version == "v1"
    assert read_item.candidate.policy_version == "v3-candidate"
    assert [m.rule_id for m in read_item.candidate.matched_rules] == ["deny-read"]
    # 预演不登记、不生效：仓库状态与开始时一模一样
    assert local.versions() == ["v1"] and local.active_version() == "v1"


def test_candidate_validation_failure_keeps_active_untouched():
    """候选包校验失败：按既有可区分原因拒绝，生效版本与登记列表完全不变。"""
    local = _local_store_with_v1()
    before_versions = local.versions()

    with pytest.raises(PolicySyntaxError):
        rehearse(local, "{not json", [REQ_READ])
    with pytest.raises(PolicySyntaxError):
        rehearse(local, json.dumps({"version": "vx", "rules": [{"id": 1}]}), [REQ_READ])
    with pytest.raises(PolicySemanticError):
        rehearse(local, json.dumps({"version": "vx", "subjects": {"a": ["b"], "b": ["a"]}}),
                 [REQ_READ])
    with pytest.raises(DuplicateVersionError):
        rehearse(local, json.dumps(V1), [REQ_READ])  # 版本号与已登记版本冲突

    assert local.versions() == before_versions
    assert local.active_version() == "v1"
    logger.info("候选包四类失败均被可区分地拒绝，生效版本仍为 v1，登记列表=%s", local.versions())


def test_rehearse_without_active_version_fails_closed():
    """无生效版本时预演 fail-closed：直接抛错，不产生部分成功的报告。"""
    local = PolicyStore()
    with pytest.raises(PolicyError):
        rehearse(local, json.dumps(CANDIDATE), [REQ_READ])


def test_malformed_requests_are_isolated():
    """批量里个别缺字段/类型错误的请求只标记该条失败，整批不报错。"""
    local = _local_store_with_v1()
    batch = [
        REQ_READ,
        {"subject": "alice", "action": "read"},          # 缺 resource
        {"subject": "alice", "action": "read", "resource": 42},  # 类型错误
        "not-a-dict",                                     # 整体不是对象
        REQ_WRITE,
    ]
    report = rehearse(local, json.dumps(CANDIDATE), batch)
    _log_report(report)

    assert report.total == 5 and report.failed == 3 and report.flipped == 2
    assert report.items[0].error is None and report.items[0].flipped is True
    assert report.items[4].error is None and report.items[4].flipped is True
    for i in (1, 2, 3):
        assert report.items[i].error is not None
        assert report.items[i].baseline is None and report.items[i].candidate is None


def test_rehearsal_is_deterministic_at_scale():
    """同一批输入重复预演结果完全一致；单次可跑几千条请求。"""
    local = _local_store_with_v1()
    batch = [
        {"subject": f"user-{i}", "action": "read" if i % 2 else "write",
         "resource": "doc", "context": {"seq": i}}
        for i in range(3000)
    ] + [REQ_READ, REQ_WRITE]
    report1 = rehearse(local, json.dumps(CANDIDATE), batch)
    report2 = rehearse(local, json.dumps(CANDIDATE), batch)
    assert report1.total == 3002 and report1.failed == 0
    assert report1 == report2
    logger.info("3002 条请求两次预演结果完全一致，flipped=%d", report1.flipped)


def test_rehearsal_consistent_under_concurrent_activate_rollback():
    """预演与激活/回滚并发交错：报告内每条结论都依据同一个自洽的版本快照。"""
    local = PolicyStore()
    local.load(json.dumps(V1))
    local.load(json.dumps(V2))
    local.activate("v1")
    expected = {"v1": "allow", "v2": "deny"}
    errors: list[str] = []
    stop = threading.Event()

    def switcher():
        while not stop.is_set():
            local.activate("v2")
            local.activate("v1")  # 回滚

    def rehearser():
        while not stop.is_set():
            report = rehearse(local, json.dumps(CANDIDATE), [REQ_READ] * 20)
            for item in report.items:
                # 每条结论必须对应报告声明的底线版本，且与该版本的预期结论一致
                if item.baseline.policy_version != report.baseline_version:
                    errors.append(f"条目版本 {item.baseline.policy_version} 与报告不一致")
                if item.baseline.outcome.value != expected[report.baseline_version]:
                    errors.append(f"版本 {report.baseline_version} 下结论矛盾")
                if item.candidate.policy_version != report.candidate_version:
                    errors.append("候选结论版本与报告不一致")
            # 预演结束后仓库里绝不能多出候选版本
            if CANDIDATE["version"] in local.versions():
                errors.append("候选包被意外登记")

    threads = ([threading.Thread(target=switcher) for _ in range(2)]
               + [threading.Thread(target=rehearser) for _ in range(4)])
    for t in threads:
        t.start()
    threading.Event().wait(0.5)
    stop.set()
    for t in threads:
        t.join()
    assert not errors, errors
    logger.info("并发预演/切换/回滚交错结束，所有报告自洽，候选包未被登记")


def test_rehearse_api_end_to_end(client):
    """HTTP 预演接口：返回完整报告，候选包不登记、生效版本不变。"""
    assert client.post("/policies", json=V1).status_code == 201
    assert client.post("/policies/v1/activate").status_code == 200

    r = client.post("/rehearse", json={
        "candidate": CANDIDATE,
        "requests": [REQ_READ, REQ_WRITE, {"subject": "alice"}],
    })
    assert r.status_code == 200
    body = r.json()
    logger.info("预演报告=%s", body)
    assert body["baseline_version"] == "v1"
    assert body["candidate_version"] == "v3-candidate"
    assert body["total"] == 3 and body["flipped"] == 2 and body["failed"] == 1
    assert body["items"][0]["baseline"]["outcome"] == "allow"
    assert body["items"][0]["candidate"]["outcome"] == "deny"
    assert body["items"][0]["candidate"]["matched_rules"][0]["rule_id"] == "deny-read"
    assert body["items"][2]["error"] is not None

    # 预演后仓库状态与开始时一模一样
    policies = client.get("/policies").json()
    assert policies == {"active": "v1", "versions": ["v1"]}
    r = client.post("/decide", json=REQ_READ)
    assert r.json()["outcome"] == "allow" and r.json()["policy_version"] == "v1"


def test_rehearse_api_rejection_reasons_distinguishable(client):
    """HTTP 预演接口的候选包失败原因与正式加载一致且可区分。"""
    client.post("/policies", json=V1)
    client.post("/policies/v1/activate")

    r = client.post("/rehearse", json={"candidate": {"version": 1}, "requests": []})
    assert r.status_code == 422 and r.json()["error"] == "syntax"
    r = client.post("/rehearse", json={
        "candidate": {"version": "vx", "subjects": {"a": ["b"], "b": ["a"]}},
        "requests": [],
    })
    assert r.status_code == 422 and r.json()["error"] == "semantic"
    r = client.post("/rehearse", json={"candidate": V1, "requests": []})
    assert r.status_code == 409 and r.json()["error"] == "duplicate_version"

    policies = client.get("/policies").json()
    assert policies == {"active": "v1", "versions": ["v1"]}
    logger.info("预演接口三类拒绝原因可区分，仓库状态未变: %s", policies)
