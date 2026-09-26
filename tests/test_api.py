"""HTTP 接口与并发下的策略切换、回滚：结论稳定，失败原因可区分。"""
import logging
import threading

import pytest
from fastapi.testclient import TestClient

from main import app, store
from policy_service.engine import evaluate
from policy_service.models import DecisionOutcome, DecisionRequest
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


@pytest.fixture(autouse=True)
def fresh_store():
    store._versions.clear()
    store._active_version = None
    yield


@pytest.fixture
def client():
    return TestClient(app)


def test_load_activate_decide_flow(client):
    assert client.post("/policies", json=V1).status_code == 201
    assert client.post("/policies/v1/activate").status_code == 200
    r = client.post("/decide", json={"subject": "alice", "action": "read", "resource": "doc"})
    body = r.json()
    logger.info("请求输入=%s 判定依据=%s", {"subject": "alice", "action": "read", "resource": "doc"}, body)
    assert body["outcome"] == "allow"
    assert body["policy_version"] == "v1"
    assert body["matched_rules"][0]["subject_path"] == ["alice", "employee"]


def test_rejection_reasons_are_distinguishable(client):
    client.post("/policies", json=V1)
    r = client.post("/policies", json={"version": 1})
    assert r.status_code == 422 and r.json()["error"] == "syntax"
    r = client.post("/policies", json={"version": "v9", "subjects": {"a": ["b"], "b": ["a"]}})
    assert r.status_code == 422 and r.json()["error"] == "semantic"
    r = client.post("/policies", json=V1)
    assert r.status_code == 409 and r.json()["error"] == "duplicate_version"
    logger.info("三类拒绝原因: syntax / semantic / duplicate_version 均可区分")


def test_failed_load_does_not_affect_active_version(client):
    client.post("/policies", json=V1)
    client.post("/policies/v1/activate")
    client.post("/policies", json={"version": "bad", "subjects": {"a": ["a"]}})
    r = client.post("/decide", json={"subject": "alice", "action": "read", "resource": "doc"})
    assert r.json()["outcome"] == "allow"
    assert r.json()["policy_version"] == "v1"


def test_rollback_to_previous_version(client):
    client.post("/policies", json=V1)
    client.post("/policies", json=V2)
    client.post("/policies/v1/activate")
    client.post("/policies/v2/activate")
    r = client.post("/decide", json={"subject": "alice", "action": "read", "resource": "doc"})
    assert r.json()["outcome"] == "deny"
    client.post("/policies/v1/activate")  # 回滚
    r = client.post("/decide", json={"subject": "alice", "action": "read", "resource": "doc"})
    body = r.json()
    logger.info("回滚后判定=%s", body)
    assert body["outcome"] == "allow" and body["policy_version"] == "v1"


def test_activate_unknown_version_fails(client):
    r = client.post("/policies/nope/activate")
    assert r.status_code == 400 and r.json()["error"] == "policy"


def test_concurrent_decide_during_switch_and_rollback():
    """并发求值与版本切换/回滚交织：每个结论都必须完整对应某个版本。"""
    local = PolicyStore()
    local.load(__import__("json").dumps(V1))
    local.load(__import__("json").dumps(V2))
    local.activate("v1")
    req = DecisionRequest("alice", "read", "doc")
    expected = {"v1": DecisionOutcome.ALLOW, "v2": DecisionOutcome.DENY}
    errors: list[str] = []
    stop = threading.Event()

    def worker():
        while not stop.is_set():
            d = evaluate(local.active(), req)
            logger.info("并发请求=%s 判定=%s %s", req, d.policy_version, d.outcome.value)
            if d.outcome != expected[d.policy_version]:
                errors.append(f"版本 {d.policy_version} 得出矛盾结论 {d.outcome}")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for _ in range(200):
        local.activate("v2")
        local.activate("v1")  # 回滚
    stop.set()
    for t in threads:
        t.join()
    assert not errors, errors
