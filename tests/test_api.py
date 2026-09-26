"""HTTP 接口：拒绝原因映射到可区分的状态码，判定结果含判定依据。"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.service import PolicyDecisionService


@pytest.fixture
def client(service_with_v1_v2):
    return TestClient(create_app(service_with_v1_v2))


def test_decide_returns_explainable_result(client):
    resp = client.post("/decide", json={
        "subject": "alice", "action": "read", "resource": "doc1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["version"] == "v1"
    assert body["winning_rule"] == "allow-eng-read"
    assert body["matched_rules"] and body["trace"] and body["reason"]


def test_decide_unknown_subject_denied(client):
    resp = client.post("/decide", json={
        "subject": "mallory", "action": "read", "resource": "doc1"})
    assert resp.json()["decision"] == "deny"


def test_load_rejections_have_distinct_status_codes(client):
    cases = [
        ("{broken", 400, "syntax_error"),
        (json.dumps({"version": "vx", "subjects": {
            "a": {"inherits": ["b"]}, "b": {"inherits": ["a"]}}}), 422, "semantic_error"),
        (json.dumps({"version": "v1", "rules": []}), 409, "duplicate_version"),
    ]
    for text, status, reason in cases:
        resp = client.post("/versions/load", json={"text": text})
        assert resp.status_code == status, (text, resp.text)
        assert resp.json()["reason"] == reason
    # 拒绝不影响当前生效版本
    assert client.get("/versions").json()["active"] == "v1"


def test_activate_switch_and_rollback_via_http(client):
    assert client.post("/versions/activate", json={"version": "v2"}).json()["version"] == "v2"
    write = client.post("/decide", json={
        "subject": "alice", "action": "write", "resource": "doc1"}).json()
    assert write["decision"] == "allow" and write["version"] == "v2"
    assert client.post("/versions/rollback").json()["version"] == "v1"
    write = client.post("/decide", json={
        "subject": "alice", "action": "write", "resource": "doc1"}).json()
    assert write["decision"] == "deny"
