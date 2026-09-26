"""本地策略即代码授权决策服务的 HTTP 入口。"""
from __future__ import annotations

import json
import logging
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from policy_service.engine import evaluate
from policy_service.errors import (
    DuplicateVersionError,
    PolicyError,
    PolicySemanticError,
    PolicySyntaxError,
)
from policy_service.models import DecisionRequest
from policy_service.store import PolicyStore

logger = logging.getLogger("policy-service")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="IAM Policy Decision Service")
store = PolicyStore()


class DecideBody(BaseModel):
    subject: str
    action: str
    resource: str
    context: dict[str, Any] = {}


@app.exception_handler(PolicySyntaxError)
async def _syntax(_: Request, exc: PolicySyntaxError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": "syntax", "detail": str(exc)})


@app.exception_handler(PolicySemanticError)
async def _semantic(_: Request, exc: PolicySemanticError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": "semantic", "detail": str(exc)})


@app.exception_handler(DuplicateVersionError)
async def _duplicate(_: Request, exc: DuplicateVersionError) -> JSONResponse:
    return JSONResponse(status_code=409, content={"error": "duplicate_version", "detail": str(exc)})


@app.exception_handler(PolicyError)
async def _policy(_: Request, exc: PolicyError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": "policy", "detail": str(exc)})


@app.post("/policies", status_code=201)
def load_policy(package: dict[str, Any]) -> dict[str, str]:
    """加载并校验新策略版本；校验失败则拒绝且不影响当前生效版本。"""
    loaded = store.load(json.dumps(package))
    return {"version": loaded.version, "status": "loaded"}


@app.post("/policies/{version}/activate")
def activate_policy(version: str) -> dict[str, str]:
    """原子切换到已登记的版本；也可用于回滚到旧版本。"""
    store.activate(version)
    return {"version": version, "status": "active"}


@app.get("/policies")
def list_policies() -> dict[str, Any]:
    return {"active": store.active_version(), "versions": store.versions()}


@app.post("/decide")
def decide(body: DecideBody) -> dict[str, Any]:
    request = DecisionRequest(
        subject=body.subject,
        action=body.action,
        resource=body.resource,
        context=body.context,
    )
    decision = evaluate(store.active(), request)
    logger.info(
        "decide request=%s outcome=%s version=%s reason=%s matched=%s",
        request, decision.outcome.value, decision.policy_version,
        decision.reason, [m.rule_id for m in decision.matched_rules],
    )
    return {
        "outcome": decision.outcome.value,
        "policy_version": decision.policy_version,
        "reason": decision.reason,
        "matched_rules": [
            {
                "rule_id": m.rule_id,
                "effect": m.effect.value,
                "priority": m.priority,
                "subject_path": list(m.subject_path),
                "resource_path": list(m.resource_path),
            }
            for m in decision.matched_rules
        ],
    }


@app.get("/")
def read_root() -> dict[str, str]:
    return {"Hello": "World"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
