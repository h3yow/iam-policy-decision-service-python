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
from policy_service.models import Decision, DecisionRequest
from policy_service.preview import PreviewReport, run_preview
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


class PreviewBody(BaseModel):
    candidate: dict[str, Any]
    requests: list[Any]


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


def _decision_dict(decision: Decision) -> dict[str, Any]:
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
    return _decision_dict(decision)


@app.post("/policies/preview")
def preview_policy(body: PreviewBody) -> dict[str, Any]:
    """变更预演：候选包完整校验后，与当前生效版本快照做批量双版本判定。

    候选包只校验不登记、不生效；校验失败按既有可区分原因拒绝，
    当前生效版本不受任何影响。单条畸形请求只标记该条失败。
    """
    candidate = store.check_candidate(json.dumps(body.candidate))
    report = run_preview(store.active(), candidate, body.requests)
    _log_preview(report)
    return {
        "active_version": report.active_version,
        "candidate_version": report.candidate_version,
        "total": report.total,
        "ok_count": report.ok_count,
        "error_count": report.error_count,
        "flipped_count": report.flipped_count,
        "items": [
            {
                "index": item.index,
                "status": item.status,
                "error": item.error,
                "flipped": item.flipped,
                "request": (
                    {
                        "subject": item.request.subject,
                        "action": item.request.action,
                        "resource": item.request.resource,
                        "context": item.request.context,
                    }
                    if item.request is not None
                    else None
                ),
                "active_decision": (
                    _decision_dict(item.active_decision)
                    if item.active_decision is not None
                    else None
                ),
                "candidate_decision": (
                    _decision_dict(item.candidate_decision)
                    if item.candidate_decision is not None
                    else None
                ),
            }
            for item in report.items
        ],
    }


def _log_preview(report: PreviewReport) -> None:
    logger.info(
        "preview active=%s candidate=%s total=%d ok=%d error=%d flipped=%d",
        report.active_version, report.candidate_version, report.total,
        report.ok_count, report.error_count, report.flipped_count,
    )
    for item in report.items:
        if item.status != "ok":
            logger.info("preview item[%d] error=%s", item.index, item.error)
            continue
        assert item.request is not None
        assert item.active_decision is not None and item.candidate_decision is not None
        logger.info(
            "preview item[%d] request=%s flipped=%s | "
            "active[%s]=%s reason=%s matched=%s | candidate[%s]=%s reason=%s matched=%s",
            item.index, item.request, item.flipped,
            item.active_decision.policy_version, item.active_decision.outcome.value,
            item.active_decision.reason,
            [m.rule_id for m in item.active_decision.matched_rules],
            item.candidate_decision.policy_version, item.candidate_decision.outcome.value,
            item.candidate_decision.reason,
            [m.rule_id for m in item.candidate_decision.matched_rules],
        )


@app.get("/")
def read_root() -> dict[str, str]:
    return {"Hello": "World"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
