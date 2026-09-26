"""FastAPI HTTP 接口层。"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .models import DecisionRequest, PolicyRejectError
from .service import PolicyDecisionService

_REJECT_STATUS = {
    "syntax_error": 400,
    "semantic_error": 422,
    "duplicate_version": 409,
}


class DecideBody(BaseModel):
    subject: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)


class LoadBody(BaseModel):
    text: str = Field(min_length=1, description="JSON 或 YAML 格式的策略包文本")


class ActivateBody(BaseModel):
    version: str = Field(min_length=1)


def create_app(service: PolicyDecisionService | None = None) -> FastAPI:
    app = FastAPI(title="本地策略即代码授权决策服务", version="0.1.0")
    svc = service or PolicyDecisionService()

    @app.exception_handler(PolicyRejectError)
    async def _on_reject(_request, exc: PolicyRejectError):
        return JSONResponse(
            status_code=_REJECT_STATUS.get(exc.reason.value, 400),
            content={
                "rejected": True,
                "reason": exc.reason.value,
                "message": exc.message,
                "details": exc.details,
            },
        )

    @app.get("/")
    def health():
        return {"service": "policy-decision-service", "active_version": svc.active_version}

    @app.post("/decide")
    def decide(body: DecideBody):
        return svc.evaluate(DecisionRequest(body.subject, body.action, body.resource))

    @app.get("/versions")
    def versions():
        return {"active": svc.active_version, "loaded": svc.loaded_versions()}

    @app.post("/versions/load", status_code=201)
    def load_version(body: LoadBody):
        version = svc.load_version(body.text)
        return {"status": "validated", "version": version, "active": svc.active_version}

    @app.post("/versions/activate")
    def activate_version(body: ActivateBody):
        svc.activate(body.version)
        return {"status": "active", "version": svc.active_version}

    @app.post("/versions/rollback")
    def rollback():
        target = svc.rollback()
        return {"status": "active", "version": target}

    return app
