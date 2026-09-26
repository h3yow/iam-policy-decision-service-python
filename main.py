"""本地启动入口：自动加载 policies/ 目录下的示例策略包。"""
from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from app.api import create_app
from app.models import PolicyRejectError
from app.service import PolicyDecisionService

POLICY_DIR = Path(os.environ.get("POLICY_DIR", "policies"))


def build_service() -> PolicyDecisionService:
    svc = PolicyDecisionService()
    loaded: list[str] = []
    for path in sorted(POLICY_DIR.glob("*")):
        if path.suffix not in (".json", ".yaml", ".yml"):
            continue
        text = path.read_text(encoding="utf-8")
        try:
            version = svc.load_version(text)
        except PolicyRejectError as exc:
            print(f"[startup] 跳过 {path.name}: {exc.reason.value}: {exc.message}")
            continue
        loaded.append(version)
        print(f"[startup] 已加载 {path.name} -> 版本 {version}")
    initial = os.environ.get("ACTIVE_VERSION", loaded[0] if loaded else "")
    if initial:
        svc.activate(initial)
        print(f"[startup] 生效版本: {initial}")
    else:
        print("[startup] 没有可用的生效策略版本，/decide 将不可用")
    return svc


app = create_app(build_service())

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
