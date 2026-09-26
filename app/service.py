"""策略决策服务：版本加载、原子切换、回滚与并发安全求值。"""
from __future__ import annotations

import threading

from .matcher import Matcher
from .models import DecisionRequest, DecisionResult, PolicyRejectError, RejectReason
from .parser import parse_bundle
from .validator import validate_bundle


class PolicyDecisionService:
    """线程安全的策略版本管理与判定入口。

    - 新版本必须先 parse + validate 全部通过才登记，登记不等于生效；
    - 校验失败（syntax / semantic）时不触碰任何既有状态；
    - activate 是一次引用原子交换，失败的版本永远不会出现在判定链路上；
    - rollback 按激活栈恢复上一个生效版本。
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._versions: dict[str, Matcher] = {}
        self._active: Matcher | None = None
        self._history: list[str | None] = []  # 每次激活前的生效版本

    def load_version(self, text: str) -> str:
        """加载并完整校验一个策略包版本；通过后登记但不自动生效。

        返回版本号。失败抛出 PolicyRejectError（原因可区分）。
        """
        bundle = parse_bundle(text)  # SYNTAX_ERROR：解析失败，不进入锁、不改状态
        with self._lock:
            if bundle.version in self._versions:
                raise PolicyRejectError(
                    RejectReason.DUPLICATE_VERSION,
                    f"版本 {bundle.version!r} 已存在，不允许重复加载",
                )
            validate_bundle(bundle)  # SEMANTIC_ERROR：校验失败，登记动作不发生
            self._versions[bundle.version] = Matcher(bundle)
            return bundle.version

    def activate(self, version: str) -> None:
        """将已加载校验通过的版本原子切换为生效版本。"""
        with self._lock:
            matcher = self._versions.get(version)
            if matcher is None:
                raise KeyError(f"版本 {version!r} 尚未加载或未通过校验")
            previous = self._active.version if self._active is not None else None
            if previous is not None and previous != version:
                self._history.append(previous)
            self._active = matcher  # 原子引用交换

    def rollback(self) -> str:
        """回滚到上一个生效版本，返回回滚后的生效版本号。"""
        with self._lock:
            if not self._history:
                raise RuntimeError("没有可回滚的生效版本")
            target = self._history.pop()
            matcher = self._versions.get(target)
            if matcher is None:
                raise RuntimeError(f"回滚目标版本 {target!r} 已不存在")
            self._active = matcher
            return target

    @property
    def active_version(self) -> str | None:
        with self._lock:
            return self._active.version if self._active is not None else None

    def loaded_versions(self) -> list[str]:
        with self._lock:
            return sorted(self._versions)

    def evaluate(self, request: DecisionRequest) -> DecisionResult:
        # 只在取快照时持锁；Matcher 自身不可变，求值期间可并发。
        with self._lock:
            matcher = self._active
        if matcher is None:
            raise RuntimeError("当前没有生效的策略版本，无法判定")
        return matcher.evaluate(request)
