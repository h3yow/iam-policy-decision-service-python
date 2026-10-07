"""变更预演：在不动当前生效版本的前提下，批量对比候选包与生效版本的判定结论。

设计约束：
- 候选包走与正式加载完全相同的一套校验（语法 -> 语义 -> 版本号冲突），
  任何失败都抛出既有的可区分错误，且不会登记、不会生效、不影响当前版本；
- 预演开始时在锁内取一次生效版本快照，整批请求都基于该快照与候选包求值，
  预演期间其他线程激活/回滚不影响本报告的自洽性；
- 单条请求畸形（缺字段、类型不对）只标记该条失败，不影响同批其他请求；
- 结果确定性：同一批输入重复预演，报告完全一致。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .engine import evaluate
from .errors import DuplicateVersionError
from .loader import parse_policy_package
from .models import Decision, DecisionRequest

logger = logging.getLogger("policy-service")


@dataclass(frozen=True)
class RehearsalItem:
    """单条请求的预演结果：两个版本各自的结论，或该条请求自身的错误。"""

    index: int
    request: dict[str, Any]
    baseline: Decision | None = None
    candidate: Decision | None = None
    flipped: bool = False
    error: str | None = None


@dataclass(frozen=True)
class RehearsalReport:
    """整批预演报告，可追溯到底线版本、候选版本与每条命中规则。"""

    baseline_version: str
    candidate_version: str
    total: int
    flipped: int
    failed: int
    items: tuple[RehearsalItem, ...] = field(default_factory=tuple)


def _parse_request(raw: Any, index: int) -> DecisionRequest:
    """把一条原始请求校验并转换为 DecisionRequest；畸形则抛 ValueError。

    只校验形状（必填字段存在且为字符串、context 为对象），不做任何
    主体/资源是否存在的判断——未知主体/资源按既定语义走默认拒绝。
    """
    where = f"requests[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{where} 必须是对象")
    for key in ("subject", "action", "resource"):
        value = raw.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{where}.{key} 必须是非空字符串")
    context = raw.get("context", {})
    if not isinstance(context, dict):
        raise ValueError(f"{where}.context 必须是对象")
    return DecisionRequest(
        subject=raw["subject"],
        action=raw["action"],
        resource=raw["resource"],
        context=dict(context),
    )


def rehearse(store: Any, candidate_raw: str, requests: list[Any]) -> RehearsalReport:
    """对候选策略包做批量预演，返回可追溯、确定性的对比报告。

    fail-closed：候选包校验失败（语法/语义/版本号冲突）或无生效版本时
    直接抛错，不产生任何「部分成功」的报告，也不改变仓库任何状态。
    """
    # 1. 候选包走与正式加载完全相同的一套完整校验，失败即抛错，不登记不生效。
    candidate = parse_policy_package(candidate_raw)
    if store.has_version(candidate.version):
        raise DuplicateVersionError(f"策略版本已存在: {candidate.version!r}")

    # 2. 在锁内取一次生效版本快照；此后整批求值都基于该不可变快照，
    #    预演期间的激活/回滚不会影响本报告的自洽性。
    baseline = store.active()

    # 3. 逐条求值；单条畸形请求只标记该条失败，不影响同批其他请求。
    items: list[RehearsalItem] = []
    flipped = 0
    failed = 0
    for index, raw in enumerate(requests):
        try:
            request = _parse_request(raw, index)
        except ValueError as exc:
            failed += 1
            items.append(RehearsalItem(index=index, request=raw, error=str(exc)))
            logger.warning("rehearse 第 %d 条请求畸形，已隔离: %s", index, exc)
            continue
        base_decision = evaluate(baseline, request)
        cand_decision = evaluate(candidate, request)
        is_flipped = base_decision.outcome != cand_decision.outcome
        flipped += 1 if is_flipped else 0
        items.append(
            RehearsalItem(
                index=index,
                request=raw,
                baseline=base_decision,
                candidate=cand_decision,
                flipped=is_flipped,
            )
        )
        logger.info(
            "rehearse 请求=%s | 生效版本 %s -> %s (%s) | 候选版本 %s -> %s (%s) | 翻转=%s",
            request,
            base_decision.policy_version, base_decision.outcome.value, base_decision.reason,
            cand_decision.policy_version, cand_decision.outcome.value, cand_decision.reason,
            is_flipped,
        )

    return RehearsalReport(
        baseline_version=baseline.version,
        candidate_version=candidate.version,
        total=len(requests),
        flipped=flipped,
        failed=failed,
        items=tuple(items),
    )
