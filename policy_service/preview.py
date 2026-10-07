"""变更预演：在不触碰当前生效版本的前提下，批量对比候选包与生效版本的判定结论。

设计约束：
- 候选包走与正式加载完全相同的校验（loader.parse_policy_package），
  并额外检查版本号冲突；任何失败都抛出可区分的 PolicyError 子类，
  候选包不会被登记、更不会生效（fail-closed，无部分成功）。
- 预演开始时对当前生效版本取一次快照（不可变对象），整批请求的
  「生效版本侧」结论都基于这同一个自洽快照，与并发的切换/回滚隔离。
- 单条请求畸形（缺字段、类型不对）只标记该条失败，不影响同批其他请求。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import evaluate
from .models import Decision, DecisionRequest, PolicyPackage


def _parse_request(raw: Any, index: int) -> DecisionRequest:
    """把一条原始请求校验并转换为 DecisionRequest；畸形则抛 ValueError。

    只校验形状（必填字段、字段类型），不做任何授权语义判断；
    抛出的异常由调用方捕获并只标记该条，整批不受影响。
    """
    where = f"requests[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{where} 必须是对象")
    for key in ("subject", "action", "resource"):
        value = raw.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{where}.{key} 必须是非空字符串，得到 {value!r}")
    context = raw.get("context", {})
    if not isinstance(context, dict) or not all(isinstance(k, str) for k in context):
        raise ValueError(f"{where}.context 必须是字符串键的对象")
    return DecisionRequest(
        subject=raw["subject"],
        action=raw["action"],
        resource=raw["resource"],
        context=dict(context),
    )


@dataclass(frozen=True)
class PreviewItem:
    """单条请求的预演结果；status 为 error 时两侧结论均为 None。"""

    index: int
    status: str  # "ok" | "error"
    request: DecisionRequest | None = None
    error: str | None = None
    active_decision: Decision | None = None
    candidate_decision: Decision | None = None
    flipped: bool = False


@dataclass(frozen=True)
class PreviewReport:
    """整批预演报告，可追溯：记录两侧各自依据的版本快照。"""

    active_version: str
    candidate_version: str
    total: int
    ok_count: int
    error_count: int
    flipped_count: int
    items: tuple[PreviewItem, ...] = field(default_factory=tuple)


def run_preview(
    active_snapshot: PolicyPackage,
    candidate: PolicyPackage,
    raw_requests: list[dict[str, Any]],
) -> PreviewReport:
    """对一批原始请求做双版本预演。

    - active_snapshot 是预演开始时取定的生效版本快照（不可变对象），
      整批请求的生效侧结论都基于它，与并发切换/回滚隔离；
    - candidate 必须已通过 check_candidate() 的完整校验；
    - 逐条解析请求：畸形请求只标记该条 error，其余请求照常求值；
    - 结果顺序与输入顺序一致，同一输入重复预演结果完全一致。
    """
    items: list[PreviewItem] = []
    for index, raw in enumerate(raw_requests):
        try:
            request = _parse_request(raw, index)
        except ValueError as exc:
            items.append(PreviewItem(index=index, status="error", error=str(exc)))
            continue
        active_decision = evaluate(active_snapshot, request)
        candidate_decision = evaluate(candidate, request)
        items.append(
            PreviewItem(
                index=index,
                status="ok",
                request=request,
                active_decision=active_decision,
                candidate_decision=candidate_decision,
                flipped=active_decision.outcome != candidate_decision.outcome,
            )
        )
    ok_items = [i for i in items if i.status == "ok"]
    return PreviewReport(
        active_version=active_snapshot.version,
        candidate_version=candidate.version,
        total=len(items),
        ok_count=len(ok_items),
        error_count=len(items) - len(ok_items),
        flipped_count=sum(1 for i in ok_items if i.flipped),
        items=tuple(items),
    )
