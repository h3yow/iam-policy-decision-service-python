"""授权判定引擎：继承求值 + 确定性冲突处理。

判定规则（全部确定、可复现）：

1. 主体/资源沿继承链向上展开（BFS，父节点按字典序遍历），
   得到候选集合及到达路径；继承环在加载期已被拒绝，此处仍用
   访问集合防御，绝不因环而放行或死循环。
2. 规则匹配：subjects/actions/resources 为空表示通配；condition 中
   每个键都必须在请求上下文中存在且相等，属性缺失即不匹配，
   不会默认放行。
3. 冲突处理：所有命中规则都会记录在 Decision.matched_rules 中，
   不跳过、不静默取舍。最终结论取最高优先级；同一最高优先级内
   同时存在 allow 与 deny 时，deny 优先（安全方向，且确定）。
4. 无任何规则命中时默认拒绝，并说明原因。
"""
from __future__ import annotations

from .models import (
    Decision,
    DecisionOutcome,
    DecisionRequest,
    Effect,
    Hierarchy,
    MatchedRule,
    PolicyPackage,
    Rule,
)


def _expand(node: str, hierarchy: Hierarchy) -> dict[str, tuple[str, ...]]:
    """返回 {祖先节点: 从 node 出发的路径}，含 node 自身。确定性 BFS。"""
    paths: dict[str, tuple[str, ...]] = {node: (node,)}
    queue = [node]
    while queue:
        current = queue.pop(0)
        for parent in sorted(hierarchy.parents.get(current, ())):
            if parent in paths:  # 防御环；加载期已保证无环
                continue
            paths[parent] = paths[current] + (parent,)
            queue.append(parent)
    return paths


def _condition_matches(rule: Rule, request: DecisionRequest) -> bool:
    return all(request.context.get(k) == v for k, v in rule.condition.items())


def _match_rule(
    rule: Rule,
    request: DecisionRequest,
    subject_paths: dict[str, tuple[str, ...]],
    resource_paths: dict[str, tuple[str, ...]],
) -> MatchedRule | None:
    subject_path: tuple[str, ...] = ()
    if rule.subjects:
        hits = [s for s in rule.subjects if s in subject_paths]
        if not hits:
            return None
        subject_path = subject_paths[min(hits)]
    if rule.actions and request.action not in rule.actions:
        return None
    resource_path: tuple[str, ...] = ()
    if rule.resources:
        hits = [r for r in rule.resources if r in resource_paths]
        if not hits:
            return None
        resource_path = resource_paths[min(hits)]
    if not _condition_matches(rule, request):
        return None
    return MatchedRule(
        rule_id=rule.rule_id,
        effect=rule.effect,
        priority=rule.priority,
        subject_path=subject_path,
        resource_path=resource_path,
    )


def evaluate(package: PolicyPackage, request: DecisionRequest) -> Decision:
    """对请求求值，返回确定且可解释的判定结论。"""
    subject_paths = _expand(request.subject, package.subject_hierarchy)
    resource_paths = _expand(request.resource, package.resource_hierarchy)

    matched = [
        m
        for rule in package.rules
        if (m := _match_rule(rule, request, subject_paths, resource_paths)) is not None
    ]
    # 稳定排序：优先级降序，规则 ID 升序
    matched.sort(key=lambda m: (-m.priority, m.rule_id))

    if not matched:
        return Decision(
            outcome=DecisionOutcome.DENY,
            policy_version=package.version,
            reason="无任何规则命中，默认拒绝",
            matched_rules=(),
        )

    top_priority = matched[0].priority
    top = [m for m in matched if m.priority == top_priority]
    top_ids = [m.rule_id for m in top]
    denies = [m for m in top if m.effect == Effect.DENY]

    if denies:
        outcome = DecisionOutcome.DENY
        reason = (
            f"最高优先级 {top_priority} 的规则 {top_ids} 中存在 deny，"
            f"deny 优先，最终拒绝"
        )
    else:
        outcome = DecisionOutcome.ALLOW
        reason = f"最高优先级 {top_priority} 的规则 {top_ids} 均为 allow，最终允许"

    return Decision(
        outcome=outcome,
        policy_version=package.version,
        reason=reason,
        matched_rules=tuple(matched),
    )
