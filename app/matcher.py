"""规则匹配与继承求值：对单个请求给出确定、可解释的判定。

判定规则（全部确定、可复现）：
1. 主体/资源未定义 -> deny（异常输入不得默认放行）。
2. 继承链有环 -> deny（加载期已拒绝，运行期防御性兜底）。
3. 规则匹配：主体/资源按"自身 + 全部继承祖先"匹配，"*" 通配；
   action 精确匹配或 "*"；条件全部满足（AND）。
4. 条件引用的属性缺失 -> 该规则视为不命中，且整体结论 fail-closed 为 deny，
   原因中明确指出缺失的属性。
5. 无任何规则命中 -> deny（默认拒绝）。
6. 多条规则命中时全部记录，排序键为 (-priority, deny 优先, rule_id 字典序)，
   取第一条为裁决规则 —— 同优先级下 deny 优先（fail-closed），
   同优先级同效果按 rule_id 字典序，保证结论稳定可复现。
"""
from __future__ import annotations

from typing import Any

from .models import (
    Condition,
    DecisionRequest,
    DecisionResult,
    MatchedRule,
    PolicyBundle,
    Rule,
)


class Matcher:
    """基于某个已生效策略包版本的求值器（不可变、可并发复用）。"""

    def __init__(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle
        # 初始化时一次性计算继承闭包与合并属性，之后只读，天然并发安全。
        self._subject_groups, self._subject_cycles = self._build_closures(
            {n: s.inherits for n, s in bundle.subjects.items()}
        )
        self._resource_groups, self._resource_cycles = self._build_closures(
            {n: r.inherits for n, r in bundle.resources.items()}
        )
        self._subject_attrs = self._build_merged_attrs(
            {n: s.attributes for n, s in bundle.subjects.items()},
            {n: s.inherits for n, s in bundle.subjects.items()},
        )
        self._resource_attrs = self._build_merged_attrs(
            {n: r.attributes for n, r in bundle.resources.items()},
            {n: r.inherits for n, r in bundle.resources.items()},
        )

    @property
    def version(self) -> str:
        return self._bundle.version

    # ---- 继承闭包与属性合并（初始化期计算） ----

    @staticmethod
    def _build_closures(
        graph: dict[str, tuple[str, ...]],
    ) -> tuple[dict[str, frozenset[str]], dict[str, tuple[str, ...]]]:
        """返回 (每个节点的祖先集合含自身, 每个节点检测到的环路径)。"""
        groups: dict[str, frozenset[str]] = {}
        cycles: dict[str, tuple[str, ...]] = {}

        def visit(node: str, stack: tuple[str, ...]) -> frozenset[str]:
            if node in groups:
                return groups[node]
            if node in stack:
                cycle = stack[stack.index(node):] + (node,)
                for member in stack[stack.index(node):]:
                    cycles[member] = cycle
                return frozenset()
            result: set[str] = {node}
            for parent in graph.get(node, ()):
                if parent in graph:
                    result |= visit(parent, stack + (node,))
            groups[node] = frozenset(result)
            return groups[node]

        for name in sorted(graph):
            visit(name, ())
        return groups, cycles

    @staticmethod
    def _build_merged_attrs(
        attrs: dict[str, dict[str, Any]],
        graph: dict[str, tuple[str, ...]],
    ) -> dict[str, dict[str, Any]]:
        """合并属性：子节点覆盖父节点；父节点按名称字典序合并保证确定性。"""
        merged: dict[str, dict[str, Any]] = {}

        def visit(node: str, stack: tuple[str, ...]) -> dict[str, Any]:
            if node in merged:
                return merged[node]
            if node in stack:
                return {}
            combined: dict[str, Any] = {}
            for parent in sorted(graph.get(node, ())):
                if parent in attrs:
                    combined.update(visit(parent, stack + (node,)))
            combined.update(attrs.get(node, {}))
            merged[node] = combined
            return combined

        for name in sorted(attrs):
            visit(name, ())
        return merged

    # ---- 条件求值 ----

    @staticmethod
    def _eval_condition(
        cond: Condition,
        subject_attrs: dict[str, Any],
        resource_attrs: dict[str, Any],
    ) -> tuple[bool, str | None]:
        """返回 (是否满足, 缺失的属性 key 或 None)。属性缺失一律视为不满足。"""
        scope, _, attr = cond.key.partition(".")
        table = subject_attrs if scope == "subject" else resource_attrs
        if cond.op == "exists":
            return (attr in table), None
        if attr not in table:
            return False, cond.key
        actual = table[attr]
        if cond.op == "eq":
            return actual == cond.value, None
        if cond.op == "neq":
            return actual != cond.value, None
        if cond.op == "in":
            return actual in cond.value, None
        if cond.op == "notin":
            return actual not in cond.value, None
        return False, cond.key  # 未知操作符 fail-closed

    # ---- 主求值入口 ----

    def evaluate(self, request: DecisionRequest) -> DecisionResult:
        trace: list[str] = []
        version = self._bundle.version

        def deny(reason: str, matched: tuple[MatchedRule, ...] = (),
                 winning: str | None = None) -> DecisionResult:
            return DecisionResult(
                decision="deny", version=version, matched_rules=matched,
                winning_rule=winning, reason=reason, trace=tuple(trace),
            )

        subject, action, resource = request.subject, request.action, request.resource
        trace.append(f"请求: subject={subject!r} action={action!r} resource={resource!r}")

        # 1. 异常输入：未定义的主体/资源 -> deny
        if subject not in self._bundle.subjects:
            return deny(f"主体 {subject!r} 未在策略包 {version} 中定义，拒绝")
        if resource not in self._bundle.resources:
            return deny(f"资源 {resource!r} 未在策略包 {version} 中定义，拒绝")

        # 2. 继承环（防御性兜底，正常情况加载期已拒绝）
        if subject in self._subject_cycles:
            cycle = " -> ".join(self._subject_cycles[subject])
            return deny(f"主体 {subject!r} 的继承链存在环 ({cycle})，拒绝")
        if resource in self._resource_cycles:
            cycle = " -> ".join(self._resource_cycles[resource])
            return deny(f"资源 {resource!r} 的继承链存在环 ({cycle})，拒绝")

        subject_groups = self._subject_groups[subject]
        resource_groups = self._resource_groups[resource]
        trace.append(f"主体继承组: {sorted(subject_groups)}")
        trace.append(f"资源继承组: {sorted(resource_groups)}")

        subject_attrs = self._subject_attrs[subject]
        resource_attrs = self._resource_attrs[resource]

        # 3. 收集全部命中规则（不跳过任何一条）
        matched: list[Rule] = []
        missing_attrs: list[str] = []
        for rule in self._bundle.rules:
            if not ("*" in rule.subjects or subject_groups & set(rule.subjects)):
                continue
            if not ("*" in rule.resources or resource_groups & set(rule.resources)):
                continue
            if not ("*" in rule.actions or action in rule.actions):
                continue
            rule_ok = True
            for cond in rule.conditions:
                ok, missing = self._eval_condition(cond, subject_attrs, resource_attrs)
                if not ok:
                    rule_ok = False
                    if missing is not None:
                        missing_attrs.append(f"规则 {rule.id!r} 需要属性 {missing!r}")
                        trace.append(
                            f"规则 {rule.id!r} 因属性缺失未命中: {missing!r}"
                        )
                    else:
                        trace.append(f"规则 {rule.id!r} 条件不满足，未命中")
                    break
            if rule_ok:
                matched.append(rule)
                trace.append(f"规则 {rule.id!r} 命中 (effect={rule.effect}, priority={rule.priority})")

        # 4. 属性缺失 -> fail-closed
        if missing_attrs:
            return deny(
                "属性缺失，无法确定性求值，拒绝: " + "; ".join(sorted(missing_attrs))
            )

        # 5. 无命中 -> 默认拒绝
        if not matched:
            return deny("没有任何规则命中，默认拒绝")

        # 6. 确定性裁决：优先级降序 -> deny 优先 -> rule_id 字典序
        ordered = sorted(matched, key=lambda r: (-r.priority, 0 if r.effect == "deny" else 1, r.id))
        winner = ordered[0]
        matched_info = tuple(
            MatchedRule(rule_id=r.id, effect=r.effect, priority=r.priority) for r in ordered
        )
        if len(ordered) > 1:
            trace.append(
                "多条规则命中，按 (-priority, deny 优先, rule_id) 排序: "
                + ", ".join(r.rule_id for r in matched_info)
            )
        trace.append(f"裁决规则: {winner.id!r} -> {winner.effect}")

        if winner.effect == "deny":
            return deny(f"被规则 {winner.id!r} 显式拒绝", matched_info, winner.id)
        return DecisionResult(
            decision="allow", version=version, matched_rules=matched_info,
            winning_rule=winner.id,
            reason=f"被规则 {winner.id!r} 允许",
            trace=tuple(trace),
        )
