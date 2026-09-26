"""策略包语义校验：引用完整性、继承环、规则矛盾。"""
from __future__ import annotations

from .models import PolicyBundle, PolicyRejectError, RejectReason


def _find_cycles(nodes: dict[str, tuple[str, ...]]) -> list[list[str]]:
    """在有向图中找所有继承环（DFS，确定性顺序）。"""
    cycles: list[list[str]] = []
    seen_cycles: set[frozenset[str]] = set()
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {name: WHITE for name in nodes}

    def dfs(node: str, stack: list[str]) -> None:
        color[node] = GRAY
        stack.append(node)
        for parent in nodes.get(node, ()):
            if parent not in nodes:
                continue  # 引用缺失由其他检查报告
            if color[parent] == GRAY:
                cycle = stack[stack.index(parent):]
                key = frozenset(cycle)
                if key not in seen_cycles:
                    seen_cycles.add(key)
                    cycles.append(cycle + [parent])
            elif color[parent] == WHITE:
                dfs(parent, stack)
        stack.pop()
        color[node] = BLACK

    for name in sorted(nodes):
        if color[name] == WHITE:
            dfs(name, [])
    return cycles


def validate_bundle(bundle: PolicyBundle) -> None:
    """对解析后的策略包做语义校验。

    发现语义冲突时抛出 PolicyRejectError(reason=SEMANTIC_ERROR)，
    details 中列出全部问题。
    """
    problems: list[str] = []

    # 1. 规则 id 唯一性
    seen_ids: set[str] = set()
    for rule in bundle.rules:
        if rule.id in seen_ids:
            problems.append(f"规则 id 重复: {rule.id!r}")
        seen_ids.add(rule.id)

    # 2. 继承引用完整性
    for kind, entities in (("subject", bundle.subjects), ("resource", bundle.resources)):
        for name, entity in entities.items():
            for parent in entity.inherits:
                if parent not in entities:
                    problems.append(f"{kind} {name!r} 继承了未定义的 {parent!r}")
                if parent == name:
                    problems.append(f"{kind} {name!r} 不能继承自身")

    # 3. 继承环检测
    for kind, entities in (("subject", bundle.subjects), ("resource", bundle.resources)):
        graph = {name: e.inherits for name, e in entities.items()}
        for cycle in _find_cycles(graph):
            problems.append(f"{kind} 继承链存在环: {' -> '.join(cycle)}")

    # 4. 规则引用的主体/资源必须已定义（"*" 除外）
    for rule in bundle.rules:
        for subject in rule.subjects:
            if subject != "*" and subject not in bundle.subjects:
                problems.append(f"规则 {rule.id!r} 引用了未定义的主体 {subject!r}")
        for resource in rule.resources:
            if resource != "*" and resource not in bundle.resources:
                problems.append(f"规则 {rule.id!r} 引用了未定义的资源 {resource!r}")

    # 5. 规则矛盾：匹配范围完全相同、优先级相同但效果相反的规则对，
    #    无法确定性地裁决，必须在加载期拒绝。
    by_scope: dict[tuple, list] = {}
    for rule in bundle.rules:
        key = (
            frozenset(rule.subjects),
            frozenset(rule.actions),
            frozenset(rule.resources),
            rule.priority,
        )
        by_scope.setdefault(key, []).append(rule)
    for rules in by_scope.values():
        effects = {r.effect for r in rules}
        if len(rules) > 1 and len(effects) > 1:
            ids = sorted(r.id for r in rules)
            problems.append(
                f"规则矛盾: {ids} 匹配范围与优先级完全相同但效果冲突，无法确定性裁决"
            )

    if problems:
        raise PolicyRejectError(
            RejectReason.SEMANTIC_ERROR,
            f"策略包 {bundle.version!r} 语义校验失败，共 {len(problems)} 个问题",
            problems,
        )
