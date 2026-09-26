"""策略包解析与校验：先语法后语义，失败抛出可区分的错误。

策略包为 JSON 文本，结构示例::

    {
      "version": "v1",
      "subjects": {"alice": ["employee"]},
      "resources": {"doc-1": ["folder-a"]},
      "rules": [
        {"id": "r1", "effect": "allow", "priority": 10,
         "subjects": ["employee"], "actions": ["read"],
         "resources": ["folder-a"], "condition": {"env": "prod"}}
      ]
    }
"""
from __future__ import annotations

import json
from typing import Any

from .errors import PolicySemanticError, PolicySyntaxError
from .models import Effect, Hierarchy, PolicyPackage, Rule

_REQUIRED_RULE_FIELDS = ("id", "effect", "priority")


def _fail_syntax(msg: str) -> None:
    raise PolicySyntaxError(msg)


def _check_str_list(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        _fail_syntax(f"{where} 必须是非字符串以外的字符串列表")
    return tuple(value)


def _parse_hierarchy(raw: Any, name: str) -> Hierarchy:
    if raw is None:
        return Hierarchy()
    if not isinstance(raw, dict):
        _fail_syntax(f"{name} 必须是对象（子节点 -> 父节点列表）")
    parents: dict[str, tuple[str, ...]] = {}
    for child, plist in raw.items():
        if not isinstance(child, str):
            _fail_syntax(f"{name} 的键必须是字符串")
        parents[child] = _check_str_list(plist, f"{name}[{child!r}]")
    return Hierarchy(parents=parents)


def _check_no_cycle(hierarchy: Hierarchy, name: str) -> None:
    """DFS 三色标记检测继承环，发现环则抛 PolicySemanticError。"""
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {}

    def visit(node: str, stack: list[str]) -> None:
        color[node] = GRAY
        stack.append(node)
        for parent in hierarchy.parents.get(node, ()):
            state = color.get(parent, WHITE)
            if state == GRAY:
                idx = stack.index(parent)
                cycle = " -> ".join(stack[idx:] + [parent])
                raise PolicySemanticError(f"{name} 存在继承环: {cycle}")
            if state == WHITE:
                visit(parent, stack)
        stack.pop()
        color[node] = BLACK

    for node in hierarchy.parents:
        if color.get(node, WHITE) == WHITE:
            visit(node, [])


def _parse_rule(raw: Any, index: int) -> Rule:
    where = f"rules[{index}]"
    if not isinstance(raw, dict):
        _fail_syntax(f"{where} 必须是对象")
    for key in _REQUIRED_RULE_FIELDS:
        if key not in raw:
            _fail_syntax(f"{where} 缺少必填字段 {key!r}")
    rule_id = raw["id"]
    if not isinstance(rule_id, str) or not rule_id:
        _fail_syntax(f"{where}.id 必须是非空字符串")
    try:
        effect = Effect(raw["effect"])
    except ValueError:
        _fail_syntax(f"{where}.effect 必须是 'allow' 或 'deny'，得到 {raw['effect']!r}")
    priority = raw["priority"]
    if not isinstance(priority, int) or isinstance(priority, bool):
        _fail_syntax(f"{where}.priority 必须是整数")
    condition = raw.get("condition", {})
    if not isinstance(condition, dict) or not all(isinstance(k, str) for k in condition):
        _fail_syntax(f"{where}.condition 必须是字符串键的对象")
    return Rule(
        rule_id=rule_id,
        effect=effect,
        priority=priority,
        subjects=_check_str_list(raw.get("subjects", []), f"{where}.subjects"),
        actions=_check_str_list(raw.get("actions", []), f"{where}.actions"),
        resources=_check_str_list(raw.get("resources", []), f"{where}.resources"),
        condition=dict(condition),
    )


def _check_rule_semantics(rules: tuple[Rule, ...]) -> None:
    seen: set[str] = set()
    for rule in rules:
        if rule.rule_id in seen:
            raise PolicySemanticError(f"规则 ID 重复: {rule.rule_id!r}")
        seen.add(rule.rule_id)
    # 完全相同的匹配面却给出相反结论且优先级相同 -> 不可判定的矛盾
    by_shape: dict[tuple, Rule] = {}
    for rule in rules:
        shape = (
            rule.subjects,
            rule.actions,
            rule.resources,
            tuple(sorted(rule.condition.items())),
            rule.priority,
        )
        other = by_shape.get(shape)
        if other is not None and other.effect != rule.effect:
            raise PolicySemanticError(
                f"规则 {other.rule_id!r} 与 {rule.rule_id!r} 匹配面相同、"
                f"优先级相同但结论相反，无法确定判定"
            )
        by_shape[shape] = rule


def parse_policy_package(raw: str) -> PolicyPackage:
    """解析并完整校验策略包文本，返回不可变的 PolicyPackage。

    校验顺序：JSON 语法 -> 字段语法 -> 语义（继承环、规则冲突）。
    任何失败都抛出 PolicyError 子类，调用方可据此区分拒绝原因。
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicySyntaxError(f"JSON 解析失败: {exc}") from exc
    if not isinstance(data, dict):
        _fail_syntax("策略包顶层必须是 JSON 对象")

    version = data.get("version")
    if not isinstance(version, str) or not version:
        _fail_syntax("version 必须是非空字符串")

    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        _fail_syntax("rules 必须是列表")
    rules = tuple(_parse_rule(r, i) for i, r in enumerate(rules_raw))

    subject_hierarchy = _parse_hierarchy(data.get("subjects"), "subjects")
    resource_hierarchy = _parse_hierarchy(data.get("resources"), "resources")

    _check_no_cycle(subject_hierarchy, "subjects")
    _check_no_cycle(resource_hierarchy, "resources")
    _check_rule_semantics(rules)

    return PolicyPackage(
        version=version,
        rules=rules,
        subject_hierarchy=subject_hierarchy,
        resource_hierarchy=resource_hierarchy,
    )
