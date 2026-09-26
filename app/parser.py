"""策略包解析：文本 -> PolicyBundle，语法层校验。"""
from __future__ import annotations

import json
from typing import Any

import yaml

from .models import (
    Condition,
    PolicyBundle,
    PolicyRejectError,
    RejectReason,
    ResourceDef,
    Rule,
    SubjectDef,
)


def _syntax_error(message: str, details: list[str] | None = None) -> PolicyRejectError:
    return PolicyRejectError(RejectReason.SYNTAX_ERROR, message, details)


def _require_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise _syntax_error(f"{where} 必须是非空字符串，得到: {value!r}")
    return value


def _require_str_list(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise _syntax_error(f"{where} 必须是非空字符串数组，得到: {value!r}")
    if not value:
        raise _syntax_error(f"{where} 不能为空数组")
    return tuple(value)


def _parse_entity(name: str, raw: Any, kind: str) -> SubjectDef | ResourceDef:
    if not isinstance(raw, dict):
        raise _syntax_error(f"{kind} {name!r} 的定义必须是对象，得到: {raw!r}")
    inherits = raw.get("inherits", [])
    if not isinstance(inherits, list) or not all(isinstance(v, str) and v for v in inherits):
        raise _syntax_error(f"{kind} {name!r} 的 inherits 必须是字符串数组")
    attributes = raw.get("attributes", {})
    if not isinstance(attributes, dict):
        raise _syntax_error(f"{kind} {name!r} 的 attributes 必须是对象")
    cls = SubjectDef if kind == "subject" else ResourceDef
    return cls(name=name, inherits=tuple(inherits), attributes=dict(attributes))


_ALLOWED_OPS = {"eq", "neq", "in", "notin", "exists"}


def _parse_conditions(raw: Any, where: str) -> tuple[Condition, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not raw:
        raise _syntax_error(f"{where} 必须是非空条件数组")
    conditions: list[Condition] = []
    for i, item in enumerate(raw):
        cwhere = f"{where}[{i}]"
        if not isinstance(item, dict):
            raise _syntax_error(f"{cwhere} 必须是对象")
        key = _require_str(item.get("key"), f"{cwhere}.key")
        op = item.get("op")
        if op not in _ALLOWED_OPS:
            raise _syntax_error(f"{cwhere}.op 必须是 {sorted(_ALLOWED_OPS)} 之一")
        if "." not in key or key.split(".", 1)[0] not in ("subject", "resource"):
            raise _syntax_error(f"{cwhere}.key 必须形如 subject.<attr> 或 resource.<attr>")
        value = item.get("value")
        if op in ("in", "notin") and (not isinstance(value, list) or not value):
            raise _syntax_error(f"{cwhere} op={op} 的 value 必须是非空数组")
        if op in ("eq", "neq") and value is None:
            raise _syntax_error(f"{cwhere} op={op} 的 value 不能为 null")
        conditions.append(Condition(key=key, op=op, value=value))
    return tuple(conditions)


def _parse_rule(raw: Any, index: int) -> Rule:
    where = f"rules[{index}]"
    if not isinstance(raw, dict):
        raise _syntax_error(f"{where} 必须是对象，得到: {raw!r}")
    rule_id = _require_str(raw.get("id"), f"{where}.id")
    effect = raw.get("effect")
    if effect not in ("allow", "deny"):
        raise _syntax_error(f"{where}.effect 必须是 'allow' 或 'deny'，得到: {effect!r}")
    priority = raw.get("priority", 0)
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise _syntax_error(f"{where}.priority 必须是整数，得到: {priority!r}")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise _syntax_error(f"{where}.description 必须是字符串")
    return Rule(
        id=rule_id,
        effect=effect,
        priority=priority,
        subjects=_require_str_list(raw.get("subjects"), f"{where}.subjects"),
        actions=_require_str_list(raw.get("actions"), f"{where}.actions"),
        resources=_require_str_list(raw.get("resources"), f"{where}.resources"),
        description=description,
        conditions=_parse_conditions(raw.get("conditions"), f"{where}.conditions"),
    )


def parse_bundle(text: str) -> PolicyBundle:
    """解析策略包文本（JSON 或 YAML）。

    语法非法时抛出 PolicyRejectError(reason=SYNTAX_ERROR)。
    """
    if not isinstance(text, str) or not text.strip():
        raise _syntax_error("策略包内容为空或不是字符串")

    data: Any
    try:
        data = json.loads(text)
    except json.JSONDecodeError as json_err:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as yaml_err:
            raise _syntax_error(
                "策略包语法非法：既不是合法 JSON 也不是合法 YAML",
                [f"JSON: {json_err}", f"YAML: {yaml_err}"],
            ) from None
        if not isinstance(data, dict):
            raise _syntax_error(
                "策略包语法非法：不是合法 JSON，按 YAML 解析后顶层也不是对象",
                [f"JSON: {json_err}"],
            )

    if not isinstance(data, dict):
        raise _syntax_error(f"策略包顶层必须是对象，得到: {type(data).__name__}")

    version = _require_str(data.get("version"), "version")

    subjects_raw = data.get("subjects", {})
    if not isinstance(subjects_raw, dict):
        raise _syntax_error("subjects 必须是对象（名称 -> 定义）")
    subjects = {
        _require_str(name, "subject 名称"): _parse_entity(name, raw, "subject")
        for name, raw in subjects_raw.items()
    }

    resources_raw = data.get("resources", {})
    if not isinstance(resources_raw, dict):
        raise _syntax_error("resources 必须是对象（名称 -> 定义）")
    resources = {
        _require_str(name, "resource 名称"): _parse_entity(name, raw, "resource")
        for name, raw in resources_raw.items()
    }

    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        raise _syntax_error("rules 必须是数组")
    rules = tuple(_parse_rule(raw, i) for i, raw in enumerate(rules_raw))

    return PolicyBundle(version=version, subjects=subjects, resources=resources, rules=rules)
