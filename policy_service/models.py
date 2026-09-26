"""策略与决策的数据模型（仅类型定义）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Rule:
    """单条授权规则。"""

    rule_id: str
    effect: Effect
    priority: int
    subjects: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    condition: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Hierarchy:
    """主体/资源继承关系：child -> parents。"""

    parents: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyPackage:
    """一个完整、不可变的策略版本。"""

    version: str
    rules: tuple[Rule, ...]
    subject_hierarchy: Hierarchy
    resource_hierarchy: Hierarchy


@dataclass(frozen=True)
class DecisionRequest:
    """一次授权判定请求。"""

    subject: str
    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MatchedRule:
    """被命中的规则及其生效路径，用于可追溯解释。"""

    rule_id: str
    effect: Effect
    priority: int
    subject_path: tuple[str, ...] = ()
    resource_path: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    """判定结论与依据。"""

    outcome: DecisionOutcome
    policy_version: str
    reason: str
    matched_rules: tuple[MatchedRule, ...] = ()
