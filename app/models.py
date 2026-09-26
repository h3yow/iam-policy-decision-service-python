"""核心数据模型：策略包、规则、决策请求与结果。"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

Effect = Literal["allow", "deny"]
Decision = Literal["allow", "deny"]


class RejectReason(str, Enum):
    """策略包被拒绝的原因分类，须可区分。"""

    SYNTAX_ERROR = "syntax_error"          # JSON/YAML 语法非法、字段类型错误
    SEMANTIC_ERROR = "semantic_error"      # 语义冲突：引用缺失、继承环、规则矛盾等
    DUPLICATE_VERSION = "duplicate_version"  # 版本号与已加载版本重复


class PolicyRejectError(Exception):
    """策略包加载/校验失败，携带可区分的拒绝原因。"""

    def __init__(self, reason: RejectReason, message: str, details: list[str] | None = None):
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.details = details or []


@dataclass(frozen=True)
class SubjectDef:
    """主体定义：可继承其他主体，携带属性。"""

    name: str
    inherits: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResourceDef:
    """资源定义：可继承其他资源，携带属性。"""

    name: str
    inherits: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Condition:
    """属性条件（全部 AND）。key 形如 subject.team / resource.classification。"""

    key: str
    op: str  # eq | neq | in | notin | exists
    value: Any = None


@dataclass(frozen=True)
class Rule:
    """单条授权规则。subjects/actions/resources 中 "*" 表示通配。"""

    id: str
    effect: Effect
    priority: int
    subjects: tuple[str, ...]
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    description: str = ""
    conditions: tuple[Condition, ...] = ()


@dataclass(frozen=True)
class PolicyBundle:
    """一个完整策略包版本。"""

    version: str
    subjects: dict[str, SubjectDef]
    resources: dict[str, ResourceDef]
    rules: tuple[Rule, ...]


@dataclass(frozen=True)
class DecisionRequest:
    subject: str
    action: str
    resource: str


@dataclass(frozen=True)
class MatchedRule:
    """命中规则的记录，用于可追溯解释。"""

    rule_id: str
    effect: Effect
    priority: int


@dataclass(frozen=True)
class DecisionResult:
    """判定结论：稳定、可解释。"""

    decision: Decision
    version: str
    matched_rules: tuple[MatchedRule, ...]
    winning_rule: str | None
    reason: str
    trace: tuple[str, ...] = ()
