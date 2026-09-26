"""策略加载与校验的错误类型，拒绝原因可区分。"""


class PolicyError(Exception):
    """策略相关错误基类。"""


class PolicySyntaxError(PolicyError):
    """策略包语法非法（JSON 解析失败、字段类型错误、必填字段缺失）。"""


class PolicySemanticError(PolicyError):
    """策略包语义冲突（继承环、重复规则 ID、矛盾规则等）。"""


class DuplicateVersionError(PolicyError):
    """策略版本号已存在。"""
