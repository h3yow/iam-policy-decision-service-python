"""策略版本仓库：加载、校验、原子切换与回滚。

- load() 先完整校验，校验失败抛错且不改变任何状态；
  版本号重复抛 DuplicateVersionError，与语法/语义错误可区分。
- activate() 只接受已登记且校验通过的版本，单条赋值完成原子切换；
  切换失败（版本不存在）不影响当前生效版本，天然支持回滚。
- active() 在锁内读取，保证并发请求拿到一致的策略包。
"""
from __future__ import annotations

import threading

from .errors import DuplicateVersionError, PolicyError
from .loader import parse_policy_package
from .models import PolicyPackage


class PolicyStore:
    """线程安全的策略版本仓库。只有校验通过的版本才能生效。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._versions: dict[str, PolicyPackage] = {}
        self._active_version: str | None = None

    def load(self, raw: str) -> PolicyPackage:
        """解析、校验并登记新版本；任何失败都不影响当前生效版本。"""
        package = parse_policy_package(raw)  # 语法/语义错误在此抛出
        with self._lock:
            if package.version in self._versions:
                raise DuplicateVersionError(f"策略版本已存在: {package.version!r}")
            self._versions[package.version] = package
        return package

    def activate(self, version: str) -> PolicyPackage:
        """原子切换到指定已登记版本；版本不存在则抛错且状态不变。"""
        with self._lock:
            package = self._versions.get(version)
            if package is None:
                raise PolicyError(f"策略版本不存在，无法切换: {version!r}")
            self._active_version = version
            return package

    def active(self) -> PolicyPackage:
        """返回当前生效版本；无生效版本时抛错。"""
        with self._lock:
            if self._active_version is None:
                raise PolicyError("当前没有生效的策略版本")
            return self._versions[self._active_version]

    def has_version(self, version: str) -> bool:
        """只读查询版本是否已登记（供预演做版本号冲突校验，不登记任何内容）。"""
        with self._lock:
            return version in self._versions

    def active_version(self) -> str | None:
        with self._lock:
            return self._active_version

    def versions(self) -> list[str]:
        with self._lock:
            return sorted(self._versions)
