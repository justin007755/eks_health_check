"""Check Engine — BaseChecker ABC 和 CheckEngine 编排器."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import yaml

from eks_health_check.models import CheckResult, ClusterConfig


class BaseChecker(ABC):
    """检查器抽象基类，所有维度 Checker 继承此类."""

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        self.rules: list[dict[str, Any]] = rules or []

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        """按 rule_id 查找规则配置."""
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None

    @abstractmethod
    def check(self, config: ClusterConfig) -> list[CheckResult]:
        """执行检查，返回检查结果列表."""


def load_rules(yaml_path: str | Path | None = None) -> list[dict[str, Any]]:
    """从 YAML 文件加载检查规则."""
    if yaml_path is None:
        yaml_path = Path(__file__).resolve().parent.parent / "check_rules.yaml"
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("rules", [])


def rules_for_dimension(rules: list[dict[str, Any]], dimension: str) -> list[dict[str, Any]]:
    """筛选指定维度的规则."""
    return [r for r in rules if r.get("dimension") == dimension]


class CheckEngine:
    """检查引擎，注册并顺序执行所有 Checker."""

    def __init__(self, checkers: list[BaseChecker] | None = None) -> None:
        self.checkers: list[BaseChecker] = checkers or []

    def register(self, checker: BaseChecker) -> None:
        self.checkers.append(checker)

    def run(self, config: ClusterConfig) -> list[CheckResult]:
        """顺序执行所有 Checker，汇总 CheckResult."""
        results: list[CheckResult] = []
        for checker in self.checkers:
            results.extend(checker.check(config))
        return results
