"""Check Engine 检查引擎层 — 公共导出."""

from __future__ import annotations

from eks_health_check.checkers.base import (
    BaseChecker,
    CheckEngine,
    load_rules,
    rules_for_dimension,
)
from eks_health_check.checkers.infrastructure import InfrastructureChecker
from eks_health_check.checkers.network import NetworkChecker
from eks_health_check.checkers.security import SecurityChecker
from eks_health_check.checkers.workload import WorkloadChecker

__all__ = [
    "BaseChecker",
    "CheckEngine",
    "InfrastructureChecker",
    "NetworkChecker",
    "SecurityChecker",
    "WorkloadChecker",
    "load_rules",
    "rules_for_dimension",
    "build_default_engine",
]


def build_default_engine(yaml_path: str | None = None) -> CheckEngine:
    """构建包含所有默认 Checker 的 CheckEngine 实例."""
    rules = load_rules(yaml_path)
    engine = CheckEngine([
        InfrastructureChecker(rules=rules_for_dimension(rules, "infrastructure")),
        NetworkChecker(rules=rules_for_dimension(rules, "network")),
        SecurityChecker(rules=rules_for_dimension(rules, "security")),
        WorkloadChecker(rules=rules_for_dimension(rules, "workload")),
    ])
    return engine
