"""InfrastructureChecker — 基础架构评估 (INFRA-001 ~ INFRA-005)."""

from __future__ import annotations

from typing import Any

from eks_health_check.models import CheckDimension, CheckResult, ClusterConfig, RiskLevel
from eks_health_check.checkers.base import BaseChecker

# EKS 版本生命周期参考（简化版，实际应从 AWS API 获取）
_EKS_EOL_VERSIONS: set[str] = {"1.23", "1.24", "1.25", "1.26"}
_EKS_APPROACHING_EOL: set[str] = {"1.27", "1.28"}

_DIM = CheckDimension.INFRASTRUCTURE


class InfrastructureChecker(BaseChecker):
    """基础架构评估：节点组、资源利用率、Autoscaler、集群版本."""

    def check(self, config: ClusterConfig) -> list[CheckResult]:
        results: list[CheckResult] = []
        results.extend(self._check_instance_diversity(config))
        results.extend(self._check_az_distribution(config))
        results.extend(self._check_resource_utilization(config))
        results.extend(self._check_autoscaler(config))
        results.extend(self._check_cluster_version(config))
        return results

    # -- INFRA-001 节点组实例类型多样性 --
    def _check_instance_diversity(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("INFRA-001")
        if rule is None:
            return []
        min_types = rule.get("threshold", {}).get("min_instance_types", 2)
        results: list[CheckResult] = []
        for ng in config.aws.node_groups:
            passed = len(ng.instance_types) >= min_types
            results.append(CheckResult(
                rule_id="INFRA-001",
                name=rule["name"],
                dimension=_DIM,
                risk_level=RiskLevel.WARNING,
                passed=passed,
                current_value=", ".join(ng.instance_types),
                expected_value=f">= {min_types} 种实例类型",
                message=(
                    f"节点组 {ng.name} 使用了 {len(ng.instance_types)} 种实例类型"
                    if passed
                    else f"节点组 {ng.name} 仅使用单一实例类型 {ng.instance_types}，建议引入多实例类型以提升可用性"
                ),
                resources=[ng.name],
            ))
        return results

    # -- INFRA-002 AZ 分布 --
    def _check_az_distribution(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("INFRA-002")
        if rule is None:
            return []
        min_azs = rule.get("threshold", {}).get("min_azs", 2)
        results: list[CheckResult] = []
        for ng in config.aws.node_groups:
            passed = len(ng.availability_zones) >= min_azs
            results.append(CheckResult(
                rule_id="INFRA-002",
                name=rule["name"],
                dimension=_DIM,
                risk_level=RiskLevel.WARNING,
                passed=passed,
                current_value=", ".join(ng.availability_zones),
                expected_value=f">= {min_azs} 个可用区",
                message=(
                    f"节点组 {ng.name} 跨 {len(ng.availability_zones)} 个可用区"
                    if passed
                    else f"节点组 {ng.name} 仅部署在 {len(ng.availability_zones)} 个可用区，建议跨多 AZ 部署"
                ),
                resources=[ng.name],
            ))
        return results

    # -- INFRA-003 节点资源利用率 --
    def _check_resource_utilization(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("INFRA-003")
        if rule is None:
            return []
        threshold = rule.get("threshold", {})
        max_cpu = threshold.get("max_cpu_ratio", 0.85)
        max_mem = threshold.get("max_memory_ratio", 0.85)

        total_cpu_request = 0.0
        total_cpu_alloc = 0.0
        total_mem_request = 0.0
        total_mem_alloc = 0.0

        for node in config.k8s.nodes:
            alloc = node.get("allocatable", {})
            total_cpu_alloc += _parse_cpu(alloc.get("cpu", "0"))
            total_mem_alloc += _parse_memory(alloc.get("memory", "0"))

        for pod in config.k8s.workloads.pods:
            for container in pod.get("containers", []):
                req = container.get("resources", {}).get("requests", {})
                total_cpu_request += _parse_cpu(req.get("cpu", "0"))
                total_mem_request += _parse_memory(req.get("memory", "0"))

        cpu_ratio = total_cpu_request / total_cpu_alloc if total_cpu_alloc > 0 else 0
        mem_ratio = total_mem_request / total_mem_alloc if total_mem_alloc > 0 else 0

        results: list[CheckResult] = []
        cpu_passed = cpu_ratio <= max_cpu
        results.append(CheckResult(
            rule_id="INFRA-003",
            name=rule["name"] + " (CPU)",
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=cpu_passed,
            current_value=f"{cpu_ratio:.1%}",
            expected_value=f"<= {max_cpu:.0%}",
            message=(
                f"CPU request 占比 {cpu_ratio:.1%}，在合理范围内"
                if cpu_passed
                else f"CPU request 占比 {cpu_ratio:.1%}，超过阈值 {max_cpu:.0%}，存在资源过度分配风险"
            ),
        ))
        mem_passed = mem_ratio <= max_mem
        results.append(CheckResult(
            rule_id="INFRA-003",
            name=rule["name"] + " (Memory)",
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=mem_passed,
            current_value=f"{mem_ratio:.1%}",
            expected_value=f"<= {max_mem:.0%}",
            message=(
                f"Memory request 占比 {mem_ratio:.1%}，在合理范围内"
                if mem_passed
                else f"Memory request 占比 {mem_ratio:.1%}，超过阈值 {max_mem:.0%}，存在资源过度分配风险"
            ),
        ))
        return results

    # -- INFRA-004 自动伸缩组件 --
    def _check_autoscaler(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("INFRA-004")
        if rule is None:
            return []
        has_autoscaler = False
        for addon in config.k8s.addons:
            name = addon.get("name", "").lower()
            if "karpenter" in name or "cluster-autoscaler" in name:
                has_autoscaler = True
                break
        # Also check deployments
        if not has_autoscaler:
            for dep in config.k8s.workloads.deployments:
                dep_name = dep.get("name", "").lower()
                if "karpenter" in dep_name or "cluster-autoscaler" in dep_name:
                    has_autoscaler = True
                    break
        return [CheckResult(
            rule_id="INFRA-004",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.INFO,
            passed=has_autoscaler,
            current_value="已启用" if has_autoscaler else "未检测到",
            expected_value="Karpenter 或 Cluster Autoscaler",
            message=(
                "集群已使用自动伸缩组件"
                if has_autoscaler
                else "未检测到 Karpenter 或 Cluster Autoscaler，建议评估引入自动伸缩组件的可行性"
            ),
        )]

    # -- INFRA-005 EKS 集群版本生命周期 --
    def _check_cluster_version(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("INFRA-005")
        if rule is None:
            return []
        version = config.k8s.cluster_version
        if version in _EKS_EOL_VERSIONS:
            passed, msg = False, f"集群版本 {version} 已超出 AWS 支持生命周期，请尽快升级"
            risk = RiskLevel.CRITICAL
        elif version in _EKS_APPROACHING_EOL:
            passed, msg = False, f"集群版本 {version} 即将到达 End of Support，建议规划升级"
            risk = RiskLevel.WARNING
        else:
            passed, msg = True, f"集群版本 {version} 在 AWS 支持的生命周期内"
            risk = RiskLevel.WARNING
        return [CheckResult(
            rule_id="INFRA-005",
            name=rule["name"],
            dimension=_DIM,
            risk_level=risk,
            passed=passed,
            current_value=version,
            expected_value="AWS 支持的 EKS 版本",
            message=msg,
        )]


# ---------------------------------------------------------------------------
# 辅助函数：解析 K8s 资源量
# ---------------------------------------------------------------------------

def _parse_cpu(value: str) -> float:
    """将 K8s CPU 值（如 '500m', '2'）转为核心数."""
    value = str(value).strip()
    if not value or value == "0":
        return 0.0
    if value.endswith("m"):
        return float(value[:-1]) / 1000
    return float(value)


def _parse_memory(value: str) -> float:
    """将 K8s 内存值（如 '512Mi', '2Gi'）转为 MiB."""
    value = str(value).strip()
    if not value or value == "0":
        return 0.0
    units = {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024, "Ti": 1024 * 1024}
    for suffix, factor in units.items():
        if value.endswith(suffix):
            return float(value[: -len(suffix)]) * factor
    # plain bytes
    try:
        return float(value) / (1024 * 1024)
    except ValueError:
        return 0.0
