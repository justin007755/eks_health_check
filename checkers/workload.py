"""WorkloadChecker — 应用适配性检查 (WORK-001 ~ WORK-006)."""

from __future__ import annotations

from eks_health_check.models import CheckDimension, CheckResult, ClusterConfig, RiskLevel
from eks_health_check.checkers.base import BaseChecker

_DIM = CheckDimension.WORKLOAD


class WorkloadChecker(BaseChecker):
    """应用适配性检查：资源配置、PDB、HPA、健康检查、Pod Identity."""

    def check(self, config: ClusterConfig) -> list[CheckResult]:
        results: list[CheckResult] = []
        results.extend(self._check_resource_requests(config))
        results.extend(self._check_resource_ratio(config))
        results.extend(self._check_pdb(config))
        results.extend(self._check_hpa(config))
        results.extend(self._check_probes(config))
        results.extend(self._check_pod_identity(config))
        return results

    # -- WORK-001 Pod 资源 request/limit 配置 --
    def _check_resource_requests(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("WORK-001")
        if rule is None:
            return []
        missing: list[str] = []
        for pod in config.k8s.workloads.pods:
            pod_name = pod.get("name", "unknown")
            ns = pod.get("namespace", "default")
            for container in pod.get("containers", []):
                res = container.get("resources", {})
                requests = res.get("requests", {})
                limits = res.get("limits", {})
                if not requests or not limits:
                    missing.append(f"{ns}/{pod_name}/{container.get('name', '?')}")
        passed = len(missing) == 0
        return [CheckResult(
            rule_id="WORK-001",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=passed,
            current_value=f"{len(missing)} 个容器未设置完整的 request/limit" if not passed else "全部已设置",
            expected_value="所有容器均设置 CPU/Memory request 和 limit",
            message=(
                "所有 Pod 容器均已设置资源 request 和 limit"
                if passed
                else f"发现 {len(missing)} 个容器未设置完整的资源 request 或 limit，可能导致调度不稳定"
            ),
            resources=missing[:20],  # 限制输出数量
        )]

    # -- WORK-002 资源 request 与 limit 差异 --
    def _check_resource_ratio(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("WORK-002")
        if rule is None:
            return []
        max_ratio = rule.get("threshold", {}).get("max_ratio", 3)
        offending: list[str] = []
        for pod in config.k8s.workloads.pods:
            pod_name = pod.get("name", "unknown")
            ns = pod.get("namespace", "default")
            for container in pod.get("containers", []):
                res = container.get("resources", {})
                requests = res.get("requests", {})
                limits = res.get("limits", {})
                if not requests or not limits:
                    continue
                for resource_type in ("cpu", "memory"):
                    req_val = _parse_resource(requests.get(resource_type, "0"), resource_type)
                    lim_val = _parse_resource(limits.get(resource_type, "0"), resource_type)
                    if req_val > 0 and lim_val > 0 and lim_val / req_val > max_ratio:
                        cname = container.get("name", "?")
                        offending.append(f"{ns}/{pod_name}/{cname} ({resource_type}: req={requests.get(resource_type)}, lim={limits.get(resource_type)})")
        passed = len(offending) == 0
        return [CheckResult(
            rule_id="WORK-002",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=passed,
            current_value=f"{len(offending)} 个容器 request/limit 差异超过 {max_ratio} 倍" if not passed else "全部合理",
            expected_value=f"request 与 limit 差异不超过 {max_ratio} 倍",
            message=(
                "所有容器的资源 request 与 limit 差异在合理范围内"
                if passed
                else f"发现 {len(offending)} 个容器 request 与 limit 差异超过 {max_ratio} 倍，存在 OOM Kill 或资源浪费风险"
            ),
            resources=offending[:20],
        )]

    # -- WORK-003 PodDisruptionBudget 配置 --
    def _check_pdb(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("WORK-003")
        if rule is None:
            return []
        pdb_selectors: set[str] = set()
        for pdb in config.k8s.workloads.pdbs:
            selector = pdb.get("match_labels", {})
            for k, v in selector.items():
                pdb_selectors.add(f"{k}={v}")

        no_pdb: list[str] = []
        for dep in config.k8s.workloads.deployments:
            dep_name = dep.get("name", "unknown")
            ns = dep.get("namespace", "default")
            labels = dep.get("labels", {})
            has_pdb = any(
                f"{k}={v}" in pdb_selectors for k, v in labels.items()
            )
            if not has_pdb:
                no_pdb.append(f"{ns}/{dep_name}")
        passed = len(no_pdb) == 0
        return [CheckResult(
            rule_id="WORK-003",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.INFO,
            passed=passed,
            current_value=f"{len(no_pdb)} 个 Deployment 未配置 PDB" if not passed else "全部已配置",
            expected_value="所有 Deployment 配置 PDB",
            message=(
                "所有 Deployment 均已配置 PodDisruptionBudget"
                if passed
                else f"发现 {len(no_pdb)} 个 Deployment 未配置 PDB，建议为关键工作负载配置 PDB 以保障可用性"
            ),
            resources=no_pdb[:20],
        )]

    # -- WORK-004 HPA 配置合理性 --
    def _check_hpa(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("WORK-004")
        if rule is None:
            return []
        issues: list[str] = []
        for hpa in config.k8s.workloads.hpas:
            hpa_name = hpa.get("name", "unknown")
            ns = hpa.get("namespace", "default")
            min_replicas = hpa.get("min_replicas", 1)
            if min_replicas <= 1:
                issues.append(f"{ns}/{hpa_name}: minReplicas={min_replicas}")
            behavior = hpa.get("behavior", {})
            scale_down = behavior.get("scaleDown", {})
            if not scale_down.get("stabilizationWindowSeconds"):
                issues.append(f"{ns}/{hpa_name}: scaleDown stabilizationWindowSeconds 未配置")
        passed = len(issues) == 0
        return [CheckResult(
            rule_id="WORK-004",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=passed,
            current_value=f"{len(issues)} 个 HPA 配置问题" if not passed else "全部合理",
            expected_value="minReplicas > 1, scaleDown stabilizationWindowSeconds 已配置",
            message=(
                "所有 HPA 配置合理"
                if passed
                else f"发现 {len(issues)} 个 HPA 配置问题，建议检查 minReplicas 和 scaleDown 策略"
            ),
            resources=issues[:20],
        )]

    # -- WORK-005 健康检查探针配置 --
    def _check_probes(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("WORK-005")
        if rule is None:
            return []
        no_probe: list[str] = []
        for pod in config.k8s.workloads.pods:
            pod_name = pod.get("name", "unknown")
            ns = pod.get("namespace", "default")
            for container in pod.get("containers", []):
                cname = container.get("name", "?")
                has_readiness = container.get("readinessProbe") is not None
                has_liveness = container.get("livenessProbe") is not None
                if not has_readiness or not has_liveness:
                    missing = []
                    if not has_readiness:
                        missing.append("readinessProbe")
                    if not has_liveness:
                        missing.append("livenessProbe")
                    no_probe.append(f"{ns}/{pod_name}/{cname} (缺少 {', '.join(missing)})")
        passed = len(no_probe) == 0
        return [CheckResult(
            rule_id="WORK-005",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=passed,
            current_value=f"{len(no_probe)} 个容器缺少健康检查探针" if not passed else "全部已配置",
            expected_value="所有容器配置 readinessProbe 和 livenessProbe",
            message=(
                "所有容器均已配置健康检查探针"
                if passed
                else f"发现 {len(no_probe)} 个容器缺少健康检查探针，建议配置以确保服务可用性"
            ),
            resources=no_probe[:20],
        )]

    # -- WORK-006 Pod Identity / IRSA 使用 --
    def _check_pod_identity(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("WORK-006")
        if rule is None:
            return []
        offending: list[str] = []
        for pod in config.k8s.workloads.pods:
            pod_name = pod.get("name", "unknown")
            ns = pod.get("namespace", "default")
            # Skip kube-system pods
            if ns == "kube-system":
                continue
            sa_name = pod.get("service_account", "default")
            has_irsa = pod.get("has_irsa", False)
            has_pod_identity = pod.get("has_pod_identity", False)
            uses_aws_env = pod.get("uses_aws_credentials", False)
            if uses_aws_env and not has_irsa and not has_pod_identity:
                offending.append(f"{ns}/{pod_name} (SA: {sa_name})")
        passed = len(offending) == 0
        return [CheckResult(
            rule_id="WORK-006",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.CRITICAL,
            passed=passed,
            current_value=f"{len(offending)} 个 Pod 直接使用 AWS 凭证" if not passed else "无",
            expected_value="所有 Pod 使用 Pod Identity 或 IRSA",
            message=(
                "所有 Pod 已使用 Pod Identity 或 IRSA 进行 IAM 权限管理"
                if passed
                else f"发现 {len(offending)} 个 Pod 直接使用 AWS 凭证而非 Pod Identity/IRSA，存在严重安全风险"
            ),
            resources=offending[:20],
        )]


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _parse_resource(value: str, resource_type: str) -> float:
    """解析 K8s 资源值为数值."""
    value = str(value).strip()
    if not value or value == "0":
        return 0.0
    if resource_type == "cpu":
        if value.endswith("m"):
            return float(value[:-1]) / 1000
        return float(value)
    # memory
    units = {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024, "Ti": 1024 * 1024}
    for suffix, factor in units.items():
        if value.endswith(suffix):
            return float(value[: -len(suffix)]) * factor
    try:
        return float(value) / (1024 * 1024)
    except ValueError:
        return 0.0
