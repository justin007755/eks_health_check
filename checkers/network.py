"""NetworkChecker — 网络能力评估 (NET-001 ~ NET-006)."""

from __future__ import annotations

from eks_health_check.models import CheckDimension, CheckResult, ClusterConfig, RiskLevel
from eks_health_check.checkers.base import BaseChecker

_DIM = CheckDimension.NETWORK

_CNI_KEY_PARAMS = [
    "WARM_ENI_TARGET",
    "WARM_IP_TARGET",
    "MINIMUM_IP_TARGET",
    "ENABLE_PREFIX_DELEGATION",
]


class NetworkChecker(BaseChecker):
    """网络能力评估：VPC CNI、CoreDNS、IP 地址、Security Group."""

    def check(self, config: ClusterConfig) -> list[CheckResult]:
        results: list[CheckResult] = []
        results.extend(self._check_cni_config(config))
        results.extend(self._check_coredns_ndots(config))
        results.extend(self._check_coredns_replicas(config))
        results.extend(self._check_nodelocal_dns(config))
        results.extend(self._check_subnet_ips(config))
        results.extend(self._check_security_groups(config))
        return results

    # -- NET-001 VPC CNI 配置参数 --
    def _check_cni_config(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("NET-001")
        if rule is None:
            return []
        cni = config.aws.network.cni_config
        missing = [p for p in _CNI_KEY_PARAMS if p not in cni]
        passed = len(missing) == 0
        return [CheckResult(
            rule_id="NET-001",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.INFO,
            passed=passed,
            current_value=str({k: cni.get(k, "未设置") for k in _CNI_KEY_PARAMS}),
            expected_value="所有关键 CNI 参数已显式配置",
            message=(
                "VPC CNI 关键参数均已配置"
                if passed
                else f"以下 VPC CNI 参数未显式配置: {', '.join(missing)}，建议根据集群规模进行调优"
            ),
        )]

    # -- NET-002 CoreDNS ndots --
    def _check_coredns_ndots(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("NET-002")
        if rule is None:
            return []
        max_ndots = rule.get("threshold", {}).get("max_ndots", 2)
        coredns_cfg = config.aws.network.coredns_config
        ndots = coredns_cfg.get("ndots", 5)  # K8s 默认 ndots=5
        passed = ndots <= max_ndots
        return [CheckResult(
            rule_id="NET-002",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=passed,
            current_value=str(ndots),
            expected_value=f"<= {max_ndots}",
            message=(
                f"CoreDNS ndots 值为 {ndots}，在合理范围内"
                if passed
                else f"CoreDNS ndots 值为 {ndots}，高于阈值 {max_ndots}，可能导致大量无效 DNS 查询，建议调整为 2"
            ),
        )]

    # -- NET-003 CoreDNS 副本数与集群规模匹配 --
    def _check_coredns_replicas(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("NET-003")
        if rule is None:
            return []
        min_per_100 = rule.get("threshold", {}).get("min_replicas_per_100_nodes", 2)
        node_count = len(config.k8s.nodes)
        replicas = config.aws.network.coredns_replicas
        expected = max(2, (node_count // 100 + 1) * min_per_100) if node_count > 0 else 2
        passed = replicas >= expected
        return [CheckResult(
            rule_id="NET-003",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=passed,
            current_value=f"{replicas} 副本",
            expected_value=f">= {expected} 副本 (基于 {node_count} 节点)",
            message=(
                f"CoreDNS 副本数 {replicas} 与集群规模匹配"
                if passed
                else f"CoreDNS 副本数 {replicas} 可能不足以支撑 {node_count} 节点的 DNS 查询量，建议增加至 {expected}"
            ),
        )]

    # -- NET-004 NodeLocal DNSCache --
    def _check_nodelocal_dns(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("NET-004")
        if rule is None:
            return []
        enabled = config.aws.network.nodelocal_dns_enabled
        return [CheckResult(
            rule_id="NET-004",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.INFO,
            passed=enabled,
            current_value="已启用" if enabled else "未启用",
            expected_value="启用 NodeLocal DNSCache",
            message=(
                "NodeLocal DNSCache 已启用，可有效减轻 CoreDNS 压力"
                if enabled
                else "未启用 NodeLocal DNSCache，建议启用以减轻 CoreDNS 压力并降低 DNS 查询延迟"
            ),
        )]

    # -- NET-005 子网可用 IP 地址 --
    def _check_subnet_ips(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("NET-005")
        if rule is None:
            return []
        min_ratio = rule.get("threshold", {}).get("min_ip_ratio", 2)
        node_count = len(config.k8s.nodes)
        subnet_ips = config.aws.network.subnet_available_ips
        if not subnet_ips:
            return []
        total_ips = sum(subnet_ips.values())
        threshold = node_count * min_ratio
        passed = total_ips >= threshold
        low_subnets = [sid for sid, cnt in subnet_ips.items() if cnt < node_count]
        return [CheckResult(
            rule_id="NET-005",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.CRITICAL,
            passed=passed,
            current_value=f"总可用 IP: {total_ips}",
            expected_value=f">= {threshold} (节点数 {node_count} × {min_ratio})",
            message=(
                f"子网可用 IP 总数 {total_ips} 充足"
                if passed
                else f"子网可用 IP 总数 {total_ips} 低于阈值 {threshold}，存在 IP 地址耗尽风险"
            ),
            resources=low_subnets,
        )]

    # -- NET-006 Security Group 过度开放 --
    def _check_security_groups(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("NET-006")
        if rule is None:
            return []
        open_sgs: list[str] = []
        for sg in config.aws.network.security_groups:
            for permission in sg.get("inbound_rules", []):
                cidr = permission.get("cidr", "")
                if cidr == "0.0.0.0/0":
                    sg_id = sg.get("id", "unknown")
                    if sg_id not in open_sgs:
                        open_sgs.append(sg_id)
        passed = len(open_sgs) == 0
        return [CheckResult(
            rule_id="NET-006",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=passed,
            current_value=f"{len(open_sgs)} 个 SG 存在 0.0.0.0/0 入站规则" if not passed else "无过度开放的 SG",
            expected_value="无 0.0.0.0/0 入站规则",
            message=(
                "Security Group 入站规则配置合理"
                if passed
                else f"发现 {len(open_sgs)} 个 Security Group 存在 0.0.0.0/0 入站规则，建议收紧访问范围"
            ),
            resources=open_sgs,
        )]
