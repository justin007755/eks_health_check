"""SecurityChecker — 安全合规扫描 (SEC-001 ~ SEC-006)."""

from __future__ import annotations

from eks_health_check.models import CheckDimension, CheckResult, ClusterConfig, RiskLevel
from eks_health_check.checkers.base import BaseChecker

_DIM = CheckDimension.SECURITY


class SecurityChecker(BaseChecker):
    """安全合规扫描：CIS Benchmark、审计日志、API Server、Secrets 加密."""

    def check(self, config: ClusterConfig) -> list[CheckResult]:
        results: list[CheckResult] = []
        results.extend(self._check_audit_logging(config))
        results.extend(self._check_endpoint_access(config))
        results.extend(self._check_secrets_encryption(config))
        results.extend(self._check_ami_version(config))
        results.extend(self._check_aws_node_role(config))
        return results

    # -- SEC-001 审计日志启用状态 --
    def _check_audit_logging(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("SEC-001")
        if rule is None:
            return []
        sec = config.aws.security
        passed = sec.audit_logging_enabled
        return [CheckResult(
            rule_id="SEC-001",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=passed,
            current_value="已启用" if passed else "未启用",
            expected_value="启用审计日志 (api, audit, authenticator)",
            message=(
                f"控制平面审计日志已启用，日志类型: {', '.join(sec.log_types)}"
                if passed
                else "控制平面审计日志未启用，建议启用 api、audit、authenticator 日志类型以满足 CIS EKS Benchmark 要求"
            ),
        )]

    # -- SEC-002 & SEC-003 API Server endpoint 访问策略 --
    def _check_endpoint_access(self, config: ClusterConfig) -> list[CheckResult]:
        sec = config.aws.security
        results: list[CheckResult] = []

        # SEC-002: endpoint access 策略概览
        rule_002 = self.get_rule("SEC-002")
        if rule_002:
            if sec.endpoint_public_access and sec.endpoint_private_access:
                access_type = "Public + Private"
            elif sec.endpoint_public_access:
                access_type = "Public"
            else:
                access_type = "Private"
            results.append(CheckResult(
                rule_id="SEC-002",
                name=rule_002["name"],
                dimension=_DIM,
                risk_level=RiskLevel.INFO,
                passed=True,  # informational
                current_value=access_type,
                expected_value="Private 或 Public+Private (带 CIDR 限制)",
                message=f"API Server endpoint 访问策略: {access_type}",
            ))

        # SEC-003: 纯 Public 无 CIDR 限制
        rule_003 = self.get_rule("SEC-003")
        if rule_003:
            is_public_only = sec.endpoint_public_access and not sec.endpoint_private_access
            no_cidr_restriction = (
                not sec.public_access_cidrs
                or sec.public_access_cidrs == ["0.0.0.0/0"]
            )
            is_critical = is_public_only and no_cidr_restriction
            results.append(CheckResult(
                rule_id="SEC-003",
                name=rule_003["name"],
                dimension=_DIM,
                risk_level=RiskLevel.CRITICAL,
                passed=not is_critical,
                current_value=(
                    f"Public only, CIDRs: {sec.public_access_cidrs}"
                    if is_critical
                    else "已配置访问限制"
                ),
                expected_value="启用 Private endpoint 或配置 Public CIDR 限制",
                message=(
                    "API Server endpoint 访问已配置适当限制"
                    if not is_critical
                    else "API Server 为纯 Public 访问且未配置 CIDR 限制，存在严重安全风险，建议立即启用 Private endpoint 或添加 CIDR 限制"
                ),
            ))
        return results

    # -- SEC-004 Secrets envelope encryption --
    def _check_secrets_encryption(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("SEC-004")
        if rule is None:
            return []
        passed = config.aws.security.secrets_encryption_enabled
        return [CheckResult(
            rule_id="SEC-004",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=passed,
            current_value="已启用" if passed else "未启用",
            expected_value="启用 Secrets envelope encryption",
            message=(
                "Secrets envelope encryption 已启用"
                if passed
                else "Secrets envelope encryption 未启用，建议启用以增强 Secret 数据的安全性"
            ),
        )]

    # -- SEC-005 节点组 AMI 版本 --
    def _check_ami_version(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("SEC-005")
        if rule is None:
            return []
        results: list[CheckResult] = []
        for ng in config.aws.node_groups:
            if ng.latest_ami_version is None:
                # 无法获取最新版本信息，跳过
                continue
            passed = ng.ami_version == ng.latest_ami_version
            results.append(CheckResult(
                rule_id="SEC-005",
                name=rule["name"],
                dimension=_DIM,
                risk_level=RiskLevel.WARNING,
                passed=passed,
                current_value=ng.ami_version,
                expected_value=ng.latest_ami_version,
                message=(
                    f"节点组 {ng.name} 使用最新 AMI 版本"
                    if passed
                    else f"节点组 {ng.name} AMI 版本 {ng.ami_version} 非最新 ({ng.latest_ami_version})，建议更新以获取安全补丁"
                ),
                resources=[ng.name],
            ))
        return results

    # -- SEC-006 aws-node 默认 IAM 角色使用 --
    def _check_aws_node_role(self, config: ClusterConfig) -> list[CheckResult]:
        rule = self.get_rule("SEC-006")
        if rule is None:
            return []
        offending: list[str] = []
        for sa in config.k8s.workloads.service_accounts:
            sa_name = sa.get("name", "")
            namespace = sa.get("namespace", "")
            # Check if SA has IRSA annotation or Pod Identity association
            annotations = sa.get("annotations", {})
            has_irsa = "eks.amazonaws.com/role-arn" in annotations
            has_pod_identity = sa.get("pod_identity_association", False)
            # aws-node SA in kube-system is expected; flag others without IRSA/Pod Identity
            if sa_name == "aws-node" and namespace == "kube-system":
                continue
            if not has_irsa and not has_pod_identity:
                if sa.get("uses_aws_credentials", False):
                    offending.append(f"{namespace}/{sa_name}")
        passed = len(offending) == 0
        return [CheckResult(
            rule_id="SEC-006",
            name=rule["name"],
            dimension=_DIM,
            risk_level=RiskLevel.WARNING,
            passed=passed,
            current_value=f"{len(offending)} 个工作负载使用默认 IAM 角色" if not passed else "无",
            expected_value="所有工作负载使用 Pod Identity 或 IRSA",
            message=(
                "所有工作负载已使用 Pod Identity 或 IRSA 进行 IAM 权限管理"
                if passed
                else f"发现 {len(offending)} 个工作负载可能使用 aws-node 默认 IAM 角色，建议迁移至 Pod Identity 或 IRSA"
            ),
            resources=offending,
        )]
