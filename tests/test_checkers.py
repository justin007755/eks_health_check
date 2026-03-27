"""Tests for Check Engine layer: all Checkers and CheckEngine orchestrator."""

from __future__ import annotations

from eks_health_check.models import (
    AwsConfig,
    CheckDimension,
    ClusterConfig,
    K8sConfig,
    NetworkConfig,
    NodeGroupInfo,
    RiskLevel,
    SecurityConfig,
    WorkloadInfo,
)
from eks_health_check.checkers.base import CheckEngine, load_rules, rules_for_dimension
from eks_health_check.checkers.infrastructure import InfrastructureChecker
from eks_health_check.checkers.network import NetworkChecker
from eks_health_check.checkers.security import SecurityChecker
from eks_health_check.checkers.workload import WorkloadChecker


# =========================================================================
# Helper — build a ClusterConfig with sensible defaults, override as needed
# =========================================================================

def _base_config(**overrides) -> ClusterConfig:
    """Return a minimal ClusterConfig. Pass keyword overrides for nested fields."""
    k8s = overrides.get("k8s", K8sConfig(cluster_version="1.30", nodes=[], workloads=WorkloadInfo()))
    aws = overrides.get("aws", AwsConfig(
        cluster_info={},
        node_groups=[],
        network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["subnet-1"]),
        security=SecurityConfig(),
        iam_roles=[],
    ))
    return ClusterConfig(k8s=k8s, aws=aws)


def _load_dimension_rules(dimension: str):
    return rules_for_dimension(load_rules(), dimension)


# =========================================================================
# InfrastructureChecker
# =========================================================================

class TestInfrastructureChecker:
    def _checker(self):
        return InfrastructureChecker(rules=_load_dimension_rules("infrastructure"))

    def test_single_instance_type_warning(self):
        """单一实例类型 → Warning, passed=False (INFRA-001)."""
        cfg = _base_config(aws=AwsConfig(
            node_groups=[NodeGroupInfo(
                name="ng-1", instance_types=["m5.large"],
                availability_zones=["us-east-1a", "us-east-1b"],
                capacity_type="ON_DEMAND", desired_size=3, min_size=1, max_size=5,
                ami_version="1.30-20250101",
            )],
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"]),
            security=SecurityConfig(),
        ))
        results = self._checker().check(cfg)
        infra001 = [r for r in results if r.rule_id == "INFRA-001"]
        assert len(infra001) == 1
        assert infra001[0].passed is False
        assert infra001[0].risk_level == RiskLevel.WARNING
        assert infra001[0].dimension == CheckDimension.INFRASTRUCTURE

    def test_multiple_instance_types_pass(self):
        """多实例类型 → passed=True (INFRA-001)."""
        cfg = _base_config(aws=AwsConfig(
            node_groups=[NodeGroupInfo(
                name="ng-1", instance_types=["m5.large", "m5.xlarge"],
                availability_zones=["us-east-1a"], capacity_type="ON_DEMAND",
                desired_size=3, min_size=1, max_size=5, ami_version="1.30-20250101",
            )],
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"]),
            security=SecurityConfig(),
        ))
        results = self._checker().check(cfg)
        infra001 = [r for r in results if r.rule_id == "INFRA-001"]
        assert infra001[0].passed is True

    def test_no_autoscaler_info(self):
        """无 Autoscaler → Info, passed=False (INFRA-004)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30", nodes=[], workloads=WorkloadInfo(deployments=[]),
            addons=[],
        ))
        results = self._checker().check(cfg)
        infra004 = [r for r in results if r.rule_id == "INFRA-004"]
        assert len(infra004) == 1
        assert infra004[0].passed is False
        assert infra004[0].risk_level == RiskLevel.INFO

    def test_has_karpenter_passes(self):
        """有 Karpenter addon → passed=True (INFRA-004)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30", nodes=[],
            workloads=WorkloadInfo(deployments=[]),
            addons=[{"name": "karpenter"}],
        ))
        results = self._checker().check(cfg)
        infra004 = [r for r in results if r.rule_id == "INFRA-004"]
        assert infra004[0].passed is True

    def test_eol_version_critical(self):
        """EOL 版本 → Critical, passed=False (INFRA-005)."""
        cfg = _base_config(k8s=K8sConfig(cluster_version="1.24"))
        results = self._checker().check(cfg)
        infra005 = [r for r in results if r.rule_id == "INFRA-005"]
        assert len(infra005) == 1
        assert infra005[0].passed is False
        assert infra005[0].risk_level == RiskLevel.CRITICAL

    def test_supported_version_passes(self):
        """支持的版本 → passed=True (INFRA-005)."""
        cfg = _base_config(k8s=K8sConfig(cluster_version="1.30"))
        results = self._checker().check(cfg)
        infra005 = [r for r in results if r.rule_id == "INFRA-005"]
        assert infra005[0].passed is True

    def test_resource_utilization_over_threshold(self):
        """CPU request 超过阈值 → Warning, passed=False (INFRA-003)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30",
            nodes=[{"allocatable": {"cpu": "4", "memory": "16Gi"}}],
            workloads=WorkloadInfo(pods=[
                {"containers": [{"resources": {"requests": {"cpu": "3600m", "memory": "2Gi"}}}]},
            ]),
        ))
        results = self._checker().check(cfg)
        infra003_cpu = [r for r in results if r.rule_id == "INFRA-003" and "CPU" in r.name]
        assert len(infra003_cpu) == 1
        assert infra003_cpu[0].passed is False
        assert infra003_cpu[0].risk_level == RiskLevel.WARNING


# =========================================================================
# NetworkChecker
# =========================================================================

class TestNetworkChecker:
    def _checker(self):
        return NetworkChecker(rules=_load_dimension_rules("network"))

    def test_ndots_high_warning(self):
        """ndots > 2 → Warning, passed=False (NET-002)."""
        cfg = _base_config(aws=AwsConfig(
            network=NetworkConfig(
                vpc_id="vpc-1", subnet_ids=["s-1"],
                coredns_config={"ndots": 5},
            ),
            security=SecurityConfig(),
        ))
        results = self._checker().check(cfg)
        net002 = [r for r in results if r.rule_id == "NET-002"]
        assert len(net002) == 1
        assert net002[0].passed is False
        assert net002[0].risk_level == RiskLevel.WARNING

    def test_ndots_low_passes(self):
        """ndots <= 2 → passed=True (NET-002)."""
        cfg = _base_config(aws=AwsConfig(
            network=NetworkConfig(
                vpc_id="vpc-1", subnet_ids=["s-1"],
                coredns_config={"ndots": 2},
            ),
            security=SecurityConfig(),
        ))
        results = self._checker().check(cfg)
        net002 = [r for r in results if r.rule_id == "NET-002"]
        assert net002[0].passed is True

    def test_subnet_ip_insufficient_critical(self):
        """子网可用 IP < 节点数×2 → Critical, passed=False (NET-005)."""
        cfg = _base_config(
            k8s=K8sConfig(cluster_version="1.30", nodes=[
                {"name": "n1"}, {"name": "n2"}, {"name": "n3"},
                {"name": "n4"}, {"name": "n5"},
            ]),
            aws=AwsConfig(
                network=NetworkConfig(
                    vpc_id="vpc-1", subnet_ids=["s-1"],
                    subnet_available_ips={"s-1": 5},  # 5 < 5*2=10
                ),
                security=SecurityConfig(),
            ),
        )
        results = self._checker().check(cfg)
        net005 = [r for r in results if r.rule_id == "NET-005"]
        assert len(net005) == 1
        assert net005[0].passed is False
        assert net005[0].risk_level == RiskLevel.CRITICAL

    def test_subnet_ip_sufficient_passes(self):
        """子网可用 IP >= 节点数×2 → passed=True (NET-005)."""
        cfg = _base_config(
            k8s=K8sConfig(cluster_version="1.30", nodes=[{"name": "n1"}, {"name": "n2"}]),
            aws=AwsConfig(
                network=NetworkConfig(
                    vpc_id="vpc-1", subnet_ids=["s-1"],
                    subnet_available_ips={"s-1": 100},
                ),
                security=SecurityConfig(),
            ),
        )
        results = self._checker().check(cfg)
        net005 = [r for r in results if r.rule_id == "NET-005"]
        assert net005[0].passed is True

    def test_security_group_open_warning(self):
        """SG 有 0.0.0.0/0 入站 → Warning, passed=False (NET-006)."""
        cfg = _base_config(aws=AwsConfig(
            network=NetworkConfig(
                vpc_id="vpc-1", subnet_ids=["s-1"],
                security_groups=[{
                    "id": "sg-1",
                    "inbound_rules": [{"cidr": "0.0.0.0/0", "port": 443}],
                }],
            ),
            security=SecurityConfig(),
        ))
        results = self._checker().check(cfg)
        net006 = [r for r in results if r.rule_id == "NET-006"]
        assert len(net006) == 1
        assert net006[0].passed is False
        assert net006[0].risk_level == RiskLevel.WARNING
        assert "sg-1" in net006[0].resources

    def test_cni_missing_params_info(self):
        """CNI 参数缺失 → Info, passed=False (NET-001)."""
        cfg = _base_config(aws=AwsConfig(
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"], cni_config={}),
            security=SecurityConfig(),
        ))
        results = self._checker().check(cfg)
        net001 = [r for r in results if r.rule_id == "NET-001"]
        assert len(net001) == 1
        assert net001[0].passed is False
        assert net001[0].risk_level == RiskLevel.INFO


# =========================================================================
# SecurityChecker
# =========================================================================

class TestSecurityChecker:
    def _checker(self):
        return SecurityChecker(rules=_load_dimension_rules("security"))

    def test_public_endpoint_no_cidr_critical(self):
        """纯 Public endpoint 无 CIDR 限制 → Critical, passed=False (SEC-003)."""
        cfg = _base_config(aws=AwsConfig(
            security=SecurityConfig(
                endpoint_public_access=True,
                endpoint_private_access=False,
                public_access_cidrs=["0.0.0.0/0"],
            ),
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"]),
        ))
        results = self._checker().check(cfg)
        sec003 = [r for r in results if r.rule_id == "SEC-003"]
        assert len(sec003) == 1
        assert sec003[0].passed is False
        assert sec003[0].risk_level == RiskLevel.CRITICAL

    def test_private_endpoint_passes(self):
        """Private endpoint → passed=True (SEC-003)."""
        cfg = _base_config(aws=AwsConfig(
            security=SecurityConfig(
                endpoint_public_access=False,
                endpoint_private_access=True,
            ),
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"]),
        ))
        results = self._checker().check(cfg)
        sec003 = [r for r in results if r.rule_id == "SEC-003"]
        assert sec003[0].passed is True

    def test_audit_logging_disabled_warning(self):
        """审计日志未启用 → Warning, passed=False (SEC-001)."""
        cfg = _base_config(aws=AwsConfig(
            security=SecurityConfig(audit_logging_enabled=False),
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"]),
        ))
        results = self._checker().check(cfg)
        sec001 = [r for r in results if r.rule_id == "SEC-001"]
        assert len(sec001) == 1
        assert sec001[0].passed is False
        assert sec001[0].risk_level == RiskLevel.WARNING

    def test_audit_logging_enabled_passes(self):
        """审计日志已启用 → passed=True (SEC-001)."""
        cfg = _base_config(aws=AwsConfig(
            security=SecurityConfig(audit_logging_enabled=True, log_types=["audit", "api"]),
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"]),
        ))
        results = self._checker().check(cfg)
        sec001 = [r for r in results if r.rule_id == "SEC-001"]
        assert sec001[0].passed is True

    def test_secrets_encryption_disabled_warning(self):
        """Secrets encryption 未启用 → Warning (SEC-004)."""
        cfg = _base_config(aws=AwsConfig(
            security=SecurityConfig(secrets_encryption_enabled=False),
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"]),
        ))
        results = self._checker().check(cfg)
        sec004 = [r for r in results if r.rule_id == "SEC-004"]
        assert len(sec004) == 1
        assert sec004[0].passed is False
        assert sec004[0].risk_level == RiskLevel.WARNING

    def test_ami_outdated_warning(self):
        """AMI 版本非最新 → Warning (SEC-005)."""
        cfg = _base_config(aws=AwsConfig(
            node_groups=[NodeGroupInfo(
                name="ng-1", instance_types=["m5.large"],
                availability_zones=["us-east-1a"], capacity_type="ON_DEMAND",
                desired_size=2, min_size=1, max_size=4,
                ami_version="1.30-20250101", latest_ami_version="1.30-20250301",
            )],
            security=SecurityConfig(),
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"]),
        ))
        results = self._checker().check(cfg)
        sec005 = [r for r in results if r.rule_id == "SEC-005"]
        assert len(sec005) == 1
        assert sec005[0].passed is False
        assert sec005[0].risk_level == RiskLevel.WARNING


# =========================================================================
# WorkloadChecker
# =========================================================================

class TestWorkloadChecker:
    def _checker(self):
        return WorkloadChecker(rules=_load_dimension_rules("workload"))

    def test_no_resource_request_warning(self):
        """容器无 resource request → Warning, passed=False (WORK-001)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30",
            workloads=WorkloadInfo(pods=[{
                "name": "app", "namespace": "default",
                "containers": [{"name": "main", "resources": {}}],
            }]),
        ))
        results = self._checker().check(cfg)
        work001 = [r for r in results if r.rule_id == "WORK-001"]
        assert len(work001) == 1
        assert work001[0].passed is False
        assert work001[0].risk_level == RiskLevel.WARNING

    def test_resource_request_set_passes(self):
        """容器已设置 request/limit → passed=True (WORK-001)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30",
            workloads=WorkloadInfo(pods=[{
                "name": "app", "namespace": "default",
                "containers": [{
                    "name": "main",
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                        "limits": {"cpu": "200m", "memory": "256Mi"},
                    },
                }],
            }]),
        ))
        results = self._checker().check(cfg)
        work001 = [r for r in results if r.rule_id == "WORK-001"]
        assert work001[0].passed is True

    def test_no_pdb_info(self):
        """Deployment 无 PDB → Info, passed=False (WORK-003)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30",
            workloads=WorkloadInfo(
                deployments=[{"name": "web", "namespace": "default", "labels": {"app": "web"}}],
                pdbs=[],
            ),
        ))
        results = self._checker().check(cfg)
        work003 = [r for r in results if r.rule_id == "WORK-003"]
        assert len(work003) == 1
        assert work003[0].passed is False
        assert work003[0].risk_level == RiskLevel.INFO

    def test_pdb_configured_passes(self):
        """Deployment 有匹配 PDB → passed=True (WORK-003)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30",
            workloads=WorkloadInfo(
                deployments=[{"name": "web", "namespace": "default", "labels": {"app": "web"}}],
                pdbs=[{"match_labels": {"app": "web"}}],
            ),
        ))
        results = self._checker().check(cfg)
        work003 = [r for r in results if r.rule_id == "WORK-003"]
        assert work003[0].passed is True

    def test_no_probes_warning(self):
        """容器无健康检查探针 → Warning (WORK-005)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30",
            workloads=WorkloadInfo(pods=[{
                "name": "app", "namespace": "default",
                "containers": [{"name": "main", "readinessProbe": None, "livenessProbe": None}],
            }]),
        ))
        results = self._checker().check(cfg)
        work005 = [r for r in results if r.rule_id == "WORK-005"]
        assert len(work005) == 1
        assert work005[0].passed is False
        assert work005[0].risk_level == RiskLevel.WARNING

    def test_pod_identity_direct_creds_critical(self):
        """Pod 直接使用 AWS 凭证 → Critical (WORK-006)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30",
            workloads=WorkloadInfo(pods=[{
                "name": "worker", "namespace": "app",
                "service_account": "default",
                "has_irsa": False, "has_pod_identity": False,
                "uses_aws_credentials": True,
                "containers": [],
            }]),
        ))
        results = self._checker().check(cfg)
        work006 = [r for r in results if r.rule_id == "WORK-006"]
        assert len(work006) == 1
        assert work006[0].passed is False
        assert work006[0].risk_level == RiskLevel.CRITICAL

    def test_hpa_min_replicas_one_warning(self):
        """HPA minReplicas=1 → Warning (WORK-004)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30",
            workloads=WorkloadInfo(hpas=[{
                "name": "web-hpa", "namespace": "default",
                "min_replicas": 1, "behavior": {},
            }]),
        ))
        results = self._checker().check(cfg)
        work004 = [r for r in results if r.rule_id == "WORK-004"]
        assert len(work004) == 1
        assert work004[0].passed is False
        assert work004[0].risk_level == RiskLevel.WARNING

    def test_resource_ratio_over_3x_warning(self):
        """request/limit 差异超过 3 倍 → Warning (WORK-002)."""
        cfg = _base_config(k8s=K8sConfig(
            cluster_version="1.30",
            workloads=WorkloadInfo(pods=[{
                "name": "app", "namespace": "default",
                "containers": [{
                    "name": "main",
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                        "limits": {"cpu": "500m", "memory": "128Mi"},  # cpu 5x
                    },
                }],
            }]),
        ))
        results = self._checker().check(cfg)
        work002 = [r for r in results if r.rule_id == "WORK-002"]
        assert len(work002) == 1
        assert work002[0].passed is False
        assert work002[0].risk_level == RiskLevel.WARNING


# =========================================================================
# CheckEngine — 汇总多个 Checker 的结果
# =========================================================================

class TestCheckEngine:
    def test_aggregates_all_checker_results(self):
        """CheckEngine 汇总所有 Checker 的结果。"""
        all_rules = load_rules()
        engine = CheckEngine(checkers=[
            InfrastructureChecker(rules=rules_for_dimension(all_rules, "infrastructure")),
            NetworkChecker(rules=rules_for_dimension(all_rules, "network")),
            SecurityChecker(rules=rules_for_dimension(all_rules, "security")),
            WorkloadChecker(rules=rules_for_dimension(all_rules, "workload")),
        ])
        cfg = _base_config(
            k8s=K8sConfig(
                cluster_version="1.30",
                nodes=[{"name": "n1", "allocatable": {"cpu": "4", "memory": "16Gi"}}],
                workloads=WorkloadInfo(
                    pods=[{
                        "name": "app", "namespace": "default",
                        "containers": [{
                            "name": "main",
                            "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                                          "limits": {"cpu": "200m", "memory": "256Mi"}},
                            "readinessProbe": {}, "livenessProbe": {},
                        }],
                    }],
                    deployments=[{"name": "web", "namespace": "default", "labels": {"app": "web"}}],
                    hpas=[], pdbs=[], service_accounts=[],
                ),
                addons=[],
            ),
            aws=AwsConfig(
                node_groups=[NodeGroupInfo(
                    name="ng-1", instance_types=["m5.large"],
                    availability_zones=["us-east-1a", "us-east-1b"],
                    capacity_type="ON_DEMAND", desired_size=3, min_size=1, max_size=5,
                    ami_version="1.30-20250101",
                )],
                network=NetworkConfig(
                    vpc_id="vpc-1", subnet_ids=["s-1"],
                    subnet_available_ips={"s-1": 100},
                    coredns_config={"ndots": 5},
                ),
                security=SecurityConfig(
                    audit_logging_enabled=False,
                    endpoint_public_access=True,
                    endpoint_private_access=False,
                    public_access_cidrs=["0.0.0.0/0"],
                ),
            ),
        )
        results = engine.run(cfg)

        # Should have results from all four dimensions
        dimensions = {r.dimension for r in results}
        assert CheckDimension.INFRASTRUCTURE in dimensions
        assert CheckDimension.NETWORK in dimensions
        assert CheckDimension.SECURITY in dimensions
        assert CheckDimension.WORKLOAD in dimensions

        # Verify we got a reasonable number of results (at least one per checker)
        assert len(results) >= 4

        # All results should be CheckResult instances with valid fields
        for r in results:
            assert r.rule_id
            assert isinstance(r.risk_level, RiskLevel)
            assert isinstance(r.passed, bool)
            assert isinstance(r.dimension, CheckDimension)

    def test_empty_engine_returns_empty(self):
        """空 CheckEngine 返回空结果。"""
        engine = CheckEngine(checkers=[])
        results = engine.run(_base_config())
        assert results == []

    def test_register_adds_checker(self):
        """register() 动态添加 Checker。"""
        engine = CheckEngine()
        assert len(engine.checkers) == 0
        engine.register(InfrastructureChecker(rules=_load_dimension_rules("infrastructure")))
        assert len(engine.checkers) == 1
        results = engine.run(_base_config(k8s=K8sConfig(cluster_version="1.30")))
        # Should have at least INFRA-004 (autoscaler) and INFRA-005 (version)
        rule_ids = {r.rule_id for r in results}
        assert "INFRA-004" in rule_ids
        assert "INFRA-005" in rule_ids
