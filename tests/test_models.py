"""Tests for EKS health check core data models and check_rules.yaml."""

from datetime import datetime
from pathlib import Path

import yaml

from eks_health_check.models import (
    AwsConfig,
    CheckDimension,
    CheckResult,
    ClusterConfig,
    DimensionScore,
    K8sConfig,
    NetworkConfig,
    NodeGroupInfo,
    Recommendation,
    ReportData,
    RiskLevel,
    SecurityConfig,
    WorkloadInfo,
)


# ---------------------------------------------------------------------------
# RiskLevel 枚举
# ---------------------------------------------------------------------------

class TestRiskLevel:
    def test_values(self):
        assert RiskLevel.CRITICAL.value == "Critical"
        assert RiskLevel.WARNING.value == "Warning"
        assert RiskLevel.INFO.value == "Info"

    def test_member_count(self):
        assert len(RiskLevel) == 3


# ---------------------------------------------------------------------------
# CheckDimension 枚举
# ---------------------------------------------------------------------------

class TestCheckDimension:
    def test_values(self):
        assert CheckDimension.INFRASTRUCTURE.value == "基础架构"
        assert CheckDimension.NETWORK.value == "网络"
        assert CheckDimension.SECURITY.value == "安全合规"
        assert CheckDimension.WORKLOAD.value == "应用适配性"

    def test_member_count(self):
        assert len(CheckDimension) == 4


# ---------------------------------------------------------------------------
# Dataclass 默认值和字段类型
# ---------------------------------------------------------------------------

class TestCheckResult:
    def test_resources_default(self):
        r = CheckResult(
            rule_id="TEST-001",
            name="test",
            dimension=CheckDimension.NETWORK,
            risk_level=RiskLevel.WARNING,
            passed=True,
            current_value="1",
            expected_value="2",
            message="ok",
        )
        assert r.resources == []

    def test_fields(self):
        r = CheckResult(
            rule_id="X",
            name="n",
            dimension=CheckDimension.SECURITY,
            risk_level=RiskLevel.CRITICAL,
            passed=False,
            current_value="a",
            expected_value="b",
            message="m",
            resources=["pod/x"],
        )
        assert r.rule_id == "X"
        assert r.passed is False
        assert r.resources == ["pod/x"]


class TestRecommendation:
    def test_defaults(self):
        rec = Recommendation(
            rule_id="R-1",
            title="t",
            description="d",
            risk_level=RiskLevel.INFO,
        )
        assert rec.steps == []
        assert rec.expected_benefit == ""
        assert rec.priority == 5


class TestDimensionScore:
    def test_fields(self):
        ds = DimensionScore(
            dimension=CheckDimension.INFRASTRUCTURE,
            score=85,
            total_checks=10,
            passed_checks=8,
            critical_count=0,
            warning_count=1,
            info_count=1,
        )
        assert ds.score == 85
        assert ds.dimension is CheckDimension.INFRASTRUCTURE


class TestReportData:
    def test_skipped_resources_default(self):
        rd = ReportData(
            cluster_name="c",
            region="us-east-1",
            scan_time=datetime(2025, 1, 1),
            cluster_version="1.30",
            node_count=3,
            pod_count=20,
            check_results=[],
            recommendations=[],
            dimension_scores=[],
            overall_score=90,
        )
        assert rd.skipped_resources == []


class TestNodeGroupInfo:
    def test_latest_ami_default(self):
        ng = NodeGroupInfo(
            name="ng-1",
            instance_types=["m5.large"],
            availability_zones=["us-east-1a"],
            capacity_type="ON_DEMAND",
            desired_size=2,
            min_size=1,
            max_size=4,
            ami_version="1.30-20250101",
        )
        assert ng.latest_ami_version is None


class TestNetworkConfig:
    def test_defaults(self):
        nc = NetworkConfig(vpc_id="vpc-123", subnet_ids=["s-1"])
        assert nc.subnet_available_ips == {}
        assert nc.cni_config == {}
        assert nc.coredns_replicas == 2
        assert nc.nodelocal_dns_enabled is False
        assert nc.security_groups == []


class TestSecurityConfig:
    def test_defaults(self):
        sc = SecurityConfig()
        assert sc.audit_logging_enabled is False
        assert sc.endpoint_public_access is True
        assert sc.endpoint_private_access is False
        assert sc.secrets_encryption_enabled is False
        assert sc.encryption_key_arn is None


class TestWorkloadInfo:
    def test_defaults(self):
        wi = WorkloadInfo()
        assert wi.pods == []
        assert wi.deployments == []
        assert wi.hpas == []
        assert wi.pdbs == []
        assert wi.service_accounts == []


class TestK8sConfig:
    def test_defaults(self):
        kc = K8sConfig()
        assert kc.cluster_version == ""
        assert kc.nodes == []
        assert isinstance(kc.workloads, WorkloadInfo)


class TestAwsConfig:
    def test_defaults(self):
        ac = AwsConfig()
        assert ac.node_groups == []
        assert ac.network.vpc_id == ""
        assert isinstance(ac.security, SecurityConfig)


class TestClusterConfig:
    def test_defaults(self):
        cc = ClusterConfig()
        assert cc.collection_errors == []
        assert cc.skipped_resources == []
        assert isinstance(cc.k8s, K8sConfig)
        assert isinstance(cc.aws, AwsConfig)


# ---------------------------------------------------------------------------
# check_rules.yaml 解析与完整性
# ---------------------------------------------------------------------------

RULES_PATH = Path(__file__).resolve().parent.parent / "check_rules.yaml"

VALID_DIMENSIONS = {"infrastructure", "network", "security", "workload"}
VALID_RISK_LEVELS = {"critical", "warning", "info"}

EXPECTED_PREFIXES = {
    "infrastructure": "INFRA",
    "network": "NET",
    "security": "SEC",
    "workload": "WORK",
}


class TestCheckRulesYaml:
    @staticmethod
    def _load_rules() -> list[dict]:
        with open(RULES_PATH) as f:
            data = yaml.safe_load(f)
        return data["rules"]

    def test_file_loads(self):
        rules = self._load_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_expected_rule_count(self):
        """设计文档定义 INFRA 5 + NET 6 + SEC 6 + WORK 6 = 23 条规则"""
        rules = self._load_rules()
        assert len(rules) == 23

    def test_required_fields(self):
        for rule in self._load_rules():
            assert "id" in rule, f"rule missing 'id': {rule}"
            assert "name" in rule, f"rule {rule['id']} missing 'name'"
            assert "dimension" in rule, f"rule {rule['id']} missing 'dimension'"
            assert "description" in rule, f"rule {rule['id']} missing 'description'"
            assert "risk_level" in rule, f"rule {rule['id']} missing 'risk_level'"

    def test_dimensions_valid(self):
        for rule in self._load_rules():
            assert rule["dimension"] in VALID_DIMENSIONS, (
                f"rule {rule['id']} has invalid dimension '{rule['dimension']}'"
            )

    def test_risk_levels_valid(self):
        for rule in self._load_rules():
            assert rule["risk_level"] in VALID_RISK_LEVELS, (
                f"rule {rule['id']} has invalid risk_level '{rule['risk_level']}'"
            )

    def test_ids_unique(self):
        ids = [r["id"] for r in self._load_rules()]
        assert len(ids) == len(set(ids)), "duplicate rule ids found"

    def test_id_prefix_matches_dimension(self):
        for rule in self._load_rules():
            prefix = rule["id"].split("-")[0]
            expected = EXPECTED_PREFIXES[rule["dimension"]]
            assert prefix == expected, (
                f"rule {rule['id']} prefix '{prefix}' doesn't match "
                f"dimension '{rule['dimension']}' (expected '{expected}')"
            )
