"""EKS 集群健康体检 POC 工具 - 核心数据模型"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "Critical"
    WARNING = "Warning"
    INFO = "Info"


class CheckDimension(Enum):
    """检查维度"""
    INFRASTRUCTURE = "基础架构"
    NETWORK = "网络"
    SECURITY = "安全合规"
    WORKLOAD = "应用适配性"


# ---------------------------------------------------------------------------
# 检查结果 & 建议
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """单个检查项的结果"""
    rule_id: str
    name: str
    dimension: CheckDimension
    risk_level: RiskLevel
    passed: bool
    current_value: str
    expected_value: str
    message: str
    resources: list[str] = field(default_factory=list)


@dataclass
class Recommendation:
    """优化建议"""
    rule_id: str
    title: str
    description: str
    risk_level: RiskLevel
    steps: list[str] = field(default_factory=list)
    expected_benefit: str = ""
    priority: int = 5


@dataclass
class DimensionScore:
    """维度评分"""
    dimension: CheckDimension
    score: int
    total_checks: int
    passed_checks: int
    critical_count: int
    warning_count: int
    info_count: int


@dataclass
class ReportData:
    """报告数据结构"""
    cluster_name: str
    region: str
    scan_time: datetime
    cluster_version: str
    node_count: int
    pod_count: int
    check_results: list[CheckResult]
    recommendations: list[Recommendation]
    dimension_scores: list[DimensionScore]
    overall_score: int
    skipped_resources: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 集群配置数据模型
# ---------------------------------------------------------------------------

@dataclass
class NodeGroupInfo:
    """节点组信息"""
    name: str
    instance_types: list[str]
    availability_zones: list[str]
    capacity_type: str  # ON_DEMAND / SPOT
    desired_size: int
    min_size: int
    max_size: int
    ami_version: str
    latest_ami_version: str | None = None


@dataclass
class NetworkConfig:
    """网络配置"""
    vpc_id: str
    subnet_ids: list[str]
    subnet_available_ips: dict[str, int] = field(default_factory=dict)
    cni_config: dict = field(default_factory=dict)
    coredns_config: dict = field(default_factory=dict)
    coredns_replicas: int = 2
    nodelocal_dns_enabled: bool = False
    security_groups: list[dict] = field(default_factory=list)


@dataclass
class SecurityConfig:
    """安全配置"""
    audit_logging_enabled: bool = False
    log_types: list[str] = field(default_factory=list)
    endpoint_public_access: bool = True
    endpoint_private_access: bool = False
    public_access_cidrs: list[str] = field(default_factory=list)
    secrets_encryption_enabled: bool = False
    encryption_key_arn: str | None = None


@dataclass
class WorkloadInfo:
    """工作负载信息"""
    pods: list[dict] = field(default_factory=list)
    deployments: list[dict] = field(default_factory=list)
    hpas: list[dict] = field(default_factory=list)
    pdbs: list[dict] = field(default_factory=list)
    service_accounts: list[dict] = field(default_factory=list)


@dataclass
class K8sConfig:
    """Kubernetes API 采集的配置"""
    cluster_version: str = ""
    nodes: list[dict] = field(default_factory=list)
    workloads: WorkloadInfo = field(default_factory=WorkloadInfo)
    network: dict = field(default_factory=dict)
    addons: list[dict] = field(default_factory=list)


@dataclass
class AwsConfig:
    """AWS API 采集的配置"""
    cluster_info: dict = field(default_factory=dict)
    node_groups: list[NodeGroupInfo] = field(default_factory=list)
    network: NetworkConfig = field(default_factory=lambda: NetworkConfig(vpc_id="", subnet_ids=[]))
    security: SecurityConfig = field(default_factory=SecurityConfig)
    iam_roles: list[dict] = field(default_factory=list)


@dataclass
class ClusterConfig:
    """聚合后的集群配置"""
    k8s: K8sConfig = field(default_factory=K8sConfig)
    aws: AwsConfig = field(default_factory=AwsConfig)
    collection_errors: list[str] = field(default_factory=list)
    skipped_resources: list[str] = field(default_factory=list)
