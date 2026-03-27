"""TemplateEngine — 基于 check_rules.yaml 预定义模板生成 Recommendation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from eks_health_check.models import CheckResult, Recommendation, RiskLevel


# 风险等级 → 优先级映射
_PRIORITY_MAP: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 1,
    RiskLevel.WARNING: 3,
    RiskLevel.INFO: 5,
}

# 每条规则的预定义建议模板: rule_id → {steps, expected_benefit}
_RULE_TEMPLATES: dict[str, dict[str, Any]] = {
    # --- Infrastructure ---
    "INFRA-001": {
        "steps": [
            "在节点组配置中添加多种实例类型（至少 2 种）",
            "选择同系列不同规格的实例以保持兼容性（如 m5.large + m5.xlarge）",
            "更新 Auto Scaling Group 的混合实例策略",
        ],
        "expected_benefit": "提升节点调度灵活性和可用性，降低单一实例类型容量不足的风险",
    },
    "INFRA-002": {
        "steps": [
            "将节点组配置为跨至少 2 个可用区部署",
            "确保子网覆盖目标可用区",
        ],
        "expected_benefit": "提升集群跨 AZ 高可用能力，防止单 AZ 故障导致服务中断",
    },
    "INFRA-003": {
        "steps": [
            "审查工作负载的 resource request 设置，移除过度分配",
            "考虑使用 VPA 自动调整 request 值",
            "监控节点实际利用率，按需扩缩节点组",
        ],
        "expected_benefit": "优化资源利用率，降低成本或避免资源不足导致的调度失败",
    },
    "INFRA-004": {
        "steps": [
            "评估引入 Karpenter 或 Cluster Autoscaler 的可行性",
            "Karpenter 适合需要快速弹性伸缩的场景",
            "Cluster Autoscaler 适合节点组管理模式的集群",
        ],
        "expected_benefit": "实现节点自动伸缩，提升资源利用率并降低运维成本",
    },
    "INFRA-005": {
        "steps": [
            "查看 AWS EKS 版本支持日历，确认当前版本的 End of Support 日期",
            "制定集群版本升级计划",
            "在非生产环境先行验证升级兼容性",
        ],
        "expected_benefit": "确保集群持续获得安全补丁和功能更新，避免版本过期带来的合规风险",
    },
    # --- Network ---
    "NET-001": {
        "steps": [
            "检查 VPC CNI 的 WARM_ENI_TARGET、WARM_IP_TARGET 等参数",
            "根据工作负载规模调整 IP 预热策略",
            "考虑启用 ENABLE_PREFIX_DELEGATION 以提升 IP 密度",
        ],
        "expected_benefit": "优化 Pod 网络 IP 分配效率，减少 IP 地址浪费或不足",
    },
    "NET-002": {
        "steps": [
            "将 Pod DNS 配置中的 ndots 值调整为 2",
            "在 Pod spec 中通过 dnsConfig 显式设置 ndots",
        ],
        "expected_benefit": "减少无效 DNS 查询次数，降低 CoreDNS 负载，提升 DNS 解析性能",
    },
    "NET-003": {
        "steps": [
            "根据集群节点数调整 CoreDNS 副本数（建议每 100 节点至少 2 副本）",
            "配置 CoreDNS HPA 实现自动伸缩",
        ],
        "expected_benefit": "确保 DNS 服务能力与集群规模匹配，避免 DNS 查询延迟或超时",
    },
    "NET-004": {
        "steps": [
            "部署 NodeLocal DNSCache DaemonSet",
            "验证 Pod DNS 查询是否命中本地缓存",
        ],
        "expected_benefit": "减轻 CoreDNS 集中压力，降低 DNS 查询延迟",
    },
    "NET-005": {
        "steps": [
            "检查子网可用 IP 数量，评估 IP 耗尽风险",
            "考虑添加新子网或启用 VPC CNI Prefix Delegation",
            "清理不再使用的 ENI 和 IP 地址",
        ],
        "expected_benefit": "避免 IP 地址耗尽导致 Pod 无法调度，保障业务连续性",
    },
    "NET-006": {
        "steps": [
            "审查 Security Group 入站规则，移除 0.0.0.0/0 开放规则",
            "按最小权限原则配置安全组，仅允许必要的源 IP 和端口",
        ],
        "expected_benefit": "降低网络攻击面，提升集群网络安全性",
    },
    # --- Security ---
    "SEC-001": {
        "steps": [
            "在 EKS 集群配置中启用控制平面审计日志",
            "将日志类型设置为包含 api、audit、authenticator",
            "配置 CloudWatch Logs 保留策略",
        ],
        "expected_benefit": "满足 CIS EKS Benchmark 合规要求，支持安全事件审计和溯源",
    },
    "SEC-002": {
        "steps": [
            "评估 API Server endpoint 访问策略",
            "建议配置为 Private 或 Public+Private 并限制 CIDR",
        ],
        "expected_benefit": "减少 API Server 暴露面，降低未授权访问风险",
    },
    "SEC-003": {
        "steps": [
            "立即为 API Server Public endpoint 配置 CIDR 限制",
            "或将 endpoint 切换为 Private 访问模式",
            "配置 VPN 或 Direct Connect 用于管理访问",
        ],
        "expected_benefit": "消除 API Server 公网无限制暴露的严重安全风险",
    },
    "SEC-004": {
        "steps": [
            "创建 KMS 密钥用于 Secrets 加密",
            "在 EKS 集群配置中启用 envelope encryption",
            "验证现有 Secrets 已被加密",
        ],
        "expected_benefit": "保护 etcd 中存储的敏感数据，满足数据加密合规要求",
    },
    "SEC-005": {
        "steps": [
            "检查当前节点组 AMI 版本与最新 EKS Optimized AMI 的差异",
            "制定节点组滚动更新计划",
            "使用 Managed Node Group 的更新功能进行滚动替换",
        ],
        "expected_benefit": "获取最新安全补丁和内核更新，降低已知漏洞风险",
    },
    "SEC-006": {
        "steps": [
            "识别使用 aws-node 默认 IAM 角色的工作负载",
            "为每个工作负载创建独立的 IAM 角色",
            "迁移至 Pod Identity 或 IRSA 进行细粒度权限管理",
        ],
        "expected_benefit": "实现最小权限原则，避免工作负载获得过多 AWS 权限",
    },
    # --- Workload ---
    "WORK-001": {
        "steps": [
            "为所有 Pod 容器设置 CPU 和内存的 request 与 limit",
            "使用 LimitRange 为命名空间设置默认值",
        ],
        "expected_benefit": "确保调度器合理分配资源，避免资源争抢和 OOM Kill",
    },
    "WORK-002": {
        "steps": [
            "调整 request 与 limit 的比值至 3 倍以内",
            "参考实际资源使用量设置合理的 request 和 limit",
        ],
        "expected_benefit": "降低 OOM Kill 风险和资源浪费，提升调度稳定性",
    },
    "WORK-003": {
        "steps": [
            "为关键 Deployment 创建 PodDisruptionBudget",
            "设置合理的 minAvailable 或 maxUnavailable 值",
        ],
        "expected_benefit": "在节点维护或升级时保障服务可用性",
    },
    "WORK-004": {
        "steps": [
            "确保 HPA minReplicas 大于 1 以保障高可用",
            "配置合理的 scaleDown stabilizationWindowSeconds 避免频繁缩容",
            "使用自定义 metrics 替代纯 CPU 指标以提升伸缩精度",
        ],
        "expected_benefit": "提升自动伸缩的稳定性和准确性",
    },
    "WORK-005": {
        "steps": [
            "为所有 Pod 配置 readinessProbe 和 livenessProbe",
            "根据应用特性设置合理的探针参数（initialDelaySeconds、periodSeconds）",
        ],
        "expected_benefit": "确保流量仅路由到健康 Pod，自动重启异常容器",
    },
    "WORK-006": {
        "steps": [
            "立即停止在 Pod 中直接使用 AWS Access Key",
            "为工作负载配置 Pod Identity 或 IRSA",
            "使用 IAM 角色实现临时凭证自动轮转",
        ],
        "expected_benefit": "消除硬编码凭证泄露风险，实现安全的 AWS 权限管理",
    },
}


class TemplateEngine:
    """基于 check_rules.yaml 预定义模板的建议生成器."""

    def __init__(self, rules_path: str | Path | None = None) -> None:
        self._rules: list[dict[str, Any]] = self._load_rules(rules_path)

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def generate(self, result: CheckResult) -> Recommendation:
        """根据 CheckResult 生成 Recommendation."""
        template = _RULE_TEMPLATES.get(result.rule_id, {})
        rule_cfg = self._find_rule(result.rule_id)
        description = rule_cfg.get("description", result.message) if rule_cfg else result.message

        return Recommendation(
            rule_id=result.rule_id,
            title=result.name,
            description=description,
            risk_level=result.risk_level,
            steps=list(template.get("steps", [f"请参考 EKS 最佳实践文档修复 {result.rule_id}"])),
            expected_benefit=template.get("expected_benefit", "提升集群健康度"),
            priority=_PRIORITY_MAP.get(result.risk_level, 5),
        )

    def generate_all(self, results: list[CheckResult]) -> list[Recommendation]:
        """为所有未通过的 CheckResult 生成建议列表."""
        return [self.generate(r) for r in results if not r.passed]

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    @staticmethod
    def _load_rules(rules_path: str | Path | None) -> list[dict[str, Any]]:
        if rules_path is None:
            rules_path = Path(__file__).resolve().parent.parent / "check_rules.yaml"
        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("rules", [])

    def _find_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self._rules:
            if r["id"] == rule_id:
                return r
        return None
