"""AIAnalyzer — 使用 Amazon Bedrock (Claude) 进行智能分析，失败时回退到 TemplateEngine."""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3

from eks_health_check.models import (
    CheckResult,
    ClusterConfig,
    Recommendation,
    RiskLevel,
)
from eks_health_check.analyzer.template_engine import TemplateEngine

logger = logging.getLogger(__name__)

_RISK_LEVEL_MAP: dict[str, RiskLevel] = {
    "critical": RiskLevel.CRITICAL,
    "warning": RiskLevel.WARNING,
    "info": RiskLevel.INFO,
}


class AIAnalyzer:
    """AI 智能分析引擎.

    Parameters
    ----------
    region : str
        AWS Region for Bedrock.
    model_id : str
        Bedrock model identifier.
    skip_ai : bool
        If *True*, skip Bedrock entirely and use TemplateEngine.
    template_engine : TemplateEngine | None
        Optional pre-built TemplateEngine instance (for testing / reuse).
    """

    def __init__(
        self,
        region: str = "us-east-1",
        model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0",
        skip_ai: bool = False,
        template_engine: TemplateEngine | None = None,
    ) -> None:
        self.region = region
        self.model_id = model_id
        self.skip_ai = skip_ai
        self._template_engine = template_engine or TemplateEngine()
        self._client: Any | None = None  # lazy-init boto3 client

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        results: list[CheckResult],
        config: ClusterConfig,
    ) -> list[Recommendation]:
        """对检查结果进行分析，返回 Recommendation 列表."""
        failed = [r for r in results if not r.passed]
        if not failed:
            return []

        if self.skip_ai:
            return self._template_engine.generate_all(results)

        try:
            return self._invoke_bedrock(failed, config)
        except Exception:
            logger.warning("Bedrock 调用失败，回退到 TemplateEngine", exc_info=True)
            return self._fallback(results)

    # ------------------------------------------------------------------
    # Bedrock interaction
    # ------------------------------------------------------------------

    def _get_client(self) -> Any:
        if self._client is None:
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self.region,
            )
        return self._client

    def _invoke_bedrock(
        self,
        failed_results: list[CheckResult],
        config: ClusterConfig,
    ) -> list[Recommendation]:
        prompt = self._build_prompt(failed_results, config)
        client = self._get_client()

        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        })

        response = client.invoke_model(
            modelId=self.model_id,
            contentType="application/json",
            accept="application/json",
            body=body,
        )

        resp_body = json.loads(response["body"].read())
        text = resp_body["content"][0]["text"]
        return self._parse_response(text, failed_results)

    # ------------------------------------------------------------------
    # Prompt building
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        results: list[CheckResult],
        config: ClusterConfig,
    ) -> str:
        cluster_summary = self._build_cluster_summary(config)
        issues_text = self._build_issues_text(results)

        return (
            "你是一位 AWS EKS 集群运维专家。请根据以下集群信息和健康检查结果，"
            "进行关联分析并生成优化建议。\n\n"
            f"## 集群概况\n{cluster_summary}\n\n"
            f"## 检查发现的问题\n{issues_text}\n\n"
            "## 输出要求\n"
            "请以 JSON 数组格式输出建议，每条建议包含以下字段：\n"
            "- rule_id: 关联的规则 ID\n"
            "- title: 建议标题\n"
            "- description: 问题描述（结合集群上下文）\n"
            "- risk_level: 风险等级 (critical / warning / info)\n"
            "- steps: 优化步骤列表\n"
            "- expected_benefit: 预期收益\n"
            "- priority: 优先级 (1=最高)\n\n"
            "请注意：\n"
            "1. 识别多个问题之间的关联性\n"
            "2. 根据集群规模和特征适配建议\n"
            "3. 仅输出 JSON 数组，不要包含其他文本\n"
        )

    @staticmethod
    def _build_cluster_summary(config: ClusterConfig) -> str:
        k8s = config.k8s
        aws = config.aws
        lines = [
            f"- 集群版本: {k8s.cluster_version}",
            f"- 节点数: {len(k8s.nodes)}",
            f"- Pod 数: {len(k8s.workloads.pods)}",
            f"- 节点组数: {len(aws.node_groups)}",
            f"- VPC: {aws.network.vpc_id}",
        ]
        if aws.node_groups:
            types = set()
            for ng in aws.node_groups:
                types.update(ng.instance_types)
            lines.append(f"- 实例类型: {', '.join(sorted(types))}")
        return "\n".join(lines)

    @staticmethod
    def _build_issues_text(results: list[CheckResult]) -> str:
        lines: list[str] = []
        for r in results:
            lines.append(
                f"- [{r.risk_level.value}] {r.rule_id} {r.name}: "
                f"{r.message} (当前值: {r.current_value}, 建议值: {r.expected_value})"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(
        self,
        text: str,
        failed_results: list[CheckResult],
    ) -> list[Recommendation]:
        """Parse Bedrock JSON response into Recommendation list."""
        try:
            # Strip markdown code fences if present
            cleaned = text.strip()
            if cleaned.startswith("```"):
                first_newline = cleaned.index("\n")
                last_fence = cleaned.rfind("```")
                cleaned = cleaned[first_newline + 1 : last_fence].strip()

            items = json.loads(cleaned)
            if not isinstance(items, list):
                raise ValueError("Expected JSON array")

            recommendations: list[Recommendation] = []
            for item in items:
                risk = _RISK_LEVEL_MAP.get(
                    str(item.get("risk_level", "info")).lower(),
                    RiskLevel.INFO,
                )
                recommendations.append(
                    Recommendation(
                        rule_id=item.get("rule_id", ""),
                        title=item.get("title", ""),
                        description=item.get("description", ""),
                        risk_level=risk,
                        steps=item.get("steps", []),
                        expected_benefit=item.get("expected_benefit", ""),
                        priority=int(item.get("priority", 5)),
                    )
                )
            return recommendations
        except Exception:
            logger.warning("Bedrock 响应解析失败，回退到 TemplateEngine", exc_info=True)
            return self._template_engine.generate_all(
                [r for r in failed_results]
            )

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------

    def _fallback(self, results: list[CheckResult]) -> list[Recommendation]:
        """Bedrock 调用失败时回退到 TemplateEngine."""
        return self._template_engine.generate_all(results)
