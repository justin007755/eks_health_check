"""报告生成器 - 编排 ScoreCalculator 和 MarkdownRenderer 生成完整报告"""

from __future__ import annotations

from datetime import datetime, timezone

from eks_health_check.models import (
    CheckDimension,
    CheckResult,
    ClusterConfig,
    Recommendation,
    ReportData,
)
from eks_health_check.report.markdown_renderer import MarkdownRenderer
from eks_health_check.report.score_calculator import ScoreCalculator


class ReportGenerator:
    """报告生成器，编排评分计算和渲染"""

    def __init__(self) -> None:
        self._scorer = ScoreCalculator()
        self._renderer = MarkdownRenderer()

    def generate(
        self,
        results: list[CheckResult],
        recommendations: list[Recommendation],
        config: ClusterConfig,
    ) -> str:
        """生成完整的 Markdown 健康报告"""
        # 计算各维度评分
        dimension_scores = [
            self._scorer.calculate_dimension_score(results, dim)
            for dim in CheckDimension
        ]
        overall_score = self._scorer.calculate_overall_score(dimension_scores)

        # 组装 ReportData
        report_data = ReportData(
            cluster_name=config.aws.cluster_info.get("name", "unknown"),
            region=config.aws.cluster_info.get("region", "unknown"),
            scan_time=datetime.now(timezone.utc).replace(microsecond=0),
            cluster_version=config.k8s.cluster_version or "unknown",
            node_count=len(config.k8s.nodes),
            pod_count=len(config.k8s.workloads.pods),
            check_results=results,
            recommendations=recommendations,
            dimension_scores=dimension_scores,
            overall_score=overall_score,
            skipped_resources=config.skipped_resources,
        )

        return self._renderer.render(report_data)
