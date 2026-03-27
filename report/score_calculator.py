"""评分计算器 - 计算各维度评分和综合健康评分"""

from __future__ import annotations

from eks_health_check.models import (
    CheckDimension,
    CheckResult,
    DimensionScore,
    RiskLevel,
)

# 综合评分的维度权重
DIMENSION_WEIGHTS: dict[CheckDimension, float] = {
    CheckDimension.INFRASTRUCTURE: 0.25,
    CheckDimension.NETWORK: 0.25,
    CheckDimension.SECURITY: 0.30,
    CheckDimension.WORKLOAD: 0.20,
}

# 各风险等级的扣分值
RISK_PENALTIES: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 20,
    RiskLevel.WARNING: 10,
    RiskLevel.INFO: 3,
}


class ScoreCalculator:
    """评分计算器"""

    def calculate_dimension_score(
        self,
        results: list[CheckResult],
        dimension: CheckDimension,
    ) -> DimensionScore:
        """计算单个维度的评分 (0-100)。

        公式: score = 100 - (critical×20 + warning×10 + info×3)，clamp 到 [0, 100]
        """
        dim_results = [r for r in results if r.dimension == dimension]

        critical = sum(1 for r in dim_results if not r.passed and r.risk_level == RiskLevel.CRITICAL)
        warning = sum(1 for r in dim_results if not r.passed and r.risk_level == RiskLevel.WARNING)
        info = sum(1 for r in dim_results if not r.passed and r.risk_level == RiskLevel.INFO)
        passed = sum(1 for r in dim_results if r.passed)

        penalty = (
            critical * RISK_PENALTIES[RiskLevel.CRITICAL]
            + warning * RISK_PENALTIES[RiskLevel.WARNING]
            + info * RISK_PENALTIES[RiskLevel.INFO]
        )
        score = max(0, min(100, 100 - penalty))

        return DimensionScore(
            dimension=dimension,
            score=score,
            total_checks=len(dim_results),
            passed_checks=passed,
            critical_count=critical,
            warning_count=warning,
            info_count=info,
        )

    def calculate_overall_score(
        self,
        dimension_scores: list[DimensionScore],
    ) -> int:
        """计算综合健康评分（加权平均）。"""
        total_weight = 0.0
        weighted_sum = 0.0
        for ds in dimension_scores:
            w = DIMENSION_WEIGHTS.get(ds.dimension, 0.0)
            weighted_sum += ds.score * w
            total_weight += w

        if total_weight == 0:
            return 100
        return round(weighted_sum / total_weight)
