"""Tests for Report Generator layer: ScoreCalculator, MarkdownRenderer, ReportParser round-trip."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from eks_health_check.models import (
    CheckDimension,
    CheckResult,
    DimensionScore,
    Recommendation,
    ReportData,
    RiskLevel,
)
from eks_health_check.report.markdown_renderer import MarkdownRenderer
from eks_health_check.report.report_parser import ReportParser
from eks_health_check.report.score_calculator import ScoreCalculator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(
    rule_id: str = "TEST-001",
    dimension: CheckDimension = CheckDimension.INFRASTRUCTURE,
    risk_level: RiskLevel = RiskLevel.WARNING,
    passed: bool = False,
) -> CheckResult:
    return CheckResult(
        rule_id=rule_id,
        name=f"check {rule_id}",
        dimension=dimension,
        risk_level=risk_level,
        passed=passed,
        current_value="actual",
        expected_value="expected",
        message=f"msg for {rule_id}",
    )


def _make_report_data(
    check_results: list[CheckResult] | None = None,
    recommendations: list[Recommendation] | None = None,
    skipped: list[str] | None = None,
) -> ReportData:
    calc = ScoreCalculator()
    results = check_results or []
    dim_scores = [calc.calculate_dimension_score(results, d) for d in CheckDimension]
    overall = calc.calculate_overall_score(dim_scores)
    return ReportData(
        cluster_name="test-cluster",
        region="us-west-2",
        scan_time=datetime(2025, 6, 15, 10, 30, 0),
        cluster_version="1.30",
        node_count=5,
        pod_count=42,
        check_results=results,
        recommendations=recommendations or [],
        dimension_scores=dim_scores,
        overall_score=overall,
        skipped_resources=skipped or [],
    )


# ---------------------------------------------------------------------------
# ScoreCalculator
# ---------------------------------------------------------------------------

class TestScoreCalculatorFormula:
    """验证评分公式: score = 100 - (critical×20 + warning×10 + info×3)"""

    def test_3_critical_2_warning(self):
        """3 critical + 2 warning → 100 - 60 - 20 = 20"""
        results = (
            [_make_result(f"C-{i}", risk_level=RiskLevel.CRITICAL) for i in range(3)]
            + [_make_result(f"W-{i}", risk_level=RiskLevel.WARNING) for i in range(2)]
        )
        calc = ScoreCalculator()
        ds = calc.calculate_dimension_score(results, CheckDimension.INFRASTRUCTURE)
        assert ds.score == 20
        assert ds.critical_count == 3
        assert ds.warning_count == 2

    def test_all_passed_gives_100(self):
        results = [_make_result(passed=True)]
        calc = ScoreCalculator()
        ds = calc.calculate_dimension_score(results, CheckDimension.INFRASTRUCTURE)
        assert ds.score == 100
        assert ds.passed_checks == 1

    def test_only_info_deductions(self):
        """2 info → 100 - 6 = 94"""
        results = [_make_result(f"I-{i}", risk_level=RiskLevel.INFO) for i in range(2)]
        calc = ScoreCalculator()
        ds = calc.calculate_dimension_score(results, CheckDimension.INFRASTRUCTURE)
        assert ds.score == 94

    def test_passed_results_not_penalized(self):
        """Passed critical should not deduct points."""
        results = [_make_result(risk_level=RiskLevel.CRITICAL, passed=True)]
        calc = ScoreCalculator()
        ds = calc.calculate_dimension_score(results, CheckDimension.INFRASTRUCTURE)
        assert ds.score == 100


class TestScoreCalculatorClamp:
    """验证 clamp 逻辑: score 不低于 0"""

    def test_many_criticals_clamp_to_zero(self):
        results = [
            _make_result(f"C-{i}", dimension=CheckDimension.SECURITY, risk_level=RiskLevel.CRITICAL)
            for i in range(10)
        ]
        calc = ScoreCalculator()
        ds = calc.calculate_dimension_score(results, CheckDimension.SECURITY)
        assert ds.score == 0

    def test_mixed_heavy_penalties_clamp_to_zero(self):
        results = [
            _make_result(f"C-{i}", dimension=CheckDimension.NETWORK, risk_level=RiskLevel.CRITICAL)
            for i in range(4)
        ] + [
            _make_result(f"W-{i}", dimension=CheckDimension.NETWORK, risk_level=RiskLevel.WARNING)
            for i in range(5)
        ]
        calc = ScoreCalculator()
        ds = calc.calculate_dimension_score(results, CheckDimension.NETWORK)
        # 4*20 + 5*10 = 130 → 100-130 = -30 → clamped to 0
        assert ds.score == 0

    def test_no_results_gives_100(self):
        calc = ScoreCalculator()
        ds = calc.calculate_dimension_score([], CheckDimension.WORKLOAD)
        assert ds.score == 100
        assert ds.total_checks == 0


class TestScoreCalculatorWeightedAverage:
    """验证加权平均计算"""

    def test_uniform_scores(self):
        """All dimensions score 80 → overall = 80"""
        scores = [
            DimensionScore(d, 80, 5, 4, 0, 1, 0) for d in CheckDimension
        ]
        calc = ScoreCalculator()
        assert calc.calculate_overall_score(scores) == 80

    def test_weighted_average(self):
        """infra=100, net=100, sec=0, work=100 → 0.25*100+0.25*100+0.30*0+0.20*100 = 70"""
        scores = [
            DimensionScore(CheckDimension.INFRASTRUCTURE, 100, 1, 1, 0, 0, 0),
            DimensionScore(CheckDimension.NETWORK, 100, 1, 1, 0, 0, 0),
            DimensionScore(CheckDimension.SECURITY, 0, 5, 0, 5, 0, 0),
            DimensionScore(CheckDimension.WORKLOAD, 100, 1, 1, 0, 0, 0),
        ]
        calc = ScoreCalculator()
        assert calc.calculate_overall_score(scores) == 70

    def test_empty_scores_gives_100(self):
        calc = ScoreCalculator()
        assert calc.calculate_overall_score([]) == 100

    def test_security_has_highest_weight(self):
        """Security weight=0.30 is highest; low security score should drag overall down more."""
        high_sec = [
            DimensionScore(CheckDimension.INFRASTRUCTURE, 50, 5, 2, 1, 2, 0),
            DimensionScore(CheckDimension.NETWORK, 50, 5, 2, 1, 2, 0),
            DimensionScore(CheckDimension.SECURITY, 100, 5, 5, 0, 0, 0),
            DimensionScore(CheckDimension.WORKLOAD, 50, 5, 2, 1, 2, 0),
        ]
        low_sec = [
            DimensionScore(CheckDimension.INFRASTRUCTURE, 50, 5, 2, 1, 2, 0),
            DimensionScore(CheckDimension.NETWORK, 50, 5, 2, 1, 2, 0),
            DimensionScore(CheckDimension.SECURITY, 0, 5, 0, 5, 0, 0),
            DimensionScore(CheckDimension.WORKLOAD, 50, 5, 2, 1, 2, 0),
        ]
        calc = ScoreCalculator()
        assert calc.calculate_overall_score(high_sec) > calc.calculate_overall_score(low_sec)


# ---------------------------------------------------------------------------
# MarkdownRenderer
# ---------------------------------------------------------------------------

class TestMarkdownRendererSections:
    """验证输出包含所有必需章节"""

    def test_all_sections_present(self):
        data = _make_report_data()
        md = MarkdownRenderer().render(data)
        assert "# EKS 集群健康体检报告" in md
        assert "## 执行摘要" in md
        assert "## 检查项明细" in md
        assert "## 风险分布统计" in md
        assert "## 维度评分" in md
        assert "## 优化建议" in md
        assert "## 附录" in md

    def test_summary_contains_cluster_info(self):
        data = _make_report_data()
        md = MarkdownRenderer().render(data)
        assert "test-cluster" in md
        assert "us-west-2" in md
        assert "1.30" in md

    def test_skipped_resources_shown(self):
        data = _make_report_data(skipped=["configmaps", "secrets"])
        md = MarkdownRenderer().render(data)
        assert "configmaps" in md
        assert "secrets" in md

    def test_no_skipped_resources(self):
        data = _make_report_data()
        md = MarkdownRenderer().render(data)
        assert "无跳过的资源" in md


class TestMarkdownRendererSorting:
    """验证检查项按 Risk_Level 从高到低排序"""

    def test_check_details_sorted_by_risk(self):
        results = [
            _make_result("INFO-1", risk_level=RiskLevel.INFO),
            _make_result("CRIT-1", risk_level=RiskLevel.CRITICAL),
            _make_result("WARN-1", risk_level=RiskLevel.WARNING),
        ]
        data = _make_report_data(check_results=results)
        md = MarkdownRenderer().render(data)

        crit_pos = md.index("CRIT-1")
        warn_pos = md.index("WARN-1")
        info_pos = md.index("INFO-1")
        assert crit_pos < warn_pos < info_pos

    def test_all_passed_shows_message(self):
        results = [_make_result(passed=True)]
        data = _make_report_data(check_results=results)
        md = MarkdownRenderer().render(data)
        assert "所有检查项均已通过" in md


# ---------------------------------------------------------------------------
# ReportParser round-trip
# ---------------------------------------------------------------------------

class TestReportParserRoundTrip:
    """测试 parse(render(data)) 等价于原始数据"""

    def test_round_trip_basic(self):
        results = [
            _make_result("SEC-001", CheckDimension.SECURITY, RiskLevel.CRITICAL),
            _make_result("NET-001", CheckDimension.NETWORK, RiskLevel.WARNING),
        ]
        recs = [
            Recommendation(
                rule_id="SEC-001",
                title="Fix endpoint access",
                description="API server is public",
                risk_level=RiskLevel.CRITICAL,
                steps=["Step one", "Step two"],
                expected_benefit="Improved security",
                priority=1,
            ),
        ]
        original = _make_report_data(check_results=results, recommendations=recs)

        renderer = MarkdownRenderer()
        parser = ReportParser()
        md = renderer.render(original)
        parsed = parser.parse(md)

        # Summary fields
        assert parsed.cluster_name == original.cluster_name
        assert parsed.region == original.region
        assert parsed.scan_time == original.scan_time
        assert parsed.cluster_version == original.cluster_version
        assert parsed.node_count == original.node_count
        assert parsed.pod_count == original.pod_count
        assert parsed.overall_score == original.overall_score

    def test_round_trip_check_results(self):
        results = [
            _make_result("INFRA-001", CheckDimension.INFRASTRUCTURE, RiskLevel.WARNING),
            _make_result("WORK-001", CheckDimension.WORKLOAD, RiskLevel.INFO),
        ]
        original = _make_report_data(check_results=results)

        md = MarkdownRenderer().render(original)
        parsed = ReportParser().parse(md)

        # Only failed results appear in the detail table
        failed_original = [r for r in original.check_results if not r.passed]
        assert len(parsed.check_results) == len(failed_original)
        for orig, prs in zip(
            sorted(failed_original, key=lambda r: r.rule_id),
            sorted(parsed.check_results, key=lambda r: r.rule_id),
        ):
            assert prs.rule_id == orig.rule_id
            assert prs.dimension == orig.dimension
            assert prs.risk_level == orig.risk_level
            assert prs.passed is False

    def test_round_trip_dimension_scores(self):
        results = [
            _make_result("SEC-001", CheckDimension.SECURITY, RiskLevel.CRITICAL),
        ]
        original = _make_report_data(check_results=results)

        md = MarkdownRenderer().render(original)
        parsed = ReportParser().parse(md)

        assert len(parsed.dimension_scores) == len(original.dimension_scores)
        for orig_ds, parsed_ds in zip(
            sorted(original.dimension_scores, key=lambda s: s.dimension.value),
            sorted(parsed.dimension_scores, key=lambda s: s.dimension.value),
        ):
            assert parsed_ds.dimension == orig_ds.dimension
            assert parsed_ds.score == orig_ds.score
            assert parsed_ds.total_checks == orig_ds.total_checks
            assert parsed_ds.passed_checks == orig_ds.passed_checks

    def test_round_trip_recommendations(self):
        recs = [
            Recommendation(
                rule_id="NET-002",
                title="Optimize DNS",
                description="ndots too high",
                risk_level=RiskLevel.WARNING,
                steps=["Lower ndots to 2", "Restart CoreDNS"],
                expected_benefit="Fewer DNS queries",
                priority=2,
            ),
        ]
        original = _make_report_data(recommendations=recs)

        md = MarkdownRenderer().render(original)
        parsed = ReportParser().parse(md)

        assert len(parsed.recommendations) == 1
        pr = parsed.recommendations[0]
        assert pr.rule_id == "NET-002"
        assert pr.title == "Optimize DNS"
        assert pr.risk_level == RiskLevel.WARNING
        assert pr.priority == 2
        assert len(pr.steps) == 2

    def test_round_trip_skipped_resources(self):
        original = _make_report_data(skipped=["configmaps", "secrets"])

        md = MarkdownRenderer().render(original)
        parsed = ReportParser().parse(md)

        assert parsed.skipped_resources == ["configmaps", "secrets"]

    def test_round_trip_empty_report(self):
        original = _make_report_data()

        md = MarkdownRenderer().render(original)
        parsed = ReportParser().parse(md)

        assert parsed.check_results == []
        assert parsed.recommendations == []
        assert parsed.skipped_resources == []
        assert parsed.overall_score == original.overall_score
