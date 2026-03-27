"""Markdown 报告渲染器 - 将 ReportData 渲染为结构化 Markdown 报告"""

from __future__ import annotations

from eks_health_check.models import (
    CheckDimension,
    CheckResult,
    DimensionScore,
    ReportData,
    Recommendation,
    RiskLevel,
)

# Risk level 排序权重（高到低）
_RISK_ORDER = {RiskLevel.CRITICAL: 0, RiskLevel.WARNING: 1, RiskLevel.INFO: 2}


class MarkdownRenderer:
    """Markdown 报告渲染器"""

    def render(self, report_data: ReportData) -> str:
        """将报告数据渲染为 Markdown 字符串"""
        sections = [
            self._render_title(),
            self._render_summary(report_data),
            self._render_check_details(report_data.check_results),
            self._render_risk_distribution(report_data),
            self._render_dimension_scores(report_data.dimension_scores, report_data.overall_score),
            self._render_recommendations(report_data.recommendations),
            self._render_appendix(report_data.skipped_resources),
        ]
        return "\n".join(sections)

    # ------------------------------------------------------------------
    # 各章节渲染
    # ------------------------------------------------------------------

    def _render_title(self) -> str:
        return "# EKS 集群健康体检报告\n"

    def _render_summary(self, data: ReportData) -> str:
        scan_time_str = data.scan_time.strftime("%Y-%m-%d %H:%M:%S")
        total = len(data.check_results)
        failed = [r for r in data.check_results if not r.passed]
        critical = sum(1 for r in failed if r.risk_level == RiskLevel.CRITICAL)
        warning = sum(1 for r in failed if r.risk_level == RiskLevel.WARNING)
        info = sum(1 for r in failed if r.risk_level == RiskLevel.INFO)

        lines = [
            "## 执行摘要\n",
            f"| 项目 | 值 |",
            f"|------|------|",
            f"| 扫描时间 | {scan_time_str} |",
            f"| 集群名称 | {data.cluster_name} |",
            f"| 区域 | {data.region} |",
            f"| 集群版本 | {data.cluster_version} |",
            f"| 节点数 | {data.node_count} |",
            f"| Pod 数 | {data.pod_count} |",
            f"| 检查项总数 | {total} |",
            f"| Critical | {critical} |",
            f"| Warning | {warning} |",
            f"| Info | {info} |",
            "",
        ]
        return "\n".join(lines)

    def _render_check_details(self, results: list[CheckResult]) -> str:
        failed = sorted(
            [r for r in results if not r.passed],
            key=lambda r: _RISK_ORDER.get(r.risk_level, 99),
        )
        if not failed:
            lines = ["## 检查项明细\n", "所有检查项均已通过。\n"]
            return "\n".join(lines)

        lines = [
            "## 检查项明细\n",
            "| 规则 ID | 名称 | 维度 | 风险等级 | 当前值 | 建议值 | 说明 |",
            "|---------|------|------|----------|--------|--------|------|",
        ]
        for r in failed:
            lines.append(
                f"| {r.rule_id} | {r.name} | {r.dimension.value} "
                f"| {r.risk_level.value} | {r.current_value} "
                f"| {r.expected_value} | {r.message} |"
            )
        lines.append("")
        return "\n".join(lines)

    def _render_risk_distribution(self, data: ReportData) -> str:
        failed = [r for r in data.check_results if not r.passed]
        dist: dict[str, dict[str, int]] = {}
        for dim in CheckDimension:
            dist[dim.value] = {"Critical": 0, "Warning": 0, "Info": 0}
        for r in failed:
            dist[r.dimension.value][r.risk_level.value] += 1

        lines = [
            "## 风险分布统计\n",
            "| 维度 | Critical | Warning | Info |",
            "|------|----------|---------|------|",
        ]
        for dim in CheckDimension:
            d = dist[dim.value]
            lines.append(f"| {dim.value} | {d['Critical']} | {d['Warning']} | {d['Info']} |")
        lines.append("")
        return "\n".join(lines)

    def _render_dimension_scores(
        self, scores: list[DimensionScore], overall: int
    ) -> str:
        lines = [
            "## 维度评分\n",
            "| 维度 | 评分 | 总检查数 | 通过数 | Critical | Warning | Info |",
            "|------|------|----------|--------|----------|---------|------|",
        ]
        for s in scores:
            lines.append(
                f"| {s.dimension.value} | {s.score} | {s.total_checks} "
                f"| {s.passed_checks} | {s.critical_count} "
                f"| {s.warning_count} | {s.info_count} |"
            )
        lines.append("")
        lines.append(f"**综合健康评分: {overall}**\n")
        return "\n".join(lines)

    def _render_recommendations(self, recs: list[Recommendation]) -> str:
        if not recs:
            return "## 优化建议\n\n暂无优化建议。\n"

        sorted_recs = sorted(recs, key=lambda r: r.priority)
        lines = ["## 优化建议\n"]
        for rec in sorted_recs:
            lines.append(f"### [{rec.risk_level.value}] {rec.title}\n")
            lines.append(f"- **规则 ID**: {rec.rule_id}")
            lines.append(f"- **问题描述**: {rec.description}")
            lines.append(f"- **风险等级**: {rec.risk_level.value}")
            lines.append(f"- **预期收益**: {rec.expected_benefit}")
            lines.append(f"- **优先级**: {rec.priority}")
            if rec.steps:
                lines.append("- **优化步骤**:")
                for i, step in enumerate(rec.steps, 1):
                    lines.append(f"  {i}. {step}")
            lines.append("")
        return "\n".join(lines)

    def _render_appendix(self, skipped: list[str]) -> str:
        lines = ["## 附录\n"]
        if skipped:
            lines.append("### 跳过的资源\n")
            lines.append("以下资源因权限不足被跳过：\n")
            for s in skipped:
                lines.append(f"- {s}")
            lines.append("")
        else:
            lines.append("无跳过的资源。\n")
        return "\n".join(lines)
