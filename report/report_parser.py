"""Markdown 报告解析器 - 将 Markdown 报告解析回 ReportData 结构（用于 round-trip 验证）"""

from __future__ import annotations

import re
from datetime import datetime

from eks_health_check.models import (
    CheckDimension,
    CheckResult,
    DimensionScore,
    Recommendation,
    ReportData,
    RiskLevel,
)

# 维度名称 → 枚举的反向映射
_DIM_MAP = {d.value: d for d in CheckDimension}
_RISK_MAP = {r.value: r for r in RiskLevel}


class ReportParser:
    """Markdown 报告解析器"""

    def parse(self, markdown: str) -> ReportData:
        """将 Markdown 报告解析回 ReportData 结构"""
        summary = self._parse_summary(markdown)
        check_results = self._parse_check_details(markdown)
        dimension_scores = self._parse_dimension_scores(markdown)
        overall_score = self._parse_overall_score(markdown)
        recommendations = self._parse_recommendations(markdown)
        skipped = self._parse_skipped_resources(markdown)

        return ReportData(
            cluster_name=summary["cluster_name"],
            region=summary["region"],
            scan_time=summary["scan_time"],
            cluster_version=summary["cluster_version"],
            node_count=summary["node_count"],
            pod_count=summary["pod_count"],
            check_results=check_results,
            recommendations=recommendations,
            dimension_scores=dimension_scores,
            overall_score=overall_score,
            skipped_resources=skipped,
        )

    # ------------------------------------------------------------------
    # 内部解析方法
    # ------------------------------------------------------------------

    def _parse_summary(self, md: str) -> dict:
        """解析执行摘要表格"""
        section = self._extract_section(md, "执行摘要")
        rows = self._parse_table_rows(section)
        row_map = {r[0].strip(): r[1].strip() for r in rows if len(r) >= 2}

        return {
            "cluster_name": row_map.get("集群名称", ""),
            "region": row_map.get("区域", ""),
            "scan_time": datetime.strptime(row_map.get("扫描时间", ""), "%Y-%m-%d %H:%M:%S"),
            "cluster_version": row_map.get("集群版本", ""),
            "node_count": int(row_map.get("节点数", "0")),
            "pod_count": int(row_map.get("Pod 数", "0")),
        }

    def _parse_check_details(self, md: str) -> list[CheckResult]:
        """解析检查项明细表格"""
        section = self._extract_section(md, "检查项明细")
        if "所有检查项均已通过" in section:
            return []

        rows = self._parse_table_rows(section)
        results: list[CheckResult] = []
        for row in rows:
            if len(row) < 7:
                continue
            results.append(
                CheckResult(
                    rule_id=row[0].strip(),
                    name=row[1].strip(),
                    dimension=_DIM_MAP[row[2].strip()],
                    risk_level=_RISK_MAP[row[3].strip()],
                    passed=False,
                    current_value=row[4].strip(),
                    expected_value=row[5].strip(),
                    message=row[6].strip(),
                )
            )
        return results

    def _parse_dimension_scores(self, md: str) -> list[DimensionScore]:
        """解析维度评分表格"""
        section = self._extract_section(md, "维度评分")
        rows = self._parse_table_rows(section)
        scores: list[DimensionScore] = []
        for row in rows:
            if len(row) < 7:
                continue
            scores.append(
                DimensionScore(
                    dimension=_DIM_MAP[row[0].strip()],
                    score=int(row[1].strip()),
                    total_checks=int(row[2].strip()),
                    passed_checks=int(row[3].strip()),
                    critical_count=int(row[4].strip()),
                    warning_count=int(row[5].strip()),
                    info_count=int(row[6].strip()),
                )
            )
        return scores

    def _parse_overall_score(self, md: str) -> int:
        """解析综合健康评分"""
        m = re.search(r"\*\*综合健康评分:\s*(\d+)\*\*", md)
        return int(m.group(1)) if m else 0

    def _parse_recommendations(self, md: str) -> list[Recommendation]:
        """解析优化建议"""
        section = self._extract_section(md, "优化建议")
        if "暂无优化建议" in section:
            return []

        recs: list[Recommendation] = []
        # 按 ### 分割各建议块
        blocks = re.split(r"^### ", section, flags=re.MULTILINE)
        for block in blocks:
            block = block.strip()
            if not block:
                continue
            rec = self._parse_single_recommendation(block)
            if rec:
                recs.append(rec)
        return recs

    def _parse_single_recommendation(self, block: str) -> Recommendation | None:
        """解析单条优化建议"""
        # 标题行: [Critical] 建议标题
        title_match = re.match(r"\[(\w+)\]\s*(.+)", block.split("\n")[0])
        if not title_match:
            return None

        risk_str = title_match.group(1)
        title = title_match.group(2).strip()

        def _field(label: str) -> str:
            m = re.search(rf"- \*\*{label}\*\*:\s*(.+)", block)
            return m.group(1).strip() if m else ""

        rule_id = _field("规则 ID")
        description = _field("问题描述")
        risk_level = _RISK_MAP.get(risk_str, RiskLevel.INFO)
        expected_benefit = _field("预期收益")
        priority_str = _field("优先级")
        priority = int(priority_str) if priority_str.isdigit() else 5

        # 解析优化步骤
        steps: list[str] = []
        step_match = re.search(r"- \*\*优化步骤\*\*:\n((?:\s+\d+\..+\n?)+)", block)
        if step_match:
            for line in step_match.group(1).strip().split("\n"):
                line = line.strip()
                step_text = re.sub(r"^\d+\.\s*", "", line)
                if step_text:
                    steps.append(step_text)

        return Recommendation(
            rule_id=rule_id,
            title=title,
            description=description,
            risk_level=risk_level,
            steps=steps,
            expected_benefit=expected_benefit,
            priority=priority,
        )

    def _parse_skipped_resources(self, md: str) -> list[str]:
        """解析跳过的资源列表"""
        section = self._extract_section(md, "附录")
        if "无跳过的资源" in section:
            return []
        items: list[str] = []
        for line in section.split("\n"):
            line = line.strip()
            if line.startswith("- ") and "权限不足" not in line:
                items.append(line[2:])
        return items

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------

    def _extract_section(self, md: str, heading: str) -> str:
        """提取 ## heading 到下一个 ## 之间的内容"""
        pattern = rf"^## {re.escape(heading)}\s*\n(.*?)(?=^## |\Z)"
        m = re.search(pattern, md, re.MULTILINE | re.DOTALL)
        return m.group(1) if m else ""

    def _parse_table_rows(self, section: str) -> list[list[str]]:
        """解析 Markdown 表格，跳过表头和分隔行，返回数据行"""
        rows: list[list[str]] = []
        lines = section.strip().split("\n")
        for i, line in enumerate(lines):
            line = line.strip()
            if not line.startswith("|"):
                continue
            # 跳过分隔行 (|---|---|)
            if re.match(r"^\|[\s\-|]+\|$", line):
                continue
            cells = [c.strip() for c in line.split("|")[1:-1]]
            # 跳过表头（第一个数据行之前）
            if i == 0 and cells:
                continue
            if cells:
                rows.append(cells)
        return rows
