"""CLI 入口 — 编排完整的 EKS 集群健康检查流程."""

from __future__ import annotations

import argparse
import sys

from eks_health_check.analyzer.ai_analyzer import AIAnalyzer
from eks_health_check.checkers import build_default_engine
from eks_health_check.report.report_generator import ReportGenerator
from eks_health_check.scanner.config_scanner import ConfigScanner


def build_parser() -> argparse.ArgumentParser:
    """构建 CLI 参数解析器."""
    parser = argparse.ArgumentParser(
        description="EKS 集群健康体检工具 — 扫描集群配置并生成优化建议报告",
    )
    parser.add_argument("--cluster", required=True, help="目标 EKS 集群名称")
    parser.add_argument("--region", required=True, help="AWS Region")
    parser.add_argument("--kubeconfig", default=None, help="自定义 kubeconfig 路径")
    parser.add_argument("--output", default="health_report.md", help="报告输出路径")
    parser.add_argument("--skip-ai", action="store_true", help="跳过 AI 分析，仅使用模板化建议")
    return parser


def run(
    cluster_name: str,
    region: str,
    kubeconfig: str | None = None,
    output: str = "health_report.md",
    skip_ai: bool = False,
) -> None:
    """主入口函数，编排整个健康检查流程."""
    # 1. Config Scanner
    print(f"[1/4] 扫描集群配置: {cluster_name} ({region}) ...")
    scanner = ConfigScanner(cluster_name=cluster_name, region=region, kubeconfig=kubeconfig)
    config = scanner.scan()

    if config.collection_errors:
        print(f"  ⚠ 采集过程中出现 {len(config.collection_errors)} 个错误:")
        for err in config.collection_errors:
            print(f"    - {err}")

    # 2. Check Engine
    print("[2/4] 执行检查规则 ...")
    engine = build_default_engine()
    results = engine.run(config)
    passed = sum(1 for r in results if r.passed)
    print(f"  检查完成: {len(results)} 项, 通过 {passed} 项")

    # 3. AI Analyzer
    print("[3/4] 生成优化建议 ...")
    analyzer = AIAnalyzer(region=region, skip_ai=skip_ai)
    recommendations = analyzer.analyze(results, config)
    print(f"  生成 {len(recommendations)} 条建议")

    # 4. Report Generator
    print("[4/4] 生成报告 ...")
    generator = ReportGenerator()
    report = generator.generate(results, recommendations, config)

    with open(output, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"报告已保存至: {output}")


def main(argv: list[str] | None = None) -> None:
    """CLI 入口点."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        run(
            cluster_name=args.cluster,
            region=args.region,
            kubeconfig=args.kubeconfig,
            output=args.output,
            skip_ai=args.skip_ai,
        )
    except Exception as exc:
        print(f"错误: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
