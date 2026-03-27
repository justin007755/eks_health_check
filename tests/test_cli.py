"""Integration tests for CLI — 从 CLI 参数到生成报告文件的端到端测试."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from eks_health_check.cli import build_parser, main, run
from eks_health_check.models import (
    AwsConfig,
    ClusterConfig,
    K8sConfig,
    NetworkConfig,
    NodeGroupInfo,
    SecurityConfig,
    WorkloadInfo,
)


# =========================================================================
# Helpers
# =========================================================================


def _mock_cluster_config() -> ClusterConfig:
    """构建一个包含典型问题的 ClusterConfig 用于端到端测试."""
    return ClusterConfig(
        k8s=K8sConfig(
            cluster_version="1.30",
            nodes=[
                {
                    "name": "node-1",
                    "allocatable_cpu": "4000m",
                    "allocatable_memory": "16Gi",
                    "capacity_cpu": "4000m",
                    "capacity_memory": "16Gi",
                    "labels": {},
                },
            ],
            workloads=WorkloadInfo(
                pods=[
                    {
                        "name": "app-pod",
                        "namespace": "default",
                        "containers": [
                            {
                                "name": "app",
                                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}},
                            }
                        ],
                        "service_account": "default",
                    }
                ],
                deployments=[{"name": "web", "namespace": "default", "replicas": 2}],
                hpas=[],
                pdbs=[],
                service_accounts=[
                    {"name": "default", "namespace": "default", "annotations": {}}
                ],
            ),
            network={
                "coredns_config": {"Corefile": ".:53 { }"},
                "coredns_replicas": 2,
            },
            addons=[],
        ),
        aws=AwsConfig(
            cluster_info={"name": "test-cluster", "region": "us-east-1"},
            node_groups=[
                NodeGroupInfo(
                    name="ng-1",
                    instance_types=["m5.large"],
                    availability_zones=["us-east-1a"],
                    capacity_type="ON_DEMAND",
                    desired_size=2,
                    min_size=1,
                    max_size=4,
                    ami_version="1.30-20250101",
                )
            ],
            network=NetworkConfig(
                vpc_id="vpc-abc",
                subnet_ids=["subnet-1"],
                subnet_available_ips={"subnet-1": 200},
                security_groups=[],
            ),
            security=SecurityConfig(
                audit_logging_enabled=True,
                endpoint_public_access=True,
                endpoint_private_access=True,
                public_access_cidrs=["10.0.0.0/8"],
                secrets_encryption_enabled=True,
            ),
        ),
    )


# =========================================================================
# Parser tests
# =========================================================================


class TestBuildParser:
    def test_required_args(self):
        parser = build_parser()
        args = parser.parse_args(["--cluster", "my-cluster", "--region", "us-west-2"])
        assert args.cluster == "my-cluster"
        assert args.region == "us-west-2"
        assert args.output == "health_report.md"
        assert args.skip_ai is False
        assert args.kubeconfig is None

    def test_all_args(self):
        parser = build_parser()
        args = parser.parse_args([
            "--cluster", "prod",
            "--region", "ap-northeast-1",
            "--kubeconfig", "/tmp/kube.conf",
            "--output", "out.md",
            "--skip-ai",
        ])
        assert args.cluster == "prod"
        assert args.region == "ap-northeast-1"
        assert args.kubeconfig == "/tmp/kube.conf"
        assert args.output == "out.md"
        assert args.skip_ai is True

    def test_missing_required_args_exits(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])


# =========================================================================
# End-to-end: full pipeline with mocked external APIs
# =========================================================================


class TestRunEndToEnd:
    """测试完整流程：ConfigScanner → CheckEngine → AIAnalyzer → ReportGenerator."""

    @patch("eks_health_check.cli.ConfigScanner")
    def test_full_pipeline_generates_report_file(self, MockScanner, tmp_path):
        """从 CLI 参数到生成报告文件的完整流程."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = _mock_cluster_config()
        MockScanner.return_value = mock_scanner

        output_path = str(tmp_path / "report.md")

        run(
            cluster_name="test-cluster",
            region="us-east-1",
            output=output_path,
            skip_ai=True,
        )

        assert os.path.exists(output_path)
        content = open(output_path, encoding="utf-8").read()
        # 报告应包含关键章节
        assert "test-cluster" in content or "unknown" in content
        assert len(content) > 100  # 非空报告

    @patch("eks_health_check.cli.ConfigScanner")
    def test_skip_ai_uses_template_engine(self, MockScanner, tmp_path):
        """--skip-ai 参数应跳过 Bedrock 调用，使用 TemplateEngine."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = _mock_cluster_config()
        MockScanner.return_value = mock_scanner

        output_path = str(tmp_path / "report_skip_ai.md")

        # skip_ai=True 不应触发任何 boto3 bedrock-runtime 调用
        with patch("eks_health_check.analyzer.ai_analyzer.boto3") as mock_boto3:
            run(
                cluster_name="test-cluster",
                region="us-east-1",
                output=output_path,
                skip_ai=True,
            )
            # Bedrock client 不应被创建
            mock_boto3.client.assert_not_called()

        assert os.path.exists(output_path)

    @patch("eks_health_check.cli.ConfigScanner")
    def test_report_contains_dimension_scores(self, MockScanner, tmp_path):
        """报告应包含各维度评分."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = _mock_cluster_config()
        MockScanner.return_value = mock_scanner

        output_path = str(tmp_path / "report_scores.md")
        run(
            cluster_name="test-cluster",
            region="us-east-1",
            output=output_path,
            skip_ai=True,
        )

        content = open(output_path, encoding="utf-8").read()
        # 报告应包含四个维度的评分
        for dim_name in ["基础架构", "网络", "安全合规", "应用适配性"]:
            assert dim_name in content

    @patch("eks_health_check.cli.ConfigScanner")
    def test_collection_errors_do_not_crash(self, MockScanner, tmp_path):
        """采集错误不应导致流程崩溃."""
        config = _mock_cluster_config()
        config.collection_errors = ["eks:DescribeCluster: AccessDenied"]
        config.skipped_resources = ["nodes"]

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = config
        MockScanner.return_value = mock_scanner

        output_path = str(tmp_path / "report_errors.md")
        run(
            cluster_name="test-cluster",
            region="us-east-1",
            output=output_path,
            skip_ai=True,
        )

        assert os.path.exists(output_path)


# =========================================================================
# Connection failure
# =========================================================================


class TestConnectionFailure:
    """测试连接失败时的错误输出."""

    @patch("eks_health_check.cli.ConfigScanner")
    def test_scanner_exception_propagates_to_main(self, MockScanner):
        """ConfigScanner 连接失败时 main() 应输出错误并退出."""
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = ConnectionError("无法连接到集群 API Server")
        MockScanner.return_value = mock_scanner

        with pytest.raises(SystemExit) as exc_info:
            main(["--cluster", "bad-cluster", "--region", "us-east-1"])
        assert exc_info.value.code == 1

    @patch("eks_health_check.cli.ConfigScanner")
    def test_scanner_exception_prints_error(self, MockScanner, capsys):
        """连接失败时应在 stderr 输出错误信息."""
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = ConnectionError("无法连接到集群 API Server")
        MockScanner.return_value = mock_scanner

        with pytest.raises(SystemExit):
            main(["--cluster", "bad-cluster", "--region", "us-east-1"])

        captured = capsys.readouterr()
        assert "无法连接到集群 API Server" in captured.err

    @patch("eks_health_check.cli.ConfigScanner")
    def test_check_engine_exception_propagates(self, MockScanner, tmp_path):
        """CheckEngine 异常时 main() 应输出错误并退出."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = _mock_cluster_config()
        MockScanner.return_value = mock_scanner

        with patch("eks_health_check.cli.build_default_engine") as mock_engine:
            mock_engine.return_value.run.side_effect = RuntimeError("规则加载失败")
            with pytest.raises(SystemExit):
                main([
                    "--cluster", "test",
                    "--region", "us-east-1",
                    "--output", str(tmp_path / "out.md"),
                ])


# =========================================================================
# __main__.py entry point
# =========================================================================


class TestMainModule:
    """测试 python -m eks_health_check 入口."""

    @patch("eks_health_check.cli.ConfigScanner")
    def test_main_entry_point(self, MockScanner, tmp_path):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = _mock_cluster_config()
        MockScanner.return_value = mock_scanner

        output_path = str(tmp_path / "main_report.md")
        main([
            "--cluster", "test-cluster",
            "--region", "us-east-1",
            "--output", output_path,
            "--skip-ai",
        ])

        assert os.path.exists(output_path)
