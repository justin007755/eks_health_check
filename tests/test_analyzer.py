"""Tests for AI Analyzer layer: TemplateEngine and AIAnalyzer."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from eks_health_check.models import (
    AwsConfig,
    CheckDimension,
    ClusterConfig,
    K8sConfig,
    NetworkConfig,
    NodeGroupInfo,
    Recommendation,
    RiskLevel,
    SecurityConfig,
    WorkloadInfo,
)
from eks_health_check.analyzer.template_engine import TemplateEngine
from eks_health_check.analyzer.ai_analyzer import AIAnalyzer


# =========================================================================
# Helpers
# =========================================================================

def _make_check_result(
    rule_id: str = "INFRA-001",
    name: str = "节点组实例类型多样性",
    dimension: CheckDimension = CheckDimension.INFRASTRUCTURE,
    risk_level: RiskLevel = RiskLevel.WARNING,
    passed: bool = False,
    current_value: str = "1 种实例类型",
    expected_value: str = "≥2 种实例类型",
    message: str = "节点组仅使用单一实例类型",
):
    from eks_health_check.models import CheckResult
    return CheckResult(
        rule_id=rule_id,
        name=name,
        dimension=dimension,
        risk_level=risk_level,
        passed=passed,
        current_value=current_value,
        expected_value=expected_value,
        message=message,
    )


def _base_config() -> ClusterConfig:
    return ClusterConfig(
        k8s=K8sConfig(
            cluster_version="1.30",
            nodes=[{"name": "n1"}],
            workloads=WorkloadInfo(pods=[{"name": "app", "namespace": "default", "containers": []}]),
        ),
        aws=AwsConfig(
            cluster_info={},
            node_groups=[NodeGroupInfo(
                name="ng-1", instance_types=["m5.large"],
                availability_zones=["us-east-1a"], capacity_type="ON_DEMAND",
                desired_size=2, min_size=1, max_size=4, ami_version="1.30-20250101",
            )],
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"]),
            security=SecurityConfig(),
        ),
    )


# =========================================================================
# TemplateEngine
# =========================================================================

class TestTemplateEngine:
    def test_generate_critical_recommendation(self):
        """Critical CheckResult → priority=1, 正确的 steps 和 benefit."""
        result = _make_check_result(
            rule_id="SEC-003",
            name="API Server 纯 Public 无 CIDR 限制",
            dimension=CheckDimension.SECURITY,
            risk_level=RiskLevel.CRITICAL,
        )
        engine = TemplateEngine()
        rec = engine.generate(result)

        assert isinstance(rec, Recommendation)
        assert rec.rule_id == "SEC-003"
        assert rec.risk_level == RiskLevel.CRITICAL
        assert rec.priority == 1
        assert len(rec.steps) > 0
        assert rec.expected_benefit != ""

    def test_generate_warning_recommendation(self):
        """Warning CheckResult → priority=3."""
        result = _make_check_result(
            rule_id="INFRA-001",
            risk_level=RiskLevel.WARNING,
        )
        engine = TemplateEngine()
        rec = engine.generate(result)

        assert rec.priority == 3
        assert rec.risk_level == RiskLevel.WARNING
        assert "实例类型" in rec.steps[0]

    def test_generate_info_recommendation(self):
        """Info CheckResult → priority=5."""
        result = _make_check_result(
            rule_id="INFRA-004",
            name="自动伸缩组件",
            risk_level=RiskLevel.INFO,
        )
        engine = TemplateEngine()
        rec = engine.generate(result)

        assert rec.priority == 5
        assert rec.risk_level == RiskLevel.INFO

    def test_generate_unknown_rule_id_fallback(self):
        """未知 rule_id → 使用默认 steps 和 benefit."""
        result = _make_check_result(rule_id="UNKNOWN-999")
        engine = TemplateEngine()
        rec = engine.generate(result)

        assert rec.rule_id == "UNKNOWN-999"
        assert len(rec.steps) == 1
        assert "UNKNOWN-999" in rec.steps[0]
        assert rec.expected_benefit == "提升集群健康度"

    def test_generate_all_skips_passed(self):
        """generate_all 只为未通过的 CheckResult 生成建议."""
        passed = _make_check_result(rule_id="INFRA-001", passed=True)
        failed = _make_check_result(rule_id="SEC-003", passed=False, risk_level=RiskLevel.CRITICAL)
        engine = TemplateEngine()
        recs = engine.generate_all([passed, failed])

        assert len(recs) == 1
        assert recs[0].rule_id == "SEC-003"

    def test_generate_all_empty_when_all_passed(self):
        """所有 CheckResult 都通过 → 空列表."""
        results = [_make_check_result(passed=True), _make_check_result(rule_id="NET-002", passed=True)]
        engine = TemplateEngine()
        assert engine.generate_all(results) == []

    def test_description_from_rules_yaml(self):
        """Recommendation.description 来自 check_rules.yaml 中的 description."""
        result = _make_check_result(rule_id="NET-002", name="CoreDNS ndots 配置")
        engine = TemplateEngine()
        rec = engine.generate(result)
        # description should come from the YAML rule, not the CheckResult message
        assert "ndots" in rec.description



# =========================================================================
# AIAnalyzer
# =========================================================================

def _bedrock_json_response(items: list[dict]) -> dict:
    """Build a mock Bedrock invoke_model response."""
    body_text = json.dumps(items)
    resp_body = json.dumps({"content": [{"text": body_text}]})
    mock_body = MagicMock()
    mock_body.read.return_value = resp_body.encode()
    return {"body": mock_body}


class TestAIAnalyzer:
    def test_skip_ai_uses_template_engine(self):
        """skip_ai=True → 直接使用 TemplateEngine，不调用 Bedrock."""
        failed = _make_check_result(rule_id="INFRA-001", passed=False)
        analyzer = AIAnalyzer(skip_ai=True)

        recs = analyzer.analyze([failed], _base_config())

        assert len(recs) == 1
        assert recs[0].rule_id == "INFRA-001"
        assert isinstance(recs[0], Recommendation)

    def test_skip_ai_no_failed_returns_empty(self):
        """skip_ai=True 但所有检查通过 → 空列表."""
        passed = _make_check_result(passed=True)
        analyzer = AIAnalyzer(skip_ai=True)
        assert analyzer.analyze([passed], _base_config()) == []

    @patch("eks_health_check.analyzer.ai_analyzer.boto3")
    def test_bedrock_success(self, mock_boto3):
        """Bedrock 正常返回 → 解析为 Recommendation 列表."""
        ai_items = [
            {
                "rule_id": "INFRA-001",
                "title": "增加实例类型多样性",
                "description": "当前仅使用单一实例类型",
                "risk_level": "warning",
                "steps": ["添加 m5.xlarge", "更新 ASG"],
                "expected_benefit": "提升可用性",
                "priority": 2,
            }
        ]
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _bedrock_json_response(ai_items)
        mock_boto3.client.return_value = mock_client

        analyzer = AIAnalyzer(skip_ai=False)
        failed = _make_check_result(rule_id="INFRA-001", passed=False)
        recs = analyzer.analyze([failed], _base_config())

        assert len(recs) == 1
        assert recs[0].rule_id == "INFRA-001"
        assert recs[0].risk_level == RiskLevel.WARNING
        assert recs[0].priority == 2
        assert recs[0].steps == ["添加 m5.xlarge", "更新 ASG"]
        mock_client.invoke_model.assert_called_once()

    @patch("eks_health_check.analyzer.ai_analyzer.boto3")
    def test_bedrock_failure_fallback_to_template(self, mock_boto3):
        """Bedrock 调用抛异常 → 回退到 TemplateEngine."""
        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = Exception("Bedrock unavailable")
        mock_boto3.client.return_value = mock_client

        analyzer = AIAnalyzer(skip_ai=False)
        failed = _make_check_result(rule_id="SEC-003", passed=False, risk_level=RiskLevel.CRITICAL)
        recs = analyzer.analyze([failed], _base_config())

        # Should get template-based recommendation instead
        assert len(recs) == 1
        assert recs[0].rule_id == "SEC-003"
        assert recs[0].priority == 1  # Critical → priority 1 from TemplateEngine

    @patch("eks_health_check.analyzer.ai_analyzer.boto3")
    def test_bedrock_invalid_json_fallback(self, mock_boto3):
        """Bedrock 返回无效 JSON → 回退到 TemplateEngine."""
        resp_body = json.dumps({"content": [{"text": "not valid json ["}]})
        mock_body = MagicMock()
        mock_body.read.return_value = resp_body.encode()
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = {"body": mock_body}
        mock_boto3.client.return_value = mock_client

        analyzer = AIAnalyzer(skip_ai=False)
        failed = _make_check_result(rule_id="NET-005", passed=False, risk_level=RiskLevel.CRITICAL)
        recs = analyzer.analyze([failed], _base_config())

        assert len(recs) == 1
        assert recs[0].rule_id == "NET-005"

    @patch("eks_health_check.analyzer.ai_analyzer.boto3")
    def test_bedrock_response_with_code_fences(self, mock_boto3):
        """Bedrock 返回带 markdown code fence 的 JSON → 正确解析."""
        ai_items = [
            {
                "rule_id": "WORK-001",
                "title": "设置资源 request",
                "description": "Pod 未设置资源请求",
                "risk_level": "warning",
                "steps": ["添加 resource requests"],
                "expected_benefit": "避免资源争抢",
                "priority": 3,
            }
        ]
        fenced = f"```json\n{json.dumps(ai_items)}\n```"
        resp_body = json.dumps({"content": [{"text": fenced}]})
        mock_body = MagicMock()
        mock_body.read.return_value = resp_body.encode()
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = {"body": mock_body}
        mock_boto3.client.return_value = mock_client

        analyzer = AIAnalyzer(skip_ai=False)
        failed = _make_check_result(rule_id="WORK-001", passed=False)
        recs = analyzer.analyze([failed], _base_config())

        assert len(recs) == 1
        assert recs[0].rule_id == "WORK-001"
        assert recs[0].steps == ["添加 resource requests"]

    def test_all_passed_returns_empty(self):
        """所有检查通过 → 空列表（不调用 Bedrock）."""
        analyzer = AIAnalyzer(skip_ai=False)
        passed = _make_check_result(passed=True)
        assert analyzer.analyze([passed], _base_config()) == []

    @patch("eks_health_check.analyzer.ai_analyzer.boto3")
    def test_prompt_contains_cluster_context(self, mock_boto3):
        """验证 prompt 包含集群上下文信息."""
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _bedrock_json_response([])
        mock_boto3.client.return_value = mock_client

        analyzer = AIAnalyzer(skip_ai=False)
        failed = _make_check_result(passed=False)
        analyzer.analyze([failed], _base_config())

        call_args = mock_client.invoke_model.call_args
        body = json.loads(call_args[1]["body"] if "body" in call_args[1] else call_args[0][0])
        prompt_text = body["messages"][0]["content"]

        assert "1.30" in prompt_text  # cluster version
        assert "vpc-1" in prompt_text  # VPC ID

    @patch("eks_health_check.analyzer.ai_analyzer.boto3")
    def test_multiple_failed_results(self, mock_boto3):
        """多个失败检查项 → Bedrock 收到所有项，返回对应建议."""
        ai_items = [
            {"rule_id": "INFRA-001", "title": "t1", "description": "d1",
             "risk_level": "warning", "steps": ["s1"], "expected_benefit": "b1", "priority": 3},
            {"rule_id": "SEC-003", "title": "t2", "description": "d2",
             "risk_level": "critical", "steps": ["s2"], "expected_benefit": "b2", "priority": 1},
        ]
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _bedrock_json_response(ai_items)
        mock_boto3.client.return_value = mock_client

        analyzer = AIAnalyzer(skip_ai=False)
        results = [
            _make_check_result(rule_id="INFRA-001", passed=False),
            _make_check_result(rule_id="SEC-003", passed=False, risk_level=RiskLevel.CRITICAL),
        ]
        recs = analyzer.analyze(results, _base_config())

        assert len(recs) == 2
        rule_ids = {r.rule_id for r in recs}
        assert rule_ids == {"INFRA-001", "SEC-003"}

    def test_custom_template_engine_injection(self):
        """可注入自定义 TemplateEngine 实例."""
        custom_engine = TemplateEngine()
        analyzer = AIAnalyzer(skip_ai=True, template_engine=custom_engine)
        assert analyzer._template_engine is custom_engine
