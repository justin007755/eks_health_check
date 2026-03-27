"""Tests for Config Scanner layer: K8sCollector, AwsCollector, ConfigScanner."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from kubernetes.client.exceptions import ApiException

from eks_health_check.models import (
    AwsConfig,
    ClusterConfig,
    K8sConfig,
    NetworkConfig,
    NodeGroupInfo,
    SecurityConfig,
    WorkloadInfo,
)
from eks_health_check.scanner.k8s_collector import K8sCollector
from eks_health_check.scanner.aws_collector import AwsCollector
from eks_health_check.scanner.config_scanner import ConfigScanner


# =========================================================================
# Helpers — lightweight K8s API mock objects
# =========================================================================

def _make_node(name: str = "node-1", version: str = "v1.30.0",
               instance_type: str = "m5.large", zone: str = "us-east-1a"):
    """Return a minimal mock Node object."""
    node = MagicMock()
    node.metadata.name = name
    node.metadata.labels = {
        "node.kubernetes.io/instance-type": instance_type,
        "topology.kubernetes.io/zone": zone,
    }
    node.status.node_info.kubelet_version = version
    node.status.allocatable = {"cpu": "4", "memory": "16Gi"}
    node.status.capacity = {"cpu": "4", "memory": "16Gi"}
    return node


def _make_pod(name: str = "app-pod", namespace: str = "default",
              sa: str = "default", has_requests: bool = True):
    """Return a minimal mock Pod object."""
    pod = MagicMock()
    pod.metadata.name = name
    pod.metadata.namespace = namespace
    pod.spec.service_account_name = sa

    container = MagicMock()
    container.name = "main"
    if has_requests:
        container.resources.requests = {"cpu": "100m", "memory": "128Mi"}
        container.resources.limits = {"cpu": "200m", "memory": "256Mi"}
    else:
        container.resources = None
    container.readiness_probe = MagicMock()
    container.liveness_probe = MagicMock()
    pod.spec.containers = [container]
    return pod


def _make_deployment(name: str = "web", namespace: str = "default"):
    dep = MagicMock()
    dep.metadata.name = name
    dep.metadata.namespace = namespace
    dep.metadata.labels = {"app": name}
    dep.spec.replicas = 2
    dep.spec.selector.match_labels = {"app": name}
    return dep


def _make_service(name: str = "web-svc", namespace: str = "default"):
    svc = MagicMock()
    svc.metadata.name = name
    svc.metadata.namespace = namespace
    svc.spec.type = "ClusterIP"
    svc.spec.cluster_ip = "10.0.0.1"
    return svc


# =========================================================================
# K8sCollector Tests
# =========================================================================

class TestK8sCollectorNormalFlow:
    """测试正常采集流程返回完整 K8sConfig。"""

    @patch("eks_health_check.scanner.k8s_collector.config")
    @patch("eks_health_check.scanner.k8s_collector.client")
    def test_collect_returns_k8s_config(self, mock_client, mock_config):
        # Arrange — wire up API mocks
        core = MagicMock()
        apps = MagicMock()
        autoscaling = MagicMock()
        policy = MagicMock()
        networking = MagicMock()

        mock_client.CoreV1Api.return_value = core
        mock_client.AppsV1Api.return_value = apps
        mock_client.AutoscalingV1Api.return_value = autoscaling
        mock_client.PolicyV1Api.return_value = policy
        mock_client.NetworkingV1Api.return_value = networking

        # Nodes
        node = _make_node()
        core.list_node.return_value = MagicMock(items=[node])

        # Pods
        pod = _make_pod()
        core.list_pod_for_all_namespaces.return_value = MagicMock(items=[pod])

        # Deployments
        dep = _make_deployment()
        apps.list_deployment_for_all_namespaces.return_value = MagicMock(items=[dep])

        # HPAs
        autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces.return_value = MagicMock(items=[])

        # PDBs
        policy.list_pod_disruption_budget_for_all_namespaces.return_value = MagicMock(items=[])

        # Services
        svc = _make_service()
        core.list_service_for_all_namespaces.return_value = MagicMock(items=[svc])

        # Ingresses
        networking.list_ingress_for_all_namespaces.return_value = MagicMock(items=[])

        # ServiceAccounts
        core.list_service_account_for_all_namespaces.return_value = MagicMock(items=[])

        # CoreDNS ConfigMap
        cm = MagicMock()
        cm.data = {"Corefile": ".:53 { }"}
        core.read_namespaced_config_map.return_value = cm

        # Addons (DaemonSets + Deployments in kube-system)
        apps.list_namespaced_daemon_set.return_value = MagicMock(items=[])
        apps.list_namespaced_deployment.return_value = MagicMock(items=[])

        # Act
        collector = K8sCollector(kubeconfig="/fake/path")
        result = collector.collect()

        # Assert
        assert isinstance(result, K8sConfig)
        assert result.cluster_version == "v1.30.0"
        assert len(result.nodes) == 1
        assert result.nodes[0]["name"] == "node-1"
        assert len(result.workloads.pods) == 1
        assert len(result.workloads.deployments) == 1
        assert result.network["coredns_config"]["Corefile"] == ".:53 { }"
        assert collector.skipped_resources == []
        assert collector.collection_errors == []


class TestK8sCollectorPermissionDenied:
    """测试权限不足时跳过资源并记录到 skipped_resources。"""

    @patch("eks_health_check.scanner.k8s_collector.config")
    @patch("eks_health_check.scanner.k8s_collector.client")
    def test_403_skips_resource(self, mock_client, mock_config):
        core = MagicMock()
        apps = MagicMock()
        autoscaling = MagicMock()
        policy = MagicMock()
        networking = MagicMock()

        mock_client.CoreV1Api.return_value = core
        mock_client.AppsV1Api.return_value = apps
        mock_client.AutoscalingV1Api.return_value = autoscaling
        mock_client.PolicyV1Api.return_value = policy
        mock_client.NetworkingV1Api.return_value = networking

        # Nodes → 403 Forbidden
        core.list_node.side_effect = ApiException(status=403, reason="Forbidden")

        # Pods → 403 Forbidden
        core.list_pod_for_all_namespaces.side_effect = ApiException(status=403, reason="Forbidden")

        # Everything else succeeds but empty
        apps.list_deployment_for_all_namespaces.return_value = MagicMock(items=[])
        autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces.return_value = MagicMock(items=[])
        policy.list_pod_disruption_budget_for_all_namespaces.return_value = MagicMock(items=[])
        core.list_service_for_all_namespaces.return_value = MagicMock(items=[])
        networking.list_ingress_for_all_namespaces.return_value = MagicMock(items=[])
        core.list_service_account_for_all_namespaces.return_value = MagicMock(items=[])
        core.read_namespaced_config_map.return_value = MagicMock(data={})
        apps.list_namespaced_daemon_set.return_value = MagicMock(items=[])
        apps.list_namespaced_deployment.return_value = MagicMock(items=[])

        collector = K8sCollector(kubeconfig="/fake/path")
        result = collector.collect()

        assert "nodes" in collector.skipped_resources
        assert "pods" in collector.skipped_resources
        assert collector.collection_errors == []
        # Still returns a valid K8sConfig with empty data
        assert isinstance(result, K8sConfig)
        assert result.nodes == []
        assert result.workloads.pods == []



class TestK8sCollectorConnectionFailure:
    """测试连接失败时返回错误信息。"""

    @patch("eks_health_check.scanner.k8s_collector.config")
    @patch("eks_health_check.scanner.k8s_collector.client")
    def test_connection_error_recorded(self, mock_client, mock_config):
        core = MagicMock()
        apps = MagicMock()
        autoscaling = MagicMock()
        policy = MagicMock()
        networking = MagicMock()

        mock_client.CoreV1Api.return_value = core
        mock_client.AppsV1Api.return_value = apps
        mock_client.AutoscalingV1Api.return_value = autoscaling
        mock_client.PolicyV1Api.return_value = policy
        mock_client.NetworkingV1Api.return_value = networking

        # Simulate connection refused on all calls
        conn_err = ConnectionError("Connection refused")
        core.list_node.side_effect = conn_err
        core.list_pod_for_all_namespaces.side_effect = conn_err
        apps.list_deployment_for_all_namespaces.side_effect = conn_err
        autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces.side_effect = conn_err
        policy.list_pod_disruption_budget_for_all_namespaces.side_effect = conn_err
        core.list_service_for_all_namespaces.side_effect = conn_err
        networking.list_ingress_for_all_namespaces.side_effect = conn_err
        core.list_service_account_for_all_namespaces.side_effect = conn_err
        core.read_namespaced_config_map.side_effect = conn_err
        apps.list_namespaced_daemon_set.side_effect = conn_err
        apps.list_namespaced_deployment.side_effect = conn_err

        collector = K8sCollector(kubeconfig="/fake/path")
        result = collector.collect()

        # All resources should have errors recorded
        assert len(collector.collection_errors) > 0
        assert all("Connection refused" in e for e in collector.collection_errors)
        # skipped_resources should be empty (403 only)
        assert collector.skipped_resources == []
        assert isinstance(result, K8sConfig)

    @patch("eks_health_check.scanner.k8s_collector.config")
    @patch("eks_health_check.scanner.k8s_collector.client")
    def test_non_403_api_exception_recorded_as_error(self, mock_client, mock_config):
        """Non-403 ApiException (e.g. 500) goes to collection_errors, not skipped."""
        core = MagicMock()
        apps = MagicMock()
        mock_client.CoreV1Api.return_value = core
        mock_client.AppsV1Api.return_value = apps
        mock_client.AutoscalingV1Api.return_value = MagicMock(
            list_horizontal_pod_autoscaler_for_all_namespaces=MagicMock(return_value=MagicMock(items=[]))
        )
        mock_client.PolicyV1Api.return_value = MagicMock(
            list_pod_disruption_budget_for_all_namespaces=MagicMock(return_value=MagicMock(items=[]))
        )
        mock_client.NetworkingV1Api.return_value = MagicMock(
            list_ingress_for_all_namespaces=MagicMock(return_value=MagicMock(items=[]))
        )

        # Nodes → 500 Internal Server Error
        core.list_node.side_effect = ApiException(status=500, reason="Internal Server Error")
        core.list_pod_for_all_namespaces.return_value = MagicMock(items=[])
        core.list_service_for_all_namespaces.return_value = MagicMock(items=[])
        core.list_service_account_for_all_namespaces.return_value = MagicMock(items=[])
        core.read_namespaced_config_map.return_value = MagicMock(data={})
        apps.list_deployment_for_all_namespaces.return_value = MagicMock(items=[])
        apps.list_namespaced_daemon_set.return_value = MagicMock(items=[])
        apps.list_namespaced_deployment.return_value = MagicMock(items=[])

        collector = K8sCollector(kubeconfig="/fake/path")
        collector.collect()

        assert "nodes" not in collector.skipped_resources
        assert any("nodes" in e for e in collector.collection_errors)


# =========================================================================
# AwsCollector Tests
# =========================================================================

class TestAwsCollectorNormalFlow:
    """测试正常 AWS 采集流程。"""

    @patch("eks_health_check.scanner.aws_collector.boto3")
    def test_collect_returns_aws_config(self, mock_boto3):
        eks = MagicMock()
        ec2 = MagicMock()
        iam = MagicMock()
        mock_boto3.client.side_effect = lambda svc, **kw: {
            "eks": eks, "ec2": ec2, "iam": iam
        }[svc]

        # DescribeCluster
        eks.describe_cluster.return_value = {
            "cluster": {
                "name": "test-cluster",
                "version": "1.30",
                "roleArn": "arn:aws:iam::123456789012:role/eks-role",
                "resourcesVpcConfig": {
                    "vpcId": "vpc-abc",
                    "subnetIds": ["subnet-1", "subnet-2"],
                    "securityGroupIds": ["sg-1"],
                    "clusterSecurityGroupId": "sg-cluster",
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": True,
                    "publicAccessCidrs": ["10.0.0.0/8"],
                },
                "logging": {
                    "clusterLogging": [
                        {"enabled": True, "types": ["audit", "api"]},
                    ]
                },
                "encryptionConfig": [
                    {
                        "resources": ["secrets"],
                        "provider": {"keyArn": "arn:aws:kms::123456789012:key/abc"},
                    }
                ],
            }
        }

        # ListNodegroups + DescribeNodegroup
        eks.list_nodegroups.return_value = {"nodegroups": ["ng-1"]}
        eks.describe_nodegroup.return_value = {
            "nodegroup": {
                "nodegroupName": "ng-1",
                "instanceTypes": ["m5.large", "m5.xlarge"],
                "subnets": ["subnet-1"],
                "capacityType": "ON_DEMAND",
                "scalingConfig": {"desiredSize": 3, "minSize": 1, "maxSize": 5},
                "releaseVersion": "1.30-20250101",
            }
        }

        # DescribeSubnets
        ec2.describe_subnets.return_value = {
            "Subnets": [
                {"SubnetId": "subnet-1", "AvailableIpAddressCount": 200},
                {"SubnetId": "subnet-2", "AvailableIpAddressCount": 150},
            ]
        }

        # DescribeSecurityGroups
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-1",
                    "GroupName": "eks-sg",
                    "IpPermissions": [],
                    "IpPermissionsEgress": [],
                },
                {
                    "GroupId": "sg-cluster",
                    "GroupName": "eks-cluster-sg",
                    "IpPermissions": [],
                    "IpPermissionsEgress": [],
                },
            ]
        }

        # GetRole
        iam.get_role.return_value = {
            "Role": {
                "RoleName": "eks-role",
                "Arn": "arn:aws:iam::123456789012:role/eks-role",
                "AssumeRolePolicyDocument": {},
            }
        }

        collector = AwsCollector(region="us-east-1")
        result = collector.collect("test-cluster")

        assert isinstance(result, AwsConfig)
        assert result.cluster_info["name"] == "test-cluster"
        assert len(result.node_groups) == 1
        assert result.node_groups[0].name == "ng-1"
        assert result.node_groups[0].instance_types == ["m5.large", "m5.xlarge"]
        assert result.network.vpc_id == "vpc-abc"
        assert result.network.subnet_available_ips["subnet-1"] == 200
        assert result.security.audit_logging_enabled is True
        assert result.security.secrets_encryption_enabled is True
        assert len(result.iam_roles) == 1
        assert collector.collection_errors == []


class TestAwsCollectorApiFailure:
    """测试 AWS API 调用失败时的优雅降级。"""

    @patch("eks_health_check.scanner.aws_collector.boto3")
    def test_describe_cluster_failure_returns_empty(self, mock_boto3):
        from botocore.exceptions import ClientError

        eks = MagicMock()
        ec2 = MagicMock()
        iam = MagicMock()
        mock_boto3.client.side_effect = lambda svc, **kw: {
            "eks": eks, "ec2": ec2, "iam": iam
        }[svc]

        # DescribeCluster fails
        eks.describe_cluster.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Cluster not found"}},
            "DescribeCluster",
        )
        # ListNodegroups also fails since cluster doesn't exist
        eks.list_nodegroups.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Cluster not found"}},
            "ListNodegroups",
        )

        collector = AwsCollector(region="us-east-1")
        result = collector.collect("nonexistent-cluster")

        assert isinstance(result, AwsConfig)
        assert result.cluster_info == {"region": "us-east-1"}
        assert result.node_groups == []
        assert len(collector.collection_errors) >= 2

    @patch("eks_health_check.scanner.aws_collector.boto3")
    def test_partial_failure_still_returns_data(self, mock_boto3):
        """Subnet/SG calls fail but cluster info succeeds."""
        from botocore.exceptions import ClientError

        eks = MagicMock()
        ec2 = MagicMock()
        iam = MagicMock()
        mock_boto3.client.side_effect = lambda svc, **kw: {
            "eks": eks, "ec2": ec2, "iam": iam
        }[svc]

        eks.describe_cluster.return_value = {
            "cluster": {
                "name": "my-cluster",
                "resourcesVpcConfig": {
                    "vpcId": "vpc-1",
                    "subnetIds": ["subnet-1"],
                    "securityGroupIds": ["sg-1"],
                    "clusterSecurityGroupId": "",
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                    "publicAccessCidrs": ["0.0.0.0/0"],
                },
                "logging": {"clusterLogging": []},
                "encryptionConfig": [],
            }
        }
        eks.list_nodegroups.return_value = {"nodegroups": []}

        # EC2 calls fail
        ec2.describe_subnets.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "no perms"}},
            "DescribeSubnets",
        )
        ec2.describe_security_groups.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "no perms"}},
            "DescribeSecurityGroups",
        )
        iam.get_role.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "role not found"}},
            "GetRole",
        )

        collector = AwsCollector(region="us-east-1")
        result = collector.collect("my-cluster")

        # Cluster info still populated
        assert result.cluster_info["name"] == "my-cluster"
        assert result.network.vpc_id == "vpc-1"
        # Degraded fields
        assert result.network.subnet_available_ips == {}
        assert result.network.security_groups == []
        assert result.iam_roles == []
        assert len(collector.collection_errors) >= 2


# =========================================================================
# ConfigScanner Tests
# =========================================================================

class TestConfigScannerIntegration:
    """测试 ConfigScanner 聚合 K8s + AWS 结果。"""

    @patch("eks_health_check.scanner.config_scanner.AwsCollector")
    @patch("eks_health_check.scanner.config_scanner.K8sCollector")
    def test_scan_aggregates_results(self, MockK8s, MockAws):
        k8s_instance = MockK8s.return_value
        aws_instance = MockAws.return_value

        k8s_config = K8sConfig(
            cluster_version="v1.30.0",
            nodes=[{"name": "node-1"}],
            workloads=WorkloadInfo(pods=[{"name": "pod-1"}]),
            network={"services": [], "coredns_config": {}},
            addons=[],
        )
        k8s_instance.collect.return_value = k8s_config
        type(k8s_instance).skipped_resources = PropertyMock(return_value=["hpas"])
        type(k8s_instance).collection_errors = PropertyMock(return_value=["nodes: timeout"])

        aws_config = AwsConfig(
            cluster_info={"name": "test"},
            node_groups=[],
            network=NetworkConfig(vpc_id="vpc-1", subnet_ids=["s-1"]),
            security=SecurityConfig(),
            iam_roles=[],
        )
        aws_instance.collect.return_value = aws_config
        type(aws_instance).collection_errors = PropertyMock(return_value=["ec2: error"])

        scanner = ConfigScanner(cluster_name="test", region="us-east-1")
        result = scanner.scan()

        assert isinstance(result, ClusterConfig)
        assert result.k8s.cluster_version == "v1.30.0"
        assert result.aws.cluster_info["name"] == "test"
        assert "hpas" in result.skipped_resources
        assert "nodes: timeout" in result.collection_errors
        assert "ec2: error" in result.collection_errors

    @patch("eks_health_check.scanner.config_scanner.AwsCollector")
    @patch("eks_health_check.scanner.config_scanner.K8sCollector")
    def test_scan_no_errors(self, MockK8s, MockAws):
        k8s_instance = MockK8s.return_value
        aws_instance = MockAws.return_value

        k8s_instance.collect.return_value = K8sConfig(
            cluster_version="v1.30.0",
            nodes=[],
            workloads=WorkloadInfo(),
            network={"services": []},
            addons=[],
        )
        type(k8s_instance).skipped_resources = PropertyMock(return_value=[])
        type(k8s_instance).collection_errors = PropertyMock(return_value=[])

        aws_instance.collect.return_value = AwsConfig(
            cluster_info={},
            node_groups=[],
            network=NetworkConfig(vpc_id="", subnet_ids=[]),
            security=SecurityConfig(),
            iam_roles=[],
        )
        type(aws_instance).collection_errors = PropertyMock(return_value=[])

        scanner = ConfigScanner(cluster_name="clean", region="us-west-2")
        result = scanner.scan()

        assert result.collection_errors == []
        assert result.skipped_resources == []
