"""AWS API 配置采集器 — 通过 boto3 采集 EKS / EC2 / IAM 配置数据。"""

from __future__ import annotations

import logging

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from eks_health_check.models import (
    AwsConfig,
    NetworkConfig,
    NodeGroupInfo,
    SecurityConfig,
)

logger = logging.getLogger(__name__)


class AwsCollector:
    """通过 AWS API 采集集群和基础设施配置，API 失败时优雅降级。"""

    def __init__(self, region: str) -> None:
        self._region = region
        self._eks = boto3.client("eks", region_name=region)
        self._ec2 = boto3.client("ec2", region_name=region)
        self._iam = boto3.client("iam", region_name=region)
        self._errors: list[str] = []

    def collect(self, cluster_name: str) -> AwsConfig:
        """采集 EKS、EC2、VPC、IAM 等配置，返回 AwsConfig。"""
        cluster_info = self._describe_cluster(cluster_name)
        # 确保 region 字段存在（describe_cluster 不直接返回 region）
        cluster_info.setdefault("region", self._region)
        node_groups = self._collect_node_groups(cluster_name)
        network = self._build_network_config(cluster_info)
        security = self._build_security_config(cluster_info)
        iam_roles = self._collect_iam_roles(cluster_info)

        return AwsConfig(
            cluster_info=cluster_info,
            node_groups=node_groups,
            network=network,
            security=security,
            iam_roles=iam_roles,
        )

    @property
    def collection_errors(self) -> list[str]:
        return list(self._errors)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _safe_call(self, resource: str, fn, *args, **kwargs):
        """Wrap an AWS API call with error handling and graceful degradation."""
        try:
            return fn(*args, **kwargs)
        except (ClientError, BotoCoreError) as exc:
            logger.error("采集 %s 失败: %s", resource, exc)
            self._errors.append(f"{resource}: {exc}")
        except Exception as exc:  # noqa: BLE001
            logger.error("采集 %s 时发生未知错误: %s", resource, exc)
            self._errors.append(f"{resource}: {exc}")
        return None

    # ------------------------------------------------------------------
    # EKS cluster
    # ------------------------------------------------------------------

    def _describe_cluster(self, cluster_name: str) -> dict:
        resp = self._safe_call(
            "eks:DescribeCluster",
            self._eks.describe_cluster,
            name=cluster_name,
        )
        if resp:
            return resp.get("cluster", {})
        return {}

    # ------------------------------------------------------------------
    # Node groups
    # ------------------------------------------------------------------

    def _collect_node_groups(self, cluster_name: str) -> list[NodeGroupInfo]:
        resp = self._safe_call(
            "eks:ListNodegroups",
            self._eks.list_nodegroups,
            clusterName=cluster_name,
        )
        if not resp:
            return []

        ng_names: list[str] = resp.get("nodegroups", [])
        results: list[NodeGroupInfo] = []
        for ng_name in ng_names:
            detail = self._safe_call(
                f"eks:DescribeNodegroup({ng_name})",
                self._eks.describe_nodegroup,
                clusterName=cluster_name,
                nodegroupName=ng_name,
            )
            if not detail:
                continue
            ng = detail.get("nodegroup", {})
            scaling = ng.get("scalingConfig", {})
            release = ng.get("releaseVersion", "")
            results.append(NodeGroupInfo(
                name=ng.get("nodegroupName", ng_name),
                instance_types=ng.get("instanceTypes", []),
                availability_zones=ng.get("subnets", []),  # subnet IDs; AZs derived later
                capacity_type=ng.get("capacityType", "ON_DEMAND"),
                desired_size=scaling.get("desiredSize", 0),
                min_size=scaling.get("minSize", 0),
                max_size=scaling.get("maxSize", 0),
                ami_version=release,
                latest_ami_version=None,
            ))
        return results

    # ------------------------------------------------------------------
    # Network config
    # ------------------------------------------------------------------

    def _build_network_config(self, cluster_info: dict) -> NetworkConfig:
        vpc_config = cluster_info.get("resourcesVpcConfig", {})
        vpc_id = vpc_config.get("vpcId", "")
        subnet_ids = vpc_config.get("subnetIds", [])
        sg_ids = vpc_config.get("securityGroupIds", []) + [
            vpc_config.get("clusterSecurityGroupId", "")
        ]
        sg_ids = [s for s in sg_ids if s]

        subnet_ips = self._collect_subnet_available_ips(subnet_ids)
        security_groups = self._collect_security_groups(sg_ids)

        return NetworkConfig(
            vpc_id=vpc_id,
            subnet_ids=subnet_ids,
            subnet_available_ips=subnet_ips,
            security_groups=security_groups,
        )

    def _collect_subnet_available_ips(self, subnet_ids: list[str]) -> dict[str, int]:
        if not subnet_ids:
            return {}
        resp = self._safe_call(
            "ec2:DescribeSubnets",
            self._ec2.describe_subnets,
            SubnetIds=subnet_ids,
        )
        if not resp:
            return {}
        return {
            s["SubnetId"]: s.get("AvailableIpAddressCount", 0)
            for s in resp.get("Subnets", [])
        }

    def _collect_security_groups(self, sg_ids: list[str]) -> list[dict]:
        if not sg_ids:
            return []
        resp = self._safe_call(
            "ec2:DescribeSecurityGroups",
            self._ec2.describe_security_groups,
            GroupIds=sg_ids,
        )
        if not resp:
            return []
        results = []
        for sg in resp.get("SecurityGroups", []):
            results.append({
                "group_id": sg.get("GroupId", ""),
                "group_name": sg.get("GroupName", ""),
                "ingress_rules": sg.get("IpPermissions", []),
                "egress_rules": sg.get("IpPermissionsEgress", []),
            })
        return results

    # ------------------------------------------------------------------
    # Security config
    # ------------------------------------------------------------------

    def _build_security_config(self, cluster_info: dict) -> SecurityConfig:
        logging_cfg = cluster_info.get("logging", {})
        log_types: list[str] = []
        audit_enabled = False
        for log_setup in logging_cfg.get("clusterLogging", []):
            if log_setup.get("enabled"):
                types = log_setup.get("types", [])
                log_types.extend(types)
                if "audit" in types:
                    audit_enabled = True

        vpc_config = cluster_info.get("resourcesVpcConfig", {})
        enc_config = cluster_info.get("encryptionConfig", [])
        secrets_encrypted = False
        enc_key_arn = None
        for ec in enc_config:
            resources = ec.get("resources", [])
            if "secrets" in resources:
                secrets_encrypted = True
                provider = ec.get("provider", {})
                enc_key_arn = provider.get("keyArn")

        return SecurityConfig(
            audit_logging_enabled=audit_enabled,
            log_types=log_types,
            endpoint_public_access=vpc_config.get("endpointPublicAccess", True),
            endpoint_private_access=vpc_config.get("endpointPrivateAccess", False),
            public_access_cidrs=vpc_config.get("publicAccessCidrs", []),
            secrets_encryption_enabled=secrets_encrypted,
            encryption_key_arn=enc_key_arn,
        )

    # ------------------------------------------------------------------
    # IAM roles
    # ------------------------------------------------------------------

    def _collect_iam_roles(self, cluster_info: dict) -> list[dict]:
        role_arn = cluster_info.get("roleArn", "")
        if not role_arn:
            return []
        role_name = role_arn.rsplit("/", 1)[-1] if "/" in role_arn else role_arn
        resp = self._safe_call(
            "iam:GetRole",
            self._iam.get_role,
            RoleName=role_name,
        )
        if not resp:
            return []
        role = resp.get("Role", {})
        return [{
            "role_name": role.get("RoleName", ""),
            "arn": role.get("Arn", ""),
            "assume_role_policy": role.get("AssumeRolePolicyDocument", {}),
        }]
