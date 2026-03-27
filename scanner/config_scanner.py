"""ConfigScanner — 聚合 K8sCollector 和 AwsCollector 的结果为 ClusterConfig。"""

from __future__ import annotations

import logging

from eks_health_check.models import ClusterConfig
from eks_health_check.scanner.aws_collector import AwsCollector
from eks_health_check.scanner.k8s_collector import K8sCollector

logger = logging.getLogger(__name__)


class ConfigScanner:
    """统一扫描入口，聚合 K8s 和 AWS 配置数据。"""

    def __init__(
        self,
        cluster_name: str,
        region: str,
        kubeconfig: str | None = None,
    ) -> None:
        self._cluster_name = cluster_name
        self._k8s = K8sCollector(kubeconfig=kubeconfig)
        self._aws = AwsCollector(region=region)

    def scan(self) -> ClusterConfig:
        """执行完整扫描，返回聚合后的 ClusterConfig。"""
        logger.info("开始扫描集群 %s ...", self._cluster_name)

        k8s_config = self._k8s.collect()
        aws_config = self._aws.collect(self._cluster_name)

        # 将 AWS 采集到的网络/DNS 信息补充到 K8sConfig 中
        aws_net = aws_config.network
        k8s_config.network.setdefault("cni_config", aws_net.cni_config)

        errors = self._k8s.collection_errors + self._aws.collection_errors
        skipped = self._k8s.skipped_resources

        logger.info(
            "扫描完成: %d 个错误, %d 个跳过的资源",
            len(errors),
            len(skipped),
        )

        return ClusterConfig(
            k8s=k8s_config,
            aws=aws_config,
            collection_errors=errors,
            skipped_resources=skipped,
        )
