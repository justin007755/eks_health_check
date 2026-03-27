"""K8s API 配置采集器 — 通过 kubernetes Python client 采集集群配置数据。"""

from __future__ import annotations

import logging
from typing import Any

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from eks_health_check.models import K8sConfig, WorkloadInfo

logger = logging.getLogger(__name__)


class K8sCollector:
    """通过 Kubernetes API 采集集群配置，权限不足时优雅降级。"""

    def __init__(self, kubeconfig: str | None = None) -> None:
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig)
        else:
            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()

        self._core = client.CoreV1Api()
        self._apps = client.AppsV1Api()
        self._autoscaling = client.AutoscalingV1Api()
        self._policy = client.PolicyV1Api()
        self._networking = client.NetworkingV1Api()
        self._skipped: list[str] = []
        self._errors: list[str] = []

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def collect(self) -> K8sConfig:
        """采集所有 K8s 资源配置，返回 K8sConfig。"""
        nodes = self._safe_list("nodes", self._collect_nodes)
        pods = self._safe_list("pods", self._collect_pods)
        deployments = self._safe_list("deployments", self._collect_deployments)
        hpas = self._safe_list("hpas", self._collect_hpas)
        pdbs = self._safe_list("pdbs", self._collect_pdbs)
        services = self._safe_list("services", self._collect_services)
        ingresses = self._safe_list("ingresses", self._collect_ingresses)
        service_accounts = self._safe_list("serviceaccounts", self._collect_service_accounts)
        coredns_config = self._safe_dict("coredns_configmap", self._collect_coredns_config)
        addons = self._safe_list("addons", self._collect_addons)

        cluster_version = ""
        if nodes:
            cluster_version = nodes[0].get("kubelet_version", "")

        workloads = WorkloadInfo(
            pods=pods,
            deployments=deployments,
            hpas=hpas,
            pdbs=pdbs,
            service_accounts=service_accounts,
        )

        network: dict[str, Any] = {
            "coredns_config": coredns_config,
            "services": services,
            "ingresses": ingresses,
        }

        return K8sConfig(
            cluster_version=cluster_version,
            nodes=nodes,
            workloads=workloads,
            network=network,
            addons=addons,
        )

    @property
    def skipped_resources(self) -> list[str]:
        return list(self._skipped)

    @property
    def collection_errors(self) -> list[str]:
        return list(self._errors)

    # ------------------------------------------------------------------
    # Safe wrappers
    # ------------------------------------------------------------------

    def _safe_list(self, resource: str, fn: Any) -> list[dict]:
        try:
            return fn()
        except ApiException as exc:
            if exc.status == 403:
                logger.warning("权限不足，跳过 %s 采集", resource)
                self._skipped.append(resource)
            else:
                logger.error("采集 %s 失败: %s", resource, exc.reason)
                self._errors.append(f"{resource}: {exc.reason}")
        except Exception as exc:  # noqa: BLE001
            logger.error("采集 %s 时发生连接/未知错误: %s", resource, exc)
            self._errors.append(f"{resource}: {exc}")
        return []

    def _safe_dict(self, resource: str, fn: Any) -> dict:
        try:
            return fn()
        except ApiException as exc:
            if exc.status == 403:
                logger.warning("权限不足，跳过 %s 采集", resource)
                self._skipped.append(resource)
            else:
                logger.error("采集 %s 失败: %s", resource, exc.reason)
                self._errors.append(f"{resource}: {exc.reason}")
        except Exception as exc:  # noqa: BLE001
            logger.error("采集 %s 时发生连接/未知错误: %s", resource, exc)
            self._errors.append(f"{resource}: {exc}")
        return {}

    # ------------------------------------------------------------------
    # Collectors
    # ------------------------------------------------------------------

    def _collect_nodes(self) -> list[dict]:
        resp = self._core.list_node()
        results = []
        for node in resp.items:
            allocatable = node.status.allocatable or {}
            capacity = node.status.capacity or {}
            labels = node.metadata.labels or {}
            results.append({
                "name": node.metadata.name,
                "kubelet_version": node.status.node_info.kubelet_version if node.status.node_info else "",
                "instance_type": labels.get("node.kubernetes.io/instance-type", ""),
                "zone": labels.get("topology.kubernetes.io/zone", ""),
                "allocatable_cpu": allocatable.get("cpu", "0"),
                "allocatable_memory": allocatable.get("memory", "0"),
                "capacity_cpu": capacity.get("cpu", "0"),
                "capacity_memory": capacity.get("memory", "0"),
                "labels": labels,
            })
        return results

    def _collect_pods(self) -> list[dict]:
        resp = self._core.list_pod_for_all_namespaces()
        results = []
        for pod in resp.items:
            containers = []
            for c in (pod.spec.containers or []):
                req = {}
                lim = {}
                if c.resources:
                    req = dict(c.resources.requests or {}) if c.resources.requests else {}
                    lim = dict(c.resources.limits or {}) if c.resources.limits else {}
                containers.append({
                    "name": c.name,
                    "resources_requests": req,
                    "resources_limits": lim,
                    "readiness_probe": c.readiness_probe is not None,
                    "liveness_probe": c.liveness_probe is not None,
                })
            sa = pod.spec.service_account_name or ""
            results.append({
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "service_account": sa,
                "containers": containers,
            })
        return results

    def _collect_deployments(self) -> list[dict]:
        resp = self._apps.list_deployment_for_all_namespaces()
        results = []
        for dep in resp.items:
            results.append({
                "name": dep.metadata.name,
                "namespace": dep.metadata.namespace,
                "replicas": dep.spec.replicas,
                "labels": dict(dep.metadata.labels or {}),
                "match_labels": dict(dep.spec.selector.match_labels or {}) if dep.spec.selector else {},
            })
        return results

    def _collect_hpas(self) -> list[dict]:
        resp = self._autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces()
        results = []
        for hpa in resp.items:
            results.append({
                "name": hpa.metadata.name,
                "namespace": hpa.metadata.namespace,
                "min_replicas": hpa.spec.min_replicas,
                "max_replicas": hpa.spec.max_replicas,
                "target_ref": {
                    "kind": hpa.spec.scale_target_ref.kind,
                    "name": hpa.spec.scale_target_ref.name,
                } if hpa.spec.scale_target_ref else {},
            })
        return results

    def _collect_pdbs(self) -> list[dict]:
        resp = self._policy.list_pod_disruption_budget_for_all_namespaces()
        results = []
        for pdb in resp.items:
            results.append({
                "name": pdb.metadata.name,
                "namespace": pdb.metadata.namespace,
                "match_labels": dict(pdb.spec.selector.match_labels or {}) if pdb.spec and pdb.spec.selector else {},
                "min_available": str(pdb.spec.min_available) if pdb.spec and pdb.spec.min_available is not None else None,
                "max_unavailable": str(pdb.spec.max_unavailable) if pdb.spec and pdb.spec.max_unavailable is not None else None,
            })
        return results

    def _collect_services(self) -> list[dict]:
        resp = self._core.list_service_for_all_namespaces()
        results = []
        for svc in resp.items:
            results.append({
                "name": svc.metadata.name,
                "namespace": svc.metadata.namespace,
                "type": svc.spec.type if svc.spec else "",
                "cluster_ip": svc.spec.cluster_ip if svc.spec else "",
            })
        return results

    def _collect_ingresses(self) -> list[dict]:
        resp = self._networking.list_ingress_for_all_namespaces()
        results = []
        for ing in resp.items:
            results.append({
                "name": ing.metadata.name,
                "namespace": ing.metadata.namespace,
                "rules_count": len(ing.spec.rules) if ing.spec and ing.spec.rules else 0,
            })
        return results

    def _collect_service_accounts(self) -> list[dict]:
        resp = self._core.list_service_account_for_all_namespaces()
        results = []
        for sa in resp.items:
            annotations = dict(sa.metadata.annotations or {})
            results.append({
                "name": sa.metadata.name,
                "namespace": sa.metadata.namespace,
                "annotations": annotations,
            })
        return results

    def _collect_coredns_config(self) -> dict:
        """采集 kube-system 下的 CoreDNS ConfigMap。"""
        cm = self._core.read_namespaced_config_map("coredns", "kube-system")
        return dict(cm.data or {})

    def _collect_addons(self) -> list[dict]:
        """采集 kube-system 下的 DaemonSet/Deployment 作为 addon 信息。"""
        addons: list[dict] = []
        ds_resp = self._apps.list_namespaced_daemon_set("kube-system")
        for ds in ds_resp.items:
            containers = ds.spec.template.spec.containers or [] if ds.spec and ds.spec.template and ds.spec.template.spec else []
            env_vars: dict[str, str] = {}
            for c in containers:
                for env in (c.env or []):
                    if env.value is not None:
                        env_vars[env.name] = env.value
            addons.append({
                "name": ds.metadata.name,
                "kind": "DaemonSet",
                "namespace": "kube-system",
                "env": env_vars,
            })
        dep_resp = self._apps.list_namespaced_deployment("kube-system")
        for dep in dep_resp.items:
            addons.append({
                "name": dep.metadata.name,
                "kind": "Deployment",
                "namespace": "kube-system",
                "replicas": dep.spec.replicas,
            })
        return addons
