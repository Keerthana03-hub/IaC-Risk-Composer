"""
services/rules_kubernetes.py
-----------------------------
Kubernetes Security Threat Detection Rules (Stage 5).

Implements security inspection rules for Kubernetes manifests:
- K8S-001: Privileged Container Execution (privileged: true)
- K8S-002: Container Running as Root (runAsUser: 0, runAsNonRoot: false)
- K8S-003: Privilege Escalation Enabled (allowPrivilegeEscalation: true)
- K8S-004: Dangerous Linux Capabilities Added (SYS_ADMIN, SYS_MODULE, SYS_PTRACE, NET_ADMIN, DAC_OVERRIDE)
- K8S-005: Host Namespace Exposure (hostNetwork, hostPID, hostIPC)
- K8S-006: Writable Root Filesystem (readOnlyRootFilesystem: false)
- K8S-007: Unrestricted Service Exposure (LoadBalancer, NodePort)
- K8S-008: Ingress Configured Without TLS
- K8S-009: Excessive RBAC Wildcard Permissions (* in verbs, resources, apiGroups)
- K8S-010: ServiceAccount Token Automount Enabled (automountServiceAccountToken: true)
- K8S-011: Missing NetworkPolicy for Namespace Workloads
- K8S-012: Untrusted Container Image Tag Configuration (latest tag or untagged)
"""

from __future__ import annotations

from typing import Any

from services.threat_templates import THREAT_TEMPLATES

CRITICAL_CAPABILITIES = {"SYS_ADMIN", "SYS_MODULE"}
HIGH_CAPABILITIES = {"SYS_PTRACE", "NET_ADMIN", "DAC_OVERRIDE"}
ALL_DANGEROUS_CAPS = CRITICAL_CAPABILITIES | HIGH_CAPABILITIES

WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
}


def _is_image_unpinned(image: str) -> tuple[bool, str]:
    """
    Check if image uses 'latest' tag or omits a tag completely.
    Returns (is_unpinned, reason).
    """
    if not image or not isinstance(image, str):
        return True, "missing image reference"

    img = image.strip()
    if "@sha256:" in img:
        return False, ""

    # Split off repository path to inspect tag
    parts = img.split("/")
    last_part = parts[-1]
    if ":" in last_part:
        tag = last_part.split(":", 1)[1]
        if tag.lower() == "latest":
            return True, "image uses 'latest' tag"
        return False, ""
    return True, "image has no explicit version tag (defaults to latest)"


# ---------------------------------------------------------------------------
# Individual Kubernetes Rule Evaluators
# ---------------------------------------------------------------------------


def detect_k8s_001_privileged_containers(
    resource_id: str,
    res_type: str,
    res_name: str,
    containers: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-001: Privileged container execution."""
    template = THREAT_TEMPLATES["K8S-001"]
    for c in containers:
        if c.get("privileged") is True:
            c_name = c.get("name") or "unnamed"
            findings.append({
                "finding_id": f"{resource_id}-K8S-001-priv-{c_name}",
                "threat_id": template.threat_id,
                "title": f"Kubernetes Container Runs With Root Privileges ({res_name} / {c_name})",
                "description": template.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "resource_id": resource_id,
                "resource_type": res_type,
                "source_format": "kubernetes",
                "severity": "Critical",
                "detection_status": "Confirmed",
                "confidence": "High",
                "evidence": {"container": c_name, "privileged": True},
                "impact": template.potential_impact,
                "recommendation": template.recommended_mitigation,
                "remediation": template.recommended_mitigation,
                "references": [
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/#privileged"
                ],
            })


def detect_k8s_002_running_as_root(
    resource_id: str,
    res_type: str,
    res_name: str,
    containers: list[dict[str, Any]],
    pod_sec: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-002: Container running as root."""
    template = THREAT_TEMPLATES["K8S-002"]

    pod_run_as_user = pod_sec.get("runAsUser")
    pod_run_as_non_root = pod_sec.get("runAsNonRoot")

    # If pod explicitly enforces non-root, check if any container overrides it
    for c in containers:
        c_name = c.get("name") or "unnamed"
        c_user = c.get("runAsUser")
        c_non_root = c.get("runAsNonRoot")

        # Container-level explicit root
        if c_user == 0 or c_non_root is False:
            findings.append({
                "finding_id": f"{resource_id}-K8S-002-root-{c_name}",
                "threat_id": template.threat_id,
                "title": f"Kubernetes Container Configured to Run as Root User ({res_name} / {c_name})",
                "description": template.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "resource_id": resource_id,
                "resource_type": res_type,
                "source_format": "kubernetes",
                "severity": "High",
                "detection_status": "Confirmed",
                "confidence": "High",
                "evidence": {
                    "container": c_name,
                    "runAsUser": c_user,
                    "runAsNonRoot": c_non_root,
                },
                "impact": template.potential_impact,
                "recommendation": template.recommended_mitigation,
                "remediation": template.recommended_mitigation,
                "references": [
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"
                ],
            })
        elif c_user is None and c_non_root is None:
            # Check pod-level setting
            if pod_run_as_user == 0 or pod_run_as_non_root is False:
                findings.append({
                    "finding_id": f"{resource_id}-K8S-002-pod-root-{c_name}",
                    "threat_id": template.threat_id,
                    "title": f"Kubernetes Pod Configured to Run as Root User ({res_name})",
                    "description": template.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "resource_id": resource_id,
                    "resource_type": res_type,
                    "source_format": "kubernetes",
                    "severity": "High",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {
                        "container": c_name,
                        "podSecurityContext": {
                            "runAsUser": pod_run_as_user,
                            "runAsNonRoot": pod_run_as_non_root,
                        },
                    },
                    "impact": template.potential_impact,
                    "recommendation": template.recommended_mitigation,
                    "remediation": template.recommended_mitigation,
                    "references": [
                        "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"
                    ],
                })


def detect_k8s_003_privilege_escalation(
    resource_id: str,
    res_type: str,
    res_name: str,
    containers: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-003: Privilege escalation enabled."""
    template = THREAT_TEMPLATES["K8S-003"]
    for c in containers:
        if c.get("allowPrivilegeEscalation") is True:
            c_name = c.get("name") or "unnamed"
            findings.append({
                "finding_id": f"{resource_id}-K8S-003-escalation-{c_name}",
                "threat_id": template.threat_id,
                "title": f"Kubernetes Container Allows Privilege Escalation ({res_name} / {c_name})",
                "description": template.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "resource_id": resource_id,
                "resource_type": res_type,
                "source_format": "kubernetes",
                "severity": "High",
                "detection_status": "Confirmed",
                "confidence": "High",
                "evidence": {"container": c_name, "allowPrivilegeEscalation": True},
                "impact": template.potential_impact,
                "recommendation": template.recommended_mitigation,
                "remediation": template.recommended_mitigation,
                "references": [
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"
                ],
            })


def detect_k8s_004_dangerous_capabilities(
    resource_id: str,
    res_type: str,
    res_name: str,
    containers: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-004: Dangerous Linux capabilities."""
    template = THREAT_TEMPLATES["K8S-004"]
    for c in containers:
        caps_add = [str(cap).upper() for cap in c.get("capabilities_add", [])]
        dangerous_found = [cap for cap in caps_add if cap in ALL_DANGEROUS_CAPS]

        if dangerous_found:
            is_crit = any(cap in CRITICAL_CAPABILITIES for cap in dangerous_found)
            c_name = c.get("name") or "unnamed"
            findings.append({
                "finding_id": f"{resource_id}-K8S-004-caps-{c_name}",
                "threat_id": template.threat_id,
                "title": f"Kubernetes Container Added Dangerous Linux Capabilities ({res_name} / {c_name})",
                "description": template.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "resource_id": resource_id,
                "resource_type": res_type,
                "source_format": "kubernetes",
                "severity": "Critical" if is_crit else "High",
                "detection_status": "Confirmed",
                "confidence": "High",
                "evidence": {
                    "container": c_name,
                    "dangerous_capabilities": dangerous_found,
                },
                "impact": template.potential_impact,
                "recommendation": template.recommended_mitigation,
                "remediation": template.recommended_mitigation,
                "references": [
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"
                ],
            })


def detect_k8s_005_host_namespaces(
    resource_id: str,
    res_type: str,
    res_name: str,
    sec: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-005: Host namespace exposure."""
    template = THREAT_TEMPLATES["K8S-005"]
    exposed: list[str] = []
    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if sec.get(flag) is True:
            exposed.append(flag)

    if exposed:
        findings.append({
            "finding_id": f"{resource_id}-K8S-005-host-ns",
            "threat_id": template.threat_id,
            "title": f"Kubernetes Workload Shares Host Namespaces ({res_name})",
            "description": template.description,
            "affected_resource_id": resource_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "resource_id": resource_id,
            "resource_type": res_type,
            "source_format": "kubernetes",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
            "evidence": {"exposed_namespaces": exposed},
            "impact": template.potential_impact,
            "recommendation": template.recommended_mitigation,
            "remediation": template.recommended_mitigation,
            "references": [
                "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"
            ],
        })


def detect_k8s_006_writable_rootfs(
    resource_id: str,
    res_type: str,
    res_name: str,
    containers: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-006: Explicitly writable root filesystem."""
    template = THREAT_TEMPLATES["K8S-006"]
    for c in containers:
        if c.get("readOnlyRootFilesystem") is False:
            c_name = c.get("name") or "unnamed"
            findings.append({
                "finding_id": f"{resource_id}-K8S-006-writable-root-{c_name}",
                "threat_id": template.threat_id,
                "title": f"Kubernetes Container Root Filesystem Explicitly Writable ({res_name} / {c_name})",
                "description": template.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "resource_id": resource_id,
                "resource_type": res_type,
                "source_format": "kubernetes",
                "severity": "Medium",
                "detection_status": "Confirmed",
                "confidence": "High",
                "evidence": {"container": c_name, "readOnlyRootFilesystem": False},
                "impact": template.potential_impact,
                "recommendation": template.recommended_mitigation,
                "remediation": template.recommended_mitigation,
                "references": [
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"
                ],
            })


def detect_k8s_007_service_exposure(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-007: Unrestricted service exposure (LoadBalancer / NodePort)."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attrs = resource.get("attributes", {}) or {}
    sec = attrs.get("security_metadata", {}) or {}
    svc_type = sec.get("type") or attrs.get("type") or "ClusterIP"
    template = THREAT_TEMPLATES["K8S-007"]

    if svc_type == "NodePort":
        findings.append({
            "finding_id": f"{resource_id}-K8S-007-nodeport",
            "threat_id": template.threat_id,
            "title": f"Kubernetes Service Exposed via NodePort ({res_name})",
            "description": template.description,
            "affected_resource_id": resource_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "resource_id": resource_id,
            "resource_type": res_type,
            "source_format": "kubernetes",
            "severity": "Medium",
            "detection_status": "Confirmed",
            "confidence": "High",
            "evidence": {"type": "NodePort", "ports": sec.get("ports", [])},
            "impact": template.potential_impact,
            "recommendation": template.recommended_mitigation,
            "remediation": template.recommended_mitigation,
            "references": [
                "https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport"
            ],
        })
    elif svc_type == "LoadBalancer":
        # LoadBalancer exposes service externally; requires review unless private annotations exist
        findings.append({
            "finding_id": f"{resource_id}-K8S-007-loadbalancer",
            "threat_id": template.threat_id,
            "title": f"Kubernetes Service Configured as LoadBalancer – External Exposure Review Required ({res_name})",
            "description": template.description,
            "affected_resource_id": resource_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "resource_id": resource_id,
            "resource_type": res_type,
            "source_format": "kubernetes",
            "severity": "High",
            "detection_status": "Needs Review",
            "confidence": "Medium",
            "evidence": {
                "type": "LoadBalancer",
                "notice": "External network exposure is possible; verify cloud load balancer ingress restrictions or annotations.",
                "ports": sec.get("ports", []),
            },
            "impact": template.potential_impact,
            "recommendation": template.recommended_mitigation,
            "remediation": template.recommended_mitigation,
            "references": [
                "https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer"
            ],
        })


def detect_k8s_008_ingress_no_tls(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-008: Ingress without TLS encryption."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attrs = resource.get("attributes", {}) or {}
    sec = attrs.get("security_metadata", {}) or {}
    template = THREAT_TEMPLATES["K8S-008"]

    tls = sec.get("tls") or attrs.get("tls")
    rules = sec.get("rules") or attrs.get("rules") or []

    if rules and not tls:
        findings.append({
            "finding_id": f"{resource_id}-K8S-008-no-tls",
            "threat_id": template.threat_id,
            "title": f"Kubernetes Ingress Routes Traffic Without TLS Configuration ({res_name})",
            "description": template.description,
            "affected_resource_id": resource_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "resource_id": resource_id,
            "resource_type": res_type,
            "source_format": "kubernetes",
            "severity": "Medium",
            "detection_status": "Confirmed",
            "confidence": "High",
            "evidence": {"tls": "missing", "rules_count": len(rules)},
            "impact": template.potential_impact,
            "recommendation": template.recommended_mitigation,
            "remediation": template.recommended_mitigation,
            "references": [
                "https://kubernetes.io/docs/concepts/services-networking/ingress/#tls"
            ],
        })


def detect_k8s_009_rbac_wildcards(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-009: Excessive RBAC wildcard permissions."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attrs = resource.get("attributes", {}) or {}
    template = THREAT_TEMPLATES["K8S-009"]

    rules = attrs.get("rules") or []
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue

        verbs = rule.get("verbs", [])
        resources = rule.get("resources", [])
        api_groups = rule.get("apiGroups", [])

        wildcards: list[str] = []
        if "*" in verbs:
            wildcards.append("verbs: [*]")
        if "*" in resources:
            wildcards.append("resources: [*]")
        if "*" in api_groups:
            wildcards.append("apiGroups: [*]")

        if wildcards:
            findings.append({
                "finding_id": f"{resource_id}-K8S-009-rbac-wildcard-{idx}",
                "threat_id": template.threat_id,
                "title": f"Kubernetes RBAC {res_type} Grants Wildcard Permissions ({res_name})",
                "description": template.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "resource_id": resource_id,
                "resource_type": res_type,
                "source_format": "kubernetes",
                "severity": "High",
                "detection_status": "Confirmed",
                "confidence": "High",
                "evidence": {
                    "rule_index": idx,
                    "wildcard_specifications": wildcards,
                    "rule": rule,
                },
                "impact": template.potential_impact,
                "recommendation": template.recommended_mitigation,
                "remediation": template.recommended_mitigation,
                "references": [
                    "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole"
                ],
            })


def detect_k8s_010_automount_sa_token(
    resource_id: str,
    res_type: str,
    res_name: str,
    automount_val: Any,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-010: ServiceAccount token automount enabled."""
    template = THREAT_TEMPLATES["K8S-010"]
    if automount_val is True:
        findings.append({
            "finding_id": f"{resource_id}-K8S-010-automount-token",
            "threat_id": template.threat_id,
            "title": f"Kubernetes Resource Explicitly Automounts ServiceAccount Token ({res_name})",
            "description": template.description,
            "affected_resource_id": resource_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "resource_id": resource_id,
            "resource_type": res_type,
            "source_format": "kubernetes",
            "severity": "Medium",
            "detection_status": "Confirmed",
            "confidence": "High",
            "evidence": {"automountServiceAccountToken": True},
            "impact": template.potential_impact,
            "recommendation": template.recommended_mitigation,
            "remediation": template.recommended_mitigation,
            "references": [
                "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server"
            ],
        })


def detect_k8s_012_image_tagging(
    resource_id: str,
    res_type: str,
    res_name: str,
    containers: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate K8S-012: Untrusted container image configuration."""
    template = THREAT_TEMPLATES["K8S-012"]
    for c in containers:
        c_name = c.get("name") or "unnamed"
        img = c.get("image", "")
        unpinned, reason = _is_image_unpinned(img)
        if unpinned:
            findings.append({
                "finding_id": f"{resource_id}-K8S-012-image-{c_name}",
                "threat_id": template.threat_id,
                "title": f"Kubernetes Container Uses Mutable or Latest Image Tag ({res_name} / {c_name})",
                "description": template.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "resource_id": resource_id,
                "resource_type": res_type,
                "source_format": "kubernetes",
                "severity": "Medium",
                "detection_status": "Confirmed",
                "confidence": "High",
                "evidence": {"container": c_name, "image": img, "reason": reason},
                "impact": template.potential_impact,
                "recommendation": template.recommended_mitigation,
                "remediation": template.recommended_mitigation,
                "references": [
                    "https://kubernetes.io/docs/concepts/configuration/overview/#container-images"
                ],
            })


# ---------------------------------------------------------------------------
# K8S-011: Missing NetworkPolicy Analysis (Evaluated across all resources)
# ---------------------------------------------------------------------------


def detect_k8s_011_missing_network_policy(
    resources: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    """
    Evaluate K8S-011: Identify namespaces containing workloads but no NetworkPolicy.
    """
    template = THREAT_TEMPLATES["K8S-011"]

    # Collect namespaces with workloads
    workloads_by_ns: dict[str, list[dict[str, Any]]] = {}
    netpols_by_ns: set[str] = set()

    for r in resources:
        rtype = r.get("type", "")
        attrs = r.get("attributes", {}) or {}
        meta = attrs.get("_metadata", {}) or {}
        ns = meta.get("namespace") or "default"

        if rtype in WORKLOAD_KINDS:
            workloads_by_ns.setdefault(ns, []).append(r)
        elif rtype == "NetworkPolicy":
            netpols_by_ns.add(ns)

    # For each namespace having workloads without NetworkPolicy:
    for ns, w_list in workloads_by_ns.items():
        if ns not in netpols_by_ns:
            # Report finding for the first workload in the namespace
            first_w = w_list[0]
            first_w_id = f"{first_w.get('type')}.{first_w.get('name')}"
            findings.append({
                "finding_id": f"Namespace.{ns}-K8S-011-no-netpol",
                "threat_id": template.threat_id,
                "title": f"Namespace '{ns}' Workloads Lack NetworkPolicy Isolation in Manifest",
                "description": template.description,
                "affected_resource_id": first_w_id,
                "affected_resource_type": first_w.get("type", "Pod"),
                "affected_resource_name": first_w.get("name", "workload"),
                "resource_id": first_w_id,
                "resource_type": first_w.get("type", "Pod"),
                "source_format": "kubernetes",
                "severity": "Medium",
                "detection_status": "Needs Review",
                "confidence": "Low",
                "evidence": {
                    "namespace": ns,
                    "workloads_in_namespace": [w.get("name") for w in w_list],
                    "workload_count": len(w_list),
                    "network_policies_in_manifest": 0,
                    "notice": "Context-dependent: NetworkPolicy may be defined in another manifest or pre-existing cluster namespace.",
                },
                "impact": template.potential_impact,
                "recommendation": template.recommended_mitigation,
                "remediation": template.recommended_mitigation,
                "references": [
                    "https://kubernetes.io/docs/concepts/services-networking/network-policies/"
                ],
            })


# ---------------------------------------------------------------------------
# Master Kubernetes Threat Evaluation Entry Point
# ---------------------------------------------------------------------------


def analyze_kubernetes_threats(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Dispatch Kubernetes resource to appropriate rule evaluations."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attrs = resource.get("attributes", {}) or {}
    sec = attrs.get("security_metadata", {}) or {}

    # 1. Workload Threat Evaluations (K8S-001, K8S-002, K8S-003, K8S-004, K8S-005, K8S-006, K8S-010, K8S-012)
    if res_type in WORKLOAD_KINDS:
        containers = sec.get("containers", [])
        pod_sec = sec.get("podSecurityContext", {})

        # K8S-001: Privileged container
        detect_k8s_001_privileged_containers(resource_id, res_type, res_name, containers, findings)

        # K8S-002: Running as root
        detect_k8s_002_running_as_root(resource_id, res_type, res_name, containers, pod_sec, findings)

        # K8S-003: Privilege escalation
        detect_k8s_003_privilege_escalation(resource_id, res_type, res_name, containers, findings)

        # K8S-004: Dangerous capabilities
        detect_k8s_004_dangerous_capabilities(resource_id, res_type, res_name, containers, findings)

        # K8S-005: Host namespaces
        detect_k8s_005_host_namespaces(resource_id, res_type, res_name, sec, findings)

        # K8S-006: Writable rootfs
        detect_k8s_006_writable_rootfs(resource_id, res_type, res_name, containers, findings)

        # K8S-010: ServiceAccount token automount
        automount = sec.get("automountServiceAccountToken")
        if automount is None:
            automount = attrs.get("automountServiceAccountToken")
        detect_k8s_010_automount_sa_token(resource_id, res_type, res_name, automount, findings)

        # K8S-012: Untagged or latest images
        detect_k8s_012_image_tagging(resource_id, res_type, res_name, containers, findings)

    # 2. Service Threat Evaluation (K8S-007)
    elif res_type == "Service":
        detect_k8s_007_service_exposure(resource, resource_id, findings)

    # 3. Ingress Threat Evaluation (K8S-008)
    elif res_type == "Ingress":
        detect_k8s_008_ingress_no_tls(resource, resource_id, findings)

    # 4. RBAC Threat Evaluation (K8S-009)
    elif res_type in ("Role", "ClusterRole"):
        detect_k8s_009_rbac_wildcards(resource, resource_id, findings)

    # 5. ServiceAccount Threat Evaluation (K8S-010)
    elif res_type == "ServiceAccount":
        automount = attrs.get("automountServiceAccountToken")
        detect_k8s_010_automount_sa_token(resource_id, res_type, res_name, automount, findings)
