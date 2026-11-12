"""
tests/test_kubernetes_threat_rules.py
-------------------------------------
Unit tests for Kubernetes Security Threat Detection Rules (Stage 5).
Covers K8S-001 through K8S-012, explicit insecure settings, clean/secure settings,
unspecified values, detection status, confidence, and remediation suggestions.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from services.kubernetes_parser import KubernetesParser
from services.remediation_engine import generate_remediations
from services.risk_engine import assess_risks
from services.threat_engine import analyze_threats


# ---------------------------------------------------------------------------
# K8S-001: Privileged Container Execution
# ---------------------------------------------------------------------------


def test_k8s_001_privileged_container_detected():
    """Detect containers with privileged: true (Critical, Confirmed, High confidence)."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: default
spec:
  containers:
  - name: root-agent
    image: agent:1.0
    securityContext:
      privileged: true
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="pod.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    k8s_findings = [f for f in findings if f["threat_id"] == "K8S-001"]
    assert len(k8s_findings) == 1
    f = k8s_findings[0]
    assert f["severity"] == "Critical"
    assert f["detection_status"] == "Confirmed"
    assert f["confidence"] == "High"
    assert f["evidence"]["privileged"] is True
    assert f["evidence"]["container"] == "root-agent"
    assert f["source_format"] == "kubernetes"
    assert f["resource_id"] == "Pod.default.privileged-pod"

    # Risk scoring
    assessed, _ = assess_risks(findings)
    af = [x for x in assessed if x["threat_id"] == "K8S-001"][0]
    assert af["risk_assessment"]["inherent_risk_score"] == 20  # Likelihood 4 x Impact 5 (Critical)
    assert af["risk_assessment"]["risk_level"] == "Critical"


def test_k8s_001_unprivileged_container_not_flagged():
    """Unprivileged container (privileged: false) does not trigger K8S-001."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: safe-pod
  namespace: default
spec:
  containers:
  - name: worker
    image: worker:1.0
    securityContext:
      privileged: false
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="safe.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    assert not any(f["threat_id"] == "K8S-001" for f in findings)


# ---------------------------------------------------------------------------
# K8S-002: Container Running as Root
# ---------------------------------------------------------------------------


def test_k8s_002_running_as_root_explicit():
    """Detect explicit runAsUser: 0 or runAsNonRoot: false (High, Confirmed)."""
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-deploy
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: api-container
        image: api:v1
        securityContext:
          runAsUser: 0
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="deploy.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    k8s_findings = [f for f in findings if f["threat_id"] == "K8S-002"]
    assert len(k8s_findings) == 1
    f = k8s_findings[0]
    assert f["severity"] == "High"
    assert f["detection_status"] == "Confirmed"
    assert f["evidence"]["runAsUser"] == 0


def test_k8s_002_non_root_enforced_not_flagged():
    """Enforced non-root user (runAsNonRoot: true, runAsUser: 10001) is not flagged."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: non-root-pod
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
  containers:
  - name: secure-app
    image: secure-app:v1
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="non_root.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    assert not any(f["threat_id"] == "K8S-002" for f in findings)


# ---------------------------------------------------------------------------
# K8S-003: Privilege Escalation Enabled
# ---------------------------------------------------------------------------


def test_k8s_003_allow_privilege_escalation_detected():
    """Detect allowPrivilegeEscalation: true (High, Confirmed)."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: escalation-pod
  namespace: default
spec:
  containers:
  - name: task-worker
    image: task:1.0
    securityContext:
      allowPrivilegeEscalation: true
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="escalation.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    f = [f for f in findings if f["threat_id"] == "K8S-003"][0]
    assert f["severity"] == "High"
    assert f["detection_status"] == "Confirmed"
    assert f["evidence"]["allowPrivilegeEscalation"] is True


# ---------------------------------------------------------------------------
# K8S-004: Dangerous Linux Capabilities Added
# ---------------------------------------------------------------------------


def test_k8s_004_dangerous_capabilities():
    """Detect SYS_ADMIN (Critical) and NET_ADMIN (High)."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: caps-pod
  namespace: default
spec:
  containers:
  - name: admin-container
    image: tool:1.0
    securityContext:
      capabilities:
        add: ["SYS_ADMIN", "NET_ADMIN"]
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="caps.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    f = [f for f in findings if f["threat_id"] == "K8S-004"][0]
    assert f["severity"] == "Critical"  # Because SYS_ADMIN is present
    assert "SYS_ADMIN" in f["evidence"]["dangerous_capabilities"]
    assert "NET_ADMIN" in f["evidence"]["dangerous_capabilities"]


# ---------------------------------------------------------------------------
# K8S-005: Host Namespace Exposure
# ---------------------------------------------------------------------------


def test_k8s_005_host_namespace_exposure():
    """Detect hostNetwork: true, hostPID: true, hostIPC: true (High, Confirmed)."""
    manifest = """
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-mon
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: mon
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: mon
        image: mon:1.0
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="mon.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    f = [f for f in findings if f["threat_id"] == "K8S-005"][0]
    assert f["severity"] == "High"
    assert "hostNetwork" in f["evidence"]["exposed_namespaces"]
    assert "hostPID" in f["evidence"]["exposed_namespaces"]


# ---------------------------------------------------------------------------
# K8S-006: Writable Root Filesystem
# ---------------------------------------------------------------------------


def test_k8s_006_writable_rootfs():
    """Detect readOnlyRootFilesystem: false when explicitly configured."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: writable-pod
  namespace: default
spec:
  containers:
  - name: app
    image: app:1.0
    securityContext:
      readOnlyRootFilesystem: false
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="writable.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    f = [f for f in findings if f["threat_id"] == "K8S-006"][0]
    assert f["severity"] == "Medium"
    assert f["evidence"]["readOnlyRootFilesystem"] is False


def test_k8s_006_unspecified_not_treated_as_false():
    """Do not treat an unspecified readOnlyRootFilesystem as an explicit false."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: default-fs-pod
  namespace: default
spec:
  containers:
  - name: app
    image: app:1.0
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="default_fs.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    assert not any(f["threat_id"] == "K8S-006" for f in findings)


# ---------------------------------------------------------------------------
# K8S-007: Unrestricted Service Exposure
# ---------------------------------------------------------------------------


def test_k8s_007_service_exposure():
    """NodePort (Medium, Confirmed) and LoadBalancer (Needs Review)."""
    manifest = """
apiVersion: v1
kind: Service
metadata:
  name: web-nodeport
  namespace: default
spec:
  type: NodePort
  ports:
  - port: 80
    nodePort: 30080
---
apiVersion: v1
kind: Service
metadata:
  name: public-lb
  namespace: default
spec:
  type: LoadBalancer
  ports:
  - port: 443
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="services.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    np_findings = [f for f in findings if f["threat_id"] == "K8S-007" and f["affected_resource_name"] == "web-nodeport"]
    assert len(np_findings) == 1
    assert np_findings[0]["detection_status"] == "Confirmed"
    assert np_findings[0]["severity"] == "Medium"

    lb_findings = [f for f in findings if f["threat_id"] == "K8S-007" and f["affected_resource_name"] == "public-lb"]
    assert len(lb_findings) == 1
    assert lb_findings[0]["detection_status"] == "Needs Review"


# ---------------------------------------------------------------------------
# K8S-008: Ingress Without TLS
# ---------------------------------------------------------------------------


def test_k8s_008_ingress_without_tls():
    """Detect Ingress with routing rules but no TLS block."""
    manifest = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cleartext-ingress
  namespace: default
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-svc
            port:
              number: 80
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="ingress.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    f = [f for f in findings if f["threat_id"] == "K8S-008"][0]
    assert f["severity"] == "Medium"
    assert f["detection_status"] == "Confirmed"
    assert f["evidence"]["tls"] == "missing"


# ---------------------------------------------------------------------------
# K8S-009: Excessive RBAC Permissions
# ---------------------------------------------------------------------------


def test_k8s_009_rbac_wildcards():
    """Detect wildcard * in RBAC Role rules (verbs, resources, apiGroups)."""
    manifest = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="rbac.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    f = [f for f in findings if f["threat_id"] == "K8S-009"][0]
    assert f["severity"] == "High"
    assert f["detection_status"] == "Confirmed"
    assert len(f["evidence"]["wildcard_specifications"]) == 3


# ---------------------------------------------------------------------------
# K8S-010: ServiceAccount Token Automount
# ---------------------------------------------------------------------------


def test_k8s_010_automount_sa_token_explicit():
    """Detect automountServiceAccountToken: true where explicitly configured."""
    manifest = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: token-sa
  namespace: default
automountServiceAccountToken: true
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="sa.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    f = [f for f in findings if f["threat_id"] == "K8S-010"][0]
    assert f["severity"] == "Medium"
    assert f["evidence"]["automountServiceAccountToken"] is True


# ---------------------------------------------------------------------------
# K8S-011: Missing NetworkPolicy
# ---------------------------------------------------------------------------


def test_k8s_011_missing_network_policy():
    """Namespace with workloads but no NetworkPolicy triggers Needs Review finding."""
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: isolated-workload
  namespace: backend-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: worker
  template:
    metadata:
      labels:
        app: worker
    spec:
      containers:
      - name: worker
        image: worker:1.0
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="no_netpol.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    f = [f for f in findings if f["threat_id"] == "K8S-011"][0]
    assert f["severity"] == "Medium"
    assert f["detection_status"] == "Needs Review"
    assert f["confidence"] == "Low"
    assert f["evidence"]["namespace"] == "backend-ns"


# ---------------------------------------------------------------------------
# K8S-012: Untrusted Container Image Configuration
# ---------------------------------------------------------------------------


def test_k8s_012_image_tagging():
    """Detect images with latest tag or missing explicit version tag."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: untagged-pod
  namespace: default
spec:
  containers:
  - name: c1
    image: nginx:latest
  - name: c2
    image: redis
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="images.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")

    img_findings = [f for f in findings if f["threat_id"] == "K8S-012"]
    assert len(img_findings) == 2
    assert any(f["evidence"]["container"] == "c1" for f in img_findings)
    assert any(f["evidence"]["container"] == "c2" for f in img_findings)


def test_k8s_remediation_generation():
    """Verify remediation engine produces actionable guidance for Kubernetes findings."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
  namespace: default
spec:
  containers:
  - name: agent
    image: agent:1.0
    securityContext:
      privileged: true
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="priv.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="kubernetes")
    assessed, _ = assess_risks(findings)
    rems = generate_remediations(assessed, infra.to_legacy_resources())

    assert len(rems) >= 1
    rem = rems[0]
    assert rem["patch_type"] in ("modification", "manual")
    assert len(rem["recommended_actions"]) > 0
    assert rem["suggested_code"] is not None
    assert "privileged: false" in rem["suggested_code"]
