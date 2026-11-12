"""
tests/test_kubernetes_parser.py
--------------------------------
Stage 4: Comprehensive test suite for Kubernetes YAML manifest parser,
multi-document handling, security metadata extraction, relationship resolution,
registry routing, and API integration.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from main import app
from services.infrastructure_schema import IaCFormat, NormalizedInfrastructure, ParsingStatus
from services.kubernetes_parser import KubernetesParser
from services.parser_registry import (
    MalformedIaCError,
    UnsupportedFormatError,
    default_parser_registry,
    identify_iac_format,
    parse_iac,
)

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test 1: Basic Pod Manifest
# ---------------------------------------------------------------------------


def test_1_basic_pod_manifest():
    """Verify parsing a standard single-container Pod manifest."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  namespace: web
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx:1.25.0
    securityContext:
      privileged: false
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="pod.yaml")

    assert isinstance(infra, NormalizedInfrastructure)
    assert infra.source_format == "kubernetes"
    assert infra.source_file == "pod.yaml"
    assert infra.resource_count == 1
    assert infra.parsing_status == ParsingStatus.VALID.value

    pod = infra.get_resource("Pod.web.nginx-pod")
    assert pod is not None
    assert pod.name == "nginx-pod"
    assert pod.type == "Pod"
    assert pod.provider == "kubernetes"
    assert pod.source_location["namespace"] == "web"
    assert pod.source_location["kind"] == "Pod"

    # Check security metadata
    sec = pod.attributes["security_metadata"]
    assert sec["hostNetwork"] is False
    containers = sec["containers"]
    assert len(containers) == 1
    c = containers[0]
    assert c["name"] == "nginx"
    assert c["image"] == "nginx:1.25.0"
    assert c["privileged"] is False
    assert c["runAsNonRoot"] is True
    assert c["readOnlyRootFilesystem"] is True
    assert "ALL" in c["capabilities_drop"]


# ---------------------------------------------------------------------------
# Test 2: Deployment Manifest
# ---------------------------------------------------------------------------


def test_2_deployment_manifest():
    """Verify parsing a Kubernetes Deployment with replicas and nested Pod template."""
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
  namespace: prod
  labels:
    tier: backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payment
  template:
    metadata:
      labels:
        app: payment
    spec:
      serviceAccountName: payment-sa
      containers:
      - name: payment-api
        image: payment-api:v2.1
        securityContext:
          allowPrivilegeEscalation: false
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="deployment.yaml")

    dep = infra.get_resource("Deployment.prod.payment-service")
    assert dep is not None
    assert dep.attributes["replicas"] == 3
    sec = dep.attributes["security_metadata"]
    assert sec["serviceAccountName"] == "payment-sa"
    assert len(sec["containers"]) == 1
    assert sec["containers"][0]["allowPrivilegeEscalation"] is False


# ---------------------------------------------------------------------------
# Test 3: StatefulSet and DaemonSet Manifests
# ---------------------------------------------------------------------------


def test_3_statefulset_and_daemonset_manifests():
    """Verify parsing StatefulSet and DaemonSet resources."""
    manifest = """
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis-cluster
  namespace: database
spec:
  replicas: 3
  serviceName: redis-headless
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7.0-alpine
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-exporter
  namespace: monitoring
spec:
  template:
    metadata:
      labels:
        app: node-exporter
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: exporter
        image: prom/node-exporter:v1.7.0
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="workloads.yaml")

    assert infra.resource_count == 2
    sts = infra.get_resource("StatefulSet.database.redis-cluster")
    assert sts is not None
    assert sts.attributes["serviceName"] == "redis-headless"

    ds = infra.get_resource("DaemonSet.monitoring.node-exporter")
    assert ds is not None
    ds_sec = ds.attributes["security_metadata"]
    assert ds_sec["hostNetwork"] is True
    assert ds_sec["hostPID"] is True


# ---------------------------------------------------------------------------
# Test 4: Service and Ingress Manifests
# ---------------------------------------------------------------------------


def test_4_service_and_ingress_manifests():
    """Verify Service port definitions and Ingress routing with relationship linking."""
    manifest = """
apiVersion: v1
kind: Service
metadata:
  name: order-service
  namespace: default
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  selector:
    app: order
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: order-ingress
  namespace: default
spec:
  rules:
  - host: orders.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: order-service
            port:
              number: 80
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="networking.yaml")

    svc = infra.get_resource("Service.default.order-service")
    assert svc is not None
    assert svc.attributes["security_metadata"]["type"] == "LoadBalancer"

    ing = infra.get_resource("Ingress.default.order-ingress")
    assert ing is not None
    # Relationship from Ingress to Service
    assert "Service.order-service" in ing.relationships


# ---------------------------------------------------------------------------
# Test 5: ConfigMap and Secret Manifests
# ---------------------------------------------------------------------------


def test_5_configmap_and_secret_manifests():
    """Verify parsing of ConfigMap and Secret with metadata and values."""
    manifest = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  LOG_LEVEL: info
  APP_ENV: production
---
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: default
type: Opaque
data:
  username: YWRtaW4=
  password: c2VjcmV0cGFzc3dvcmQ=
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="configs.yaml")

    cm = infra.get_resource("ConfigMap.default.app-config")
    assert cm is not None
    assert cm.attributes["data"]["LOG_LEVEL"] == "info"

    sec = infra.get_resource("Secret.default.db-credentials")
    assert sec is not None
    assert sec.attributes["type"] == "Opaque"
    assert "password" in sec.attributes["data"]


# ---------------------------------------------------------------------------
# Test 6: ServiceAccount Manifest
# ---------------------------------------------------------------------------


def test_6_serviceaccount_manifest():
    """Verify parsing a ServiceAccount with token automounting preference."""
    manifest = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-runner
  namespace: payments
automountServiceAccountToken: false
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="sa.yaml")

    sa = infra.get_resource("ServiceAccount.payments.app-runner")
    assert sa is not None
    assert sa.name == "app-runner"
    assert sa.type == "ServiceAccount"


# ---------------------------------------------------------------------------
# Test 7: Role and ClusterRole Manifests
# ---------------------------------------------------------------------------


def test_7_role_and_clusterrole_manifests():
    """Verify Role and ClusterRole RBAC rules and cluster scope identification."""
    manifest = """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-admin
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["*"]
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="rbac_roles.yaml")

    role = infra.get_resource("Role.default.pod-reader")
    assert role is not None
    assert len(role.attributes["rules"]) == 1
    assert "pods" in role.attributes["rules"][0]["resources"]

    # ClusterRole is cluster-scoped (no namespace in ID)
    crole = infra.get_resource("ClusterRole.secret-admin")
    assert crole is not None
    assert crole.attributes["rules"][0]["verbs"] == ["*"]


# ---------------------------------------------------------------------------
# Test 8: RoleBinding and ClusterRoleBinding Manifests
# ---------------------------------------------------------------------------


def test_8_rolebinding_and_clusterrolebinding_relationships():
    """Verify RoleBinding and ClusterRoleBinding reference roles and subjects."""
    manifest = """
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: app-runner
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: global-secret-binding
subjects:
- kind: User
  name: security-auditor
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: secret-admin
  apiGroup: rbac.authorization.k8s.io
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="bindings.yaml")

    rb = infra.get_resource("RoleBinding.default.read-pods-binding")
    assert rb is not None
    assert "Role.pod-reader" in rb.relationships
    assert "ServiceAccount.app-runner" in rb.relationships

    crb = infra.get_resource("ClusterRoleBinding.global-secret-binding")
    assert crb is not None
    assert "ClusterRole.secret-admin" in crb.relationships
    assert "User.security-auditor" in crb.relationships


# ---------------------------------------------------------------------------
# Test 9: NetworkPolicy Manifest
# ---------------------------------------------------------------------------


def test_9_networkpolicy_manifest():
    """Verify NetworkPolicy ingress/egress rules and podSelector."""
    manifest = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-netpol
  namespace: default
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: frontend
    ports:
    - protocol: TCP
      port: 8080
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="netpol.yaml")

    netpol = infra.get_resource("NetworkPolicy.default.backend-netpol")
    assert netpol is not None
    sec = netpol.attributes["security_metadata"]
    assert "Ingress" in sec["policyTypes"]
    assert "Egress" in sec["policyTypes"]
    assert len(sec["ingress"]) == 1


# ---------------------------------------------------------------------------
# Test 10: PersistentVolume and PersistentVolumeClaim Manifests
# ---------------------------------------------------------------------------


def test_10_persistentvolume_and_claim_manifests():
    """Verify PV and PVC parsing with volume binding relationship."""
    manifest = """
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-data-volume
spec:
  capacity:
    storage: 50Gi
  accessModes:
  - ReadWriteOnce
  hostPath:
    path: /mnt/data
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc-claim
  namespace: default
spec:
  accessModes:
  - ReadWriteOnce
  volumeName: pv-data-volume
  resources:
    requests:
      storage: 50Gi
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="storage.yaml")

    pv = infra.get_resource("PersistentVolume.pv-data-volume")
    assert pv is not None
    assert "ReadWriteOnce" in pv.attributes["security_metadata"]["accessModes"]

    pvc = infra.get_resource("PersistentVolumeClaim.default.pvc-claim")
    assert pvc is not None
    assert "PersistentVolume.pv-data-volume" in pvc.relationships


# ---------------------------------------------------------------------------
# Test 11: Namespace Manifest
# ---------------------------------------------------------------------------


def test_11_namespace_manifest():
    """Verify cluster-scoped Namespace resource parsing."""
    manifest = """
apiVersion: v1
kind: Namespace
metadata:
  name: production-tier
  labels:
    security-zone: restricted
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="ns.yaml")

    ns = infra.get_resource("Namespace.production-tier")
    assert ns is not None
    assert ns.name == "production-tier"
    assert ns.type == "Namespace"
    assert ns.provider == "kubernetes"


# ---------------------------------------------------------------------------
# Test 12: Multiple YAML Documents in One File
# ---------------------------------------------------------------------------


def test_12_multi_document_manifest():
    """Verify multi-document YAML parsing and selector-based cross-document relationship."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: auth-pod
  namespace: default
  labels:
    role: auth
spec:
  containers:
  - name: auth-app
    image: auth:1.0
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: default
spec:
  selector:
    role: auth
  ports:
  - port: 8080
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="auth-stack.yaml")

    assert infra.resource_count == 2
    assert infra.get_resource("Pod.default.auth-pod") is not None
    svc = infra.get_resource("Service.default.auth-service")
    assert svc is not None
    # Service selector matched Pod.default.auth-pod
    assert "Pod.default.auth-pod" in svc.relationships


# ---------------------------------------------------------------------------
# Test 13: Empty YAML Documents (Leading/Trailing/Consecutive ---)
# ---------------------------------------------------------------------------


def test_13_empty_documents_handling():
    """Verify empty documents from leading, trailing, or double separators are safely ignored."""
    manifest = """
---

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: isolated-config
  namespace: default
data:
  KEY: value
---

---
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="empty_docs.yaml")

    assert infra.resource_count == 1
    cm = infra.get_resource("ConfigMap.default.isolated-config")
    assert cm is not None
    assert cm.name == "isolated-config"


# ---------------------------------------------------------------------------
# Test 14: Unknown But Structurally Valid Kubernetes Kind (CRD)
# ---------------------------------------------------------------------------


def test_14_unknown_crd_kind_preservation():
    """Verify custom resources (e.g. CertManager Certificate) are parsed and preserved."""
    manifest = """
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: tls-cert
  namespace: web
spec:
  secretName: tls-secret
  dnsNames:
  - example.com
"""
    parser = KubernetesParser()
    infra = parser.parse(manifest, filename="certificate.yaml")

    assert infra.resource_count == 1
    cert = infra.get_resource("Certificate.web.tls-cert")
    assert cert is not None
    assert cert.type == "Certificate"
    assert cert.parsing_status == ParsingStatus.VALID.value
    assert any("Certificate" in err for err in cert.validation_errors)


# ---------------------------------------------------------------------------
# Test 15: Missing apiVersion Error
# ---------------------------------------------------------------------------


def test_15_missing_api_version():
    """Verify MalformedIaCError when apiVersion is missing."""
    manifest = """
kind: Pod
metadata:
  name: broken-pod
spec:
  containers: []
"""
    parser = KubernetesParser()
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse(manifest, filename="no_apiversion.yaml")
    assert "apiVersion" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 16: Missing kind Error
# ---------------------------------------------------------------------------


def test_16_missing_kind():
    """Verify MalformedIaCError when kind is missing."""
    manifest = """
apiVersion: v1
metadata:
  name: broken-pod
spec:
  containers: []
"""
    parser = KubernetesParser()
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse(manifest, filename="no_kind.yaml")
    assert "kind" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 17: Missing metadata.name Error
# ---------------------------------------------------------------------------


def test_17_missing_metadata_name():
    """Verify MalformedIaCError when metadata.name is missing."""
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  namespace: default
spec:
  containers: []
"""
    parser = KubernetesParser()
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse(manifest, filename="no_name.yaml")
    assert "metadata.name" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 18: Malformed YAML Syntax Error
# ---------------------------------------------------------------------------


def test_18_malformed_yaml_syntax():
    """Verify MalformedIaCError on invalid YAML indentation/tokens."""
    broken_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: broken
    bad_indentation: true
 [unclosed bracket
"""
    parser = KubernetesParser()
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse(broken_yaml, filename="broken.yaml")
    assert "YAML syntax" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 19: Generic YAML Rejection
# ---------------------------------------------------------------------------


def test_19_generic_yaml_rejection():
    """Verify that arbitrary non-K8s YAML is rejected with UnsupportedFormatError."""
    generic_yaml = """
version: '3.8'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
"""
    with pytest.raises(UnsupportedFormatError) as exc_info:
        identify_iac_format("docker-compose.yml", generic_yaml)
    assert "generic YAML file" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 20: CloudFormation YAML Compatibility
# ---------------------------------------------------------------------------


def test_20_cloudformation_yaml_not_misidentified_as_kubernetes():
    """Ensure AWS CloudFormation templates are NOT misclassified as Kubernetes."""
    cfn_yaml = """
AWSTemplateFormatVersion: '2010-09-09'
Description: AWS S3 Bucket
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: cfn-isolated-bucket
"""
    fmt = identify_iac_format("template.yaml", cfn_yaml)
    assert fmt == IaCFormat.CLOUDFORMATION
    assert fmt != IaCFormat.KUBERNETES


# ---------------------------------------------------------------------------
# Test 21: Terraform .tf Compatibility
# ---------------------------------------------------------------------------


def test_21_terraform_tf_compatibility():
    """Verify Terraform .tf files continue to route and parse correctly."""
    tf_hcl = """
resource "aws_s3_bucket" "my_tf_bucket" {
  bucket = "tf-preserved-bucket"
}
"""
    fmt = identify_iac_format("main.tf", tf_hcl)
    assert fmt == IaCFormat.TERRAFORM

    infra = parse_iac(tf_hcl, filename="main.tf")
    assert infra.source_format == "terraform"
    assert infra.resource_count == 1
    assert infra.get_resource("aws_s3_bucket.my_tf_bucket") is not None


# ---------------------------------------------------------------------------
# Test 22: Terraform .tf.json Compatibility
# ---------------------------------------------------------------------------


def test_22_terraform_tf_json_compatibility():
    """Verify Terraform .tf.json continues to route and parse correctly."""
    tf_json = json.dumps({
        "resource": {
            "aws_s3_bucket": {
                "json_bucket": {
                    "bucket": "json-tf-preserved"
                }
            }
        }
    })
    fmt = identify_iac_format("infra.tf.json", tf_json)
    assert fmt == IaCFormat.TERRAFORM

    infra = parse_iac(tf_json, filename="infra.tf.json")
    assert infra.source_format == "terraform"
    assert infra.resource_count == 1


# ---------------------------------------------------------------------------
# Test 23: Registry Selecting KubernetesParser Correctly
# ---------------------------------------------------------------------------


def test_23_registry_routes_kubernetes_manifest():
    """Verify default_parser_registry routes a Kubernetes YAML manifest to KubernetesParser."""
    k8s_yaml = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: registry-test-sa
  namespace: test
"""
    fmt = default_parser_registry.identify_format("manifest.yaml", k8s_yaml)
    assert fmt == IaCFormat.KUBERNETES

    parser = default_parser_registry.get_parser_for_file("manifest.yaml", k8s_yaml)
    assert isinstance(parser, KubernetesParser)

    infra = default_parser_registry.parse(k8s_yaml, filename="manifest.yaml")
    assert infra.source_format == "kubernetes"
    assert infra.resource_count == 1
    assert infra.resources[0].name == "registry-test-sa"


# ---------------------------------------------------------------------------
# Test 24: /api/analyze Endpoint Accepts Kubernetes Manifest
# ---------------------------------------------------------------------------


def test_24_api_analyze_kubernetes_manifest_integration():
    """Verify POST /api/analyze accepts a Kubernetes manifest and returns full response structure."""
    k8s_manifest = b"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend-app
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: web
        image: nginx:1.24
---
apiVersion: v1
kind: Service
metadata:
  name: frontend-svc
  namespace: default
spec:
  selector:
    app: frontend
  ports:
  - port: 80
    targetPort: 80
"""
    res = client.post(
        "/api/analyze",
        files={"file": ("k8s-app.yaml", k8s_manifest, "application/x-yaml")},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["filename"] == "k8s-app.yaml"
    assert data["resource_count"] == 2
    assert "Deployment" in data["resource_types"]
    assert "Service" in data["resource_types"]
    assert "infrastructure_map" in data
    assert len(data["infrastructure_map"]["nodes"]) == 2
    assert "risk_summary" in data
    assert "remediations" in data
    assert data["id"] is not None  # Persisted to database
