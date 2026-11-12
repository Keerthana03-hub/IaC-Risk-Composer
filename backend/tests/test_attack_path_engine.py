"""
tests/test_attack_path_engine.py
--------------------------------
Comprehensive test suite for Relationship-Aware Attack Path Analysis Engine (Stage 6).

Covers all 14 required validation scenarios:
1. Public EC2 → IAM Role → S3 Bucket path.
2. Kubernetes Ingress → Service → Pod path.
3. Kubernetes Pod → ServiceAccount → RoleBinding → Role → Secret path.
4. Workload → sensitive storage path.
5. Infrastructure with no attack paths.
6. Cyclic relationships handling (no infinite loops).
7. Duplicate relationships deduplication.
8. Unresolved resource references handling.
9. Missing threat findings resilience.
10. Needs Review / Provisional classification for incomplete evidence.
11. Terraform regression preservation.
12. CloudFormation regression preservation.
13. Kubernetes regression preservation.
14. API integration (POST /api/analyze and GET /api/analysis/{id}/attack-paths).
"""

from __future__ import annotations

import io
from typing import Any

import pytest
from fastapi.testclient import TestClient

from main import app
from services.attack_path_engine import (
    DirectedAttackGraph,
    GraphNode,
    analyze_attack_paths,
    build_directed_attack_graph,
    discover_attack_paths,
)
from services.parser_registry import default_parser_registry

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test 1: Public EC2 → IAM Role → S3 Bucket Path (Terraform)
# ---------------------------------------------------------------------------


def test_1_public_ec2_iam_role_s3_path():
    """Verify discovery of Public SG → EC2 Instance → IAM Role → S3 Bucket path."""
    tf_content = """
resource "aws_security_group" "web_sg" {
  name        = "web_sg"
  description = "Public ingress"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app_role" {
  name = "app_role"
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "s3:*"
      Resource = "${aws_s3_bucket.data_vault.arn}"
    }]
  })
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app_profile"
  role = aws_iam_role.app_role.name
}

resource "aws_instance" "web_server" {
  ami                  = "ami-123456"
  instance_type        = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile = aws_iam_instance_profile.app_profile.name
}

resource "aws_s3_bucket" "data_vault" {
  bucket = "company-data-vault"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="main.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-1",
            "threat_id": "THREAT-001",
            "title": "Open SSH Ingress",
            "affected_resource_id": "aws_security_group.web_sg",
            "severity": "Critical",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    assert len(paths) >= 1
    target_path = next(
        (p for p in paths if p["target_resource"] == "aws_s3_bucket.data_vault"), None
    )
    assert target_path is not None
    assert target_path["entry_point"] == "aws_security_group.web_sg"
    assert "aws_instance.web_server" in target_path["resource_path"]
    assert "aws_iam_role.app_role" in target_path["resource_path"]
    assert target_path["severity"] in ("Critical", "High")
    assert len(target_path["evidence"]) >= 3
    assert "THREAT-001" in target_path["related_findings"]


# ---------------------------------------------------------------------------
# Test 2: Kubernetes Ingress → Service → Pod Path
# ---------------------------------------------------------------------------


def test_2_k8s_ingress_service_pod_path():
    """Verify discovery of Ingress → Service → Pod → Secret path."""
    k8s_content = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  namespace: prod
spec:
  rules:
  - http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 80
---
apiVersion: v1
kind: Service
metadata:
  name: api-service
  namespace: prod
spec:
  selector:
    app: api-workload
  ports:
  - port: 80
    targetPort: 8080
---
apiVersion: v1
kind: Pod
metadata:
  name: api-pod
  namespace: prod
  labels:
    app: api-workload
spec:
  containers:
  - name: api
    image: company/api:1.0
  volumes:
  - name: creds
    secret:
      secretName: api-secret
---
apiVersion: v1
kind: Secret
metadata:
  name: api-secret
  namespace: prod
type: Opaque
stringData:
  DB_PASSWORD: "SuperSecretPassword"
"""
    norm_infra = default_parser_registry.parse(k8s_content, filename="api.yaml")
    resources = norm_infra.to_legacy_resources()

    findings = [
        {
            "finding_id": "k8s-1",
            "threat_id": "K8S-008",
            "title": "Ingress Without TLS",
            "affected_resource_id": "Ingress.prod.api-ingress",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=findings,
        source_format="kubernetes",
        normalized_infrastructure=norm_infra,
    )

    assert len(paths) >= 1
    found_path = next(
        (p for p in paths if p["target_resource"] == "Secret.prod.api-secret"), None
    )
    assert found_path is not None
    assert found_path["entry_point"] == "Ingress.prod.api-ingress"
    assert found_path["resource_path"] == [
        "Ingress.prod.api-ingress",
        "Service.prod.api-service",
        "Pod.prod.api-pod",
        "Secret.prod.api-secret",
    ]
    assert len(found_path["evidence"]) == 3


# ---------------------------------------------------------------------------
# Test 3: Kubernetes Pod → ServiceAccount → RoleBinding → Role → Secret Path
# ---------------------------------------------------------------------------


def test_3_k8s_pod_sa_rolebinding_role_path():
    """Verify discovery of Pod → ServiceAccount → RoleBinding → Role → Secret path."""
    k8s_content = """
apiVersion: v1
kind: Service
metadata:
  name: public-service
  namespace: default
spec:
  type: LoadBalancer
  selector:
    app: worker
  ports:
  - port: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: worker-pod
  namespace: default
  labels:
    app: worker
spec:
  serviceAccountName: worker-sa
  containers:
  - name: worker
    image: worker:1.0
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: worker-sa
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: worker-rb
  namespace: default
subjects:
- kind: ServiceAccount
  name: worker-sa
  namespace: default
roleRef:
  kind: Role
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
---
apiVersion: v1
kind: Secret
metadata:
  name: vault-keys
  namespace: default
type: Opaque
"""
    norm_infra = default_parser_registry.parse(k8s_content, filename="rbac.yaml")
    resources = norm_infra.to_legacy_resources()

    findings = [
        {
            "finding_id": "k8s-lb",
            "threat_id": "K8S-007",
            "title": "Public LoadBalancer Service",
            "affected_resource_id": "Service.default.public-service",
            "severity": "Medium",
            "detection_status": "Needs Review",
            "confidence": "Medium",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=findings,
        source_format="kubernetes",
        normalized_infrastructure=norm_infra,
    )

    assert len(paths) >= 1
    found = next((p for p in paths if p["target_resource"] == "Secret.default.vault-keys"), None)
    assert found is not None
    assert found["entry_point"] == "Service.default.public-service"
    assert "Pod.default.worker-pod" in found["resource_path"]
    assert "ServiceAccount.default.worker-sa" in found["resource_path"]
    assert "RoleBinding.default.worker-rb" in found["resource_path"]
    assert "Role.default.secret-reader" in found["resource_path"]


# ---------------------------------------------------------------------------
# Test 4: Workload → Sensitive Storage Path (CloudFormation)
# ---------------------------------------------------------------------------


def test_4_workload_sensitive_storage_path():
    """Verify discovery of CloudFormation Public SG → EC2 Instance → Volume path."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Public access
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
  AppServer:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-12345
      SecurityGroupIds:
        - !Ref PublicSG
  DatabaseDisk:
    Type: AWS::EC2::Volume
    Properties:
      Size: 100
      Encrypted: false
  DiskAttachment:
    Type: AWS::EC2::VolumeAttachment
    Properties:
      InstanceId: !Ref AppServer
      VolumeId: !Ref DatabaseDisk
      Device: /dev/sdf
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="storage.yaml")
    resources = norm_infra.to_legacy_resources()

    findings = [
        {
            "finding_id": "cfn-1",
            "threat_id": "CFN-004",
            "title": "Open Ingress",
            "affected_resource_id": "AWS::EC2::SecurityGroup.PublicSG",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        },
        {
            "finding_id": "cfn-2",
            "threat_id": "CFN-005",
            "title": "Unencrypted EBS Volume",
            "affected_resource_id": "AWS::EC2::Volume.DatabaseDisk",
            "severity": "Medium",
            "detection_status": "Confirmed",
            "confidence": "High",
        },
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=findings,
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    assert len(paths) >= 1
    path = next(
        (p for p in paths if p["target_resource"] == "AWS::EC2::Volume.DatabaseDisk"), None
    )
    assert path is not None
    assert path["entry_point"] == "AWS::EC2::SecurityGroup.PublicSG"
    assert "AWS::EC2::Instance.AppServer" in path["resource_path"]
    assert path["severity"] in ("High", "Critical")


# ---------------------------------------------------------------------------
# Test 5: Infrastructure With No Attack Paths
# ---------------------------------------------------------------------------


def test_5_infrastructure_no_attack_paths():
    """Verify that private infrastructure with no public entry points produces 0 attack paths."""
    tf_content = """
resource "aws_security_group" "internal_only" {
  name = "internal_sg"
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_instance" "internal_db" {
  ami                    = "ami-123"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.internal_only.id]
}

resource "aws_s3_bucket" "strictly_private" {
  bucket = "strictly-private-internal-bucket"
  acl    = "private"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="internal.tf")
    resources = norm_infra.to_legacy_resources()

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=[],
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    assert paths == []


# ---------------------------------------------------------------------------
# Test 6: Cyclic Relationships Handling
# ---------------------------------------------------------------------------


def test_6_cyclic_relationships():
    """Verify that cyclic graph references do not cause infinite recursion or hang."""
    graph = DirectedAttackGraph(source_format="terraform")

    # Construct nodes A <-> B (Cycle)
    node_a = GraphNode(
        id="res_a",
        name="a",
        resource_type="aws_security_group",
        source_format="terraform",
        categories={"entry_point"},
    )
    node_b = GraphNode(
        id="res_b",
        name="b",
        resource_type="aws_instance",
        source_format="terraform",
        categories={"workload"},
    )
    node_c = GraphNode(
        id="res_c",
        name="c",
        resource_type="aws_s3_bucket",
        source_format="terraform",
        categories={"sensitive"},
    )

    graph.add_node(node_a)
    graph.add_node(node_b)
    graph.add_node(node_c)

    # Cyclic edge between A and B
    graph.add_edge("res_a", "res_b", "exposes", "A exposes B")
    graph.add_edge("res_b", "res_a", "references", "B references A")
    # B reaches C
    graph.add_edge("res_b", "res_c", "accesses", "B accesses C")

    paths = discover_attack_paths(graph)
    assert len(paths) == 1
    assert paths[0].resource_path == ["res_a", "res_b", "res_c"]


# ---------------------------------------------------------------------------
# Test 7: Duplicate Relationships Deduplication
# ---------------------------------------------------------------------------


def test_7_duplicate_relationships():
    """Verify that redundant edges or duplicate paths are strictly deduplicated."""
    graph = DirectedAttackGraph(source_format="terraform")

    node_sg = GraphNode(
        id="sg-1",
        name="sg-1",
        resource_type="aws_security_group",
        source_format="terraform",
        categories={"entry_point"},
    )
    node_ec2 = GraphNode(
        id="ec2-1",
        name="ec2-1",
        resource_type="aws_instance",
        source_format="terraform",
        categories={"workload"},
    )
    node_s3 = GraphNode(
        id="s3-1",
        name="s3-1",
        resource_type="aws_s3_bucket",
        source_format="terraform",
        categories={"sensitive"},
    )

    graph.add_node(node_sg)
    graph.add_node(node_ec2)
    graph.add_node(node_s3)

    # Attempt adding duplicate edges
    graph.add_edge("sg-1", "ec2-1", "exposes", "SG exposes EC2")
    graph.add_edge("sg-1", "ec2-1", "exposes", "SG exposes EC2 duplicate")
    graph.add_edge("ec2-1", "s3-1", "accesses", "EC2 accesses S3")
    graph.add_edge("ec2-1", "s3-1", "accesses", "EC2 accesses S3 duplicate")

    # Only 1 unique edge should exist between each pair
    assert len(graph.adjacency["sg-1"]) == 1
    assert len(graph.adjacency["ec2-1"]) == 1

    paths = discover_attack_paths(graph)
    assert len(paths) == 1


# ---------------------------------------------------------------------------
# Test 8: Unresolved Resource References Handling
# ---------------------------------------------------------------------------


def test_8_unresolved_resource_references():
    """Verify that references to absent external resources are noted as limitations."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Public
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  WebInstance:
    Type: AWS::EC2::Instance
    Properties:
      SecurityGroupIds:
        - !Ref PublicSG
      IamInstanceProfile: "arn:aws:iam::123456789012:instance-profile/ExternalProfile"
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="unresolved.yaml")
    resources = norm_infra.to_legacy_resources()

    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=[],
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    inst_node = graph.nodes["AWS::EC2::Instance.WebInstance"]
    # Unresolved IAM reference recorded on node
    assert len(inst_node.unresolved_references) > 0


# ---------------------------------------------------------------------------
# Test 9: Missing Threat Findings Resilience
# ---------------------------------------------------------------------------


def test_9_missing_threat_findings():
    """Verify that attack path analysis functions normally without threat findings."""
    tf_content = """
resource "aws_security_group" "open_sg" {
  name = "open_sg"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-123"
  vpc_security_group_ids = [aws_security_group.open_sg.id]
}

resource "aws_ebs_volume" "disk" {
  availability_zone = "us-east-1a"
  size              = 10
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="open.tf")
    resources = norm_infra.to_legacy_resources()

    # Manual link for testing
    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=[],
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )
    graph.add_edge("aws_instance.web", "aws_ebs_volume.disk", "attaches_storage", "Attached disk")

    paths = discover_attack_paths(graph)
    assert len(paths) >= 1
    assert paths[0].entry_point == "aws_security_group.open_sg"
    assert paths[0].target_resource == "aws_ebs_volume.disk"


# ---------------------------------------------------------------------------
# Test 10: Needs Review / Provisional Classification for Incomplete Evidence
# ---------------------------------------------------------------------------


def test_10_needs_review_classification_for_incomplete_evidence():
    """Verify that a path with Needs Review finding receives Provisional assessment_status."""
    graph = DirectedAttackGraph(source_format="kubernetes")

    node_entry = GraphNode(
        id="Service.default.svc",
        name="svc",
        resource_type="Service",
        source_format="kubernetes",
        categories={"entry_point"},
        findings=[
            {
                "threat_id": "K8S-007",
                "severity": "Medium",
                "detection_status": "Needs Review",
            }
        ],
    )
    node_sec = GraphNode(
        id="Secret.default.sec",
        name="sec",
        resource_type="Secret",
        source_format="kubernetes",
        categories={"sensitive"},
    )

    graph.add_node(node_entry)
    graph.add_node(node_sec)
    graph.add_edge("Service.default.svc", "Secret.default.sec", "routes_to", "Exposed service")

    paths = discover_attack_paths(graph)
    assert len(paths) == 1
    assert paths[0].assessment_status == "Provisional"
    assert paths[0].confidence == "Medium"


# ---------------------------------------------------------------------------
# Test 11: Terraform Regression Preservation
# ---------------------------------------------------------------------------


def test_11_terraform_regression():
    """Verify standard Terraform analysis preserves threat findings while adding attack paths."""
    tf_content = b"""
resource "aws_security_group" "allow_ssh" {
  name = "allow_ssh"
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "bastion" {
  ami                    = "ami-12345"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.allow_ssh.id]
}

resource "aws_s3_bucket" "public_vault" {
  bucket = "company-public-vault"
  acl    = "public-read"
}
"""
    res = client.post(
        "/api/analyze",
        files={"file": ("main.tf", tf_content, "text/plain")},
    )
    assert res.status_code == 200
    data = res.json()

    assert "threat_findings" in data
    threat_ids = {f["threat_id"] for f in data["threat_findings"]}
    assert "THREAT-001" in threat_ids
    assert "THREAT-002" in threat_ids
    assert "attack_paths" in data
    assert isinstance(data["attack_paths"], list)
    assert len(data["attack_paths"]) >= 1


# ---------------------------------------------------------------------------
# Test 12: CloudFormation Regression Preservation
# ---------------------------------------------------------------------------


def test_12_cloudformation_regression():
    """Verify CloudFormation analysis returns threat findings and attack paths."""
    cfn_content = b"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  OpenSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Open SSH
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  WebVault:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
"""
    res = client.post(
        "/api/analyze",
        files={"file": ("template.yaml", cfn_content, "application/x-yaml")},
    )
    assert res.status_code == 200
    data = res.json()

    threat_ids = {f["threat_id"] for f in data["threat_findings"]}
    assert "CFN-001" in threat_ids
    assert "CFN-004" in threat_ids
    assert "attack_paths" in data
    # Direct exposure of public S3 bucket
    assert any(p["target_resource"] == "AWS::S3::Bucket.WebVault" for p in data["attack_paths"])


# ---------------------------------------------------------------------------
# Test 13: Kubernetes Regression Preservation
# ---------------------------------------------------------------------------


def test_13_kubernetes_regression():
    """Verify Kubernetes analysis returns threat findings and attack paths."""
    k8s_content = b"""
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-ingress
spec:
  rules:
  - http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-service
            port:
              number: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web-service
spec:
  selector:
    app: web
  ports:
  - port: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: web-pod
  labels:
    app: web
spec:
  containers:
  - name: web
    image: web:latest
  volumes:
  - name: token
    secret:
      secretName: app-secret
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
type: Opaque
"""
    res = client.post(
        "/api/analyze",
        files={"file": ("k8s.yaml", k8s_content, "application/x-yaml")},
    )
    assert res.status_code == 200
    data = res.json()

    assert "attack_paths" in data
    assert any(p["entry_point"] == "Ingress.default.web-ingress" for p in data["attack_paths"])


# ---------------------------------------------------------------------------
# Test 14: API Integration (POST /api/analyze & GET /api/analysis/{id}/attack-paths)
# ---------------------------------------------------------------------------


def test_14_api_analyze_and_get_attack_paths_endpoint():
    """Verify POST /api/analyze persists attack paths and GET /api/analysis/{id}/attack-paths retrieves them."""
    tf_content = b"""
resource "aws_security_group" "pub_sg" {
  name = "pub_sg"
  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "exposed_bucket" {
  bucket = "company-public-bucket"
  acl    = "public-read"
}
"""
    analyze_res = client.post(
        "/api/analyze",
        files={"file": ("main.tf", tf_content, "text/plain")},
    )
    assert analyze_res.status_code == 200
    analyze_data = analyze_res.json()
    analysis_id = analyze_data.get("id")
    assert analysis_id is not None
    assert "attack_paths" in analyze_data

    # Retrieve attack paths via dedicated endpoint
    get_res = client.get(f"/api/analysis/{analysis_id}/attack-paths")
    assert get_res.status_code == 200
    paths = get_res.json()
    assert isinstance(paths, list)
    assert len(paths) == len(analyze_data["attack_paths"])

    # Nonexistent analysis returns 404
    err_res = client.get("/api/analysis/nonexistent-id-99999/attack-paths")
    assert err_res.status_code == 404


# ===========================================================================
# STAGE 6 REVIEW FIXES: BATCH 1 REGRESSION TESTS
# ===========================================================================


# ---------------------------------------------------------------------------
# Batch 1 - Test 1: Substring Name Collision Prevention (Terraform)
# ---------------------------------------------------------------------------


def test_batch1_1_substring_name_collision_prevented():
    """Verify that substring prefix matching does not create false positive edges."""
    tf_content = """
resource "aws_security_group" "web" {
  name        = "web"
  description = "Public ingress"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "web_internal" {
  name        = "web_internal"
  description = "Internal ingress"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_instance" "app_server" {
  ami                    = "ami-123456"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_internal.id]
}

resource "aws_s3_bucket" "target_bucket" {
  bucket = "company-target-bucket"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="main.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-sg-web",
            "threat_id": "THREAT-001",
            "title": "Open SSH Ingress",
            "affected_resource_id": "aws_security_group.web",
            "severity": "Critical",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    # web must NOT expose app_server
    assert not any(
        "aws_instance.app_server" in p["resource_path"] and p["entry_point"] == "aws_security_group.web"
        for p in paths
    )


# ---------------------------------------------------------------------------
# Batch 1 - Test 2: Kubernetes Namespace Isolation
# ---------------------------------------------------------------------------


def test_batch1_2_kubernetes_namespace_isolation():
    """Verify that Kubernetes Role permissions remain strictly isolated within their namespace."""
    k8s_content = """
apiVersion: v1
kind: Service
metadata:
  name: dev-service
  namespace: dev
spec:
  type: LoadBalancer
  selector:
    app: dev-worker
  ports:
  - port: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: dev-pod
  namespace: dev
  labels:
    app: dev-worker
spec:
  serviceAccountName: dev-sa
  containers:
  - name: worker
    image: worker:1.0
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: dev-sa
  namespace: dev
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-rb
  namespace: dev
subjects:
- kind: ServiceAccount
  name: dev-sa
  namespace: dev
roleRef:
  kind: Role
  name: dev-secret-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dev-secret-reader
  namespace: dev
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
---
apiVersion: v1
kind: Secret
metadata:
  name: prod-secret
  namespace: prod
type: Opaque
data:
  token: "cHJvZC10b2tlbg=="
"""
    norm_infra = default_parser_registry.parse(k8s_content, filename="rbac_ns.yaml")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "k8s-lb",
            "threat_id": "K8S-007",
            "title": "Public LoadBalancer Service",
            "affected_resource_id": "Service.dev.dev-service",
            "severity": "Medium",
            "detection_status": "Needs Review",
            "confidence": "Medium",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="kubernetes",
        normalized_infrastructure=norm_infra,
    )

    # dev-service must NEVER have an attack path reaching prod-secret!
    assert not any(p["target_resource"] == "Secret.prod.prod-secret" for p in paths)


# ---------------------------------------------------------------------------
# Batch 1 - Test 3: Terraform THREAT-006 Wildcard Admin Detection
# ---------------------------------------------------------------------------


def test_batch1_3_terraform_threat_006_wildcard_detection():
    """Verify that THREAT-006 triggers wildcard administrative access in Terraform."""
    tf_content = """
resource "aws_security_group" "open_sg" {
  name = "open_sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "admin_role" {
  name = "admin_role"
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_instance_profile" "admin_profile" {
  name = "admin_profile"
  role = aws_iam_role.admin_role.name
}

resource "aws_instance" "bastion" {
  ami                  = "ami-12345"
  instance_type        = "t3.micro"
  vpc_security_group_ids = [aws_security_group.open_sg.id]
  iam_instance_profile = aws_iam_instance_profile.admin_profile.name
}

resource "aws_s3_bucket" "confidential_data" {
  bucket = "company-confidential-data"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="main.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-sg",
            "threat_id": "THREAT-001",
            "title": "Open SSH Ingress",
            "affected_resource_id": "aws_security_group.open_sg",
            "severity": "Critical",
            "detection_status": "Confirmed",
            "confidence": "High",
        },
        {
            "finding_id": "tf-iam",
            "threat_id": "THREAT-006",
            "title": "Overly Permissive IAM Policy",
            "affected_resource_id": "aws_iam_role.admin_role",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        },
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    assert len(paths) >= 1
    admin_path = next(
        (p for p in paths if p["target_resource"] == "aws_s3_bucket.confidential_data"), None
    )
    assert admin_path is not None
    assert "aws_iam_role.admin_role" in admin_path["resource_path"]


# ---------------------------------------------------------------------------
# Batch 1 - Test 4: CloudFormation CFN-003 Wildcard Admin Detection
# ---------------------------------------------------------------------------


def test_batch1_4_cloudformation_cfn_003_wildcard_detection():
    """Verify that CFN-003 triggers wildcard administrative access in CloudFormation."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Public SSH
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  WildcardRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
  AppInstance:
    Type: AWS::EC2::Instance
    Properties:
      SecurityGroupIds:
        - !Ref PublicSG
      IamInstanceProfile: !Ref WildcardRole
  SecretBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: internal-secret-bucket
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="template.yaml")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "cfn-sg",
            "threat_id": "CFN-004",
            "title": "Open Ingress",
            "affected_resource_id": "AWS::EC2::SecurityGroup.PublicSG",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        },
        {
            "finding_id": "cfn-iam",
            "threat_id": "CFN-003",
            "title": "Overly Permissive IAM Policy",
            "affected_resource_id": "AWS::IAM::Role.WildcardRole",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        },
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    assert len(paths) >= 1
    target_path = next(
        (p for p in paths if p["target_resource"] == "AWS::S3::Bucket.SecretBucket"), None
    )
    assert target_path is not None
    assert "AWS::IAM::Role.WildcardRole" in target_path["resource_path"]


# ---------------------------------------------------------------------------
# Batch 1 - Test 5: Terraform IAM Policy Attachment Resolution
# ---------------------------------------------------------------------------


def test_batch1_5_terraform_iam_policy_attachment_resolution():
    """Verify resolution of role -> aws_iam_role_policy_attachment -> aws_iam_policy -> target."""
    tf_content = """
resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app_role" {
  name = "app_role"
}

resource "aws_iam_policy" "s3_access_policy" {
  name   = "s3_access_policy"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = "${aws_s3_bucket.data_archive.arn}"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app_attachment" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_access_policy.arn
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app_profile"
  role = aws_iam_role.app_role.name
}

resource "aws_instance" "web_server" {
  ami                    = "ami-12345"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app_profile.name
}

resource "aws_s3_bucket" "data_archive" {
  bucket = "company-data-archive"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="main.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-1",
            "threat_id": "THREAT-001",
            "title": "Open Ingress",
            "affected_resource_id": "aws_security_group.web_sg",
            "severity": "Medium",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    assert len(paths) >= 1
    path = next(
        (p for p in paths if p["target_resource"] == "aws_s3_bucket.data_archive"), None
    )
    assert path is not None
    assert "aws_iam_role.app_role" in path["resource_path"]
    assert "aws_iam_role_policy_attachment.app_attachment" in path["resource_path"]
    assert "aws_iam_policy.s3_access_policy" in path["resource_path"]


# ---------------------------------------------------------------------------
# Batch 1 - Test 6: Detached IAM Policy Does Not Grant Access
# ---------------------------------------------------------------------------


def test_batch1_6_unattached_iam_policy_does_not_grant_access():
    """Verify that detached IAM policies do not create attack paths through unattached roles."""
    tf_content = """
resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "unprivileged_role" {
  name = "unprivileged_role"
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app_profile"
  role = aws_iam_role.unprivileged_role.name
}

resource "aws_instance" "web_server" {
  ami                    = "ami-12345"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app_profile.name
}

# Orphan policy with full S3 access, but NOT attached to unprivileged_role
resource "aws_iam_policy" "orphan_policy" {
  name   = "orphan_policy"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = "${aws_s3_bucket.vault.arn}"
    }]
  })
}

resource "aws_s3_bucket" "vault" {
  bucket = "company-secret-vault"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="main.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-1",
            "threat_id": "THREAT-001",
            "title": "Open Ingress",
            "affected_resource_id": "aws_security_group.web_sg",
            "severity": "Medium",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    # Since orphan_policy is not attached, web_server cannot reach vault
    assert not any(p["target_resource"] == "aws_s3_bucket.vault" for p in paths)


# ---------------------------------------------------------------------------
# Batch 1 - Test 7: Unresolved References Do Not Create Edges
# ---------------------------------------------------------------------------


def test_batch1_7_unresolved_references_do_not_create_edges():
    """Verify that unresolvable external references are recorded in node unresolved_references."""
    tf_content = """
resource "aws_instance" "web" {
  ami                    = "ami-12345"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.non_existent.id]
  iam_instance_profile   = aws_iam_instance_profile.missing_prof.name
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="main.tf")
    resources = norm_infra.to_legacy_resources()

    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=[],
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    inst_node = graph.nodes["aws_instance.web"]
    assert len(inst_node.unresolved_references) >= 2
    assert any("non_existent" in ref for ref in inst_node.unresolved_references)
    assert any("missing_prof" in ref for ref in inst_node.unresolved_references)
    # Ensure no outgoing or incoming edges exist on the instance
    assert len(graph.adjacency.get("aws_instance.web", [])) == 0



# ---------------------------------------------------------------------------
# Batch 2 - Test 1: Severity Not Inflated Without Findings
# ---------------------------------------------------------------------------


def test_batch2_1_severity_not_inflated_without_findings():
    """Verify that multi-hop paths without findings are not inflated to High or Medium severity."""
    graph = DirectedAttackGraph(source_format="terraform")

    # 3-hop path: entry -> workload -> sensitive target
    node_sg = GraphNode(
        id="aws_security_group.public_sg",
        name="public_sg",
        resource_type="aws_security_group",
        source_format="terraform",
        categories={"entry_point"},
    )
    node_ec2 = GraphNode(
        id="aws_instance.bastion",
        name="bastion",
        resource_type="aws_instance",
        source_format="terraform",
        categories={"workload"},
    )
    node_s3 = GraphNode(
        id="aws_s3_bucket.data_vault",
        name="data_vault",
        resource_type="aws_s3_bucket",
        source_format="terraform",
        categories={"sensitive"},
    )

    graph.add_node(node_sg)
    graph.add_node(node_ec2)
    graph.add_node(node_s3)

    graph.add_edge("aws_security_group.public_sg", "aws_instance.bastion", "attaches_security_group", "Applies SG")
    graph.add_edge("aws_instance.bastion", "aws_s3_bucket.data_vault", "accesses_storage", "Accesses S3")

    paths = discover_attack_paths(graph)
    assert len(paths) == 1
    p = paths[0]
    # Without findings, path severity must NOT be inflated to High or Medium based on length or sensitive target
    assert p.severity == "Low"
    assert p.assessment_status == "Provisional"
    assert p.confidence == "Low"
    assert p.description.startswith("[Provisional]")
    assert any("structural relationships" in lim for lim in p.limitations)


# ---------------------------------------------------------------------------
# Batch 2 - Test 2: Provisional Status for Needs Review and Mixed Evidence
# ---------------------------------------------------------------------------


def test_batch2_2_provisional_status_for_needs_review_and_mixed():
    """Verify that paths relying on Needs Review findings or mixed evidence remain Provisional."""
    graph = DirectedAttackGraph(source_format="kubernetes")

    node_ing = GraphNode(
        id="Ingress.prod.api_ing",
        name="api_ing",
        resource_type="Ingress",
        source_format="kubernetes",
        categories={"entry_point"},
        findings=[
            {
                "threat_id": "K8S-008",
                "severity": "Medium",
                "detection_status": "Confirmed",
            }
        ],
    )
    node_svc = GraphNode(
        id="Service.prod.api_svc",
        name="api_svc",
        resource_type="Service",
        source_format="kubernetes",
        categories={"network"},
        findings=[
            {
                "threat_id": "K8S-007",
                "severity": "High",
                "detection_status": "Needs Review",
            }
        ],
    )
    node_pod = GraphNode(
        id="Pod.prod.api_pod",
        name="api_pod",
        resource_type="Pod",
        source_format="kubernetes",
        categories={"sensitive"},
    )

    graph.add_node(node_ing)
    graph.add_node(node_svc)
    graph.add_node(node_pod)

    graph.add_edge("Ingress.prod.api_ing", "Service.prod.api_svc", "routes_to", "Routes to service")
    graph.add_edge("Service.prod.api_svc", "Pod.prod.api_pod", "selects_pod", "Selects backend pod")

    paths = discover_attack_paths(graph)
    assert len(paths) == 1
    p = paths[0]
    # Mixed confirmed and provisional findings must result in Provisional status
    assert p.assessment_status == "Provisional"
    assert p.confidence == "Medium"
    assert p.severity == "High"
    assert p.description.startswith("[Provisional]")
    assert any("mixed" in lim.lower() for lim in p.limitations)


# ---------------------------------------------------------------------------
# Batch 2 - Test 3: Kubernetes RBAC Verbs and ResourceNames Validation
# ---------------------------------------------------------------------------


def test_batch2_3_k8s_rbac_verbs_and_resourcenames_validation():
    """Verify that watch/list alone with resourceNames does not establish access to secrets."""
    k8s_content = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: worker-sa
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-watcher
  namespace: prod
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["api-key"]
    verbs: ["watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: worker-watcher-binding
  namespace: prod
subjects:
  - kind: ServiceAccount
    name: worker-sa
    namespace: prod
roleRef:
  kind: Role
  name: secret-watcher
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Secret
metadata:
  name: api-key
  namespace: prod
"""
    norm_infra = default_parser_registry.parse(k8s_content, filename="k8s_watch.yaml")
    resources = norm_infra.to_legacy_resources()

    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=[],
        source_format="kubernetes",
        normalized_infrastructure=norm_infra,
    )

    # In K8s RBAC, watch or list with resourceNames cannot perform collection GETs without field selectors
    # Static engine requires 'get' or '*' for named secret access.
    role_node = graph.nodes.get("Role.prod.secret-watcher")
    assert role_node is not None
    assert not any(edge.target == "Secret.prod.api-key" for edge in graph.adjacency.get("Role.prod.secret-watcher", []))


# ---------------------------------------------------------------------------
# Batch 2 - Test 4: IAM Deny Overrides Allow
# ---------------------------------------------------------------------------


def test_batch2_4_iam_deny_overrides_allow():
    """Verify AWS IAM explicit Deny statement strictly overrides Allow statement."""
    tf_content = """
resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app_role" {
  name = "app_role"
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app_profile"
  role = aws_iam_role.app_role.name
}

resource "aws_instance" "web_server" {
  ami                    = "ami-12345"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app_profile.name
}

resource "aws_iam_policy" "deny_override_policy" {
  name = "deny_override_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowRead"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::confidential-vault/*"
      },
      {
        Sid      = "ExplicitDenyRead"
        Effect   = "Deny"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::confidential-vault/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "deny_override_attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.deny_override_policy.arn
}

resource "aws_s3_bucket" "confidential_vault" {
  bucket = "confidential-vault"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="deny.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-1",
            "threat_id": "THREAT-001",
            "title": "Open Port",
            "affected_resource_id": "aws_security_group.web_sg",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    # Explicit Deny must override Allow; no attack path to confidential_vault should exist
    assert not any(p["target_resource"] == "aws_s3_bucket.confidential_vault" for p in paths)


# ---------------------------------------------------------------------------
# Batch 2 - Test 5: IAM Unrelated Actions Do Not Grant Access
# ---------------------------------------------------------------------------


def test_batch2_5_iam_unrelated_actions_do_not_grant_access():
    """Verify that metadata actions (e.g. s3:GetBucketLocation) do not grant data access."""
    tf_content = """
resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app_role" {
  name = "app_role"
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app_profile"
  role = aws_iam_role.app_role.name
}

resource "aws_instance" "web_server" {
  ami                    = "ami-12345"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app_profile.name
}

resource "aws_iam_policy" "metadata_only_policy" {
  name = "metadata_only_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetBucketLocation", "s3:GetBucketTagging"]
        Resource = "arn:aws:s3:::metadata-bucket"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "meta_attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.metadata_only_policy.arn
}

resource "aws_s3_bucket" "metadata_bucket" {
  bucket = "metadata-bucket"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="meta.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-1",
            "threat_id": "THREAT-001",
            "title": "Open Port",
            "affected_resource_id": "aws_security_group.web_sg",
            "severity": "Medium",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    # Bucket metadata actions do not provide S3 object access
    assert not any(p["target_resource"] == "aws_s3_bucket.metadata_bucket" for p in paths)


# ---------------------------------------------------------------------------
# Batch 2 - Test 6: Kubernetes ResourceNames get vs list/watch
# ---------------------------------------------------------------------------


def test_batch2_6_k8s_resourcenames_get_vs_list_watch():
    """Verify that get with resourceNames grants access only to the named secret."""
    k8s_content = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: worker-sa
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: specific-secret-reader
  namespace: prod
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["allowed-secret"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: reader-binding
  namespace: prod
subjects:
  - kind: ServiceAccount
    name: worker-sa
    namespace: prod
roleRef:
  kind: Role
  name: specific-secret-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Secret
metadata:
  name: allowed-secret
  namespace: prod
---
apiVersion: v1
kind: Secret
metadata:
  name: restricted-secret
  namespace: prod
"""
    norm_infra = default_parser_registry.parse(k8s_content, filename="k8s_resourcenames.yaml")
    resources = norm_infra.to_legacy_resources()

    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=[],
        source_format="kubernetes",
        normalized_infrastructure=norm_infra,
    )

    role_edges = graph.adjacency.get("Role.prod.specific-secret-reader", [])
    assert any(edge.target == "Secret.prod.allowed-secret" for edge in role_edges)
    assert not any(edge.target == "Secret.prod.restricted-secret" for edge in role_edges)


# ---------------------------------------------------------------------------
# Batch 2 - Test 7: IAM Dynamic Conditions Result in Provisional Paths
# ---------------------------------------------------------------------------


def test_batch2_7_iam_deny_with_supported_and_unsupported_conditions():
    """Verify that unresolvable dynamic IAM conditions produce Provisional paths."""
    tf_content = """
resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app_role" {
  name = "app_role"
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app_profile"
  role = aws_iam_role.app_role.name
}

resource "aws_instance" "web_server" {
  ami                    = "ami-12345"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app_profile.name
}

resource "aws_iam_policy" "conditional_policy" {
  name = "conditional_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::conditional-vault/*"
      },
      {
        Effect   = "Deny"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::conditional-vault/*"
        Condition = {
          "NotIpAddress" = {
            "aws:SourceIp" = "203.0.113.0/24"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cond_attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.conditional_policy.arn
}

resource "aws_s3_bucket" "conditional_vault" {
  bucket = "conditional-vault"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="cond.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-1",
            "threat_id": "THREAT-001",
            "title": "Open Port",
            "affected_resource_id": "aws_security_group.web_sg",
            "severity": "Medium",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    assert len(paths) >= 1
    p = next((p for p in paths if p["target_resource"] == "aws_s3_bucket.conditional_vault"), None)
    assert p is not None
    # Dynamic conditions cannot be evaluated statically, making the path provisional
    assert p["assessment_status"] == "Provisional"
    assert p["confidence"] in ("Low", "Medium")
    assert any("conditional" in lim.lower() for lim in p["limitations"])


# ---------------------------------------------------------------------------
# Batch 2 - Test 8: S3 Bucket ARN vs Object ARN Semantics
# ---------------------------------------------------------------------------


def test_batch2_8_s3_bucket_arn_vs_object_arn():
    """Verify s3:GetObject on Bucket ARN does not match, but Object ARN matches."""
    tf_content = """
resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app_role" {
  name = "app_role"
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app_profile"
  role = aws_iam_role.app_role.name
}

resource "aws_instance" "web_server" {
  ami                    = "ami-12345"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app_profile.name
}

# Policy A: Invalid GetObject on Bucket ARN (arn:aws:s3:::invalid-bucket)
resource "aws_iam_policy" "invalid_arn_policy" {
  name = "invalid_arn_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::invalid-bucket"
      }
    ]
  })
}

# Policy B: Valid GetObject on Object ARN (arn:aws:s3:::valid-bucket/*)
resource "aws_iam_policy" "valid_arn_policy" {
  name = "valid_arn_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::valid-bucket/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_invalid" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.invalid_arn_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_valid" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.valid_arn_policy.arn
}

resource "aws_s3_bucket" "invalid_bucket" {
  bucket = "invalid-bucket"
}

resource "aws_s3_bucket" "valid_bucket" {
  bucket = "valid-bucket"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="arns.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-1",
            "threat_id": "THREAT-001",
            "title": "Open Port",
            "affected_resource_id": "aws_security_group.web_sg",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    # invalid_bucket must NOT be reached because s3:GetObject cannot target bucket ARN
    assert not any(p["target_resource"] == "aws_s3_bucket.invalid_bucket" for p in paths)
    # valid_bucket must be reached because s3:GetObject targets object ARN
    assert any(p["target_resource"] == "aws_s3_bucket.valid_bucket" for p in paths)


# ---------------------------------------------------------------------------
# Batch 2 - Test 9: EC2 Describe Actions Do Not Grant EBS Data Access
# ---------------------------------------------------------------------------


def test_batch2_9_ec2_describe_actions_vs_ebs_data_access():
    """Verify that ec2:Describe* and AttachVolume do not create data access edges to EBS."""
    tf_content = """
resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app_role" {
  name = "app_role"
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app_profile"
  role = aws_iam_role.app_role.name
}

resource "aws_instance" "web_server" {
  ami                    = "ami-12345"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app_profile.name
}

resource "aws_iam_policy" "ebs_describe_policy" {
  name = "ebs_describe_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:AttachVolume"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_ebs_desc" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.ebs_describe_policy.arn
}

resource "aws_ebs_volume" "database_disk" {
  availability_zone = "us-east-1a"
  size              = 100
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="ebs.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-1",
            "threat_id": "THREAT-001",
            "title": "Open Port",
            "affected_resource_id": "aws_security_group.web_sg",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    # Describe / attach volume alone do not establish confirmed data exfiltration
    assert not any(p["target_resource"] == "aws_ebs_volume.database_disk" for p in paths)


# ---------------------------------------------------------------------------
# Batch 2 - Test 10: Unrelated Deny Does Not Block Different Bucket
# ---------------------------------------------------------------------------


def test_batch2_10_unrelated_deny_does_not_block_different_bucket():
    """Verify that an explicit Deny on one bucket does not block access to another bucket."""
    tf_content = """
resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app_role" {
  name = "app_role"
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app_profile"
  role = aws_iam_role.app_role.name
}

resource "aws_instance" "web_server" {
  ami                    = "ami-12345"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app_profile.name
}

resource "aws_iam_policy" "mixed_bucket_policy" {
  name = "mixed_bucket_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowBoth"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = [
          "arn:aws:s3:::allowed-vault/*",
          "arn:aws:s3:::denied-vault/*"
        ]
      },
      {
        Sid      = "DenyOnlyOne"
        Effect   = "Deny"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::denied-vault/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_mixed" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.mixed_bucket_policy.arn
}

resource "aws_s3_bucket" "allowed_vault" {
  bucket = "allowed-vault"
}

resource "aws_s3_bucket" "denied_vault" {
  bucket = "denied-vault"
}
"""
    norm_infra = default_parser_registry.parse(tf_content, filename="mixed.tf")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "tf-1",
            "threat_id": "THREAT-001",
            "title": "Open Port",
            "affected_resource_id": "aws_security_group.web_sg",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="terraform",
        normalized_infrastructure=norm_infra,
    )

    # denied_vault must be blocked by explicit Deny
    assert not any(p["target_resource"] == "aws_s3_bucket.denied_vault" for p in paths)
    # allowed_vault must NOT be blocked by the unrelated Deny
    assert any(p["target_resource"] == "aws_s3_bucket.allowed_vault" for p in paths)



# ---------------------------------------------------------------------------
# Batch 3 - Test 1: CloudFormation ELBv2 Default Scheme Is Internet-Facing
# ---------------------------------------------------------------------------


def test_batch3_1_cfn_elbv2_default_scheme_is_internet_facing():
    """Verify that ALB with omitted Scheme defaults to internet-facing and is an entry point."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicALB:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: public-alb
  AppServer:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-12345
  DataVault:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: public-alb-vault
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="alb_default.yaml")
    resources = norm_infra.to_legacy_resources()

    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=[],
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    alb_node = graph.nodes.get("AWS::ElasticLoadBalancingV2::LoadBalancer.PublicALB")
    assert alb_node is not None
    # AWS CloudFormation defaults omitted Scheme to internet-facing
    assert alb_node.is_entry_point


# ---------------------------------------------------------------------------
# Batch 3 - Test 2: CloudFormation ELBv2 Explicit Internal Is Not Entry Point
# ---------------------------------------------------------------------------


def test_batch3_2_cfn_elbv2_explicit_internal_not_entry_point():
    """Verify that ALB with explicit Scheme: internal is NOT classified as entry point."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  InternalALB:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Scheme: internal
  AppServer:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-12345
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="alb_internal.yaml")
    resources = norm_infra.to_legacy_resources()

    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=[],
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    alb_node = graph.nodes.get("AWS::ElasticLoadBalancingV2::LoadBalancer.InternalALB")
    assert alb_node is not None
    assert not alb_node.is_entry_point


# ---------------------------------------------------------------------------
# Batch 3 - Test 3: CloudFormation ELBv2 Explicit Internet-Facing
# ---------------------------------------------------------------------------


def test_batch3_3_cfn_elbv2_explicit_internet_facing():
    """Verify that NLB with explicit Scheme: internet-facing is classified as entry point."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicNLB:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: network
      Scheme: internet-facing
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="nlb_public.yaml")
    resources = norm_infra.to_legacy_resources()

    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=[],
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    nlb_node = graph.nodes.get("AWS::ElasticLoadBalancingV2::LoadBalancer.PublicNLB")
    assert nlb_node is not None
    assert nlb_node.is_entry_point


# ---------------------------------------------------------------------------
# Batch 3 - Test 4: CloudFormation Gateway Load Balancer Never Entry Point
# ---------------------------------------------------------------------------


def test_batch3_4_cfn_gateway_load_balancer_never_entry_point():
    """Verify that Gateway Load Balancers (Type: gateway) are never classified as entry points."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  InVpcGatewayLB:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: gateway
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="gwlb.yaml")
    resources = norm_infra.to_legacy_resources()

    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=[],
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    gwlb_node = graph.nodes.get("AWS::ElasticLoadBalancingV2::LoadBalancer.InVpcGatewayLB")
    assert gwlb_node is not None
    assert not gwlb_node.is_entry_point


# ---------------------------------------------------------------------------
# Batch 3 - Test 5: CloudFormation Inline Policy Allow, Deny, and Precedence Matrix
# ---------------------------------------------------------------------------


def test_batch3_5_cfn_inline_policy_allow_deny_and_unresolved_matrix():
    """Verify Deny overrides Allow and string-leaf fallback is removed in CFN inline policies."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Open SSH
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  AppServer:
    Type: AWS::EC2::Instance
    Properties:
      SecurityGroupIds:
        - !Ref PublicSG
      IamInstanceProfile: !Ref AppProfile
  AppProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref AppRole
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: AppRole
      Policies:
        - PolicyName: S3InlinePolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Sid: AllowTargetA
                Effect: Allow
                Action:
                  - s3:GetObject
                Resource:
                  - arn:aws:s3:::allowed-vault/*
                  - arn:aws:s3:::denied-vault/*
              - Sid: ExplicitDenyTargetB
                Effect: Deny
                Action:
                  - s3:GetObject
                Resource: arn:aws:s3:::denied-vault/*
              - Sid: UnmodeledExternalLake
                Effect: Allow
                Action:
                  - s3:GetObject
                Resource: arn:aws:s3:::external-unmodeled-lake/*
  AllowedVault:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: allowed-vault
  DeniedVault:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: denied-vault
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="cfn_inline.yaml")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "cfn-1",
            "threat_id": "CFN-004",
            "title": "Open SSH",
            "affected_resource_id": "AWS::EC2::SecurityGroup.PublicSG",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    # 1. AllowedVault must be reached
    assert any(p["target_resource"] == "AWS::S3::Bucket.AllowedVault" for p in paths)
    # 2. DeniedVault must NOT be reached (explicit Deny overrides Allow; string-leaf fallback eliminated)
    assert not any(p["target_resource"] == "AWS::S3::Bucket.DeniedVault" for p in paths)
    # 3. No phantom attack paths created to unmodeled external lake
    assert not any("external-unmodeled-lake" in p["target_resource"] for p in paths)


# ---------------------------------------------------------------------------
# Batch 3 - Test 6: Standalone AWS::IAM::Policy Chain Resolution
# ---------------------------------------------------------------------------


def test_batch3_6_cfn_standalone_iam_policy_chain_resolution():
    """Verify EC2 Instance -> IAM Role -> standalone AWS::IAM::Policy -> S3 Bucket chain."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Public Ingress
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
  WebServer:
    Type: AWS::EC2::Instance
    Properties:
      SecurityGroupIds:
        - !Ref PublicSG
      IamInstanceProfile: !Ref WebProfile
  WebProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref WebRole
  WebRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: WebRole
  StandaloneS3Policy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: StandaloneS3Policy
      Roles:
        - !Ref WebRole
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - s3:GetObject
            Resource: arn:aws:s3:::secure-data-vault/*
  SecureDataVault:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: secure-data-vault
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="standalone_policy.yaml")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "cfn-1",
            "threat_id": "CFN-004",
            "title": "Open Port",
            "affected_resource_id": "AWS::EC2::SecurityGroup.PublicSG",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    assert len(paths) >= 1
    target_path = next(
        (p for p in paths if p["target_resource"] == "AWS::S3::Bucket.SecureDataVault"), None
    )
    assert target_path is not None
    # Verify complete 4-hop chain
    assert "AWS::EC2::SecurityGroup.PublicSG" in target_path["resource_path"]
    assert "AWS::EC2::Instance.WebServer" in target_path["resource_path"]
    assert "AWS::IAM::Role.WebRole" in target_path["resource_path"]
    assert "AWS::IAM::Policy.StandaloneS3Policy" in target_path["resource_path"]
    assert "AWS::S3::Bucket.SecureDataVault" in target_path["resource_path"]


# ---------------------------------------------------------------------------
# Batch 3 - Test 7: Unbound Standalone AWS::IAM::Policy Does Not Grant Access
# ---------------------------------------------------------------------------


def test_batch3_7_cfn_unbound_iam_policy_does_not_grant_access():
    """Verify that standalone IAM policy attached to another role does not grant access."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
  WebServer:
    Type: AWS::EC2::Instance
    Properties:
      SecurityGroupIds:
        - !Ref PublicSG
      IamInstanceProfile: !Ref WebProfile
  WebProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref WebRole
  WebRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: WebRole
  OtherRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: OtherRole
  # Policy binds strictly to OtherRole, NOT WebRole
  OtherPolicy:
    Type: AWS::IAM::Policy
    Properties:
      Roles:
        - !Ref OtherRole
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource: arn:aws:s3:::vault/*
  Vault:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: vault
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="unbound_policy.yaml")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "cfn-1",
            "threat_id": "CFN-004",
            "title": "Open Port",
            "affected_resource_id": "AWS::EC2::SecurityGroup.PublicSG",
            "severity": "Medium",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    # WebServer cannot reach Vault because OtherPolicy is not attached to WebRole
    assert not any(p["target_resource"] == "AWS::S3::Bucket.Vault" for p in paths)


# ---------------------------------------------------------------------------
# Batch 3 - Test 8: IAM Policy With External ARN Does Not Invent Phantom Nodes
# ---------------------------------------------------------------------------


def test_batch3_8_cfn_iam_policy_external_arn_no_phantom_paths():
    """Verify that policy referencing external unmodeled ARN does not create phantom attack paths."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
  WebServer:
    Type: AWS::EC2::Instance
    Properties:
      SecurityGroupIds:
        - !Ref PublicSG
      IamInstanceProfile: !Ref WebProfile
  WebProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref WebRole
  WebRole:
    Type: AWS::IAM::Role
  ExternalLakePolicy:
    Type: AWS::IAM::Policy
    Properties:
      Roles:
        - !Ref WebRole
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource: arn:aws:s3:::external-unmodeled-corp-data/*
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="external_policy.yaml")
    resources = norm_infra.to_legacy_resources()

    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=[],
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    # 1. No phantom bucket nodes created in the graph
    assert not any("external-unmodeled-corp-data" in node_id for node_id in graph.nodes)
    # 2. Zero discovered attack paths because there are no sensitive targets in the template
    paths = discover_attack_paths(graph)
    assert len(paths) == 0


# ---------------------------------------------------------------------------
# Batch 3 - Test 9: VolumeAttachment Uncertainty Isolation (Two Conditions)
# ---------------------------------------------------------------------------


def test_batch3_9_cfn_volume_attachment_uncertainty_isolation():
    """Verify that storage attachment uncertainty does NOT pollute unrelated IAM-to-S3 paths."""
    cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
  WebServer:
    Type: AWS::EC2::Instance
    Properties:
      SecurityGroupIds:
        - !Ref PublicSG
      IamInstanceProfile: !Ref WebProfile
  WebProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref WebRole
  WebRole:
    Type: AWS::IAM::Role
  DataPolicy:
    Type: AWS::IAM::Policy
    Properties:
      Roles:
        - !Ref WebRole
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource: arn:aws:s3:::production-vault/*
  ProductionVault:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: production-vault
  # Unresolved VolumeAttachment referencing unmodeled external volume
  UnresolvedDiskAttachment:
    Type: AWS::EC2::VolumeAttachment
    Properties:
      InstanceId: !Ref WebServer
      VolumeId: vol-unmodeled-external-999
"""
    norm_infra = default_parser_registry.parse(cfn_content, filename="vol_isolation.yaml")
    resources = norm_infra.to_legacy_resources()

    threat_findings = [
        {
            "finding_id": "cfn-1",
            "threat_id": "CFN-004",
            "title": "Open Port",
            "affected_resource_id": "AWS::EC2::SecurityGroup.PublicSG",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
        }
    ]

    paths = analyze_attack_paths(
        resources=resources,
        threat_findings=threat_findings,
        source_format="cloudformation",
        normalized_infrastructure=norm_infra,
    )

    # Condition 1: No phantom storage path is claimed to the unmodeled volume
    assert not any("vol-unmodeled-external-999" in p["target_resource"] for p in paths)

    # Condition 2: Unrelated IAM-to-S3 path remains Confirmed with High confidence
    s3_path = next(
        (p for p in paths if p["target_resource"] == "AWS::S3::Bucket.ProductionVault"), None
    )
    assert s3_path is not None
    assert s3_path["assessment_status"] == "Confirmed"
    assert s3_path["confidence"] == "High"
    assert not s3_path["description"].startswith("[Provisional]")
    # The unrelated S3 path must NOT have volume attachment limitations
    assert not any("VolumeAttachment" in lim for lim in s3_path["limitations"])
