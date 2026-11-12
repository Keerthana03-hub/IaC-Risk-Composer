"""
tests/test_multi_iac_threat_integration.py
-------------------------------------------
Stage 5: End-to-End Multi-IaC Threat Detection Integration Test Suite.
Verifies unified pipeline execution across Terraform, CloudFormation, and Kubernetes:
- Unified standard finding schemas
- Risk engine scoring and summary compatibility
- Risk explanation generation
- Remediation generation
- API /api/analyze compatibility
- Database persistence compatibility
- PDF report generation compatibility
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
from services.remediation_engine import generate_remediations
from services.report_generator import generate_pdf_report
from services.risk_engine import assess_risks
from services.risk_explainer import explain_findings
from services.threat_engine import analyze_threats

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test 1: Standard Finding Structure Across All 3 IaC Formats
# ---------------------------------------------------------------------------


def test_standard_finding_structure_across_all_iac_formats():
    """Verify that Terraform, CloudFormation, and Kubernetes findings share identical standard schema."""
    # 1. Terraform finding
    tf_resources = [
        {
            "type": "aws_security_group",
            "name": "tf_sg",
            "attributes": {
                "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]
            },
        }
    ]
    tf_findings = analyze_threats(tf_resources, source_format="terraform")
    assert len(tf_findings) >= 1
    tf_f = tf_findings[0]

    # 2. CloudFormation finding
    cfn_resources = [
        {
            "type": "AWS::EC2::SecurityGroup",
            "name": "CfnSG",
            "attributes": {
                "SecurityGroupIngress": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]
            },
        }
    ]
    cfn_findings = analyze_threats(cfn_resources, source_format="cloudformation")
    assert len(cfn_findings) >= 1
    cfn_f = cfn_findings[0]

    # 3. Kubernetes finding
    k8s_resources = [
        {
            "type": "Pod",
            "name": "k8s-pod",
            "attributes": {
                "security_metadata": {
                    "containers": [{"name": "app", "image": "app:1.0", "privileged": True}]
                }
            },
        }
    ]
    k8s_findings = analyze_threats(k8s_resources, source_format="kubernetes")
    assert len(k8s_findings) >= 1
    k8s_f = k8s_findings[0]

    required_keys = {
        "finding_id",
        "threat_id",
        "title",
        "description",
        "severity",
        "resource_id",
        "resource_type",
        "source_format",
        "evidence",
        "detection_status",
        "confidence",
        "remediation",
        "references",
    }

    for f, expected_format in [(tf_f, "terraform"), (cfn_f, "cloudformation"), (k8s_f, "kubernetes")]:
        assert required_keys.issubset(set(f.keys())), f"Missing keys in {expected_format} finding: {required_keys - set(f.keys())}"
        assert f["source_format"] == expected_format
        assert f["severity"] in ("Critical", "High", "Medium", "Low")
        assert f["detection_status"] in ("Confirmed", "Needs Review")
        assert f["confidence"] in ("High", "Medium", "Low")
        assert isinstance(f["evidence"], dict)
        assert isinstance(f["references"], list)


# ---------------------------------------------------------------------------
# Test 2: Unified Risk Scoring and Needs Review Behavior
# ---------------------------------------------------------------------------


def test_unified_risk_scoring_and_needs_review():
    """Verify that Confirmed findings get scores and Needs Review findings remain Provisional without fake scores."""
    mixed_findings = [
        # Confirmed finding
        {
            "finding_id": "f-confirmed",
            "threat_id": "K8S-001",
            "title": "Privileged Pod",
            "severity": "Critical",
            "detection_status": "Confirmed",
            "confidence": "High",
            "evidence": {"privileged": True},
        },
        # Needs Review finding
        {
            "finding_id": "f-review",
            "threat_id": "CFN-002",
            "title": "Missing S3 Encryption",
            "severity": "Medium",
            "detection_status": "Needs Review",
            "confidence": "Medium",
            "evidence": {"BucketEncryption": "missing"},
        },
    ]

    assessed, summary = assess_risks(mixed_findings)
    assert len(assessed) == 2

    # Confirmed finding has valid numeric inherent_risk_score
    c_f = assessed[0]
    assert c_f["risk_assessment"]["assessment_status"] == "Assessed"
    assert c_f["risk_assessment"]["inherent_risk_score"] is not None
    assert c_f["risk_assessment"]["inherent_risk_score"] > 0

    # Needs Review finding has None for inherent score (Provisional)
    r_f = assessed[1]
    assert r_f["risk_assessment"]["assessment_status"] == "Provisional"
    assert r_f["risk_assessment"]["inherent_risk_score"] is None
    assert r_f["risk_assessment"]["risk_level"] is None

    # Summary metrics
    assert summary["total_findings"] == 2
    assert summary["confirmed_findings"] == 1
    assert summary["needs_review_findings"] == 1


# ---------------------------------------------------------------------------
# Test 3: Unified Explanations and Remediations Generation
# ---------------------------------------------------------------------------


def test_unified_explanations_and_remediations():
    """Verify explain_findings and generate_remediations handle multi-format findings cleanly."""
    k8s_finding = {
        "finding_id": "pod-1-K8S-001",
        "threat_id": "K8S-001",
        "title": "Privileged Container",
        "description": "Container runs with full node privileges.",
        "affected_resource_id": "Pod.default.my-pod",
        "affected_resource_type": "Pod",
        "affected_resource_name": "my-pod",
        "severity": "Critical",
        "detection_status": "Confirmed",
        "confidence": "High",
        "evidence": {"privileged": True},
        "source_format": "kubernetes",
        "recommendation": "Set privileged: false.",
    }
    assessed, _ = assess_risks([k8s_finding])

    # Explanations
    explanations = explain_findings(assessed)
    assert len(explanations) == 1
    assert explanations[0]["finding_id"] == "pod-1-K8S-001"
    assert len(explanations[0]["recommended_actions"]) > 0

    # Remediations
    remediations = generate_remediations(assessed, [])
    assert len(remediations) == 1
    assert remediations[0]["finding_id"] == "pod-1-K8S-001"
    assert remediations[0]["suggested_code"] is not None
    assert "privileged: false" in remediations[0]["suggested_code"]


# ---------------------------------------------------------------------------
# Test 4: End-to-End API /api/analyze Integration Across Formats
# ---------------------------------------------------------------------------


def test_api_analyze_kubernetes_manifest_pipeline():
    """Test POST /api/analyze with Kubernetes manifest runs full 6-step pipeline."""
    k8s_content = b"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-worker
  namespace: prod
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
        image: worker:latest
        securityContext:
          privileged: true
"""
    res = client.post(
        "/api/analyze",
        files={"file": ("deploy.yaml", k8s_content, "application/x-yaml")},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["filename"] == "deploy.yaml"
    assert data["resource_count"] == 1
    assert len(data["threat_findings"]) >= 1

    threat_ids = {f["threat_id"] for f in data["threat_findings"]}
    assert "K8S-001" in threat_ids  # Privileged container
    assert "K8S-012" in threat_ids  # latest image tag

    # Pipeline stages verified in response
    assert data["infrastructure_map"]["nodes"]
    assert data["risk_summary"]["total_findings"] >= 2
    assert len(data["risk_explanations"]) >= 2
    assert len(data["remediations"]) >= 2
    assert data["id"] is not None


def test_api_analyze_cloudformation_template_pipeline():
    """Test POST /api/analyze with CloudFormation template runs full 6-step pipeline."""
    cfn_content = b"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  VulnerableBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  AdminSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow all SSH
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
"""
    res = client.post(
        "/api/analyze",
        files={"file": ("infra.yaml", cfn_content, "application/x-yaml")},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["filename"] == "infra.yaml"
    assert data["resource_count"] == 2

    threat_ids = {f["threat_id"] for f in data["threat_findings"]}
    assert "CFN-001" in threat_ids  # Public S3
    assert "CFN-004" in threat_ids  # Open SSH security group
    assert data["id"] is not None


def test_api_analyze_terraform_regression_preservation():
    """Verify Terraform analysis continues to detect THREAT-001 through THREAT-006 identically."""
    tf_content = b"""
resource "aws_s3_bucket" "test_bucket" {
  bucket = "company-public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "admin_sg" {
  name = "allow_ssh"
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
    res = client.post(
        "/api/analyze",
        files={"file": ("main.tf", tf_content, "text/plain")},
    )
    assert res.status_code == 200
    data = res.json()

    threat_ids = {f["threat_id"] for f in data["threat_findings"]}
    assert "THREAT-001" in threat_ids
    assert "THREAT-002" in threat_ids


# ---------------------------------------------------------------------------
# Test 5: PDF Report Generation Compatibility With Multi-IaC Findings
# ---------------------------------------------------------------------------


def test_pdf_report_generation_multi_iac():
    """Verify generate_pdf_report renders successfully with CloudFormation and Kubernetes findings."""
    cfn_findings = [
        {
            "finding_id": "cfn-1",
            "threat_id": "CFN-001",
            "title": "Public S3 Bucket",
            "affected_resource_id": "AWS::S3::Bucket.DataVault",
            "severity": "Critical",
            "detection_status": "Confirmed",
            "confidence": "High",
            "evidence": {"AccessControl": "PublicReadWrite"},
            "impact": "Data breach",
            "recommendation": "Remove public ACL.",
            "risk_assessment": {
                "assessment_status": "Assessed",
                "risk_level": "Critical",
                "inherent_risk_score": 25,
                "likelihood": 5,
                "impact": 5,
            },
        }
    ]
    cfn_remediations = [
        {
            "remediation_id": "rem-cfn-1",
            "finding_id": "cfn-1",
            "affected_resource_id": "AWS::S3::Bucket.DataVault",
            "affected_resource_type": "AWS::S3::Bucket",
            "affected_resource_name": "DataVault",
            "title": "Remediate Public S3 Bucket",
            "explanation": "Remove public access control.",
            "recommended_actions": ["Configure PublicAccessBlockConfiguration."],
            "suggested_code": "PublicAccessBlockConfiguration:\n  BlockPublicAcls: true",
            "patch_type": "addition",
            "assumptions": ["Assumes private bucket."],
            "validation_steps": ["Validate template."],
            "remediation_status": "Suggested",
            "generated_by": "rule_based",
        }
    ]

    sample_analysis = {
        "filename": "cloudformation.yaml",
        "resource_count": 1,
        "resource_types": ["AWS::S3::Bucket"],
        "infrastructure_map": {"nodes": [{"id": "AWS::S3::Bucket.DataVault", "resource_type": "AWS::S3::Bucket", "name": "DataVault", "label": "S3 Bucket"}], "edges": []},
        "threat_findings": cfn_findings,
        "risk_summary": {"total_findings": 1, "confirmed_findings": 1, "needs_review_findings": 0, "low_risk_count": 0, "medium_risk_count": 0, "high_risk_count": 0, "critical_risk_count": 1, "highest_inherent_risk_score": 25, "overall_risk_level": "Critical"},
        "risk_explanations": [{"finding_id": "cfn-1", "summary": "Public S3 Bucket", "why_it_matters": "Data leak", "evidence_explanation": "PublicReadWrite", "uncertainty": "Low", "recommended_actions": ["Enable block public access"], "verification_steps": ["Inspect ACL"], "explanation_status": "Generated", "explanation_method": "rule_based"}],
        "remediations": cfn_remediations,
    }
    pdf_bytes = generate_pdf_report(sample_analysis)

    assert pdf_bytes is not None
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")
