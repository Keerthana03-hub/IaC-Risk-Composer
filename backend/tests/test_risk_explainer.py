"""
tests/test_risk_explainer.py
-----------------------------
Automated test suite for AI-Powered Risk Explanation Engine (Step 5).

Run with:
    .venv\\Scripts\\python.exe -m pytest tests/test_risk_explainer.py -v

Verifies:
    1. Confirmed finding with sufficient evidence produces an explanation tied to actual fields.
    2. Needs Review / Provisional finding remains explicitly uncertain and not described as confirmed.
    3. Missing evidence and optional fields do not crash the service.
    4. Empty threat_findings returns an empty explanation list.
    5. Each explanation has the correct finding_id.
    6. POST /api/analyze returns all previous fields plus risk_explanations.
    7. Modular provider interface (BaseExplanationProvider).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from services.risk_explainer import (  # noqa: E402
    BaseExplanationProvider,
    RuleBasedExplanationProvider,
    explain_finding,
    explain_findings,
    get_explanation_provider,
)

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test 1: Confirmed Finding Produces Grounded Explanation Tied to Fields
# ---------------------------------------------------------------------------


def test_1_confirmed_finding_explanation():
    """A confirmed finding with sufficient evidence produces an explanation tied to its actual fields."""
    finding = {
        "finding_id": "aws_security_group.web_sg-THREAT-002-ssh-0",
        "threat_id": "THREAT-002",
        "title": "Unrestricted SSH Access on Port 22 (web_sg)",
        "description": "Detects security group ingress rules that permit inbound SSH access from unrestricted CIDR 0.0.0.0/0.",
        "affected_resource_id": "aws_security_group.web_sg",
        "affected_resource_type": "aws_security_group",
        "affected_resource_name": "web_sg",
        "severity": "High",
        "detection_status": "Confirmed",
        "confidence": "High",
        "evidence": {
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "unrestricted_cidrs": ["0.0.0.0/0"],
        },
        "impact": "Attackers may attempt remote access to exposed systems via brute-force password attacks.",
        "recommendation": "Restrict SSH access to trusted IP ranges or use AWS Systems Manager Session Manager.",
        "risk_assessment": {
            "likelihood": 4,
            "impact": 4,
            "inherent_risk_score": 16,
            "risk_level": "High",
            "confidence_factor": 1.0,
            "confidence_adjusted_score": 16.0,
            "assessment_status": "Assessed",
            "scoring_explanation": "Likelihood 4 x Impact 4 = 16 (High).",
            "scoring_method": "Likelihood × Impact",
        },
    }

    explanation = explain_finding(finding)

    # 1. Correct finding_id
    assert explanation["finding_id"] == "aws_security_group.web_sg-THREAT-002-ssh-0"

    # 2. Status & method
    assert explanation["explanation_status"] == "Generated"
    assert explanation["explanation_method"] == "rule_based"

    # 3. Grounded summary
    assert "Confirmed" in explanation["summary"]
    assert "aws_security_group.web_sg" in explanation["summary"]

    # 4. Why it matters mentions impact and risk level
    assert "High" in explanation["why_it_matters"]
    assert "Attackers" in explanation["why_it_matters"]

    # 5. Evidence explanation explains actual CIDR and port
    assert "0.0.0.0/0" in explanation["evidence_explanation"]
    assert "22" in explanation["evidence_explanation"]
    assert "tcp" in explanation["evidence_explanation"]

    # 6. Uncertainty notes low uncertainty for confirmed finding
    assert "Low uncertainty" in explanation["uncertainty"]

    # 7. Recommended actions and verification steps present
    assert len(explanation["recommended_actions"]) >= 1
    assert any("SSH" in action or "cidr_blocks" in action for action in explanation["recommended_actions"])
    assert len(explanation["verification_steps"]) >= 1
    assert any("ec2 describe-security-groups" in step for step in explanation["verification_steps"])


# ---------------------------------------------------------------------------
# Test 2: Needs Review / Provisional Finding Remains Explicitly Uncertain
# ---------------------------------------------------------------------------


def test_2_needs_review_provisional_finding_explanation():
    """A Needs Review / Provisional finding remains explicitly uncertain and is not described as confirmed."""
    finding = {
        "finding_id": "aws_s3_bucket.data_bucket-THREAT-005-encryption",
        "threat_id": "THREAT-005",
        "title": "S3 Bucket Server-Side Encryption Not Explicitly Configured (data_bucket)",
        "description": "Storage encryption is not explicitly configured in Terraform.",
        "affected_resource_id": "aws_s3_bucket.data_bucket",
        "affected_resource_type": "aws_s3_bucket",
        "affected_resource_name": "data_bucket",
        "severity": "Medium",
        "detection_status": "Needs Review",
        "confidence": "Medium",
        "evidence": {
            "server_side_encryption_configuration": "missing",
        },
        "impact": "Unencrypted data at rest is vulnerable to unauthorized access if media is improperly accessed.",
        "recommendation": "Enable appropriate storage encryption.",
        "risk_assessment": {
            "likelihood": None,
            "impact": None,
            "inherent_risk_score": None,
            "risk_level": None,
            "confidence_factor": 0.75,
            "confidence_adjusted_score": None,
            "assessment_status": "Provisional",
            "scoring_explanation": "Provisional finding: configuration is unconfirmed.",
            "scoring_method": "Likelihood × Impact",
        },
    }

    explanation = explain_finding(finding)

    # 1. Correct status
    assert explanation["explanation_status"] == "Needs Review"

    # 2. Must NOT claim to be a confirmed vulnerability
    assert "Confirmed security misconfiguration" not in explanation["summary"]
    assert "review required" in explanation["summary"].lower()

    # 3. Evidence explanation distinguishes missing from confirmed disabled
    assert "omits" in explanation["evidence_explanation"].lower() or "unconfigured" in explanation["evidence_explanation"].lower()
    assert "server_side_encryption_configuration" in explanation["evidence_explanation"]

    # 4. Uncertainty explicitly explains what is unknown
    assert "High uncertainty" in explanation["uncertainty"]
    assert "account-level" in explanation["uncertainty"].lower() or "runtime" in explanation["uncertainty"].lower()

    # 5. Verification steps guide the user to verify runtime status
    assert len(explanation["verification_steps"]) >= 1
    assert any("get-bucket-encryption" in step or "s3" in step for step in explanation["verification_steps"])


# ---------------------------------------------------------------------------
# Test 3: Missing Evidence and Optional Fields Do Not Crash
# ---------------------------------------------------------------------------


def test_3_missing_evidence_and_optional_fields():
    """Missing evidence and optional fields do not crash the service."""
    # Completely bare finding
    bare_finding = {"finding_id": "bare_1"}
    exp1 = explain_finding(bare_finding)
    assert exp1["finding_id"] == "bare_1"
    assert exp1["explanation_status"] in ("Generated", "Needs Review")
    assert "No specific attribute evidence" in exp1["evidence_explanation"]

    # Finding with None evidence and None risk_assessment
    none_finding = {
        "finding_id": "none_1",
        "title": "Minimal Finding",
        "evidence": None,
        "risk_assessment": None,
        "detection_status": "Needs Review",
    }
    exp2 = explain_finding(none_finding)
    assert exp2["finding_id"] == "none_1"
    assert exp2["explanation_status"] == "Needs Review"

    # Completely non-dict input
    exp3 = explain_finding("not_a_dict")  # type: ignore[arg-type]
    assert exp3["explanation_status"] == "Needs Review"


# ---------------------------------------------------------------------------
# Test 4: Empty Threat Findings Returns Empty List
# ---------------------------------------------------------------------------


def test_4_empty_threat_findings():
    """Empty threat_findings returns an empty explanation list."""
    assert explain_findings([]) == []
    assert explain_findings(None) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Test 5: Each Explanation Has Correct finding_id in Multiple Findings
# ---------------------------------------------------------------------------


def test_5_multiple_findings_matching_ids():
    """Each explanation has the correct finding_id corresponding to its source finding."""
    findings = [
        {"finding_id": "find_1", "detection_status": "Confirmed", "title": "Issue 1"},
        {"finding_id": "find_2", "detection_status": "Needs Review", "title": "Issue 2"},
        {"finding_id": "find_3", "detection_status": "Confirmed", "title": "Issue 3"},
    ]

    exps = explain_findings(findings)
    assert len(exps) == 3
    assert [e["finding_id"] for e in exps] == ["find_1", "find_2", "find_3"]
    assert exps[0]["explanation_status"] == "Generated"
    assert exps[1]["explanation_status"] == "Needs Review"
    assert exps[2]["explanation_status"] == "Generated"


# ---------------------------------------------------------------------------
# Test 6: Complete POST /api/analyze Endpoint Returns risk_explanations
# ---------------------------------------------------------------------------


def test_6_api_analyze_endpoint_returns_risk_explanations():
    """
    POST /api/analyze returns all previous fields (infrastructure_map,
    threat_findings, risk_summary) and now includes risk_explanations.
    """
    tf_content = b"""
resource "aws_security_group" "web_sg" {
  name = "web-sec-group"

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "prod_db" {
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_s3_bucket" "asset_bucket" {
  bucket = "company-assets-public"
  acl    = "public-read"
}
"""
    response = client.post(
        "/api/analyze",
        files={"file": ("infra.tf", tf_content, "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()

    # Step 1 & 2 fields preserved
    assert data["filename"] == "infra.tf"
    assert data["resource_count"] == 3
    assert len(data["resources"]) == 3
    assert "infrastructure_map" in data
    assert len(data["infrastructure_map"]["nodes"]) == 3

    # Step 3 & 4 fields preserved
    assert "threat_findings" in data
    assert len(data["threat_findings"]) >= 4
    for finding in data["threat_findings"]:
        assert "risk_assessment" in finding
        assert finding["risk_assessment"] is not None

    assert "risk_summary" in data
    assert data["risk_summary"]["total_findings"] == len(data["threat_findings"])
    assert data["risk_summary"]["overall_risk_level"] in ("High", "Critical")

    # Step 5: risk_explanations present and aligned
    assert "risk_explanations" in data
    explanations = data["risk_explanations"]
    assert len(explanations) == len(data["threat_findings"])

    finding_ids = [f["finding_id"] for f in data["threat_findings"]]
    explanation_ids = [e["finding_id"] for e in explanations]
    assert explanation_ids == finding_ids

    # Validate explanation schema
    for exp in explanations:
        assert exp["finding_id"] in finding_ids
        assert exp["summary"]
        assert exp["why_it_matters"]
        assert exp["evidence_explanation"]
        assert exp["uncertainty"]
        assert isinstance(exp["recommended_actions"], list)
        assert len(exp["recommended_actions"]) > 0
        assert isinstance(exp["verification_steps"], list)
        assert len(exp["verification_steps"]) > 0
        assert exp["explanation_status"] in ("Generated", "Needs Review")
        assert exp["explanation_method"] == "rule_based"


# ---------------------------------------------------------------------------
# Test 7: Modular Explanation Provider Interface Verification
# ---------------------------------------------------------------------------


def test_7_explanation_provider_interface():
    """Verify that get_explanation_provider returns a BaseExplanationProvider instance."""
    provider = get_explanation_provider()
    assert isinstance(provider, BaseExplanationProvider)
    assert isinstance(provider, RuleBasedExplanationProvider)

    # Calling explain directly works and returns structured dictionary
    test_finding = {
        "finding_id": "test_provider_id",
        "title": "Provider Test",
        "detection_status": "Confirmed",
    }
    result = provider.explain(test_finding)
    assert result["finding_id"] == "test_provider_id"
    assert result["explanation_method"] == "rule_based"
