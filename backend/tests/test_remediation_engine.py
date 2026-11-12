"""
tests/test_remediation_engine.py
---------------------------------
Automated test suite for Security Recommendations and Safe Terraform Fix Generation (Step 6).

Run with:
    .venv\\Scripts\\python.exe -m pytest tests/test_remediation_engine.py -v

Verifies:
    1. S3 encryption finding produces suggested patch referencing correct Terraform resource.
    2. Suggested patch does not invent KMS ARN (uses AES256, no invented key).
    3. Needs Review / Provisional finding produces non-final remediation_status ("Needs Review").
    4. Missing resource info returns manual remediation actions without code patch.
    5. Unsupported threat types (SSH, Public DB, IAM wildcard) return manual remediation actions.
    6. Existing equivalent encryption configuration avoids duplicate patch generation.
    7. Empty findings list returns empty list ([]).
    8. POST /api/analyze returns remediations array and preserves all previous response fields.
    9. Modular provider interface verification (BaseRemediationProvider).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from services.remediation_engine import (  # noqa: E402
    BaseRemediationProvider,
    RuleBasedRemediationProvider,
    generate_remediation,
    generate_remediations,
    get_remediation_provider,
)

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test 1: S3 Encryption Finding Produces Safe Suggested Patch
# ---------------------------------------------------------------------------


def test_1_s3_encryption_patch_references_correct_resource():
    """S3 encryption finding produces a suggested patch referencing aws_s3_bucket.<name>.id."""
    finding = {
        "finding_id": "aws_s3_bucket.data_lake-THREAT-005-encryption",
        "threat_id": "THREAT-005",
        "title": "Unencrypted S3 Bucket (data_lake)",
        "affected_resource_id": "aws_s3_bucket.data_lake",
        "affected_resource_type": "aws_s3_bucket",
        "affected_resource_name": "data_lake",
        "severity": "Medium",
        "detection_status": "Confirmed",
        "confidence": "High",
        "recommendation": "Configure server-side encryption with AWS KMS or Amazon S3-managed keys (SSE-S3).",
        "risk_assessment": {
            "assessment_status": "Assessed",
            "risk_level": "Medium",
        },
    }
    resources = [
        {
            "type": "aws_s3_bucket",
            "name": "data_lake",
            "attributes": {"bucket": "my-prod-data-lake-2026"},
        }
    ]

    remediation = generate_remediation(finding, resources, existing_labels=set())

    # Required Schema Fields
    assert remediation["remediation_id"] == "rem-aws_s3_bucket.data_lake-THREAT-005-encryption"
    assert remediation["finding_id"] == "aws_s3_bucket.data_lake-THREAT-005-encryption"
    assert remediation["affected_resource_id"] == "aws_s3_bucket.data_lake"
    assert remediation["affected_resource_type"] == "aws_s3_bucket"
    assert remediation["affected_resource_name"] == "data_lake"
    assert remediation["patch_type"] == "addition"
    assert remediation["remediation_status"] == "Suggested"
    assert remediation["generated_by"] == "rule_based"

    # Suggested Code Checks
    suggested_code = remediation["suggested_code"]
    assert suggested_code is not None
    assert 'resource "aws_s3_bucket_server_side_encryption_configuration"' in suggested_code
    assert "bucket = aws_s3_bucket.data_lake.id" in suggested_code

    # Actions, Assumptions, Validation Steps
    assert len(remediation["recommended_actions"]) > 0
    assert len(remediation["assumptions"]) > 0
    assert len(remediation["validation_steps"]) > 0


# ---------------------------------------------------------------------------
# Test 2: Suggested Patch Does Not Invent KMS ARN
# ---------------------------------------------------------------------------


def test_2_s3_encryption_patch_no_invented_kms_arn():
    """Suggested patch uses standard AES256 and never invents a KMS ARN or fake key ID."""
    finding = {
        "finding_id": "aws_s3_bucket.backup-THREAT-005-encryption",
        "threat_id": "THREAT-005",
        "affected_resource_id": "aws_s3_bucket.backup",
        "affected_resource_type": "aws_s3_bucket",
        "affected_resource_name": "backup",
        "detection_status": "Confirmed",
    }
    resources = [
        {
            "type": "aws_s3_bucket",
            "name": "backup",
            "attributes": {"bucket": "daily-backups"},
        }
    ]

    remediation = generate_remediation(finding, resources, existing_labels=set())
    suggested_code = remediation["suggested_code"]

    assert suggested_code is not None
    # Uses standard SSE-S3 AES256
    assert 'sse_algorithm = "AES256"' in suggested_code
    # Never invents KMS ARN or kms_master_key_id
    assert "arn:aws:kms" not in suggested_code
    assert "kms_master_key_id" not in suggested_code
    assert "arn:aws" not in suggested_code

    # Assumptions acknowledge AES256 usage
    assert any("AES256" in a for a in remediation["assumptions"])


# ---------------------------------------------------------------------------
# Test 3: Needs Review / Provisional Finding Produces Non-Final Status
# ---------------------------------------------------------------------------


def test_3_needs_review_provisional_finding_status():
    """Findings with Needs Review detection status or Provisional assessment produce non-final status."""
    # Case A: detection_status == "Needs Review"
    finding_a = {
        "finding_id": "aws_s3_bucket.temp-THREAT-005-encryption",
        "threat_id": "THREAT-005",
        "affected_resource_id": "aws_s3_bucket.temp",
        "affected_resource_type": "aws_s3_bucket",
        "affected_resource_name": "temp",
        "detection_status": "Needs Review",
    }
    resources = [{"type": "aws_s3_bucket", "name": "temp", "attributes": {}}]

    rem_a = generate_remediation(finding_a, resources, existing_labels=set())
    assert rem_a["remediation_status"] == "Needs Review"
    assert rem_a["remediation_status"] != "Resolved"
    assert rem_a["remediation_status"] != "Fixed"

    # Case B: risk_assessment.assessment_status == "Provisional"
    finding_b = {
        "finding_id": "aws_s3_bucket.temp2-THREAT-005-encryption",
        "threat_id": "THREAT-005",
        "affected_resource_id": "aws_s3_bucket.temp2",
        "affected_resource_type": "aws_s3_bucket",
        "affected_resource_name": "temp2",
        "detection_status": "Confirmed",
        "risk_assessment": {"assessment_status": "Provisional"},
    }
    resources_b = [{"type": "aws_s3_bucket", "name": "temp2", "attributes": {}}]

    rem_b = generate_remediation(finding_b, resources_b, existing_labels=set())
    assert rem_b["remediation_status"] == "Needs Review"


# ---------------------------------------------------------------------------
# Test 4: Missing Resource Info Returns Manual Guidance Without Code
# ---------------------------------------------------------------------------


def test_4_missing_resource_info_returns_manual_guidance():
    """If target resource cannot be found in resources, safe manual guidance is returned without code."""
    # Target bucket 'ghost_bucket' not present in resources list
    finding = {
        "finding_id": "aws_s3_bucket.ghost_bucket-THREAT-005-encryption",
        "threat_id": "THREAT-005",
        "affected_resource_id": "aws_s3_bucket.ghost_bucket",
        "affected_resource_type": "aws_s3_bucket",
        "affected_resource_name": "ghost_bucket",
        "detection_status": "Confirmed",
    }
    resources = [
        {"type": "aws_s3_bucket", "name": "other_bucket", "attributes": {}}
    ]

    rem = generate_remediation(finding, resources, existing_labels=set())

    assert rem["suggested_code"] is None
    assert rem["patch_type"] == "manual"
    assert "could not be safely verified" in rem["explanation"]
    assert len(rem["recommended_actions"]) > 0


# ---------------------------------------------------------------------------
# Test 5: Unsupported Threat Types Return Manual Remediation Guidance
# ---------------------------------------------------------------------------


def test_5_unsupported_threat_types_return_manual_actions():
    """Unsupported threat rules (SSH, Public DB, IAM Admin) return manual actions without code."""
    test_cases = [
        ("THREAT-001", "aws_s3_bucket", "public_bucket", "S3 Public Access"),
        ("THREAT-002", "aws_security_group", "ssh_sg", "Unrestricted SSH"),
        ("THREAT-003", "aws_security_group", "db_sg", "Sensitive Port Ingress"),
        ("THREAT-004", "aws_db_instance", "prod_db", "Publicly Accessible DB"),
        ("THREAT-006", "aws_iam_policy", "admin_policy", "Broad IAM Admin"),
    ]

    for threat_id, res_type, res_name, title in test_cases:
        finding = {
            "finding_id": f"{res_type}.{res_name}-{threat_id}",
            "threat_id": threat_id,
            "title": title,
            "affected_resource_id": f"{res_type}.{res_name}",
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "detection_status": "Confirmed",
        }
        rem = generate_remediation(finding, [], existing_labels=set())

        assert rem["suggested_code"] is None
        assert rem["patch_type"] == "manual"
        assert len(rem["recommended_actions"]) > 0
        assert len(rem["validation_steps"]) > 0
        assert "Manual remediation guidance" in rem["explanation"]


# ---------------------------------------------------------------------------
# Test 6: Existing Equivalent Encryption Avoids Duplicate Patch
# ---------------------------------------------------------------------------


def test_6_existing_encryption_avoids_duplicate_patch():
    """If equivalent encryption configuration already exists, do not generate a duplicate patch."""
    # Case A: server_side_encryption_configuration inline in aws_s3_bucket
    finding = {
        "finding_id": "aws_s3_bucket.secure_b-THREAT-005-encryption",
        "threat_id": "THREAT-005",
        "affected_resource_id": "aws_s3_bucket.secure_b",
        "affected_resource_type": "aws_s3_bucket",
        "affected_resource_name": "secure_b",
        "detection_status": "Needs Review",
    }
    resources_a = [
        {
            "type": "aws_s3_bucket",
            "name": "secure_b",
            "attributes": {
                "server_side_encryption_configuration": {"rule": {}}
            },
        }
    ]
    rem_a = generate_remediation(finding, resources_a, existing_labels=set())
    assert rem_a["suggested_code"] is None
    assert rem_a["patch_type"] == "manual"
    assert "already appears to be declared" in rem_a["explanation"]

    # Case B: standalone aws_s3_bucket_server_side_encryption_configuration resource exists
    resources_b = [
        {"type": "aws_s3_bucket", "name": "secure_b", "attributes": {}},
        {
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "name": "secure_b_sse",
            "attributes": {"bucket": "${aws_s3_bucket.secure_b.id}"},
        },
    ]
    rem_b = generate_remediation(finding, resources_b, existing_labels=set())
    assert rem_b["suggested_code"] is None
    assert rem_b["patch_type"] == "manual"
    assert "already appears to be declared" in rem_b["explanation"]


# ---------------------------------------------------------------------------
# Test 7: Empty Findings List Returns Empty List
# ---------------------------------------------------------------------------


def test_7_empty_findings_returns_empty_list():
    """Empty threat findings input returns an empty list without error."""
    assert generate_remediations([], []) == []
    assert generate_remediations(None, []) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Test 8: POST /api/analyze Returns Remediations and Preserves All Fields
# ---------------------------------------------------------------------------


def test_8_api_analyze_returns_remediations_and_preserves_pipeline():
    """
    POST /api/analyze returns all previous fields (infrastructure_map,
    threat_findings, risk_summary, risk_explanations) and now includes remediations.
    """
    tf_content = b"""
resource "aws_security_group" "web_sg" {
  name = "web-sg"

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-sample-unencrypted-bucket"
  acl    = "private"
}
"""
    response = client.post(
        "/api/analyze",
        files={"file": ("infra.tf", tf_content, "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()

    # Step 1 & 2: Structural parsing and infra map
    assert data["filename"] == "infra.tf"
    assert data["resource_count"] == 2
    assert len(data["resources"]) == 2
    assert "infrastructure_map" in data

    # Step 3 & 4: Threat findings and risk summary
    assert "threat_findings" in data
    assert len(data["threat_findings"]) >= 2
    assert "risk_summary" in data

    # Step 5: Risk explanations
    assert "risk_explanations" in data
    assert len(data["risk_explanations"]) == len(data["threat_findings"])

    # Step 6: Remediations present and aligned with findings
    assert "remediations" in data
    remediations = data["remediations"]
    assert len(remediations) == len(data["threat_findings"])

    finding_ids = [f["finding_id"] for f in data["threat_findings"]]
    rem_finding_ids = [r["finding_id"] for r in remediations]
    assert rem_finding_ids == finding_ids

    # Validate remediation schema and content
    for rem in remediations:
        assert rem["remediation_id"].startswith("rem-")
        assert rem["finding_id"] in finding_ids
        assert rem["affected_resource_id"]
        assert rem["affected_resource_type"]
        assert rem["affected_resource_name"]
        assert rem["title"]
        assert rem["explanation"]
        assert isinstance(rem["recommended_actions"], list)
        assert len(rem["recommended_actions"]) > 0
        assert rem["patch_type"] in ("addition", "manual")
        assert isinstance(rem["assumptions"], list)
        assert isinstance(rem["validation_steps"], list)
        assert rem["remediation_status"] in ("Suggested", "Needs Review")
        assert rem["generated_by"] == "rule_based"

    # S3 encryption finding gets safe code addition referencing aws_s3_bucket.unencrypted_bucket.id
    s3_rems = [
        r for r in remediations
        if r["affected_resource_type"] == "aws_s3_bucket" and r["patch_type"] == "addition"
    ]
    assert len(s3_rems) >= 1
    s3_rem = s3_rems[0]
    assert s3_rem["suggested_code"] is not None
    assert 'resource "aws_s3_bucket_server_side_encryption_configuration"' in s3_rem["suggested_code"]
    assert "bucket = aws_s3_bucket.unencrypted_bucket.id" in s3_rem["suggested_code"]
    assert 'sse_algorithm = "AES256"' in s3_rem["suggested_code"]

    # SSH finding gets manual guidance with no code
    ssh_rems = [
        r for r in remediations
        if r["affected_resource_type"] == "aws_security_group"
    ]
    assert len(ssh_rems) >= 1
    ssh_rem = ssh_rems[0]
    assert ssh_rem["suggested_code"] is None
    assert ssh_rem["patch_type"] == "manual"


# ---------------------------------------------------------------------------
# Test 9: Modular Provider Interface Verification
# ---------------------------------------------------------------------------


def test_9_remediation_provider_interface():
    """Verify that get_remediation_provider returns a BaseRemediationProvider instance."""
    provider = get_remediation_provider()
    assert isinstance(provider, BaseRemediationProvider)
    assert isinstance(provider, RuleBasedRemediationProvider)

    # Calling generate directly produces expected structured dictionary
    test_finding = {
        "finding_id": "test_provider_id",
        "title": "Provider Test",
        "affected_resource_id": "res.test",
        "detection_status": "Confirmed",
    }
    result = provider.generate(test_finding, [], set())
    assert result["finding_id"] == "test_provider_id"
    assert result["patch_type"] == "manual"
    assert result["generated_by"] == "rule_based"

    # Malformed finding input returns safe fallback without exception
    fallback = generate_remediation("not_a_dict", [], set())  # type: ignore[arg-type]
    assert fallback["remediation_id"] == "rem-invalid"
    assert fallback["patch_type"] == "manual"
    assert fallback["suggested_code"] is None
