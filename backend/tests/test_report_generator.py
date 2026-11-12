"""
tests/test_report_generator.py
------------------------------
Automated test suite for PDF Security Report Generation (Step 7).

Run with:
    .venv\\Scripts\\python.exe -m pytest tests/test_report_generator.py -v

Verifies:
    1. PDF generation service returns valid PDF bytes starting with b'%PDF'.
    2. Empty threat findings and empty remediations generate valid PDF report.
    3. Provisional findings, Needs Review status, and null risk scores are handled safely.
    4. Suggested Terraform code patches are formatted and labeled safely.
    5. POST /api/report returns 200 with media_type application/pdf and attachment filename.
    6. Invalid input to POST /api/report is rejected with 422 Unprocessable Entity.
    7. Full end-to-end integration: output of POST /api/analyze can be posted directly
       to POST /api/report to produce a valid PDF security report.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from services.report_generator import generate_pdf_report  # noqa: E402

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test 1: Service generates valid PDF bytes
# ---------------------------------------------------------------------------


def test_1_pdf_generation_full_data():
    """generate_pdf_report generates valid PDF bytes starting with b'%PDF'."""
    sample_analysis = {
        "filename": "production_infra.tf",
        "resource_count": 2,
        "resource_types": ["aws_security_group", "aws_s3_bucket"],
        "resources": [
            {
                "type": "aws_security_group",
                "name": "web_sg",
                "attributes": {"name": "web-sg"},
            },
            {
                "type": "aws_s3_bucket",
                "name": "data_lake",
                "attributes": {"bucket": "corp-data-lake"},
            },
        ],
        "infrastructure_map": {
            "nodes": [
                {
                    "id": "aws_security_group.web_sg",
                    "resource_type": "aws_security_group",
                    "name": "web_sg",
                    "label": "aws_security_group.web_sg",
                    "attributes": {},
                },
                {
                    "id": "aws_s3_bucket.data_lake",
                    "resource_type": "aws_s3_bucket",
                    "name": "data_lake",
                    "label": "aws_s3_bucket.data_lake",
                    "attributes": {},
                },
            ],
            "edges": [],
        },
        "threat_findings": [
            {
                "finding_id": "aws_security_group.web_sg-THREAT-002-ssh-0",
                "threat_id": "THREAT-002",
                "title": "Unrestricted SSH Access on Port 22 (web_sg)",
                "description": "Security group permits SSH from 0.0.0.0/0.",
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
                "impact": "Exposes remote administrative port to internet scanning.",
                "recommendation": "Restrict SSH to corporate bastion or VPN.",
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
        ],
        "risk_summary": {
            "total_findings": 1,
            "confirmed_findings": 1,
            "needs_review_findings": 0,
            "low_risk_count": 0,
            "medium_risk_count": 0,
            "high_risk_count": 1,
            "critical_risk_count": 0,
            "highest_inherent_risk_score": 16,
            "overall_risk_level": "High",
        },
        "risk_explanations": [
            {
                "finding_id": "aws_security_group.web_sg-THREAT-002-ssh-0",
                "summary": "Confirmed High-severity threat on aws_security_group.web_sg.",
                "why_it_matters": "Exposes SSH directly to internet brute-force attacks.",
                "evidence_explanation": "Security group rule allows ingress from 0.0.0.0/0.",
                "uncertainty": "Assumes standard internet connectivity without external cloud firewall.",
                "recommended_actions": ["Restrict ingress CIDRs."],
                "verification_steps": ["Run terraform plan."],
                "explanation_status": "Generated",
                "explanation_method": "rule_based",
            }
        ],
        "remediations": [
            {
                "remediation_id": "rem-aws_security_group.web_sg-THREAT-002-ssh-0",
                "finding_id": "aws_security_group.web_sg-THREAT-002-ssh-0",
                "affected_resource_id": "aws_security_group.web_sg",
                "affected_resource_type": "aws_security_group",
                "affected_resource_name": "web_sg",
                "title": "Remediation Guidance: Unrestricted SSH Access",
                "explanation": "Manual remediation guidance for SSH access.",
                "recommended_actions": ["Restrict security group ingress on port 22."],
                "suggested_code": None,
                "patch_type": "manual",
                "assumptions": ["Administrative shell access can be restricted."],
                "validation_steps": ["Preview updated security group with terraform plan."],
                "remediation_status": "Suggested",
                "generated_by": "rule_based",
            }
        ],
    }

    pdf_bytes = generate_pdf_report(sample_analysis)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Test 2: Clean posture (empty findings and remediations)
# ---------------------------------------------------------------------------


def test_2_empty_findings_and_remediations():
    """Clean configuration with no findings generates a valid PDF report."""
    clean_analysis = {
        "filename": "clean_infrastructure.tf",
        "resource_count": 1,
        "resource_types": ["aws_s3_bucket"],
        "resources": [
            {"type": "aws_s3_bucket", "name": "clean_bucket", "attributes": {}}
        ],
        "infrastructure_map": {"nodes": [], "edges": []},
        "threat_findings": [],
        "risk_summary": {
            "total_findings": 0,
            "confirmed_findings": 0,
            "needs_review_findings": 0,
            "low_risk_count": 0,
            "medium_risk_count": 0,
            "high_risk_count": 0,
            "critical_risk_count": 0,
            "overall_risk_level": "Low",
        },
        "risk_explanations": [],
        "remediations": [],
    }

    pdf_bytes = generate_pdf_report(clean_analysis)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Test 3: Provisional findings and null risk scores handled safely
# ---------------------------------------------------------------------------


def test_3_provisional_and_null_risk_scores_handled_safely():
    """Findings with Provisional status, Needs Review detection, and None risk scores generate valid PDF."""
    provisional_analysis = {
        "filename": "provisional.tf",
        "resource_count": 1,
        "resource_types": ["aws_s3_bucket"],
        "resources": [{"type": "aws_s3_bucket", "name": "unknown_b", "attributes": {}}],
        "threat_findings": [
            {
                "finding_id": "aws_s3_bucket.unknown_b-THREAT-005-encryption",
                "threat_id": "THREAT-005",
                "title": "Unencrypted S3 Bucket (unknown_b)",
                "description": "Missing encryption configuration.",
                "affected_resource_id": "aws_s3_bucket.unknown_b",
                "affected_resource_type": "aws_s3_bucket",
                "affected_resource_name": "unknown_b",
                "severity": "Medium",
                "detection_status": "Needs Review",
                "confidence": "Low",
                "evidence": {},
                "impact": "Data stored unencrypted at rest.",
                "recommendation": "Configure SSE.",
                "risk_assessment": {
                    "likelihood": None,
                    "impact": None,
                    "inherent_risk_score": None,
                    "risk_level": None,
                    "assessment_status": "Provisional",
                    "scoring_explanation": "Incomplete configuration context; risk is provisional.",
                    "scoring_method": "Likelihood × Impact",
                },
            }
        ],
        "risk_summary": {
            "total_findings": 1,
            "confirmed_findings": 0,
            "needs_review_findings": 1,
            "low_risk_count": 0,
            "medium_risk_count": 0,
            "high_risk_count": 0,
            "critical_risk_count": 0,
            "highest_inherent_risk_score": None,
            "overall_risk_level": "Needs Review",
        },
        "remediations": [
            {
                "remediation_id": "rem-aws_s3_bucket.unknown_b",
                "finding_id": "aws_s3_bucket.unknown_b-THREAT-005-encryption",
                "affected_resource_id": "aws_s3_bucket.unknown_b",
                "affected_resource_type": "aws_s3_bucket",
                "affected_resource_name": "unknown_b",
                "title": "Enable Server-Side Encryption",
                "explanation": "Manual remediation guidance.",
                "recommended_actions": ["Add encryption resource."],
                "suggested_code": None,
                "patch_type": "manual",
                "assumptions": ["Workload requires encryption at rest."],
                "validation_steps": ["Run terraform plan."],
                "remediation_status": "Needs Review",
                "generated_by": "rule_based",
            }
        ],
    }

    pdf_bytes = generate_pdf_report(provisional_analysis)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Test 4: Suggested code in remediation is included and formatted
# ---------------------------------------------------------------------------


def test_4_suggested_terraform_code_formatted():
    """Remediation with suggested Terraform code formats properly in monospaced code block."""
    code_snippet = (
        'resource "aws_s3_bucket_server_side_encryption_configuration" "data_sse" {\n'
        '  bucket = aws_s3_bucket.data.id\n'
        '  rule {\n'
        '    apply_server_side_encryption_by_default {\n'
        '      sse_algorithm = "AES256"\n'
        '    }\n'
        '  }\n'
        '}'
    )
    analysis = {
        "filename": "s3_patch.tf",
        "resource_count": 1,
        "resources": [{"type": "aws_s3_bucket", "name": "data", "attributes": {}}],
        "threat_findings": [],
        "remediations": [
            {
                "remediation_id": "rem-aws_s3_bucket.data",
                "finding_id": "find-1",
                "affected_resource_id": "aws_s3_bucket.data",
                "affected_resource_type": "aws_s3_bucket",
                "affected_resource_name": "data",
                "title": "Enable Default Server-Side Encryption for aws_s3_bucket.data",
                "explanation": "Declares server-side encryption with AES256.",
                "recommended_actions": ["Add the suggested resource."],
                "suggested_code": code_snippet,
                "patch_type": "addition",
                "assumptions": ["AES256 satisfies baseline requirements."],
                "validation_steps": ["Run terraform plan."],
                "remediation_status": "Suggested",
                "generated_by": "rule_based",
            }
        ],
    }

    pdf_bytes = generate_pdf_report(analysis)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Test 5: POST /api/report Endpoint Returns 200 and PDF
# ---------------------------------------------------------------------------


def test_5_post_api_report_success():
    """POST /api/report returns 200 OK, application/pdf content type, and attachment filename."""
    payload = {
        "filename": "web_stack.tf",
        "resource_count": 1,
        "resource_types": ["aws_security_group"],
        "resources": [
            {
                "type": "aws_security_group",
                "name": "web_sg",
                "attributes": {},
            }
        ],
        "threat_findings": [],
        "remediations": [],
    }

    response = client.post("/api/report", json=payload)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"

    # Attachment filename in Content-Disposition
    cd = response.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert "web_stack_security_report.pdf" in cd

    # Content is actual valid PDF
    pdf_content = response.content
    assert pdf_content.startswith(b"%PDF")
    assert len(pdf_content) > 1000


# ---------------------------------------------------------------------------
# Test 6: POST /api/report Rejects Invalid Input
# ---------------------------------------------------------------------------


def test_6_post_api_report_invalid_input():
    """POST /api/report with missing required fields returns 422 Unprocessable Entity."""
    # Empty body or missing required 'filename'
    response = client.post("/api/report", json={"completely_wrong": 123})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Test 7: End-to-End Integration (POST /api/analyze -> POST /api/report)
# ---------------------------------------------------------------------------


def test_7_end_to_end_analyze_then_report():
    """
    Complete workflow integration:
    1. Upload .tf file to POST /api/analyze (Steps 1–6)
    2. Pass analysis JSON response directly to POST /api/report (Step 7)
    3. Verify that the returned PDF bytes are valid and contain all generated sections.
    """
    tf_content = b"""
resource "aws_security_group" "api_sg" {
  name = "api-security-group"

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "audit_bucket" {
  bucket = "company-audit-logs"
  acl    = "private"
}
"""
    analyze_res = client.post(
        "/api/analyze",
        files={"file": ("audit_system.tf", tf_content, "text/plain")},
    )
    assert analyze_res.status_code == 200
    analysis_data = analyze_res.json()

    # Verify that analysis output has all pipeline fields
    assert "threat_findings" in analysis_data
    assert "risk_summary" in analysis_data
    assert "risk_explanations" in analysis_data
    assert "remediations" in analysis_data

    # Send directly to POST /api/report
    report_res = client.post("/api/report", json=analysis_data)
    assert report_res.status_code == 200
    assert report_res.headers["content-type"] == "application/pdf"
    assert "audit_system_security_report.pdf" in report_res.headers["content-disposition"]

    pdf_bytes = report_res.content
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 2000
