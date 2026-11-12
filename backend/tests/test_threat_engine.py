"""
tests/test_threat_engine.py
----------------------------
Automated test suite for Threat Detection Engine (Step 3).

Run with (from backend/ directory):
    $env:PYTHONPATH="C:\\ibm_bob\\iac\\iac-risk-composer-step2-infra-mapping\\project\\backend\\.venv\\Lib\\site-packages;."
    python -m pytest tests/test_threat_engine.py -v

Covers all 9 required test scenarios:
    Test 1: AWS SG permits SSH access from 0.0.0.0/0 -> confirmed unrestricted SSH finding.
    Test 2: AWS SG permits SSH only from restricted CIDR (192.168.1.0/24) -> no unrestricted SSH finding.
    Test 3: S3 bucket explicit public access configuration -> finding only when config satisfies rule.
    Test 4: Database has publicly_accessible = true -> confirmed public database finding.
    Test 5: Database has publicly_accessible = false -> no public database finding.
    Test 6: IAM policy contains broad administrative permissions -> confirmed wildcard finding.
    Test 7: Resource has incomplete attributes -> no false confirmed finding; Needs Review only when meaningful.
    Test 8: Empty Terraform resource list -> empty threat_findings list without crashing.
    Test 9: Complete POST /api/analyze API request -> response includes infrastructure_map and threat_findings.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from services.infrastructure_mapper import build_infrastructure_map  # noqa: E402
from services.threat_engine import analyze_threats  # noqa: E402
from services.threat_templates import get_threat_template, list_threat_templates  # noqa: E402

client = TestClient(app)


# ---------------------------------------------------------------------------
# Template Registry Tests
# ---------------------------------------------------------------------------


def test_threat_templates_registry():
    """Verify all 6 core threat templates are registered with valid metadata."""
    templates = list_threat_templates()
    assert len(templates) >= 6

    expected_threat_ids = [
        "THREAT-001",
        "THREAT-002",
        "THREAT-003",
        "THREAT-004",
        "THREAT-005",
        "THREAT-006",
    ]
    for tid in expected_threat_ids:
        tpl = get_threat_template(tid)
        assert tpl is not None, f"Missing threat template {tid}"
        assert tpl.threat_id == tid
        assert tpl.threat_name
        assert tpl.description
        assert len(tpl.applicable_resource_types) > 0
        assert tpl.rule_identifier
        assert tpl.default_severity in ("Critical", "High", "Medium", "Low")
        assert tpl.potential_impact
        assert tpl.recommended_mitigation


# ---------------------------------------------------------------------------
# Test 1: AWS Security Group permits SSH from 0.0.0.0/0 -> Confirmed Finding
# ---------------------------------------------------------------------------


def test_1_security_group_unrestricted_ssh():
    """An AWS security group permits SSH access from 0.0.0.0/0 -> Confirmed unrestricted SSH finding."""
    resources = [
        {
            "type": "aws_security_group",
            "name": "ssh_sg",
            "attributes": {
                "name": "allow-ssh-all",
                "ingress": [
                    {
                        "protocol": "tcp",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ],
            },
        }
    ]
    infra_map = build_infrastructure_map(resources)
    findings = analyze_threats(resources, infra_map)

    ssh_findings = [f for f in findings if f["threat_id"] == "THREAT-002"]
    assert len(ssh_findings) == 1
    f = ssh_findings[0]
    assert f["affected_resource_id"] == "aws_security_group.ssh_sg"
    assert f["affected_resource_type"] == "aws_security_group"
    assert f["affected_resource_name"] == "ssh_sg"
    assert f["detection_status"] == "Confirmed"
    assert f["severity"] == "High"
    assert f["confidence"] == "High"
    assert "0.0.0.0/0" in f["evidence"]["unrestricted_cidrs"]
    assert f["evidence"]["from_port"] == 22


# ---------------------------------------------------------------------------
# Test 2: AWS Security Group permits SSH only from restricted CIDR -> No Finding
# ---------------------------------------------------------------------------


def test_2_security_group_restricted_ssh():
    """An AWS security group permits SSH only from a restricted CIDR (192.168.1.0/24) -> No finding."""
    resources = [
        {
            "type": "aws_security_group",
            "name": "corp_sg",
            "attributes": {
                "name": "allow-ssh-internal",
                "ingress": [
                    {
                        "protocol": "tcp",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["192.168.1.0/24"],
                    }
                ],
            },
        }
    ]
    infra_map = build_infrastructure_map(resources)
    findings = analyze_threats(resources, infra_map)

    ssh_findings = [f for f in findings if f["threat_id"] == "THREAT-002"]
    assert len(ssh_findings) == 0


# ---------------------------------------------------------------------------
# Test 3: S3 Bucket explicit public-access configuration -> Finding only when rule satisfied
# ---------------------------------------------------------------------------


def test_3_s3_bucket_public_access():
    """S3 bucket has explicit public-access configuration -> Finding only when configuration satisfies rule."""
    # Case A: Explicitly public ACL
    public_s3 = [
        {
            "type": "aws_s3_bucket",
            "name": "public_data",
            "attributes": {
                "bucket": "company-public-data",
                "acl": "public-read",
            },
        }
    ]
    infra_map_a = build_infrastructure_map(public_s3)
    findings_a = analyze_threats(public_s3, infra_map_a)

    public_findings_a = [f for f in findings_a if f["threat_id"] == "THREAT-001"]
    assert len(public_findings_a) == 1
    assert public_findings_a[0]["detection_status"] == "Confirmed"
    assert public_findings_a[0]["evidence"]["acl"] == "public-read"

    # Case B: Explicitly private ACL
    private_s3 = [
        {
            "type": "aws_s3_bucket",
            "name": "private_data",
            "attributes": {
                "bucket": "company-private-data",
                "acl": "private",
                "server_side_encryption_configuration": {"rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}},
            },
        }
    ]
    infra_map_b = build_infrastructure_map(private_s3)
    findings_b = analyze_threats(private_s3, infra_map_b)

    public_findings_b = [f for f in findings_b if f["threat_id"] == "THREAT-001"]
    assert len(public_findings_b) == 0


# ---------------------------------------------------------------------------
# Test 4: Database has publicly_accessible = true -> Confirmed Public DB Finding
# ---------------------------------------------------------------------------


def test_4_database_publicly_accessible_true():
    """A database has publicly_accessible = true -> Confirmed public database finding."""
    resources = [
        {
            "type": "aws_db_instance",
            "name": "prod_db",
            "attributes": {
                "engine": "postgres",
                "instance_class": "db.t3.micro",
                "publicly_accessible": True,
                "storage_encrypted": True,
            },
        }
    ]
    infra_map = build_infrastructure_map(resources)
    findings = analyze_threats(resources, infra_map)

    db_public_findings = [f for f in findings if f["threat_id"] == "THREAT-004"]
    assert len(db_public_findings) == 1
    f = db_public_findings[0]
    assert f["affected_resource_id"] == "aws_db_instance.prod_db"
    assert f["detection_status"] == "Confirmed"
    assert f["severity"] == "High"
    assert f["confidence"] == "High"
    assert f["evidence"]["publicly_accessible"] is True


# ---------------------------------------------------------------------------
# Test 5: Database has publicly_accessible = false -> No Public DB Finding
# ---------------------------------------------------------------------------


def test_5_database_publicly_accessible_false():
    """A database has publicly_accessible = false -> No public database finding."""
    resources = [
        {
            "type": "aws_db_instance",
            "name": "internal_db",
            "attributes": {
                "engine": "postgres",
                "instance_class": "db.t3.micro",
                "publicly_accessible": False,
                "storage_encrypted": True,
            },
        }
    ]
    infra_map = build_infrastructure_map(resources)
    findings = analyze_threats(resources, infra_map)

    db_public_findings = [f for f in findings if f["threat_id"] == "THREAT-004"]
    assert len(db_public_findings) == 0


# ---------------------------------------------------------------------------
# Test 6: IAM Policy contains broad administrative permissions -> Confirmed Finding
# ---------------------------------------------------------------------------


def test_6_iam_policy_broad_admin():
    """An IAM policy contains broad administrative permissions -> Finding when policy structure satisfies rule."""
    resources = [
        {
            "type": "aws_iam_policy",
            "name": "admin_policy",
            "attributes": {
                "name": "full-admin",
                "policy": '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}',
            },
        }
    ]
    infra_map = build_infrastructure_map(resources)
    findings = analyze_threats(resources, infra_map)

    iam_findings = [f for f in findings if f["threat_id"] == "THREAT-006"]
    assert len(iam_findings) == 1
    f = iam_findings[0]
    assert f["affected_resource_id"] == "aws_iam_policy.admin_policy"
    assert f["detection_status"] == "Confirmed"
    assert f["severity"] == "Critical"
    assert f["confidence"] == "High"
    assert f["evidence"]["statement"]["Action"] == "*"
    assert f["evidence"]["statement"]["Resource"] == "*"


# ---------------------------------------------------------------------------
# Test 7: Resource has incomplete attributes -> No false confirmed finding
# ---------------------------------------------------------------------------


def test_7_resource_incomplete_attributes():
    """A resource has incomplete attributes -> No false confirmed finding. Return Needs Review only when meaningful."""
    # Empty security group
    resources_sg = [
        {
            "type": "aws_security_group",
            "name": "bare_sg",
            "attributes": {},
        }
    ]
    findings_sg = analyze_threats(resources_sg, build_infrastructure_map(resources_sg))
    # Must not falsely claim confirmed SSH or open ports
    confirmed_sg = [f for f in findings_sg if f["detection_status"] == "Confirmed"]
    assert len(confirmed_sg) == 0

    # Database with unspecified publicly_accessible
    resources_db = [
        {
            "type": "aws_db_instance",
            "name": "db_no_attrs",
            "attributes": {"engine": "postgres"},
        }
    ]
    findings_db = analyze_threats(resources_db, build_infrastructure_map(resources_db))
    # Must not falsely claim publicly accessible
    public_db_confirmed = [f for f in findings_db if f["threat_id"] == "THREAT-004" and f["detection_status"] == "Confirmed"]
    assert len(public_db_confirmed) == 0
    # But storage encryption unconfigured can generate a meaningful Needs Review
    needs_review_enc = [f for f in findings_db if f["threat_id"] == "THREAT-005" and f["detection_status"] == "Needs Review"]
    assert len(needs_review_enc) == 1


# ---------------------------------------------------------------------------
# Test 8: Empty Terraform resource list -> Empty findings list without crashing
# ---------------------------------------------------------------------------


def test_8_empty_resource_list():
    """An empty Terraform resource list -> Empty threat_findings list without crashing."""
    findings = analyze_threats([], {"nodes": [], "edges": []})
    assert findings == []

    # Also test with None infrastructure_map
    findings_none_map = analyze_threats([])
    assert findings_none_map == []


# ---------------------------------------------------------------------------
# Test 9: Complete POST /api/analyze API Request
# ---------------------------------------------------------------------------


def test_9_api_analyze_endpoint_complete_pipeline():
    """
    POST /api/analyze request returns filename, resource_count, resource_types,
    resources, infrastructure_map, and threat_findings together.
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

  ingress {
    protocol    = "tcp"
    from_port   = 3306
    to_port     = 3306
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "app_db" {
  engine              = "mysql"
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
        files={"file": ("infrastructure.tf", tf_content, "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()

    # Original fields preserved
    assert data["filename"] == "infrastructure.tf"
    assert data["resource_count"] == 3
    assert sorted(data["resource_types"]) == ["aws_db_instance", "aws_s3_bucket", "aws_security_group"]
    assert len(data["resources"]) == 3

    # Infrastructure map preserved
    assert "infrastructure_map" in data
    assert len(data["infrastructure_map"]["nodes"]) == 3

    # Step 3: Threat findings present
    assert "threat_findings" in data
    findings = data["threat_findings"]
    assert len(findings) >= 4  # SSH, MySQL, DB public, DB unencrypted, S3 public

    threat_ids_found = {f["threat_id"] for f in findings}
    assert "THREAT-001" in threat_ids_found  # S3 public
    assert "THREAT-002" in threat_ids_found  # SSH unrestricted
    assert "THREAT-003" in threat_ids_found  # MySQL port 3306 unrestricted
    assert "THREAT-004" in threat_ids_found  # DB publicly accessible
    assert "THREAT-005" in threat_ids_found  # DB storage unencrypted

    # Validate schema of each finding
    for finding in findings:
        assert "finding_id" in finding
        assert "threat_id" in finding
        assert "title" in finding
        assert "description" in finding
        assert "affected_resource_id" in finding
        assert "affected_resource_type" in finding
        assert "affected_resource_name" in finding
        assert finding["severity"] in ("Critical", "High", "Medium", "Low")
        assert finding["detection_status"] in ("Confirmed", "Needs Review")
        assert finding["confidence"] in ("High", "Medium", "Low")
        assert "evidence" in finding
        assert "impact" in finding
        assert "recommendation" in finding


# ---------------------------------------------------------------------------
# Extra tests: Sensitive Ports, Standalone Security Group Rules & EBS
# ---------------------------------------------------------------------------


def test_sensitive_ports_and_all_ports():
    """Test all-ports open rule and sensitive database/RDP ports."""
    resources = [
        {
            "type": "aws_security_group",
            "name": "wide_open_sg",
            "attributes": {
                "ingress": [
                    {
                        "protocol": "-1",
                        "from_port": 0,
                        "to_port": 0,
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ]
            },
        }
    ]
    findings = analyze_threats(resources, build_infrastructure_map(resources))
    all_ports_findings = [f for f in findings if f["threat_id"] == "THREAT-003" and "All Ports" in f["title"]]
    assert len(all_ports_findings) == 1
    assert all_ports_findings[0]["severity"] == "Critical"


def test_ebs_volume_encryption():
    """Test EBS volume encryption: confirmed disabled vs encrypted."""
    resources = [
        {
            "type": "aws_ebs_volume",
            "name": "unencrypted_vol",
            "attributes": {"encrypted": False},
        },
        {
            "type": "aws_ebs_volume",
            "name": "encrypted_vol",
            "attributes": {"encrypted": True},
        },
    ]
    findings = analyze_threats(resources, build_infrastructure_map(resources))
    unencrypted = [f for f in findings if f["affected_resource_name"] == "unencrypted_vol"]
    encrypted = [f for f in findings if f["affected_resource_name"] == "encrypted_vol"]

    assert len(unencrypted) == 1
    assert unencrypted[0]["detection_status"] == "Confirmed"
    assert unencrypted[0]["severity"] == "High"
    assert len(encrypted) == 0


def test_standalone_security_group_rule():
    """Test standalone aws_security_group_rule resource."""
    resources = [
        {
            "type": "aws_security_group",
            "name": "base_sg",
            "attributes": {"name": "base"},
        },
        {
            "type": "aws_security_group_rule",
            "name": "ingress_rule",
            "attributes": {
                "type": "ingress",
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["::/0"],
                "security_group_id": "${aws_security_group.base_sg.id}",
            },
        },
    ]
    findings = analyze_threats(resources, build_infrastructure_map(resources))
    ssh_findings = [f for f in findings if f["threat_id"] == "THREAT-002"]
    assert len(ssh_findings) == 1
    assert ssh_findings[0]["affected_resource_id"] == "aws_security_group_rule.ingress_rule"
    assert ssh_findings[0]["detection_status"] == "Confirmed"
