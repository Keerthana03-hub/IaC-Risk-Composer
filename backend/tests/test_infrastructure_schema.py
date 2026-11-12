"""
tests/test_infrastructure_schema.py
-----------------------------------
Stage 1: Unit tests for Normalized Infrastructure Schema and backward compatibility.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.infrastructure_mapper import build_infrastructure_map
from services.infrastructure_schema import (
    IaCFormat,
    NormalizedInfrastructure,
    NormalizedResource,
    ParsingStatus,
    PlatformProvider,
)
from services.threat_engine import analyze_threats


def test_normalized_resource_initialization():
    """Verify all required schema fields are correctly populated and accessible."""
    res = NormalizedResource(
        id="aws_s3_bucket.payment_vault",
        name="payment_vault",
        type="aws_s3_bucket",
        source_format=IaCFormat.TERRAFORM.value,
        provider=PlatformProvider.AWS.value,
        attributes={"bucket": "payment-vault-prod", "acl": "private"},
        relationships=["aws_kms_key.vault_key"],
        source_file="main.tf",
        source_location={"line": 15, "format": "hcl2"},
        parsing_status=ParsingStatus.VALID.value,
        validation_errors=[],
    )

    assert res.id == "aws_s3_bucket.payment_vault"
    assert res.name == "payment_vault"
    assert res.type == "aws_s3_bucket"
    assert res.source_format == "terraform"
    assert res.provider == "aws"
    assert res.attributes["bucket"] == "payment-vault-prod"
    assert res.relationships == ["aws_kms_key.vault_key"]
    assert res.source_file == "main.tf"
    assert res.source_location["line"] == 15
    assert res.parsing_status == "valid"
    assert res.validation_errors == []


def test_normalized_resource_dict_protocol_compatibility():
    """Verify legacy dictionary access (r['type'], r.get('attributes')) works identically to dict."""
    res = NormalizedResource(
        id="aws_security_group.web_sg",
        name="web_sg",
        type="aws_security_group",
        attributes={"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp"}]},
    )

    # __getitem__
    assert res["type"] == "aws_security_group"
    assert res["name"] == "web_sg"
    assert "ingress" in res["attributes"]

    # get()
    assert res.get("type") == "aws_security_group"
    assert res.get("nonexistent", "default_val") == "default_val"

    # __contains__
    assert "type" in res
    assert "attributes" in res
    assert "name" in res
    assert "nonexistent_field" not in res

    # to_legacy_dict()
    legacy = res.to_legacy_dict()
    assert set(legacy.keys()) == {"type", "name", "attributes"}
    assert legacy["type"] == "aws_security_group"


def test_normalized_resource_from_terraform_factory():
    """Verify creating a normalized resource from legacy parser output."""
    raw_tf = {
        "type": "aws_db_instance",
        "name": "prod_db",
        "attributes": {"allocated_storage": 20, "publicly_accessible": False},
    }
    norm = NormalizedResource.from_terraform(raw_tf, filename="database.tf")

    assert norm.id == "aws_db_instance.prod_db"
    assert norm.name == "prod_db"
    assert norm.type == "aws_db_instance"
    assert norm.source_format == "terraform"
    assert norm.provider == "aws"
    assert norm.source_file == "database.tf"
    assert norm.attributes["publicly_accessible"] is False


def test_normalized_infrastructure_container():
    """Verify NormalizedInfrastructure aggregation, properties, and export."""
    r1 = NormalizedResource(
        id="aws_instance.web",
        name="web",
        type="aws_instance",
        attributes={"ami": "ami-12345", "vpc_security_group_ids": ["${aws_security_group.web_sg.id}"]},
    )
    r2 = NormalizedResource(
        id="aws_security_group.web_sg",
        name="web_sg",
        type="aws_security_group",
        attributes={"name": "web_sg"},
    )

    infra = NormalizedInfrastructure(
        source_format=IaCFormat.TERRAFORM.value,
        source_file="main.tf",
        resources=[r1, r2],
    )

    assert infra.resource_count == 2
    assert infra.resource_types == ["aws_instance", "aws_security_group"]
    assert infra.get_resource("aws_instance.web") == r1
    assert infra.get_resource("nonexistent") is None

    legacy_list = infra.to_legacy_resources()
    assert len(legacy_list) == 2
    assert legacy_list[0] == {"type": "aws_instance", "name": "web", "attributes": r1.attributes}


def test_compatibility_with_infrastructure_mapper_and_threat_engine():
    """Verify that NormalizedResource objects can be passed directly to existing mapper and threat engines."""
    # S3 bucket with public ACL to trigger THREAT-001
    r_s3 = NormalizedResource.from_terraform(
        {
            "type": "aws_s3_bucket",
            "name": "insecure_bucket",
            "attributes": {"bucket": "insecure-test", "acl": "public-read"},
        },
        filename="s3.tf",
    )

    # Security group with unrestricted SSH to trigger THREAT-002
    r_sg = NormalizedResource.from_terraform(
        {
            "type": "aws_security_group",
            "name": "ssh_sg",
            "attributes": {
                "ingress": {
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            },
        },
        filename="sg.tf",
    )

    # 1. Test infrastructure mapper with normalized resources
    infra_map = build_infrastructure_map([r_s3, r_sg])
    assert "nodes" in infra_map
    assert "edges" in infra_map
    assert len(infra_map["nodes"]) == 2
    node_ids = {n["id"] for n in infra_map["nodes"]}
    assert "aws_s3_bucket.insecure_bucket" in node_ids
    assert "aws_security_group.ssh_sg" in node_ids

    # 2. Test threat engine with normalized resources
    findings = analyze_threats([r_s3, r_sg], infra_map)
    threat_ids = {f["threat_id"] for f in findings}
    assert "THREAT-001" in threat_ids  # Public S3
    assert "THREAT-002" in threat_ids  # Unrestricted SSH
