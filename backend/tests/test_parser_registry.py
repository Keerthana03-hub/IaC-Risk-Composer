"""
tests/test_parser_registry.py
-----------------------------
Stage 2: Unit tests for Multi-IaC Parser Registry, Terraform Parser, and API integration.
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
from services.parser_registry import (
    BaseIaCParser,
    MalformedIaCError,
    ParserRegistry,
    TerraformParser,
    UnsupportedFormatError,
    default_parser_registry,
    identify_iac_format,
    parse_iac,
)

client = TestClient(app)


# ---------------------------------------------------------------------------
# Unit Tests: Format Detection & Identification
# ---------------------------------------------------------------------------


def test_terraform_tf_detection():
    """Verify that .tf files are identified as Terraform format."""
    tf_code = 'resource "aws_s3_bucket" "test" { bucket = "my-bucket" }'
    fmt = identify_iac_format("main.tf", tf_code)
    assert fmt == IaCFormat.TERRAFORM

    # Case insensitivity
    fmt_upper = identify_iac_format("INFRASTRUCTURE.TF", tf_code)
    assert fmt_upper == IaCFormat.TERRAFORM


def test_terraform_tf_json_detection():
    """Verify that .tf.json files are identified as Terraform format."""
    tf_json = json.dumps({
        "resource": {
            "aws_s3_bucket": {
                "b1": {"bucket": "bucket-one"}
            }
        }
    })
    fmt = identify_iac_format("terraform.tf.json", tf_json)
    assert fmt == IaCFormat.TERRAFORM


def test_unsupported_file_extensions():
    """Verify that unsupported extensions raise UnsupportedFormatError."""
    with pytest.raises(UnsupportedFormatError) as exc_info:
        identify_iac_format("script.sh", "echo 'hello'")
    assert "Unsupported file format" in str(exc_info.value)

    with pytest.raises(UnsupportedFormatError):
        identify_iac_format("document.pdf", "%PDF-1.4...")


def test_arbitrary_yaml_and_json_rejected():
    """Verify that generic YAML or non-IaC JSON is not misidentified as valid IaC."""
    generic_yaml = """
version: 1.0
author: Developer
settings:
  timeout: 30
"""
    with pytest.raises(UnsupportedFormatError) as exc_info:
        identify_iac_format("config.yaml", generic_yaml)
    assert "generic YAML file" in str(exc_info.value)

    generic_json = json.dumps({"package": "express", "version": "4.17.1"})
    with pytest.raises(UnsupportedFormatError) as exc_info:
        identify_iac_format("package.json", generic_json)
    assert "generic JSON file" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Unit Tests: Parser Registration & Lifecycle
# ---------------------------------------------------------------------------


def test_parser_registration_and_selection():
    """Verify registering, retrieving, and unregistering parsers in ParserRegistry."""
    registry = ParserRegistry()
    assert len(registry.list_parsers()) == 0

    tf_parser = TerraformParser()
    registry.register(tf_parser)

    assert len(registry.list_parsers()) == 1
    assert registry.get_parser(IaCFormat.TERRAFORM) == tf_parser
    assert registry.get_parser("terraform") == tf_parser
    assert registry.get_parser("unknown") is None

    # Retrieve parser for file
    resolved = registry.get_parser_for_file("network.tf", "")
    assert resolved == tf_parser

    # Unregister
    registry.unregister(IaCFormat.TERRAFORM)
    assert len(registry.list_parsers()) == 0


# ---------------------------------------------------------------------------
# Unit Tests: Terraform Parser Execution & Output
# ---------------------------------------------------------------------------


def test_terraform_parser_normalized_output_hcl():
    """Verify parsing HCL2 text into a complete NormalizedInfrastructure instance."""
    hcl = """
resource "aws_security_group" "api_sg" {
  name = "api-security-group"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "api_server" {
  ami = "ami-0123456789"
  vpc_security_group_ids = [aws_security_group.api_sg.id]
}
"""
    infra = parse_iac(hcl, filename="api_service.tf")

    assert isinstance(infra, NormalizedInfrastructure)
    assert infra.source_format == "terraform"
    assert infra.source_file == "api_service.tf"
    assert infra.resource_count == 2
    assert infra.resource_types == ["aws_instance", "aws_security_group"]
    assert infra.parsing_status == ParsingStatus.VALID.value

    # Validate individual normalized resources
    sg = infra.get_resource("aws_security_group.api_sg")
    assert sg is not None
    assert sg.type == "aws_security_group"
    assert sg.name == "api_sg"
    assert sg.provider == "aws"
    assert "ingress" in sg.attributes

    server = infra.get_resource("aws_instance.api_server")
    assert server is not None
    assert server.type == "aws_instance"
    assert server.attributes["ami"] == "ami-0123456789"


def test_terraform_parser_normalized_output_json():
    """Verify parsing .tf.json into a complete NormalizedInfrastructure instance."""
    tf_json = json.dumps({
        "resource": [
            {
                "aws_s3_bucket": {
                    "backup_vault": {
                        "bucket": "corp-backup-vault-2026",
                        "acl": "private"
                    }
                }
            }
        ]
    })
    infra = parse_iac(tf_json, filename="backup.tf.json")

    assert infra.source_format == "terraform"
    assert infra.resource_count == 1
    bucket = infra.get_resource("aws_s3_bucket.backup_vault")
    assert bucket is not None
    assert bucket.attributes["bucket"] == "corp-backup-vault-2026"
    assert bucket.attributes["acl"] == "private"


def test_terraform_parser_error_handling():
    """Verify handling of empty or syntactically invalid files."""
    parser = TerraformParser()

    # Empty content
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse("", filename="empty.tf")
    assert "File is empty" in str(exc_info.value)

    # Invalid HCL syntax
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse("resource aws_s3_bucket { invalid syntax !!!", filename="broken.tf")
    assert "syntax" in str(exc_info.value).lower()

    # Invalid JSON in .tf.json
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse("{ not valid json", filename="broken.tf.json")
    assert "JSON syntax" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Integration Tests: /api/analyze Endpoint Compatibility
# ---------------------------------------------------------------------------


def test_api_analyze_compatibility_hcl_tf():
    """Verify that POST /api/analyze seamlessly works with standard .tf via the registry."""
    tf_content = b"""
resource "aws_s3_bucket" "public_test" {
  bucket = "insecure-bucket-demo"
  acl    = "public-read"
}
"""
    res = client.post(
        "/api/analyze",
        files={"file": ("storage.tf", tf_content, "text/plain")},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["filename"] == "storage.tf"
    assert data["resource_count"] == 1
    assert len(data["threat_findings"]) >= 1
    assert data["threat_findings"][0]["threat_id"] == "THREAT-001"


def test_api_analyze_compatibility_tf_json():
    """Verify that POST /api/analyze accepts .tf.json format via the registry."""
    tf_json_content = json.dumps({
        "resource": {
            "aws_s3_bucket": {
                "json_bucket": {
                    "bucket": "json-uploaded-bucket",
                    "acl": "public-read"
                }
            }
        }
    }).encode("utf-8")

    res = client.post(
        "/api/analyze",
        files={"file": ("infra.tf.json", tf_json_content, "application/json")},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["filename"] == "infra.tf.json"
    assert data["resource_count"] == 1
    assert len(data["threat_findings"]) >= 1
    assert data["threat_findings"][0]["threat_id"] == "THREAT-001"
