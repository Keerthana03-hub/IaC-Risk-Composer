"""
tests/test_infrastructure_mapper.py
-------------------------------------
Focused tests for the Infrastructure Mapping Engine (Step 2).

Run with (from the backend/ directory):
    pytest tests/test_infrastructure_mapper.py -v

Covers the 6 required cases:
    1. Two resources with a valid reference          -> 2 nodes, 1 edge
    2. Two unrelated resources                        -> 2 nodes, 0 edges
    3. Multiple references to the same resource        -> no duplicate edges
    4. A resource referencing itself                   -> no self-edge
    5. Empty resource list                              -> empty nodes/edges
    6. A real .tf file through POST /api/analyze        -> infrastructure_map present
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `pytest` to be run directly from backend/ (this file lives in
# backend/tests/, and the app's modules are imported as top-level
# packages relative to backend/, e.g. `from services...`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from services.infrastructure_mapper import build_infrastructure_map  # noqa: E402
from services.terraform_parser import parse_terraform  # noqa: E402

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test 1 — Two resources with a valid reference
# ---------------------------------------------------------------------------


def test_two_resources_with_valid_reference():
    resources = [
        {"type": "aws_security_group", "name": "web_sg", "attributes": {"name": "web-security-group"}},
        {
            "type": "aws_instance",
            "name": "web_server",
            "attributes": {
                "ami": "ami-12345678",
                "instance_type": "t2.micro",
                "vpc_security_group_ids": ["${aws_security_group.web_sg.id}"],
            },
        },
    ]

    result = build_infrastructure_map(resources)

    assert len(result["nodes"]) == 2
    assert len(result["edges"]) == 1

    edge = result["edges"][0]
    assert edge["source"] == "aws_instance.web_server"
    assert edge["target"] == "aws_security_group.web_sg"
    assert edge["relationship"] == "references"


# ---------------------------------------------------------------------------
# Test 2 — Two unrelated resources
# ---------------------------------------------------------------------------


def test_two_unrelated_resources_produce_no_edges():
    resources = [
        {"type": "aws_s3_bucket", "name": "data_bucket", "attributes": {"bucket": "my-test-bucket"}},
        {"type": "aws_security_group", "name": "web_sg", "attributes": {"name": "web-security-group"}},
    ]

    result = build_infrastructure_map(resources)

    assert len(result["nodes"]) == 2
    assert len(result["edges"]) == 0


# ---------------------------------------------------------------------------
# Test 3 — Multiple references to the same resource -> no duplicate edges
# ---------------------------------------------------------------------------


def test_multiple_references_do_not_duplicate_edges():
    resources = [
        {"type": "aws_security_group", "name": "web_sg", "attributes": {"name": "web-security-group"}},
        {
            "type": "aws_instance",
            "name": "web_server",
            "attributes": {
                # The same target resource id is mentioned three times.
                "vpc_security_group_ids": [
                    "${aws_security_group.web_sg.id}",
                    "${aws_security_group.web_sg.id}",
                ],
                "tags": {"sg_name": "${aws_security_group.web_sg.name}"},
            },
        },
    ]

    result = build_infrastructure_map(resources)

    assert len(result["nodes"]) == 2
    assert len(result["edges"]) == 1  # not 3


# ---------------------------------------------------------------------------
# Test 4 — A resource referencing itself -> no self-referencing edge
# ---------------------------------------------------------------------------


def test_self_reference_produces_no_edge():
    resources = [
        {
            "type": "aws_instance",
            "name": "self_ref_test",
            "attributes": {"depends_on": ["${aws_instance.self_ref_test}"]},
        },
    ]

    result = build_infrastructure_map(resources)

    assert len(result["nodes"]) == 1
    assert len(result["edges"]) == 0


# ---------------------------------------------------------------------------
# Test 5 — Empty resource list -> empty nodes and edges, no crash
# ---------------------------------------------------------------------------


def test_empty_resource_list():
    result = build_infrastructure_map([])

    assert result == {"nodes": [], "edges": []}


# ---------------------------------------------------------------------------
# Test 6 — Upload a real Terraform file through POST /api/analyze
# ---------------------------------------------------------------------------


def test_analyze_endpoint_returns_infrastructure_map():
    tf_content = b"""
resource "aws_security_group" "web_sg" {
  name = "web-security-group"
}

resource "aws_instance" "web_server" {
  ami                    = "ami-12345678"
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-test-bucket"
}
"""

    response = client.post(
        "/api/analyze",
        files={"file": ("main.tf", tf_content, "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()

    # Existing fields must still be present and correct.
    assert data["filename"] == "main.tf"
    assert data["resource_count"] == 3
    assert sorted(data["resource_types"]) == [
        "aws_instance",
        "aws_s3_bucket",
        "aws_security_group",
    ]
    assert len(data["resources"]) == 3

    # New field.
    assert "infrastructure_map" in data
    infra_map = data["infrastructure_map"]
    assert len(infra_map["nodes"]) == 3
    assert len(infra_map["edges"]) == 1
    assert infra_map["edges"][0] == {
        "source": "aws_instance.web_server",
        "target": "aws_security_group.web_sg",
        "relationship": "references",
        "label": "Uses Security Group",
    }


# ---------------------------------------------------------------------------
# Extra: parser -> mapper integration, and empty-file-with-no-resources case
# ---------------------------------------------------------------------------


def test_parser_output_feeds_directly_into_mapper():
    """Sanity check that build_infrastructure_map accepts parse_terraform's
    real output shape directly (not just hand-built test dicts)."""
    tf_content = """
resource "aws_security_group" "web_sg" {
  name = "web-security-group"
}

resource "aws_instance" "web_server" {
  vpc_security_group_ids = [aws_security_group.web_sg.id]
}
"""
    resources = parse_terraform(tf_content)
    result = build_infrastructure_map(resources)

    assert len(result["nodes"]) == 2
    assert len(result["edges"]) == 1


def test_analyze_endpoint_handles_file_with_no_resource_blocks():
    """A syntactically valid .tf file with zero `resource` blocks should
    return empty nodes/edges, not an error."""
    tf_content = b"""
variable "region" {
  default = "us-east-1"
}
"""
    response = client.post(
        "/api/analyze",
        files={"file": ("vars_only.tf", tf_content, "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["resource_count"] == 0
    assert data["infrastructure_map"] == {"nodes": [], "edges": []}
