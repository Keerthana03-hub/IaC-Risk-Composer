"""
tests/test_storage_and_history.py
---------------------------------
Automated test suite for persistent analysis storage, history retrieval,
report management, and dashboard metrics.

Run with:
    .venv\\Scripts\\python.exe -m pytest tests/test_storage_and_history.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402

client = TestClient(app)


def test_1_analyze_persists_and_returns_id():
    """POST /api/analyze persists the analysis to SQLite and returns report id."""
    tf_content = b"""
resource "aws_security_group" "db_sg" {
  name = "db-security-group"

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "secure_vault" {
  bucket = "company-secure-vault-2026"
  acl    = "private"
}
"""
    res = client.post(
        "/api/analyze",
        files={"file": ("vault_infra.tf", tf_content, "text/plain")},
    )
    assert res.status_code == 200
    data = res.json()

    assert "id" in data
    assert data["id"].startswith("RPT-")
    assert "created_at" in data
    assert data["resource_count"] == 2
    assert len(data["threat_findings"]) >= 2

    report_id = data["id"]

    # Verify listing includes this report
    list_res = client.get("/api/reports")
    assert list_res.status_code == 200
    reports = list_res.json()
    assert any(r["id"] == report_id for r in reports)

    # Verify retrieving full saved report by ID
    get_res = client.get(f"/api/reports/{report_id}")
    assert get_res.status_code == 200
    fetched = get_res.json()
    assert fetched["id"] == report_id
    assert fetched["filename"] == "vault_infra.tf"
    assert "threat_findings" in fetched
    assert "risk_summary" in fetched
    assert "risk_explanations" in fetched
    assert "remediations" in fetched

    # Verify downloading PDF by ID
    pdf_res = client.get(f"/api/reports/{report_id}/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF")
    assert "attachment" in pdf_res.headers.get("content-disposition", "")


def test_2_dashboard_stats_endpoint():
    """GET /api/dashboard/stats returns real aggregated posture metrics."""
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    stats = res.json()

    assert "total_scans" in stats
    assert "total_resources" in stats
    assert "open_findings" in stats
    assert "projects_analysed" in stats
    assert "recent_findings" in stats
    assert isinstance(stats["recent_findings"], list)


def test_3_delete_report_endpoint():
    """DELETE /api/reports/{id} removes the report and subsequent GET returns 404."""
    # First create an analysis
    tf_content = b"""
resource "aws_s3_bucket" "temp_bucket" {
  bucket = "temp-to-delete"
}
"""
    create_res = client.post(
        "/api/analyze",
        files={"file": ("to_delete.tf", tf_content, "text/plain")},
    )
    report_id = create_res.json()["id"]

    # Delete it
    del_res = client.delete(f"/api/reports/{report_id}")
    assert del_res.status_code == 200
    assert del_res.json()["id"] == report_id

    # Confirm 404 on subsequent retrieval
    get_res = client.get(f"/api/reports/{report_id}")
    assert get_res.status_code == 404

    # Confirm 404 on PDF retrieval
    pdf_res = client.get(f"/api/reports/{report_id}/pdf")
    assert pdf_res.status_code == 404


def test_4_nonexistent_report_returns_404():
    """Retrieving a non-existent report ID returns 404 Not Found."""
    res = client.get("/api/reports/NON-EXISTENT-ID")
    assert res.status_code == 404

    res_pdf = client.get("/api/reports/NON-EXISTENT-ID/pdf")
    assert res_pdf.status_code == 404

    res_del = client.delete("/api/reports/NON-EXISTENT-ID")
    assert res_del.status_code == 404
