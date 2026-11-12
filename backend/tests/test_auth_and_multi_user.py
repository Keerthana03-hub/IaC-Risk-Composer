"""
tests/test_auth_and_multi_user.py
---------------------------------
Automated tests for multi-developer registration, login, workspaces/projects,
and strict multi-tenant data isolation.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_registration_validation():
    """Verify registration field validation rules."""
    # Passwords mismatch
    res = client.post(
        "/api/auth/register",
        json={
            "full_name": "Test Developer",
            "username": "testdev_val",
            "email": "testdev_val@example.com",
            "password": "Password123!",
            "confirm_password": "DifferentPassword!",
        },
    )
    assert res.status_code == 400
    assert "Passwords do not match" in res.json()["detail"]

    # Invalid email
    res = client.post(
        "/api/auth/register",
        json={
            "full_name": "Test Developer",
            "username": "testdev_val",
            "email": "not-an-email",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )
    assert res.status_code == 400

    # Short password
    res = client.post(
        "/api/auth/register",
        json={
            "full_name": "Test Developer",
            "username": "testdev_val",
            "email": "testdev_val@example.com",
            "password": "short",
            "confirm_password": "short",
        },
    )
    assert res.status_code == 422


def test_multi_developer_flow_and_data_isolation():
    """
    Test complete multi-tenant workflow:
    1. Register Developer Alice
    2. Alice creates a project and uploads an IaC file
    3. Register Developer Bob
    4. Bob cannot see Alice's projects or analyses
    5. Bob cannot access Alice's report by ID (404)
    6. Bob creates his own project and analysis
    7. Alice logs in again and retrieves her original project and analysis
    """
    import uuid
    suffix = uuid.uuid4().hex[:6]
    alice_user = f"alice_{suffix}"
    alice_email = f"alice_{suffix}@cloudsec.example.com"

    # 1. Register Alice
    alice_reg = client.post(
        "/api/auth/register",
        json={
            "full_name": "Alice Developer",
            "username": alice_user,
            "email": alice_email,
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
            "organization": "Alice Cloud Team",
        },
    )
    assert alice_reg.status_code == 200
    alice_data = alice_reg.json()
    alice_token = alice_data["token"]
    alice_headers = {"Authorization": f"Bearer {alice_token}"}

    # Verify Alice's profile
    me_res = client.get("/api/auth/me", headers=alice_headers)
    assert me_res.status_code == 200
    assert me_res.json()["username"] == alice_user

    # Alice has an initial default project created
    projects_res = client.get("/api/projects", headers=alice_headers)
    assert projects_res.status_code == 200
    alice_projects = projects_res.json()
    assert len(alice_projects) >= 1
    alice_proj_id = alice_projects[0]["id"]

    # Alice creates a custom project
    new_proj_res = client.post(
        "/api/projects",
        headers=alice_headers,
        json={"name": "Payment Gateway Infrastructure", "description": "PCI-DSS compliant VPC"},
    )
    assert new_proj_res.status_code == 201
    alice_payment_proj_id = new_proj_res.json()["id"]

    # Alice uploads an analysis to her Payment Gateway project
    alice_tf = b"""
resource "aws_s3_bucket" "alice_payments" {
  bucket = "alice-pci-payments-vault"
  acl    = "public-read"
}
"""
    analyze_res = client.post(
        "/api/analyze",
        headers=alice_headers,
        data={"project_id": alice_payment_proj_id},
        files={"file": ("alice_payment_infra.tf", alice_tf, "text/plain")},
    )
    assert analyze_res.status_code == 200
    alice_report_id = analyze_res.json()["id"]
    assert analyze_res.json()["project_id"] == alice_payment_proj_id

    # Verify Alice sees her report in /api/reports
    alice_reports_res = client.get("/api/reports", headers=alice_headers)
    assert alice_reports_res.status_code == 200
    alice_report_ids = [r["id"] for r in alice_reports_res.json()]
    assert alice_report_id in alice_report_ids

    bob_user = f"bob_{suffix}"
    bob_email = f"bob_{suffix}@fintech.example.com"

    # 2. Register Bob
    bob_reg = client.post(
        "/api/auth/register",
        json={
            "full_name": "Bob Architect",
            "username": bob_user,
            "email": bob_email,
            "password": "SecurePassword456!",
            "confirm_password": "SecurePassword456!",
            "organization": "Bob Systems",
        },
    )
    assert bob_reg.status_code == 200
    bob_token = bob_reg.json()["token"]
    bob_headers = {"Authorization": f"Bearer {bob_token}"}

    # 3. Bob checks his projects -> He does NOT see Alice's project!
    bob_projects_res = client.get("/api/projects", headers=bob_headers)
    assert bob_projects_res.status_code == 200
    bob_proj_names = [p["name"] for p in bob_projects_res.json()]
    assert "Payment Gateway Infrastructure" not in bob_proj_names

    # 4. Bob checks his reports -> He does NOT see Alice's report!
    bob_reports_res = client.get("/api/reports", headers=bob_headers)
    assert bob_reports_res.status_code == 200
    bob_report_ids = [r["id"] for r in bob_reports_res.json()]
    assert alice_report_id not in bob_report_ids

    # 5. Bob tries to access Alice's report directly by ID -> 404 Not Found!
    direct_hack_res = client.get(f"/api/reports/{alice_report_id}", headers=bob_headers)
    assert direct_hack_res.status_code == 404

    direct_hack_pdf = client.get(f"/api/reports/{alice_report_id}/pdf", headers=bob_headers)
    assert direct_hack_pdf.status_code == 404

    # 6. Bob creates his own project and analysis
    bob_proj_res = client.post(
        "/api/projects",
        headers=bob_headers,
        json={"name": "Bob Analytics Cluster", "description": "Spark & Kafka workers"},
    )
    assert bob_proj_res.status_code == 201
    bob_proj_id = bob_proj_res.json()["id"]

    bob_tf = b"""
resource "aws_security_group" "bob_cluster_sg" {
  name = "analytics-sg"
}
"""
    bob_analyze_res = client.post(
        "/api/analyze",
        headers=bob_headers,
        data={"project_id": bob_proj_id},
        files={"file": ("bob_cluster.tf", bob_tf, "text/plain")},
    )
    assert bob_analyze_res.status_code == 200
    bob_report_id = bob_analyze_res.json()["id"]

    # Bob's reports list contains Bob's report and NOT Alice's
    bob_reports_after = client.get("/api/reports", headers=bob_headers).json()
    bob_after_ids = [r["id"] for r in bob_reports_after]
    assert bob_report_id in bob_after_ids
    assert alice_report_id not in bob_after_ids

    # 7. Alice logs in again using username and password (Returning User Experience)
    alice_login_res = client.post(
        "/api/auth/login",
        json={"username_or_email": alice_user, "password": "SecurePassword123!"},
    )
    assert alice_login_res.status_code == 200
    fresh_alice_token = alice_login_res.json()["token"]
    fresh_alice_headers = {"Authorization": f"Bearer {fresh_alice_token}"}

    # Alice's projects are retrieved!
    alice_retrieved_projects = client.get("/api/projects", headers=fresh_alice_headers).json()
    alice_p_names = [p["name"] for p in alice_retrieved_projects]
    assert "Payment Gateway Infrastructure" in alice_p_names

    # Alice's previous analysis is retrieved!
    alice_retrieved_reports = client.get("/api/reports", headers=fresh_alice_headers).json()
    alice_r_ids = [r["id"] for r in alice_retrieved_reports]
    assert alice_report_id in alice_r_ids


def test_user_profile_and_account_management():
    """Verify profile updates, preference saving, password change, and account deletion."""
    import uuid
    uid = uuid.uuid4().hex[:6]
    username = f"charlie_{uid}"
    email = f"charlie_{uid}@test.org"

    # Register
    reg = client.post(
        "/api/auth/register",
        json={
            "full_name": "Charlie Engineer",
            "username": username,
            "email": email,
            "password": "InitialPassword123!",
            "confirm_password": "InitialPassword123!",
        },
    )
    assert reg.status_code == 200
    token = reg.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Update profile & preferences
    up_res = client.put(
        "/api/auth/profile",
        headers=headers,
        json={
            "full_name": "Charlie Lead Architect",
            "organization": "Security Corp",
            "preferences": {"theme": "light", "notify_critical": True, "min_severity": "medium"},
        },
    )
    assert up_res.status_code == 200
    profile = up_res.json()
    assert profile["full_name"] == "Charlie Lead Architect"
    assert profile["organization"] == "Security Corp"
    assert profile["preferences"]["theme"] == "light"

    # Change password
    pwd_res = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={
            "current_password": "InitialPassword123!",
            "new_password": "UpdatedPassword456!",
            "confirm_password": "UpdatedPassword456!",
        },
    )
    assert pwd_res.status_code == 200

    # Old password fails
    fail_res = client.post(
        "/api/auth/login",
        json={"username_or_email": username, "password": "InitialPassword123!"},
    )
    assert fail_res.status_code == 401

    # New password succeeds
    ok_res = client.post(
        "/api/auth/login",
        json={"username_or_email": username, "password": "UpdatedPassword456!"},
    )
    assert ok_res.status_code == 200
    new_token = ok_res.json()["token"]

    # Delete account
    del_res = client.delete("/api/auth/account", headers={"Authorization": f"Bearer {new_token}"})
    assert del_res.status_code == 200

    # Account no longer exists
    after_del = client.post(
        "/api/auth/login",
        json={"username_or_email": username, "password": "UpdatedPassword456!"},
    )
    assert after_del.status_code == 401

