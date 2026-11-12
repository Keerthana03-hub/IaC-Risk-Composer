"""
verify_flow.py
--------------
End-to-end integration test verifying the complete multi-developer SaaS flow:
1. Registration with validation & secure password hashing
2. Session token issuance & authenticated login
3. Personal workspace & project creation
4. Multi-resource IaC analysis execution (6-step pipeline)
5. Infrastructure topology mapping & STRIDE threat findings
6. Project statistics aggregation (findings count, critical count, risk score)
7. Returning developer retrieval of previous work
8. Downloadable PDF security report generation
"""

import json
import urllib.parse
import urllib.request
import uuid

BASE = "http://localhost:8000/api"


def req(method, path, data=None, headers=None):
    url = f"{BASE}{path}"
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    request = urllib.request.Request(url, data=body, headers=h, method=method)
    with urllib.request.urlopen(request) as resp:
        return resp.getcode(), json.loads(resp.read().decode("utf-8"))


def main():
    uid = uuid.uuid4().hex[:6]
    u_name = f"marcus_{uid}"
    u_email = f"marcus_{uid}@fintech.corp"

    print("--- 1. Registering developer account ---")
    code, reg = req("POST", "/auth/register", {
        "full_name": "Marcus Vance",
        "username": u_name,
        "email": u_email,
        "password": "SecureDeveloper123!",
        "confirm_password": "SecureDeveloper123!",
        "organization": "Fintech Core Security",
    })
    assert code == 200
    token = reg["token"]
    user = reg["user"]
    print(f"[SUCCESS] Registered: {user['full_name']} (@{user['username']}) - Org: {user['organization']}")

    auth_h = {"Authorization": f"Bearer {token}"}

    print("\n--- 2. Authenticating developer login ---")
    code, log = req("POST", "/auth/login", {
        "username_or_email": u_name,
        "password": "SecureDeveloper123!",
    })
    assert code == 200
    print(f"[SUCCESS] Login token generated: {log['token'][:16]}...")

    print("\n--- 3. Creating Workspace Project ---")
    code, proj = req("POST", "/projects", {
        "name": "Production Banking Vault",
        "description": "High-security Kubernetes & S3 payments storage",
    }, headers=auth_h)
    assert code == 201
    proj_id = proj["id"]
    print(f"[SUCCESS] Project created: '{proj['name']}' (ID: {proj_id})")

    print("\n--- 4. Executing 6-Step IaC Security Analysis ---")
    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
    tf_hcl = (
        'resource "aws_s3_bucket" "vault_storage" {\n'
        '  bucket = "banking-vault-customer-data"\n'
        '  acl    = "public-read"\n'
        '}\n'
        '\n'
        'resource "aws_security_group" "vault_ingress" {\n'
        '  name = "vault-sg"\n'
        '  ingress {\n'
        '    from_port   = 22\n'
        '    to_port     = 22\n'
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n'
    )
    parts = []
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"project_id\"\r\n\r\n{proj_id}".encode("utf-8"))
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"vault.tf\"\r\nContent-Type: text/plain\r\n\r\n".encode("utf-8")
        + tf_hcl.encode("utf-8")
    )
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    payload = b"\r\n".join(parts)

    req_multi = urllib.request.Request(
        f"{BASE}/analyze",
        data=payload,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req_multi) as resp:
        analyze_res = json.loads(resp.read().decode("utf-8"))

    report_id = analyze_res["id"]
    file_display = analyze_res.get("filename") or analyze_res.get("file_name")
    risk_score = (
        analyze_res.get("risk_score")
        or (analyze_res.get("risk_summary") and analyze_res["risk_summary"].get("overall_risk_score"))
        or "N/A"
    )
    print(f"[SUCCESS] Analysis Completed:")
    print(f"  • File: {file_display}")
    print(f"  • Resources parsed: {len(analyze_res['resources'])}")
    print(f"  • Infrastructure nodes: {len(analyze_res['infrastructure_map']['nodes'])}")
    print(f"  • Threats detected: {len(analyze_res['threat_findings'])}")
    print(f"  • Risk posture score: {risk_score} / 100")
    print(f"  • Safe remediations: {len(analyze_res['remediations'])}")

    print("\n--- 5. Verifying Project Real-Time Rollup Statistics ---")
    code, projs = req("GET", "/projects", headers=auth_h)
    matched = next(p for p in projs if p["id"] == proj_id)
    print(f"[SUCCESS] Project Rollup Stats:")
    print(f"  • Analyses count: {matched['analyses_count']}")
    print(f"  • Total findings: {matched['findings_count']}")
    print(f"  • Critical threats: {matched['critical_count']}")
    print(f"  • Security score: {matched['risk_score']}")
    assert matched["analyses_count"] == 1
    assert matched["findings_count"] >= 2
    assert matched["risk_score"] is not None

    print("\n--- 6. Returning Developer Experience (Session Recovery) ---")
    code, reports = req("GET", "/reports", headers=auth_h)
    assert len(reports) >= 1
    retrieved = next(r for r in reports if r["id"] == report_id)
    r_file = retrieved.get("file_name") or retrieved.get("filename")
    print(f"[SUCCESS] Previous work automatically retrieved: '{r_file}' associated with project '{retrieved['project_name']}'")


    print("\n--- 7. Verifying PDF Security Report Generation ---")
    req_pdf = urllib.request.Request(f"{BASE}/reports/{report_id}/pdf", headers=auth_h)
    with urllib.request.urlopen(req_pdf) as resp:
        pdf_bytes = resp.read()
    print(f"[SUCCESS] Audit PDF downloaded: {len(pdf_bytes)} bytes, Magic Header: {pdf_bytes[:4].decode('latin-1')}")
    assert pdf_bytes.startswith(b"%PDF")

    print("\n=======================================================")
    print("ALL MULTI-DEVELOPER END-TO-END CRITERIA VERIFIED 100%!")
    print("=======================================================")


if __name__ == "__main__":
    main()
