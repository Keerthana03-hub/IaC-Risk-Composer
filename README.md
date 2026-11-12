# IaC Risk Composer

> **Cybersecurity platform for analysing Infrastructure-as-Code (IaC) and generating threat-model information.**

---

## Project Structure

```
iac-risk-composer/
├── frontend/           React + Vite + Tailwind CSS + React Router
├── backend/            Python FastAPI REST API
├── threat_engine/      (future) Rule-based Terraform / CloudFormation scanner
├── ml_model/           (future) Custom ML risk-prediction model
├── threat_templates/   (future) STRIDE / MITRE ATT&CK threat templates
├── reports/            (future) Generated PDF / HTML reports
└── README.md
```

---

## Quick Start

### Prerequisites

| Tool    | Version  |
|---------|----------|
| Node.js | ≥ 18     |
| Python  | ≥ 3.11   |
| pip     | latest   |

---

### 1 – Start the Backend

```bash
cd iac-risk-composer/backend

# Create and activate a virtual environment
py -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the dev server (hot-reload)
uvicorn main:app --reload --port 8000
```

The API will be available at **http://localhost:8000**

Interactive docs (Swagger UI): **http://localhost:8000/docs**

---

### 2 – Start the Frontend

```bash
cd iac-risk-composer/frontend

# Install dependencies
npm install

# Start the Vite dev server
npm run dev
```

The app will be available at **http://localhost:5173**

> Vite proxies all `/api/*` requests to `http://localhost:8000` automatically —
> no manual CORS configuration needed during development.

---

### Demo Credentials

| Username | Password |
|----------|----------|
| admin    | admin    |

---

## API Reference

| Method | Path           | Description                        |
|--------|----------------|------------------------------------|
| GET    | `/api/health`  | Liveness probe – returns API version |
| POST   | `/api/analyze` | Submit IaC content for analysis    |

### POST /api/analyze – Request body

```json
{
  "iac_content": "resource \"aws_s3_bucket\" ...",
  "iac_type": "terraform",
  "project_name": "my-project"
}
```

`iac_type` accepts: `terraform` | `cloudformation` | `kubernetes` | `ansible`

### POST /api/analyze – Response (Phase 1 placeholder)

```json
{
  "status": "placeholder",
  "message": "...",
  "findings": [ { "id": "...", "severity": "HIGH", ... } ],
  "risk_score": 72,
  "iac_type": "terraform"
}
```

---

## Frontend Pages

| Route        | Page             | Description                             |
|--------------|------------------|-----------------------------------------|
| `/login`     | Login            | Demo auth (admin / admin)               |
| `/dashboard` | Dashboard        | Platform overview + API health check    |
| `/analyze`   | IaC Analysis     | Submit IaC → view findings + risk score |
| `/reports`   | Threat Reports   | List of generated reports (mocked)      |
| `/history`   | Project History  | Chronological scan history (mocked)     |

---

## Planned Features (Future Phases)

- [ ] **Terraform parser** – HCL AST analysis via `python-hcl2`
- [ ] **CloudFormation parser** – YAML/JSON template analysis
- [ ] **Threat detection engine** – Rule-based finding engine in `threat_engine/`
- [ ] **ML risk prediction** – Custom model in `ml_model/`
- [ ] **AI/LLM explanations** – GPT / watsonx remediation advice
- [ ] **Security control recommendations** – Mapped to CIS / NIST benchmarks
- [ ] **GitHub PR integration** – Automated scan on pull-request webhook
- [ ] **PDF report export** – Generated reports stored in `reports/`
- [ ] **Persistent storage** – PostgreSQL via SQLAlchemy
- [ ] **Real authentication** – JWT / Auth0 / Cognito

---

## Development Notes

- Backend CORS is configured to allow `http://localhost:5173` only. Update
  `main.py` `allow_origins` for production deployments.
- All mock/placeholder data is clearly labeled with comments and UI notices.
- The `threat_engine/`, `ml_model/`, `threat_templates/`, and `reports/`
  directories each contain a `README.md` describing what will go there.

# IaC-Risk-Composer

