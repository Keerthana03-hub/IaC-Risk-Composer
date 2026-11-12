# IaC Risk Composer

A modern cybersecurity platform for analysing Infrastructure as Code (IaC) templates, identifying security risks, and generating actionable remediation guidance for cloud-native environments.

The platform helps teams review Terraform, CloudFormation, and Kubernetes infrastructure definitions before deployment, surfacing misconfigurations, exposure paths, and risk-prone design patterns in a clear, developer-friendly interface.

## Why this project exists

Infrastructure definitions are often treated as code, but security review is frequently delayed until after deployment. IaC Risk Composer brings risk analysis earlier in the lifecycle by combining:

- IaC parsing and normalization
- Threat detection for common cloud misconfigurations
- Infrastructure graph mapping
- Risk scoring and attack-path analysis
- Evidence-based explanations and safe remediation suggestions
- Persistent project and report history for development teams

## Key features

- Terraform analysis with structure extraction and resource mapping
- CloudFormation and Kubernetes support through a shared parser registry
- Threat detection across common security categories such as public exposure, weak access control, unsafe encryption, and service exposure
- Risk assessment using likelihood, impact, and confidence-based scoring
- Attack-path analysis to identify how an exposed asset could lead to a sensitive target
- Rule-based remediation recommendations and safe Terraform patch generation
- Developer-friendly web UI for analysis, reports, history, and dashboard metrics
- Multi-user project workspace with authentication and persisted analysis records

## Architecture

This application follows a modular architecture:

- Frontend: React + Vite + Tailwind CSS
- Backend: Python + FastAPI
- Data layer: SQLite for local persistence
- Analysis engine: parser registry, threat engine, infrastructure mapper, risk engine, and remediation engine

## Project structure

```text
project/
├── backend/
│   ├── docs/
│   ├── routers/
│   ├── services/
│   ├── tests/
│   ├── database.py
│   ├── main.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── tailwind.config.js
├── README.md
└── .gitignore
```

## Technology stack

| Layer | Technologies |
| --- | --- |
| Frontend | React, Vite, Tailwind CSS, React Router |
| Backend | Python, FastAPI, Pydantic |
| Persistence | SQLite |
| IaC parsing | Python HCL parser, registry-based extensible parsers |
| Reporting | PDF generation for security assessment exports |

## Prerequisites

- Node.js 18+
- Python 3.11+
- pip

## Quick start

### 1. Start the backend

```bash
cd project/backend

python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The API will be available at:

- http://localhost:8000
- Swagger UI: http://localhost:8000/docs

### 2. Start the frontend

```bash
cd project/frontend
npm install
npm run dev
```

The application will be available at:

- http://localhost:5173

The frontend dev server is configured to proxy API requests to the backend automatically during local development.

## Demo authentication

A default development user is available for quick access:

| Username | Password |
| --- | --- |
| admin | admin |

## Main API endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/health | Health check for the backend service |
| POST | /api/auth/register | Register a new developer account |
| POST | /api/auth/login | Authenticate and receive a token |
| GET | /api/projects | List project workspaces |
| POST | /api/projects | Create a project |
| POST | /api/analyze | Submit IaC content for analysis |
| GET | /api/reports | List saved analyses and reports |
| GET | /api/reports/{report_id} | Retrieve a saved analysis |
| POST | /api/report | Generate a downloadable PDF report |
| GET | /api/dashboard/stats | Retrieve dashboard metrics |

## Example analysis flow

1. Upload or define an IaC template
2. Parse infrastructure resources and normalize them into a graph
3. Detect mapping and threat patterns
4. Score risks based on exposure and impact
5. Generate evidence-supported explanations
6. Provide remediation and safe patch suggestions
7. Persist the analysis and export a report PDF

## Notes on implementation

This project is designed as a functional security analysis prototype with a deterministic rule-based engine. It is suitable for local development, security assessment workflows, and iterative extension with additional parsers or LLM-based explanation providers in the future.

## Contributing

Contributions are welcome. To keep the project maintainable:

- keep backend services modular and focused
- add tests for parsing, threat detection, and remediation logic
- prefer deterministic security logic where evidence is required
- document any new parser or rule additions clearly

## License

This project is intended for internal or educational use unless otherwise specified by the owning organization.

