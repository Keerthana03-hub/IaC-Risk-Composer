"""
routers/analysis.py
---------------------
Analysis route definitions.

Current routes
--------------
GET  /api/health   – liveness probe
POST /api/analyze  – upload a Terraform (.tf) file, parse it (Step 1),
                      generate an infrastructure map of nodes/edges (Step 2),
                      detect security threats via templates (Step 3),
                      assess inherent/adjusted risks and summary (Step 4),
                      generate evidence-grounded risk explanations (Step 5),
                      and generate safe remediation recommendations/fixes (Step 6).

Note on Step 5 and Step 6:
-------------------------
Steps 5 and 6 currently use deterministic, rule-based generation
(`services.risk_explainer.RuleBasedExplanationProvider` and
`services.remediation_engine.RuleBasedRemediationProvider`), not a live external LLM.
Safe Terraform code patches are generated only for supported rules (e.g. S3 missing
encryption via aws_s3_bucket_server_side_encryption_configuration) without inventing
KMS ARNs. User files are never modified or overwritten automatically.
Integration with an authorized LLM (such as IBM watsonx.ai) is supported via the
modular provider interfaces as a future extension.
"""

from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from database import UserRecord, get_analysis, save_analysis
from routers.auth import get_current_user_optional
from services.attack_path_engine import analyze_attack_paths
from services.infrastructure_mapper import build_infrastructure_map
from services.parser_registry import (
    MalformedIaCError,
    UnsupportedFormatError,
    default_parser_registry,
)
from services.remediation_engine import generate_remediations
from services.risk_engine import assess_risks
from services.risk_explainer import explain_findings
from services.terraform_parser import TerraformParseError, parse_terraform
from services.threat_engine import analyze_threats

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str
    version: str


class RiskAssessment(BaseModel):
    """Risk assessment scoring details for a single threat finding (Step 4)."""

    likelihood: int | None = None
    impact: int | None = None
    inherent_risk_score: int | None = None
    risk_level: str | None = None
    confidence_factor: float | None = None
    confidence_adjusted_score: float | None = None
    assessment_status: str
    scoring_explanation: str
    scoring_method: str = "Likelihood × Impact"


class RiskSummary(BaseModel):
    """Aggregate risk posture metrics for the uploaded infrastructure (Step 4)."""

    total_findings: int
    confirmed_findings: int
    needs_review_findings: int
    low_risk_count: int
    medium_risk_count: int
    high_risk_count: int
    critical_risk_count: int
    highest_inherent_risk_score: int | None = None
    overall_risk_level: str


class RiskExplanation(BaseModel):
    """Evidence-grounded explanation for a security threat finding (Step 5)."""

    finding_id: str
    summary: str
    why_it_matters: str
    evidence_explanation: str
    uncertainty: str
    recommended_actions: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    explanation_status: str
    explanation_method: str = "rule_based"


class RemediationRecommendation(BaseModel):
    """Actionable remediation recommendation and safe Terraform patch (Step 6)."""

    remediation_id: str
    finding_id: str
    affected_resource_id: str
    affected_resource_type: str
    affected_resource_name: str
    title: str
    explanation: str
    recommended_actions: list[str] = Field(default_factory=list)
    suggested_code: str | None = None
    patch_type: str
    assumptions: list[str] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)
    remediation_status: str
    generated_by: str = "rule_based"


class ThreatFinding(BaseModel):
    """A single security finding produced by the threat detection engine."""

    finding_id: str
    threat_id: str
    title: str
    description: str
    affected_resource_id: str
    affected_resource_type: str
    affected_resource_name: str
    resource_id: str | None = None
    resource_type: str | None = None
    source_format: str | None = None
    severity: str
    detection_status: str
    confidence: str
    evidence: Any = Field(default_factory=dict)
    impact: str
    recommendation: str
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    risk_assessment: RiskAssessment | None = None


class TerraformResource(BaseModel):
    """A single flattened `resource "type" "name" {...}` block."""

    type: str
    name: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class AttackPathHopModel(BaseModel):
    """A single hop along an attack path."""

    step: int
    source: str
    target: str
    relationship: str
    details: str


class AttackPathModel(BaseModel):
    """A potential attack path from exposed entry point to sensitive target."""

    path_id: str
    source_format: str
    entry_point: str
    target_resource: str
    resource_path: list[str] = Field(default_factory=list)
    severity: str
    confidence: str
    assessment_status: str
    description: str
    evidence: list[AttackPathHopModel] = Field(default_factory=list)
    related_findings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class TerraformAnalysisResponse(BaseModel):
    """
    Result of parsing an uploaded .tf file.

    Includes:
    - structural parsing (resources, resource_types, resource_count)
    - infrastructure_map (nodes and edges)
    - threat_findings (detected security misconfigurations from Step 3 with Step 4 risk assessments)
    - risk_summary (aggregate posture metrics from Step 4)
    - risk_explanations (evidence-grounded explanations from Step 5)
    - remediations (actionable remediation recommendations and safe code patches from Step 6)
    - attack_paths (relationship-aware attack paths from Step 7 / Stage 6)
    """

    id: str | None = None
    user_id: str | None = None
    project_id: str | None = None
    project_name: str | None = None
    created_at: str | None = None
    filename: str
    resource_count: int = 0
    resource_types: list[str] = Field(default_factory=list)
    resources: list[TerraformResource] = Field(default_factory=list)
    infrastructure_map: "InfrastructureMap" = Field(default_factory=lambda: InfrastructureMap())
    threat_findings: list[ThreatFinding] = Field(default_factory=list)
    risk_summary: RiskSummary | None = None
    risk_explanations: list[RiskExplanation] = Field(default_factory=list)
    remediations: list[RemediationRecommendation] = Field(default_factory=list)
    attack_paths: list[AttackPathModel] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Infrastructure Mapping (Nodes & Edges) — Step 2
# ---------------------------------------------------------------------------


class InfrastructureNode(BaseModel):
    """A single infrastructure resource, as a graph node."""

    id: str
    resource_type: str
    name: str
    label: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class InfrastructureEdge(BaseModel):
    """
    A relationship between two resources, discovered from an actual
    reference in one resource's attributes to another resource's id.
    `source` is the resource that contains the reference; `target` is
    the resource being referenced.
    """

    source: str
    target: str
    relationship: str
    label: str


class InfrastructureMap(BaseModel):
    """The full infrastructure graph produced from one Terraform file."""

    nodes: list[InfrastructureNode] = Field(default_factory=list)
    edges: list[InfrastructureEdge] = Field(default_factory=list)


TerraformAnalysisResponse.model_rebuild()


# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    tags=["system"],
)
def health_check() -> HealthResponse:
    """Return a simple liveness response so the frontend can verify connectivity."""
    return HealthResponse(status="ok", version="0.2.0")


# ---------------------------------------------------------------------------
# POST /api/analyze
# ---------------------------------------------------------------------------


@router.post(
    "/analyze",
    response_model=TerraformAnalysisResponse,
    summary="Upload and parse a Terraform (.tf) file",
    tags=["analysis"],
)
async def analyze_terraform(
    file: UploadFile = File(...),
    project_id: str | None = Form(None),
    user: UserRecord | None = Depends(get_current_user_optional),
) -> TerraformAnalysisResponse:
    """
    Accept a single Terraform (.tf) file upload, parse it with
    `python-hcl2`, and return the resource blocks it declares.

    Handles: no file, invalid extension, empty file, invalid Terraform
    syntax / parsing errors — each with a clear message and an
    appropriate HTTP status code.
    """
    # ── No file ──────────────────────────────────────────────────────────
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file was provided.")

    # ── Invalid extension ───────────────────────────────────────────────
    allowed_exts = (".tf", ".tf.json", ".yaml", ".yml", ".json")
    if not any(file.filename.lower().endswith(ext) for ext in allowed_exts):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file extension. Supported extensions are: {', '.join(allowed_exts)}",
        )

    raw_bytes = await file.read()

    # ── Empty file ───────────────────────────────────────────────────────
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # ── Not decodable as text ───────────────────────────────────────────
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"File is not valid UTF-8 text: {exc}",
        ) from exc

    # ── Parsing via Multi-IaC Parser Registry ────────────────────────────
    try:
        norm_infra = default_parser_registry.parse(content, filename=file.filename)
        resources = norm_infra.to_legacy_resources()
    except (MalformedIaCError, TerraformParseError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except UnsupportedFormatError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Infrastructure mapping (Step 2): build the nodes/edges graph from
    # the same parsed resources. Returns {"nodes": [], "edges": []}
    # without error when `resources` is empty.
    infrastructure_map = build_infrastructure_map(resources)

    threat_findings = analyze_threats(
        resources,
        infrastructure_map,
        source_format=norm_infra.source_format,
        normalized_infrastructure=norm_infra,
    )

    # Risk Assessment and Scoring Engine (Step 4): compute Likelihood, Impact,
    # Inherent Risk Score, Risk Level, Confidence-Adjusted Score, and Risk Summary.
    assessed_findings, risk_summary = assess_risks(threat_findings)

    # AI-Powered Risk Explanation Engine (Step 5): generate evidence-grounded,
    # plain-language explanations for all findings.
    risk_explanations = explain_findings(assessed_findings)

    # Security Recommendations and Safe Terraform Fix Generation (Step 6):
    # generate actionable remediation recommendations and safe code patches.
    remediations = generate_remediations(assessed_findings, resources)

    # Relationship-Aware Attack Path Analysis Engine (Step 7 / Stage 6):
    # discover potential lateral movement paths from exposed entry points to sensitive targets.
    attack_paths = analyze_attack_paths(
        resources=resources,
        threat_findings=assessed_findings,
        source_format=norm_infra.source_format,
        normalized_infrastructure=norm_infra,
        infrastructure_map=infrastructure_map,
    )

    # Persistent Storage: Save complete analysis to SQLite database scoped to user & project
    user_id = user.id if user else None
    analysis_payload = {
        "filename": file.filename,
        "resource_count": len(resources),
        "resource_types": sorted({r["type"] for r in resources}),
        "resources": resources,
        "infrastructure_map": infrastructure_map,
        "threat_findings": assessed_findings,
        "risk_summary": risk_summary,
        "risk_explanations": risk_explanations,
        "remediations": remediations,
        "attack_paths": attack_paths,
    }
    saved_meta = save_analysis(
        analysis_data=analysis_payload,
        user_id=user_id,
        project_id=project_id,
    )

    return TerraformAnalysisResponse(
        id=saved_meta.get("id"),
        user_id=saved_meta.get("user_id"),
        project_id=saved_meta.get("project_id"),
        project_name=saved_meta.get("project_name"),
        created_at=saved_meta.get("created_at"),
        filename=file.filename,
        resource_count=len(resources),
        resource_types=sorted({r["type"] for r in resources}),
        resources=resources,
        infrastructure_map=infrastructure_map,
        threat_findings=assessed_findings,
        risk_summary=risk_summary,
        risk_explanations=risk_explanations,
        remediations=remediations,
        attack_paths=attack_paths,
    )


# ---------------------------------------------------------------------------
# GET /api/analysis/{analysis_id}/attack-paths
# ---------------------------------------------------------------------------


@router.get(
    "/analysis/{analysis_id}/attack-paths",
    response_model=list[AttackPathModel],
    summary="Retrieve discovered attack paths for a specific analysis ID",
    tags=["analysis"],
)
def get_attack_paths_for_analysis(
    analysis_id: str,
    user: UserRecord | None = Depends(get_current_user_optional),
) -> list[dict[str, Any]]:
    """
    Retrieve all relationship-aware attack paths discovered for a saved analysis.
    """
    user_id = user.id if user else None
    analysis = get_analysis(analysis_id, user_id=user_id)
    if not analysis:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis '{analysis_id}' not found.",
        )
    return analysis.get("attack_paths", [])

