"""
routers/reports.py
------------------
Report and historical analysis route definitions with multi-tenant developer isolation.

Endpoints:
----------
POST   /api/report                  – Generate and download PDF from analysis payload
GET    /api/reports                 – List all saved analyses/reports (filtered by developer)
GET    /api/reports/{report_id}     – Retrieve a single full saved analysis JSON
GET    /api/reports/{report_id}/pdf – Download PDF for a saved analysis
DELETE /api/reports/{report_id}     – Delete a saved analysis record
GET    /api/dashboard/stats         – Aggregated metrics for live dashboard
GET    /api/reports/stats           – Alias for aggregated metrics
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from database import (
    UserRecord,
    delete_analysis,
    get_analysis,
    get_analysis_pdf,
    get_dashboard_stats,
    list_analyses,
)
from routers.analysis import TerraformAnalysisResponse
from routers.auth import get_current_user_optional
from services.report_generator import generate_pdf_report

router = APIRouter(tags=["reports"])


@router.post(
    "/report",
    summary="Generate and download a PDF security assessment report",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Returns a downloadable PDF security assessment report.",
        },
        400: {"description": "Invalid analysis data provided."},
        422: {"description": "Validation error in analysis payload."},
        500: {"description": "Failed to compile PDF report."},
    },
)
async def generate_report_endpoint(analysis: TerraformAnalysisResponse) -> Response:
    """
    Accept an existing Terraform analysis response (produced by POST /api/analyze)
    and generate a professional, downloadable PDF security assessment report.
    """
    try:
        pdf_bytes = generate_pdf_report(analysis)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate security assessment report: {exc}",
        ) from exc

    # Sanitize the input filename for the Content-Disposition header
    raw_stem = Path(analysis.filename).stem if analysis.filename else "iac_security"
    safe_stem = re.sub(r"[^a-zA-Z0-9_\-]", "_", raw_stem).strip("_") or "iac_security"
    download_filename = f"{safe_stem}_security_report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{download_filename}"',
            "Content-Type": "application/pdf",
        },
    )


@router.get(
    "/reports",
    summary="List saved security reports/analyses for authenticated developer",
    response_model=list[dict[str, Any]],
)
def get_saved_reports_endpoint(
    project_id: str | None = Query(None),
    user: UserRecord | None = Depends(get_current_user_optional),
) -> list[dict[str, Any]]:
    """Retrieve all saved analyses/reports in newest-first order, scoped to developer."""
    user_id = user.id if user else None
    return list_analyses(user_id=user_id, project_id=project_id)


@router.get(
    "/reports/{report_id}",
    summary="Retrieve full saved analysis result by report ID",
    response_model=dict[str, Any],
)
def get_report_by_id_endpoint(
    report_id: str,
    user: UserRecord | None = Depends(get_current_user_optional),
) -> dict[str, Any]:
    """Retrieve full saved analysis result by ID, verifying tenant access."""
    user_id = user.id if user else None
    record = get_analysis(report_id, user_id=user_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return record


@router.get(
    "/reports/{report_id}/pdf",
    summary="Download PDF for a saved report ID",
    response_class=Response,
)
def download_report_pdf_endpoint(
    report_id: str,
    user: UserRecord | None = Depends(get_current_user_optional),
) -> Response:
    """Download the PDF security report for a specific saved analysis."""
    user_id = user.id if user else None
    result = get_analysis_pdf(report_id, user_id=user_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    pdf_bytes, filename = result
    raw_stem = Path(filename).stem if filename else "iac_security"
    safe_stem = re.sub(r"[^a-zA-Z0-9_\-]", "_", raw_stem).strip("_") or "iac_security"
    download_filename = f"{safe_stem}_security_report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{download_filename}"',
            "Content-Type": "application/pdf",
        },
    )


@router.delete(
    "/reports/{report_id}",
    summary="Delete a saved analysis report by ID",
)
def delete_report_endpoint(
    report_id: str,
    user: UserRecord | None = Depends(get_current_user_optional),
) -> dict[str, Any]:
    """Delete a saved analysis report from persistent storage."""
    user_id = user.id if user else None
    deleted = delete_analysis(report_id, user_id=user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return {"message": f"Report '{report_id}' deleted successfully.", "id": report_id}


@router.get(
    "/dashboard/stats",
    summary="Retrieve live aggregated statistics for the developer's dashboard",
)
def get_dashboard_stats_endpoint(
    user: UserRecord | None = Depends(get_current_user_optional),
) -> dict[str, Any]:
    """Retrieve real statistics aggregated across developer's saved analysis runs."""
    user_id = user.id if user else None
    return get_dashboard_stats(user_id=user_id)


@router.get(
    "/reports/stats",
    summary="Alias for dashboard stats",
)
def get_reports_stats_alias_endpoint(
    user: UserRecord | None = Depends(get_current_user_optional),
) -> dict[str, Any]:
    """Alias for retrieving aggregated statistics."""
    user_id = user.id if user else None
    return get_dashboard_stats(user_id=user_id)
