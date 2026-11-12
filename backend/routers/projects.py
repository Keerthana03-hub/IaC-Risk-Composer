"""
routers/projects.py
-------------------
Workspace and Project management routes for multi-developer workflows:
- GET    /api/projects
- POST   /api/projects
- GET    /api/projects/{project_id}
- PUT    /api/projects/{project_id}
- DELETE /api/projects/{project_id}
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from database import (
    UserRecord,
    create_project,
    delete_project,
    get_project,
    list_projects,
    update_project,
)
from routers.auth import get_current_user_optional

router = APIRouter(prefix="/projects", tags=["projects"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: str | None = None


class UpdateProjectRequest(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=100)
    description: str | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=list[dict[str, Any]])
def list_user_projects(
    user: UserRecord = Depends(get_current_user_optional),
) -> list[dict[str, Any]]:
    """Retrieve all projects for the authenticated developer, with summary stats."""
    user_id = user.id if user else "usr_admin"
    return list_projects(user_id=user_id)


@router.post("", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
def create_user_project(
    req: CreateProjectRequest,
    user: UserRecord = Depends(get_current_user_optional),
) -> dict[str, Any]:
    """Create a new project workspace for the authenticated developer."""
    user_id = user.id if user else "usr_admin"
    return create_project(
        user_id=user_id,
        name=req.name,
        description=req.description or "",
    )


@router.get("/{project_id}", response_model=dict[str, Any])
def get_user_project(
    project_id: str,
    user: UserRecord = Depends(get_current_user_optional),
) -> dict[str, Any]:
    """Get project details and list of its historical analyses."""
    user_id = user.id if user else "usr_admin"
    proj = get_project(project_id=project_id, user_id=user_id)
    if not proj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{project_id}' not found.",
        )
    return proj


@router.put("/{project_id}", response_model=dict[str, Any])
def update_user_project(
    project_id: str,
    req: UpdateProjectRequest,
    user: UserRecord = Depends(get_current_user_optional),
) -> dict[str, Any]:
    """Update project name or description."""
    user_id = user.id if user else "usr_admin"
    updated = update_project(
        project_id=project_id,
        user_id=user_id,
        name=req.name,
        description=req.description,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{project_id}' not found.",
        )
    return updated


@router.delete("/{project_id}")
def delete_user_project(
    project_id: str,
    user: UserRecord = Depends(get_current_user_optional),
) -> dict[str, str]:
    """Delete a project and its associated analyses."""
    user_id = user.id if user else "usr_admin"
    ok = delete_project(project_id=project_id, user_id=user_id)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{project_id}' not found.",
        )
    return {"message": f"Project '{project_id}' deleted successfully.", "id": project_id}
