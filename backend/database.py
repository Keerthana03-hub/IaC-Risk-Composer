"""
database.py
-----------
Persistent SQLite database storage using SQLAlchemy for IaC Risk Composer.
Supports multi-tenant developer accounts, workspaces/projects, and isolated
IaC security analysis records.

Preserves all Step 1–6 analysis data:
- Resources and topology graph (infrastructure_map)
- Threat findings, detection statuses, confidence levels
- Inherent and adjusted risk scores
- Plain language risk explanations
- Actionable remediations and safe code patches
- Pre-generated ReportLab PDF bytes
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    create_engine,
    desc,
    text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

# ---------------------------------------------------------------------------
# Database Configuration
# ---------------------------------------------------------------------------

DB_PATH = Path(__file__).resolve().parent / "iac_risk_composer.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    bind=engine,
)
Base = declarative_base()


# ---------------------------------------------------------------------------
# SQLAlchemy Models
# ---------------------------------------------------------------------------


class UserRecord(Base):
    """Developer user account."""

    __tablename__ = "users"

    id = Column(String(64), primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    organization = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=False)
    salt = Column(String(64), nullable=False)
    preferences_json = Column(Text, nullable=True)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    projects = relationship("ProjectRecord", back_populates="user", cascade="all, delete-orphan")
    analyses = relationship("AnalysisRecord", back_populates="user", cascade="all, delete-orphan")

    def to_dict(self) -> dict[str, Any]:
        prefs = {}
        if self.preferences_json:
            try:
                prefs = json.loads(self.preferences_json)
            except Exception:
                prefs = {}

        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "organization": self.organization or "Independent Developer",
            "preferences": prefs,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else datetime.now(timezone.utc).isoformat()
            ),
        }


class ProjectRecord(Base):
    """Developer workspace / project container."""

    __tablename__ = "projects"

    id = Column(String(64), primary_key=True, index=True)
    user_id = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    user = relationship("UserRecord", back_populates="projects")
    analyses = relationship("AnalysisRecord", back_populates="project")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "description": self.description or "",
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else datetime.now(timezone.utc).isoformat()
            ),
            "updated_at": (
                self.updated_at.isoformat()
                if self.updated_at
                else datetime.now(timezone.utc).isoformat()
            ),
        }


class AnalysisRecord(Base):
    """Stores full analysis responses and metadata for persistent history and reports."""

    __tablename__ = "analyses"

    id = Column(String(64), primary_key=True, index=True)
    user_id = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    project_name = Column(String(255), nullable=True)
    filename = Column(String(255), nullable=False)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    resource_count = Column(Integer, default=0, nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)
    overall_risk_level = Column(String(64), default="Not Assessed", nullable=False)
    risk_summary_json = Column(Text, nullable=True)
    full_analysis_json = Column(Text, nullable=False)
    pdf_bytes = Column(LargeBinary, nullable=True)

    user = relationship("UserRecord", back_populates="analyses")
    project = relationship("ProjectRecord", back_populates="analyses")

    def to_summary_dict(self) -> dict[str, Any]:
        """Convert record to lightweight metadata dictionary for list views."""
        risk_summary = {}
        if self.risk_summary_json:
            try:
                risk_summary = json.loads(self.risk_summary_json)
            except Exception:
                risk_summary = {}

        return {
            "id": self.id,
            "user_id": self.user_id,
            "project_id": self.project_id,
            "project_name": self.project_name or "Primary Infrastructure",
            "filename": self.filename,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else datetime.now(timezone.utc).isoformat()
            ),
            "resource_count": self.resource_count,
            "findings_count": self.findings_count,
            "overall_risk_level": self.overall_risk_level,
            "risk_summary": risk_summary,
        }


# ---------------------------------------------------------------------------
# Database Initialization & Schema Migration
# ---------------------------------------------------------------------------


def init_db() -> None:
    """Initialize database tables, apply migrations, and seed default user/project."""
    Base.metadata.create_all(bind=engine)

    # Migrate existing analyses table if missing columns
    db = SessionLocal()
    try:
        raw_conn = engine.raw_connection()
        cursor = raw_conn.cursor()
        cursor.execute("PRAGMA table_info(analyses)")
        existing_cols = {row[1] for row in cursor.fetchall()}

        if "user_id" not in existing_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN user_id VARCHAR(64)")
        if "project_id" not in existing_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN project_id VARCHAR(64)")
        if "project_name" not in existing_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN project_name VARCHAR(255)")

        raw_conn.commit()
        cursor.close()
        raw_conn.close()

        # Seed default admin user if none exists
        admin_user = db.query(UserRecord).filter(UserRecord.username == "admin").first()
        if not admin_user:
            from services.auth_service import hash_password

            pwd_hash, salt = hash_password("admin")
            admin_user = UserRecord(
                id="usr_admin",
                username="admin",
                email="admin@iac-risk-composer.local",
                full_name="Alex Morgan",
                organization="CyberSec Engineering",
                password_hash=pwd_hash,
                salt=salt,
                preferences_json=json.dumps({
                    "theme": "light",
                    "notifications": {
                        "security_alerts": True,
                        "analysis_completed": True,
                        "critical_threats": True,
                    },
                    "analysis_preferences": {
                        "default_severity": "low",
                        "auto_map": True,
                    }
                }),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)

        # Seed default project for admin if none exists
        default_project = (
            db.query(ProjectRecord)
            .filter(ProjectRecord.user_id == admin_user.id)
            .first()
        )
        if not default_project:
            default_project = ProjectRecord(
                id="prj_default",
                user_id=admin_user.id,
                name="Primary Cloud Infrastructure",
                description="Core cloud resources, VPC networking, and production storage tier.",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(default_project)
            db.commit()
            db.refresh(default_project)

        # Assign any unowned legacy analyses to the default admin user & project
        db.execute(
            text(
                "UPDATE analyses SET user_id = :uid, project_id = :pid, project_name = :pname "
                "WHERE user_id IS NULL OR user_id = ''"
            ),
            {
                "uid": admin_user.id,
                "pid": default_project.id,
                "pname": default_project.name,
            },
        )
        db.commit()

    finally:
        db.close()


# ---------------------------------------------------------------------------
# User CRUD & Authentication Services
# ---------------------------------------------------------------------------


def create_user(
    full_name: str,
    username: str,
    email: str,
    password_hash: str,
    salt: str,
    organization: str | None = None,
) -> UserRecord:
    """Create a new developer user and an initial default project workspace."""
    init_db()
    db = SessionLocal()
    try:
        user_id = f"usr_{uuid.uuid4().hex[:12]}"
        user = UserRecord(
            id=user_id,
            username=username.strip().lower(),
            email=email.strip().lower(),
            full_name=full_name.strip(),
            organization=organization.strip() if organization else "Independent Developer",
            password_hash=password_hash,
            salt=salt,
            preferences_json=json.dumps({
                "theme": "light",
                "notifications": {
                    "security_alerts": True,
                    "analysis_completed": True,
                    "critical_threats": True,
                },
                "analysis_preferences": {
                    "default_severity": "low",
                    "auto_map": True,
                }
            }),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Automatically create initial workspace for developer
        project_id = f"prj_{uuid.uuid4().hex[:8]}"
        project = ProjectRecord(
            id=project_id,
            user_id=user.id,
            name="My Cloud Infrastructure",
            description="Default workspace for infrastructure-as-code security analysis.",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(project)
        db.commit()

        return user
    finally:
        db.close()


def get_user_by_id(user_id: str) -> UserRecord | None:
    """Find user by unique ID."""
    init_db()
    db = SessionLocal()
    try:
        return db.query(UserRecord).filter(UserRecord.id == user_id).first()
    finally:
        db.close()


def get_user_by_username_or_email(identifier: str) -> UserRecord | None:
    """Find user by username or email (case-insensitive)."""
    init_db()
    db = SessionLocal()
    try:
        id_clean = identifier.strip().lower()
        return (
            db.query(UserRecord)
            .filter(
                (UserRecord.username == id_clean) | (UserRecord.email == id_clean)
            )
            .first()
        )
    finally:
        db.close()


def update_user_profile(
    user_id: str,
    full_name: str | None = None,
    organization: str | None = None,
    preferences: dict[str, Any] | None = None,
) -> UserRecord | None:
    """Update profile information or preferences for a user."""
    init_db()
    db = SessionLocal()
    try:
        user = db.query(UserRecord).filter(UserRecord.id == user_id).first()
        if not user:
            return None

        if full_name:
            user.full_name = full_name.strip()
        if organization is not None:
            user.organization = organization.strip()
        if preferences is not None:
            existing_prefs = {}
            if user.preferences_json:
                try:
                    existing_prefs = json.loads(user.preferences_json)
                except Exception:
                    existing_prefs = {}
            existing_prefs.update(preferences)
            user.preferences_json = json.dumps(existing_prefs)

        user.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def update_user_password(
    user_id: str,
    password_hash: str,
    salt: str,
) -> bool:
    """Update password hash and salt for a user."""
    init_db()
    db = SessionLocal()
    try:
        user = db.query(UserRecord).filter(UserRecord.id == user_id).first()
        if not user:
            return False
        user.password_hash = password_hash
        user.salt = salt
        user.updated_at = datetime.now(timezone.utc)
        db.commit()
        return True
    finally:
        db.close()


def delete_user_account(user_id: str) -> bool:
    """Delete a user account and cascade delete all their projects and analyses."""
    init_db()
    db = SessionLocal()
    try:
        user = db.query(UserRecord).filter(UserRecord.id == user_id).first()
        if not user:
            return False
        db.delete(user)
        db.commit()
        return True
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Project / Workspace CRUD
# ---------------------------------------------------------------------------


def create_project(user_id: str, name: str, description: str = "") -> dict[str, Any]:
    """Create a new project workspace for a user."""
    init_db()
    db = SessionLocal()
    try:
        project_id = f"prj_{uuid.uuid4().hex[:8]}"
        project = ProjectRecord(
            id=project_id,
            user_id=user_id,
            name=name.strip(),
            description=description.strip() if description else "",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(project)
        db.commit()
        db.refresh(project)
        return project.to_dict()
    finally:
        db.close()


def list_projects(user_id: str) -> list[dict[str, Any]]:
    """
    List all projects for a user, enriched with live statistics:
    - analysis count
    - last analyzed timestamp
    - latest analysis risk score & risk level
    - total findings count & critical count
    """
    init_db()
    db = SessionLocal()
    try:
        projects = (
            db.query(ProjectRecord)
            .filter(ProjectRecord.user_id == user_id)
            .order_by(desc(ProjectRecord.updated_at))
            .all()
        )

        result: list[dict[str, Any]] = []
        for p in projects:
            p_dict = p.to_dict()

            # Find analyses for this project
            analyses = (
                db.query(AnalysisRecord)
                .filter(AnalysisRecord.project_id == p.id)
                .order_by(desc(AnalysisRecord.created_at))
                .all()
            )

            p_dict["analyses_count"] = len(analyses)
            latest = analyses[0] if analyses else None
            p_dict["last_analyzed"] = (
                latest.created_at.isoformat() if latest and latest.created_at else None
            )
            p_dict["latest_analysis_id"] = latest.id if latest else None
            p_dict["latest_filename"] = latest.filename if latest else None
            p_dict["overall_risk_level"] = (
                latest.overall_risk_level if latest else "Not Assessed"
            )

            # Compute findings counts across latest analysis
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0
            total_findings = 0
            risk_score = None

            if latest:
                total_findings = latest.findings_count
                if latest.risk_summary_json:
                    try:
                        rs = json.loads(latest.risk_summary_json)
                        critical_count = rs.get("critical_risk_count", 0)
                        high_count = rs.get("high_risk_count", 0)
                        medium_count = rs.get("medium_risk_count", 0)
                        low_count = rs.get("low_risk_count", 0)
                        risk_score = rs.get("highest_inherent_risk_score")
                    except Exception:
                        pass

            p_dict["findings_count"] = total_findings
            p_dict["critical_count"] = critical_count
            p_dict["high_count"] = high_count
            p_dict["medium_count"] = medium_count
            p_dict["low_count"] = low_count
            p_dict["risk_score"] = risk_score

            result.append(p_dict)

        return result
    finally:
        db.close()


def get_project(project_id: str, user_id: str | None = None) -> dict[str, Any] | None:
    """Get project details and list of its analyses."""
    init_db()
    db = SessionLocal()
    try:
        query = db.query(ProjectRecord).filter(ProjectRecord.id == project_id)
        if user_id:
            query = query.filter(ProjectRecord.user_id == user_id)
        project = query.first()
        if not project:
            return None

        p_dict = project.to_dict()
        analyses = (
            db.query(AnalysisRecord)
            .filter(AnalysisRecord.project_id == project.id)
            .order_by(desc(AnalysisRecord.created_at))
            .all()
        )
        p_dict["analyses"] = [a.to_summary_dict() for a in analyses]
        return p_dict
    finally:
        db.close()


def update_project(
    project_id: str,
    user_id: str,
    name: str | None = None,
    description: str | None = None,
) -> dict[str, Any] | None:
    """Update project name or description."""
    init_db()
    db = SessionLocal()
    try:
        project = (
            db.query(ProjectRecord)
            .filter(ProjectRecord.id == project_id, ProjectRecord.user_id == user_id)
            .first()
        )
        if not project:
            return None

        if name:
            project.name = name.strip()
            # Also update project_name in associated analyses
            db.query(AnalysisRecord).filter(AnalysisRecord.project_id == project.id).update(
                {"project_name": project.name}
            )

        if description is not None:
            project.description = description.strip()

        project.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(project)
        return project.to_dict()
    finally:
        db.close()


def delete_project(project_id: str, user_id: str) -> bool:
    """Delete a project and its associated analyses."""
    init_db()
    db = SessionLocal()
    try:
        project = (
            db.query(ProjectRecord)
            .filter(ProjectRecord.id == project_id, ProjectRecord.user_id == user_id)
            .first()
        )
        if not project:
            return False

        # Delete associated analyses
        db.query(AnalysisRecord).filter(AnalysisRecord.project_id == project.id).delete()
        db.delete(project)
        db.commit()
        return True
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Analysis & Storage Service Functions
# ---------------------------------------------------------------------------


def save_analysis(
    analysis_data: dict[str, Any],
    pdf_bytes: bytes | None = None,
    user_id: str | None = None,
    project_id: str | None = None,
) -> dict[str, Any]:
    """
    Save complete analysis response in persistent SQLite storage.
    Associates the analysis with user_id and project_id for multi-user isolation.
    """
    init_db()
    db = SessionLocal()
    try:
        # Default user if not provided (e.g. unauthenticated test client)
        if not user_id:
            admin = db.query(UserRecord).filter(UserRecord.username == "admin").first()
            user_id = admin.id if admin else "usr_admin"

        # Resolve or create default project if not provided
        resolved_project_id = project_id
        resolved_project_name = "Primary Infrastructure"

        if resolved_project_id:
            proj = (
                db.query(ProjectRecord)
                .filter(ProjectRecord.id == resolved_project_id, ProjectRecord.user_id == user_id)
                .first()
            )
            if proj:
                resolved_project_name = proj.name
            else:
                resolved_project_id = None

        if not resolved_project_id:
            # Pick user's first project or create default
            first_proj = (
                db.query(ProjectRecord)
                .filter(ProjectRecord.user_id == user_id)
                .order_by(ProjectRecord.created_at)
                .first()
            )
            if first_proj:
                resolved_project_id = first_proj.id
                resolved_project_name = first_proj.name
            else:
                new_proj = ProjectRecord(
                    id=f"prj_{uuid.uuid4().hex[:8]}",
                    user_id=user_id,
                    name="My Cloud Infrastructure",
                    description="Default workspace for security scans.",
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                db.add(new_proj)
                db.commit()
                db.refresh(new_proj)
                resolved_project_id = new_proj.id
                resolved_project_name = new_proj.name

        # Generate a friendly, unique report ID: e.g. RPT-A1B2C3D4
        report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"

        filename = str(analysis_data.get("filename") or "infrastructure.tf")
        resource_count = int(analysis_data.get("resource_count") or 0)
        threat_findings = analysis_data.get("threat_findings") or []
        findings_count = len(threat_findings)

        risk_summary = analysis_data.get("risk_summary") or {}
        overall_risk_level = (
            risk_summary.get("overall_risk_level")
            if isinstance(risk_summary, dict)
            else None
        )
        if not overall_risk_level:
            overall_risk_level = "Not Assessed" if not threat_findings else "Assessed"

        # Ensure the full analysis payload includes the generated ID and metadata
        full_data = dict(analysis_data)
        full_data["id"] = report_id
        full_data["user_id"] = user_id
        full_data["project_id"] = resolved_project_id
        full_data["project_name"] = resolved_project_name

        # If PDF bytes not provided, try to pre-generate with services.report_generator
        if pdf_bytes is None:
            try:
                from services.report_generator import generate_pdf_report

                pdf_bytes = generate_pdf_report(full_data)
            except Exception:
                pdf_bytes = None

        record = AnalysisRecord(
            id=report_id,
            user_id=user_id,
            project_id=resolved_project_id,
            project_name=resolved_project_name,
            filename=filename,
            created_at=datetime.now(timezone.utc),
            resource_count=resource_count,
            findings_count=findings_count,
            overall_risk_level=str(overall_risk_level),
            risk_summary_json=json.dumps(risk_summary) if risk_summary else None,
            full_analysis_json=json.dumps(full_data),
            pdf_bytes=pdf_bytes,
        )

        db.add(record)

        # Update project's updated_at
        if resolved_project_id:
            db.query(ProjectRecord).filter(ProjectRecord.id == resolved_project_id).update(
                {"updated_at": datetime.now(timezone.utc)}
            )

        db.commit()
        db.refresh(record)
        return record.to_summary_dict()
    finally:
        db.close()


def list_analyses(
    user_id: str | None = None,
    project_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Retrieve list of saved analyses in newest-first order, filtered by user/project."""
    init_db()
    db = SessionLocal()
    try:
        query = db.query(AnalysisRecord)
        if user_id:
            query = query.filter(AnalysisRecord.user_id == user_id)
        if project_id:
            query = query.filter(AnalysisRecord.project_id == project_id)

        records = query.order_by(desc(AnalysisRecord.created_at)).limit(limit).all()
        return [r.to_summary_dict() for r in records]
    finally:
        db.close()


def get_analysis(report_id: str, user_id: str | None = None) -> dict[str, Any] | None:
    """Retrieve the full analysis JSON by ID, verifying user ownership if user_id is provided."""
    init_db()
    db = SessionLocal()
    try:
        query = db.query(AnalysisRecord).filter(AnalysisRecord.id == report_id)
        if user_id:
            query = query.filter(AnalysisRecord.user_id == user_id)

        record = query.first()
        if not record:
            return None

        data = json.loads(record.full_analysis_json)
        data["id"] = record.id
        data["user_id"] = record.user_id
        data["project_id"] = record.project_id
        data["project_name"] = record.project_name or "Primary Infrastructure"
        data["created_at"] = (
            record.created_at.isoformat()
            if record.created_at
            else datetime.now(timezone.utc).isoformat()
        )
        return data
    finally:
        db.close()


def get_analysis_pdf(report_id: str, user_id: str | None = None) -> tuple[bytes, str] | None:
    """Retrieve PDF bytes and target filename for a report, checking user ownership."""
    init_db()
    db = SessionLocal()
    try:
        query = db.query(AnalysisRecord).filter(AnalysisRecord.id == report_id)
        if user_id:
            query = query.filter(AnalysisRecord.user_id == user_id)

        record = query.first()
        if not record:
            return None

        if record.pdf_bytes:
            return record.pdf_bytes, record.filename

        # Regenerate on demand
        data = json.loads(record.full_analysis_json)
        from services.report_generator import generate_pdf_report

        generated_pdf = generate_pdf_report(data)
        record.pdf_bytes = generated_pdf
        db.commit()
        return generated_pdf, record.filename
    finally:
        db.close()


def delete_analysis(report_id: str, user_id: str | None = None) -> bool:
    """Delete an analysis record by ID, checking user ownership."""
    init_db()
    db = SessionLocal()
    try:
        query = db.query(AnalysisRecord).filter(AnalysisRecord.id == report_id)
        if user_id:
            query = query.filter(AnalysisRecord.user_id == user_id)

        record = query.first()
        if not record:
            return False
        db.delete(record)
        db.commit()
        return True
    finally:
        db.close()


def get_dashboard_stats(user_id: str | None = None) -> dict[str, Any]:
    """Calculate live dashboard metrics from real persisted analyses for a specific user."""
    init_db()
    db = SessionLocal()
    try:
        query = db.query(AnalysisRecord)
        if user_id:
            query = query.filter(AnalysisRecord.user_id == user_id)

        records = query.order_by(desc(AnalysisRecord.created_at)).limit(100).all()

        total_scans = len(records)
        total_resources = sum(r.resource_count for r in records)

        # Collect recent findings and risk stats
        recent_findings: list[dict[str, Any]] = []
        all_findings_count = 0
        risk_scores: list[int] = []
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for r in records:
            all_findings_count += r.findings_count
            try:
                data = json.loads(r.full_analysis_json)
                findings = data.get("threat_findings") or []
                for f in findings:
                    sev = str(f.get("severity", "MEDIUM")).upper()
                    if sev == "CRITICAL":
                        critical_count += 1
                    elif sev == "HIGH":
                        high_count += 1
                    elif sev == "MEDIUM":
                        medium_count += 1
                    elif sev == "LOW":
                        low_count += 1

                    if len(recent_findings) < 10:
                        recent_findings.append(
                            {
                                "id": f.get("finding_id")
                                or f.get("threat_id", "FINDING"),
                                "severity": sev,
                                "rule": f.get("title", "Security Finding"),
                                "resource": f.get("affected_resource_id", "—"),
                                "report_id": r.id,
                                "filename": r.filename,
                                "project_name": r.project_name or "Primary Infrastructure",
                            }
                        )
                    # Track risk scores if available
                    score = (f.get("risk_assessment") or {}).get(
                        "inherent_risk_score"
                    )
                    if score is not None:
                        risk_scores.append(score)
            except Exception:
                continue

        avg_score = (
            round(sum(risk_scores) / len(risk_scores)) if risk_scores else None
        )

        # Count projects
        project_count = 0
        if user_id:
            project_count = (
                db.query(ProjectRecord)
                .filter(ProjectRecord.user_id == user_id)
                .count()
            )
        else:
            project_count = db.query(ProjectRecord).count()

        return {
            "total_scans": total_scans,
            "total_resources": total_resources,
            "open_findings": all_findings_count,
            "avg_risk_score": avg_score,
            "projects_analysed": project_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "recent_findings": recent_findings,
            "recent_scans": [r.to_summary_dict() for r in records[:5]],
        }
    finally:
        db.close()
