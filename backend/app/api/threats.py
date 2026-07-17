"""
ThreatShield AI - Threat Analysis API Routes
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.core.security import get_current_user, is_admin
from app.models.threat import ThreatAnalysis, ThreatScore
from app.models.email import Email
from app.schemas import ThreatAnalysisResponse, ThreatScoreResponse

router = APIRouter(prefix="/api/threats", tags=["Threats"])


@router.get("/analyses")
async def list_threat_analyses(
    threat_type: str = None,
    severity: str = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List threat analyses with optional filtering.

    Scoped via the linked email's ownership (ThreatAnalysis.email_id ->
    Email.uploaded_by), same rule as /api/emails: admins see all, everyone
    else sees their own uploads/scans plus the shared mailbox's emails.
    """
    query = select(ThreatAnalysis).where(ThreatAnalysis.threat_detected == True)

    if not is_admin(current_user):
        query = query.join(Email, ThreatAnalysis.email_id == Email.id).where(
            (Email.source_type == "gmail_watch") | (Email.uploaded_by == current_user["id"])
        )

    if threat_type:
        query = query.where(ThreatAnalysis.threat_type == threat_type)
    if severity:
        query = query.where(ThreatAnalysis.severity == severity)

    query = query.order_by(desc(ThreatAnalysis.analyzed_at)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    analyses = result.scalars().all()

    return {
        "analyses": [ThreatAnalysisResponse.model_validate(a) for a in analyses],
        "page": page,
        "per_page": per_page,
    }


@router.get("/email/{email_id}")
async def get_threat_for_email(
    email_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get full threat analysis for a specific email — only if you own that email (or are admin)."""
    email_record = (await db.execute(select(Email).where(Email.id == email_id))).scalar_one_or_none()
    if not email_record:
        raise HTTPException(status_code=404, detail="Threat analysis not found")

    if not is_admin(current_user):
        owns = (
            email_record.source_type == "gmail_watch" or
            email_record.uploaded_by == current_user["id"]
        )
        if not owns:
            raise HTTPException(status_code=404, detail="Threat analysis not found")

    threat = (await db.execute(select(ThreatAnalysis).where(ThreatAnalysis.email_id == email_id))).scalar_one_or_none()
    score = (await db.execute(select(ThreatScore).where(ThreatScore.email_id == email_id))).scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=404, detail="Threat analysis not found")

    return {
        "threat_analysis": ThreatAnalysisResponse.model_validate(threat),
        "threat_score": ThreatScoreResponse.model_validate(score) if score else None,
    }