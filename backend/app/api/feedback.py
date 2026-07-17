"""
ThreatShield AI - Feedback & Continuous Learning API
Allows analysts to correct ML predictions and trigger retraining.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional

from app.core.database import get_db
from app.core.security import get_current_user, require_roles, ADMIN_ONLY, ADMIN_AND_ANALYST
from app.models.email import Email
from app.models.threat import ThreatAnalysis
from app.models.feedback import Feedback
from app.services.continuous_learning import (
    save_feedback_to_dataset,
    retrain_model_async,
    get_retrain_status,
    get_feedback_count,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/feedback", tags=["Feedback"])

VALID_LABELS = ["safe", "bomb_threat", "violence", "terror", "extortion", "harassment", "school_threat"]


class FeedbackRequest(BaseModel):
    email_id: int
    correct_label: str
    notes: Optional[str] = None


class RetrainRequest(BaseModel):
    min_samples: int = 5


@router.post("")
async def submit_feedback(
    body: FeedbackRequest,
    current_user: dict = Depends(require_roles(ADMIN_AND_ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """
    Submit analyst feedback correcting an ML prediction.
    This saves the correction for use in the next model retrain.
    """
    if body.correct_label not in VALID_LABELS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid label. Must be one of: {VALID_LABELS}"
        )

    # Get the email
    result = await db.execute(select(Email).where(Email.id == body.email_id))
    email = result.scalar_one_or_none()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    # Get original prediction
    threat_result = await db.execute(
        select(ThreatAnalysis).where(ThreatAnalysis.email_id == body.email_id)
    )
    threat = threat_result.scalar_one_or_none()
    original_label = threat.threat_type if threat else "unknown"

    # Build email text for retraining
    email_text = " ".join(filter(None, [
        email.subject or "",
        email.body_text or "",
    ])).strip()

    if not email_text:
        raise HTTPException(status_code=400, detail="Email has no text content to learn from")

    # Save feedback to DB
    is_false_positive = (original_label != "safe" and body.correct_label == "safe")

    feedback = Feedback(
        email_id=body.email_id,
        analyst_id=current_user["id"],
        original_label=original_label,
        original_confidence=str(round(threat.confidence_score, 2)) if threat else "0",
        correct_label=body.correct_label,
        is_false_positive=is_false_positive,
        email_text_snapshot=email_text[:5000],  # cap at 5000 chars
        notes=body.notes,
    )
    db.add(feedback)
    await db.commit()

    # Save to dataset file for retraining
    total_feedback = save_feedback_to_dataset(email_text, body.correct_label)

    return {
        "success": True,
        "message": "Feedback recorded. Thank you!",
        "original_label": original_label,
        "correct_label": body.correct_label,
        "is_false_positive": is_false_positive,
        "total_feedback_samples": total_feedback,
    }


@router.get("/status")
async def feedback_status(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current feedback count and retrain status."""
    feedback_count = get_feedback_count()
    retrain_status = get_retrain_status()

    # Count false positives in DB
    from sqlalchemy import func
    fp_result = await db.execute(
        select(func.count(Feedback.id)).where(Feedback.is_false_positive == True)
    )
    total_false_positives = fp_result.scalar() or 0

    total_result = await db.execute(select(func.count(Feedback.id)))
    total_feedback = total_result.scalar() or 0

    return {
        "pending_feedback_samples": feedback_count,
        "total_feedback_in_db": total_feedback,
        "total_false_positives": total_false_positives,
        "ready_to_retrain": feedback_count >= 5,
        "min_samples_required": 5,
        "retrain_status": retrain_status,
    }


@router.post("/retrain")
async def trigger_retrain(
    body: RetrainRequest = RetrainRequest(),
    current_user: dict = Depends(require_roles(ADMIN_ONLY)),
):
    """
    Admin-only: Trigger model retraining using collected feedback.
    Runs asynchronously — check /status for progress.
    """
    retrain_status = get_retrain_status()
    if retrain_status["is_running"]:
        raise HTTPException(status_code=409, detail="Retrain already in progress")

    feedback_count = get_feedback_count()
    if feedback_count < body.min_samples:
        raise HTTPException(
            status_code=400,
            detail=f"Not enough feedback samples. Have {feedback_count}, need {body.min_samples}."
        )

    # Run retrain asynchronously
    result = await retrain_model_async(min_feedback_samples=body.min_samples)

    return result


@router.get("/history")
async def feedback_history(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get recent feedback submissions."""
    result = await db.execute(
        select(Feedback).order_by(Feedback.created_at.desc()).limit(50)
    )
    feedbacks = result.scalars().all()

    return {
        "feedbacks": [
            {
                "id": f.id,
                "email_id": f.email_id,
                "original_label": f.original_label,
                "correct_label": f.correct_label,
                "is_false_positive": f.is_false_positive,
                "notes": f.notes,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in feedbacks
        ]
    }