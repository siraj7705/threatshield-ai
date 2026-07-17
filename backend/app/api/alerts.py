"""
ThreatShield AI - Alerts API Routes
"""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.core.security import get_current_user, require_roles, ADMIN_AND_ANALYST, is_admin
from app.models.alert import Alert
from app.models.email import Email
from app.schemas import AlertResponse, AlertListResponse

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List alerts with filtering.

    Alerts inherit ownership from the email they're attached to (joined via
    Alert.email_id -> Email.uploaded_by). An alert is visible to: admins
    (always), the user who uploaded/scanned the underlying email, or anyone
    if the underlying email came from the shared mailbox watcher (no single
    owner) or the alert has no linked email at all (also no single owner).
    """
    query = select(Alert)
    count_q = select(func.count(Alert.id))

    if not is_admin(current_user):
        # LEFT OUTER JOIN so alerts with no linked email (Alert.email_id IS
        # NULL) still show up — those have no owner to restrict by.
        query = query.outerjoin(Email, Alert.email_id == Email.id)
        count_q = count_q.select_from(Alert).outerjoin(Email, Alert.email_id == Email.id)

        ownership_filter = (
            (Alert.email_id.is_(None)) |
            (Email.source_type == "gmail_watch") |
            (Email.uploaded_by == current_user["id"])
        )
        query = query.where(ownership_filter)
        count_q = count_q.where(ownership_filter)

    if severity:
        query = query.where(Alert.severity == severity)
        count_q = count_q.where(Alert.severity == severity)
    if acknowledged is not None:
        query = query.where(Alert.is_acknowledged == acknowledged)
        count_q = count_q.where(Alert.is_acknowledged == acknowledged)

    total_result = await db.execute(count_q)
    total = total_result.scalar() or 0

    # Fetch
    query = query.order_by(desc(Alert.created_at)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    alerts = [AlertResponse.model_validate(a) for a in result.scalars().all()]

    return AlertListResponse(total=total, alerts=alerts)


async def _check_alert_access(current_user: dict, alert: Alert, db: AsyncSession):
    """Raise 404 if the current user doesn't own the email this alert is attached to (admins exempt)."""
    if is_admin(current_user):
        return
    if alert.email_id is None:
        return  # no linked email -> no single owner -> visible to all
    result = await db.execute(select(Email).where(Email.id == alert.email_id))
    email_record = result.scalar_one_or_none()
    if not email_record:
        return  # orphaned reference; don't block access over a data anomaly
    if email_record.source_type == "gmail_watch":
        return  # shared mailbox -> no single owner
    if email_record.uploaded_by != current_user["id"]:
        raise HTTPException(status_code=404, detail="Alert not found")


@router.put("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    current_user: dict = Depends(require_roles(ADMIN_AND_ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Acknowledge an alert. Admin/analyst only — investigators are read-only — and only on alerts you can see."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    await _check_alert_access(current_user, alert, db)

    alert.is_acknowledged = True
    alert.acknowledged_by = current_user["id"]
    alert.acknowledged_at = datetime.now(timezone.utc)

    return {"message": "Alert acknowledged", "alert_id": alert_id}


@router.get("/unacknowledged/count")
async def unacknowledged_count(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get count of unacknowledged alerts visible to the current user."""
    query = select(func.count(Alert.id)).where(Alert.is_acknowledged == False)

    if not is_admin(current_user):
        query = query.select_from(Alert).outerjoin(Email, Alert.email_id == Email.id).where(
            (Alert.email_id.is_(None)) |
            (Email.source_type == "gmail_watch") |
            (Email.uploaded_by == current_user["id"])
        )

    result = await db.execute(query)
    count = result.scalar() or 0
    return {"count": count}