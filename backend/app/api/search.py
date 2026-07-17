"""
ThreatShield AI - Cross-Entity Search & CSV Export API Routes
"""
import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, or_, cast, String, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, is_admin
from app.models.email import Email
from app.models.threat import ThreatAnalysis, ThreatScore
from app.models.alert import Alert
from app.models.case import Case

router = APIRouter(tags=["Search & Export"])


# ---------------------------------------------------------------------------
# Cross-entity search
# ---------------------------------------------------------------------------

@router.get("/api/search")
async def search(
    q: str = Query(..., min_length=2, description="Search term (min 2 chars)"),
    entity: Optional[str] = Query(None, description="Filter to one entity: emails, threats, alerts, cases"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Search across emails, threat analyses, alerts, and cases in a single call.

    Returns hits grouped by entity type. Each hit includes the entity id,
    a short human-readable summary, and a relevance hint (which field matched).

    Scoping rules are identical to the per-entity list endpoints:
    admins see everything; analysts/investigators see only what they own
    plus shared-mailbox emails.
    """
    term = f"%{q}%"
    admin = is_admin(current_user)
    uid = current_user["id"]

    hits: list[dict] = []

    # ── Emails ───────────────────────────────────────────────────────────────
    if entity in (None, "emails"):
        eq = (
            select(Email)
            .where(
                or_(
                    Email.subject.ilike(term),
                    Email.sender_email.ilike(term),
                    Email.sender_name.ilike(term),
                    Email.recipient_email.ilike(term),
                    Email.body_text.ilike(term),
                )
            )
            .order_by(desc(Email.upload_date))
            .limit(per_page)
            .offset((page - 1) * per_page)
        )
        if not admin:
            eq = eq.where(
                or_(Email.uploaded_by == uid, Email.source_type == "gmail_watch")
            )
        rows = (await db.execute(eq)).scalars().all()
        for e in rows:
            # Determine which field(s) matched for a useful hint
            matched = []
            if q.lower() in (e.subject or "").lower():
                matched.append("subject")
            if q.lower() in (e.sender_email or "").lower():
                matched.append("sender")
            if q.lower() in (e.body_text or "").lower():
                matched.append("body")
            hits.append({
                "entity": "email",
                "id": e.id,
                "title": e.subject or "(no subject)",
                "subtitle": e.sender_email or "",
                "meta": f"uploaded {e.upload_date.date() if e.upload_date else ''}  ·  {e.status}",
                "matched_fields": matched,
                "severity": None,
                "url": f"/emails/{e.id}",
            })

    # ── Threat Analyses ───────────────────────────────────────────────────────
    if entity in (None, "threats"):
        tq = (
            select(ThreatAnalysis)
            .where(
                or_(
                    ThreatAnalysis.threat_type.ilike(term),
                    ThreatAnalysis.threat_target.ilike(term),
                    ThreatAnalysis.threat_description.ilike(term),
                    ThreatAnalysis.keywords_found.ilike(term),
                )
            )
            .order_by(desc(ThreatAnalysis.analyzed_at))
            .limit(per_page)
            .offset((page - 1) * per_page)
        )
        if not admin:
            tq = tq.join(Email, ThreatAnalysis.email_id == Email.id).where(
                or_(Email.uploaded_by == uid, Email.source_type == "gmail_watch")
            )
        rows = (await db.execute(tq)).scalars().all()
        for t in rows:
            hits.append({
                "entity": "threat",
                "id": t.id,
                "email_id": t.email_id,
                "title": f"{t.threat_type or 'unknown'} threat",
                "subtitle": t.threat_description or "",
                "meta": f"confidence {t.confidence_score:.0%}  ·  {t.severity}",
                "matched_fields": ["threat_type" if q.lower() in (t.threat_type or "").lower() else "description"],
                "severity": t.severity,
                "url": f"/emails/{t.email_id}",
            })

    # ── Alerts ────────────────────────────────────────────────────────────────
    if entity in (None, "alerts"):
        aq = (
            select(Alert)
            .where(
                or_(
                    Alert.title.ilike(term),
                    Alert.message.ilike(term),
                    Alert.alert_type.ilike(term),
                )
            )
            .order_by(desc(Alert.created_at))
            .limit(per_page)
            .offset((page - 1) * per_page)
        )
        if not admin:
            # Alerts inherit email ownership; alerts with no linked email are
            # visible to everyone (no single owner).
            aq = aq.outerjoin(Email, Alert.email_id == Email.id).where(
                or_(
                    Alert.email_id.is_(None),
                    Email.source_type == "gmail_watch",
                    Email.uploaded_by == uid,
                )
            )
        rows = (await db.execute(aq)).scalars().all()
        for a in rows:
            hits.append({
                "entity": "alert",
                "id": a.id,
                "email_id": a.email_id,
                "title": a.title,
                "subtitle": a.message[:120] + ("…" if len(a.message) > 120 else ""),
                "meta": f"{a.alert_type}  ·  {'acknowledged' if a.is_acknowledged else 'open'}",
                "matched_fields": ["title" if q.lower() in a.title.lower() else "message"],
                "severity": a.severity,
                "url": f"/alerts/{a.id}",
            })

    # ── Cases ─────────────────────────────────────────────────────────────────
    if entity in (None, "cases"):
        cq = (
            select(Case)
            .where(
                or_(
                    Case.case_number.ilike(term),
                    Case.title.ilike(term),
                    Case.description.ilike(term),
                    Case.notes.ilike(term),
                )
            )
            .order_by(desc(Case.created_at))
            .limit(per_page)
            .offset((page - 1) * per_page)
        )
        if not admin:
            cq = cq.where(
                or_(Case.created_by == uid, Case.assigned_to == uid)
            )
        rows = (await db.execute(cq)).scalars().all()
        for c in rows:
            hits.append({
                "entity": "case",
                "id": c.id,
                "title": c.title,
                "subtitle": c.case_number,
                "meta": f"{c.status}  ·  priority: {c.priority}",
                "matched_fields": ["title" if q.lower() in c.title.lower() else "notes"],
                "severity": None,
                "url": f"/cases/{c.id}",
            })

    return {
        "query": q,
        "total": len(hits),
        "page": page,
        "per_page": per_page,
        "results": hits,
    }


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def _make_csv(fieldnames: list[str], rows: list[dict]) -> str:
    """Render a list of dicts to a CSV string."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def _csv_response(content: str, filename: str) -> StreamingResponse:
    return StreamingResponse(
        iter([content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/export/emails.csv")
async def export_emails_csv(
    status: Optional[str] = None,
    action: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Export the email list as a CSV file, optionally filtered by status/action.
    Includes the composite threat score and severity pulled from ThreatScore.
    Respects the same ownership scoping as GET /api/emails.
    """
    admin = is_admin(current_user)
    uid = current_user["id"]

    # Join Email → ThreatScore for score columns
    q = select(Email, ThreatScore).outerjoin(
        ThreatScore, ThreatScore.email_id == Email.id
    )
    if not admin:
        q = q.where(or_(Email.uploaded_by == uid, Email.source_type == "gmail_watch"))
    if status:
        q = q.where(Email.status == status)
    if action:
        q = q.where(Email.action_taken == action)
    q = q.order_by(desc(Email.upload_date)).limit(10_000)  # safety cap

    rows_raw = (await db.execute(q)).all()

    fields = [
        "id", "upload_date", "file_name", "subject", "sender_email", "sender_name",
        "recipient_email", "source_type", "status", "action_taken",
        "threat_score", "category", "severity_category", "recommended_action",
    ]
    rows = []
    for email, score in rows_raw:
        rows.append({
            "id": email.id,
            "upload_date": email.upload_date.isoformat() if email.upload_date else "",
            "file_name": email.file_name or "",
            "subject": email.subject or "",
            "sender_email": email.sender_email or "",
            "sender_name": email.sender_name or "",
            "recipient_email": email.recipient_email or "",
            "source_type": email.source_type or "",
            "status": email.status or "",
            "action_taken": email.action_taken or "",
            "threat_score": round(score.overall_score, 2) if score else "",
            "category": score.category if score else "",
            "severity_category": score.category if score else "",
            "recommended_action": score.recommended_action if score else "",
        })

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _csv_response(_make_csv(fields, rows), f"threatshield_emails_{ts}.csv")


@router.get("/api/export/threats.csv")
async def export_threats_csv(
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Export detected threat analyses as CSV.
    Only includes emails where threat_detected = true.
    """
    admin = is_admin(current_user)
    uid = current_user["id"]

    q = (
        select(ThreatAnalysis, Email.subject, Email.sender_email, Email.upload_date)
        .join(Email, ThreatAnalysis.email_id == Email.id)
        .where(ThreatAnalysis.threat_detected == True)  # noqa: E712
    )
    if not admin:
        q = q.where(or_(Email.uploaded_by == uid, Email.source_type == "gmail_watch"))
    if threat_type:
        q = q.where(ThreatAnalysis.threat_type == threat_type)
    if severity:
        q = q.where(ThreatAnalysis.severity == severity)
    q = q.order_by(desc(ThreatAnalysis.analyzed_at)).limit(10_000)

    rows_raw = (await db.execute(q)).all()
    fields = [
        "id", "email_id", "analyzed_at", "email_subject", "sender_email",
        "threat_type", "severity", "confidence_score", "intent_score",
        "urgency_score", "threat_target", "threat_description", "keywords_found",
    ]
    rows = []
    for ta, subject, sender, upload_date in rows_raw:
        try:
            kw = ", ".join(json.loads(ta.keywords_found)) if ta.keywords_found else ""
        except Exception:
            kw = ta.keywords_found or ""
        rows.append({
            "id": ta.id,
            "email_id": ta.email_id,
            "analyzed_at": ta.analyzed_at.isoformat() if ta.analyzed_at else "",
            "email_subject": subject or "",
            "sender_email": sender or "",
            "threat_type": ta.threat_type or "",
            "severity": ta.severity or "",
            "confidence_score": round(ta.confidence_score, 4) if ta.confidence_score is not None else "",
            "intent_score": round(ta.intent_score, 4) if ta.intent_score is not None else "",
            "urgency_score": round(ta.urgency_score, 4) if ta.urgency_score is not None else "",
            "threat_target": ta.threat_target or "",
            "threat_description": ta.threat_description or "",
            "keywords_found": kw,
        })

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _csv_response(_make_csv(fields, rows), f"threatshield_threats_{ts}.csv")


@router.get("/api/export/alerts.csv")
async def export_alerts_csv(
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export alert log as CSV."""
    admin = is_admin(current_user)
    uid = current_user["id"]

    q = select(Alert).outerjoin(Email, Alert.email_id == Email.id)
    if not admin:
        q = q.where(
            or_(
                Alert.email_id.is_(None),
                Email.source_type == "gmail_watch",
                Email.uploaded_by == uid,
            )
        )
    if severity:
        q = q.where(Alert.severity == severity)
    if acknowledged is not None:
        q = q.where(Alert.is_acknowledged == acknowledged)
    q = q.order_by(desc(Alert.created_at)).limit(10_000)

    rows_raw = (await db.execute(q)).scalars().all()
    fields = [
        "id", "created_at", "alert_type", "severity", "title", "message",
        "email_id", "is_acknowledged", "acknowledged_at",
    ]
    rows = [
        {
            "id": a.id,
            "created_at": a.created_at.isoformat() if a.created_at else "",
            "alert_type": a.alert_type,
            "severity": a.severity,
            "title": a.title,
            "message": a.message,
            "email_id": a.email_id or "",
            "is_acknowledged": a.is_acknowledged,
            "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else "",
        }
        for a in rows_raw
    ]

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _csv_response(_make_csv(fields, rows), f"threatshield_alerts_{ts}.csv")