"""
ThreatShield AI - Reports API Routes
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import io
import json
import csv

from app.core.database import get_db
from app.core.security import get_current_user, is_admin
from app.models.email import Email
from app.models.threat import ThreatAnalysis, ThreatScore
from app.models.header import HeaderAnalysis
from app.models.alert import Alert
from app.models.case import Case
from app.services.report_generator import report_generator

router = APIRouter(prefix="/api/reports", tags=["Reports"])


def _check_email_report_access(current_user: dict, email_record: Email):
    """Raise 404 if the current user can't access this email's report (admins exempt)."""
    if is_admin(current_user):
        return
    owns = (
        email_record.source_type == "gmail_watch" or
        email_record.uploaded_by == current_user["id"]
    )
    if not owns:
        raise HTTPException(status_code=404, detail="Email not found")


@router.get("/email/{email_id}/pdf")
async def generate_email_pdf_report(
    email_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate PDF forensic report for a specific email — only if you own it (or are admin)."""
    # Fetch all analysis data
    email_result = await db.execute(select(Email).where(Email.id == email_id))
    email_record = email_result.scalar_one_or_none()
    if not email_record:
        raise HTTPException(status_code=404, detail="Email not found")
    _check_email_report_access(current_user, email_record)

    threat_result = await db.execute(select(ThreatAnalysis).where(ThreatAnalysis.email_id == email_id))
    threat = threat_result.scalar_one_or_none()

    score_result = await db.execute(select(ThreatScore).where(ThreatScore.email_id == email_id))
    score = score_result.scalar_one_or_none()

    header_result = await db.execute(select(HeaderAnalysis).where(HeaderAnalysis.email_id == email_id))
    header = header_result.scalar_one_or_none()

    # Build analysis data dict
    analysis_data = {
        "email": {
            "id": email_record.id,
            "subject": email_record.subject,
            "sender_email": email_record.sender_email,
            "recipient_email": email_record.recipient_email,
            "received_date": str(email_record.received_date) if email_record.received_date else "N/A",
            "status": email_record.status,
            "action_taken": email_record.action_taken,
        },
    }

    if threat:
        analysis_data["threat_analysis"] = {
            "threat_detected": threat.threat_detected,
            "threat_type": threat.threat_type,
            "threat_target": threat.threat_target,
            "threat_description": threat.threat_description,
            "confidence_score": threat.confidence_score,
            "severity": threat.severity,
            "intent_score": threat.intent_score,
            "urgency_score": threat.urgency_score,
            "keywords_found": threat.keywords_found,
        }

    if score:
        analysis_data["threat_score"] = {
            "overall_score": score.overall_score,
            "nlp_score": score.nlp_score,
            "keyword_score": score.keyword_score,
            "sender_score": score.sender_score,
            "header_score": score.header_score,
            "urgency_score": score.urgency_score,
            "attachment_score": score.attachment_score,
            "category": score.category,
            "explanation": score.explanation,
            "recommended_action": score.recommended_action,
        }

    if header:
        analysis_data["header_analysis"] = {
            "spf_result": header.spf_result,
            "dkim_result": header.dkim_result,
            "dmarc_result": header.dmarc_result,
            "from_domain": header.from_domain,
            "return_path_domain": header.return_path_domain,
            "domain_match": header.domain_match,
            "spoofing_detected": header.spoofing_detected,
            "originating_ip": header.originating_ip,
            "mail_client": header.mail_client,
            "header_risk_score": header.header_risk_score,
            "routing_anomalies": header.routing_anomalies,
        }

    # Generate PDF
    pdf_bytes = report_generator.generate_email_report(analysis_data)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=threatshield_report_{email_id}.pdf"
        },
    )


@router.get("/executive-summary/pdf")
async def generate_executive_summary_pdf(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate executive summary PDF report. Scoped to your own data unless you're an admin."""
    admin_view = is_admin(current_user)
    user_id = current_user["id"]

    def email_owned():
        return (Email.source_type == "gmail_watch") | (Email.uploaded_by == user_id)

    # Gather stats
    total_q = select(func.count(Email.id))
    if not admin_view:
        total_q = total_q.where(email_owned())
    total = (await db.execute(total_q)).scalar() or 0

    threats_q = select(func.count(ThreatAnalysis.id)).where(ThreatAnalysis.threat_detected == True)
    if not admin_view:
        threats_q = threats_q.join(Email, ThreatAnalysis.email_id == Email.id).where(email_owned())
    threats = (await db.execute(threats_q)).scalar() or 0

    blocked_q = select(func.count(Email.id)).where(Email.action_taken == "block")
    if not admin_view:
        blocked_q = blocked_q.where(email_owned())
    blocked = (await db.execute(blocked_q)).scalar() or 0

    quarantined_q = select(func.count(Email.id)).where(Email.action_taken == "quarantine")
    if not admin_view:
        quarantined_q = quarantined_q.where(email_owned())
    quarantined = (await db.execute(quarantined_q)).scalar() or 0

    critical_q = select(func.count(Alert.id)).where(Alert.severity == "critical")
    if not admin_view:
        critical_q = critical_q.select_from(Alert).outerjoin(Email, Alert.email_id == Email.id).where(
            (Alert.email_id.is_(None)) | email_owned()
        )
    critical_alerts = (await db.execute(critical_q)).scalar() or 0

    cases_q = select(func.count(Case.id)).where(Case.status.in_(["open", "in_progress"]))
    if not admin_view:
        cases_q = cases_q.where((Case.created_by == user_id) | (Case.assigned_to == user_id))
    active_cases = (await db.execute(cases_q)).scalar() or 0

    stats = {
        "total_emails": total,
        "threat_emails": threats,
        "safe_emails": total - threats,
        "blocked_emails": blocked,
        "quarantined_emails": quarantined,
        "critical_alerts": critical_alerts,
        "active_cases": active_cases,
    }

    # Recent threats
    threats_detail_q = (
        select(ThreatAnalysis, ThreatScore, Email)
        .join(ThreatScore, ThreatAnalysis.email_id == ThreatScore.email_id)
        .join(Email, ThreatAnalysis.email_id == Email.id)
        .where(ThreatAnalysis.threat_detected == True)
    )
    if not admin_view:
        threats_detail_q = threats_detail_q.where(email_owned())
    threats_detail_q = threats_detail_q.order_by(ThreatScore.overall_score.desc()).limit(20)
    result = await db.execute(threats_detail_q)
    recent_threats = []
    for row in result.all():
        threat, score, email = row
        recent_threats.append({
            "threat_type": threat.threat_type,
            "severity": threat.severity,
            "overall_score": score.overall_score,
            "sender": email.sender_email,
        })

    pdf_bytes = report_generator.generate_executive_summary(stats, recent_threats)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=threatshield_executive_summary.pdf"
        },
    )


@router.get("/email/{email_id}/json")
async def export_email_json(
    email_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export email analysis as JSON — only if you own it (or are admin)."""
    email_result = await db.execute(select(Email).where(Email.id == email_id))
    email_record = email_result.scalar_one_or_none()
    if not email_record:
        raise HTTPException(status_code=404, detail="Email not found")
    _check_email_report_access(current_user, email_record)

    threat_result = await db.execute(select(ThreatAnalysis).where(ThreatAnalysis.email_id == email_id))
    threat = threat_result.scalar_one_or_none()

    score_result = await db.execute(select(ThreatScore).where(ThreatScore.email_id == email_id))
    score = score_result.scalar_one_or_none()

    data = {
        "email_id": email_record.id,
        "subject": email_record.subject,
        "sender": email_record.sender_email,
        "status": email_record.status,
        "action_taken": email_record.action_taken,
    }

    if threat:
        data["threat_analysis"] = {
            "detected": threat.threat_detected,
            "type": threat.threat_type,
            "confidence": threat.confidence_score,
            "severity": threat.severity,
        }

    if score:
        data["risk_score"] = {
            "overall": score.overall_score,
            "category": score.category,
            "recommended_action": score.recommended_action,
        }

    return data