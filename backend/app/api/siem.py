"""
LOCATION: threatshield-ai/backend/app/api/siem.py

ThreatShield AI - SIEM API Endpoints

Endpoints:
  GET  /api/siem/health          ES cluster health + doc counts
  POST /api/siem/search          query any ES index
  POST /api/siem/reindex/emails  backfill existing DB emails into ES
  POST /api/siem/reindex/alerts  backfill existing DB alerts into ES
  POST /api/siem/reindex/audit   backfill existing audit logs into ES

Admin-only endpoints: reindex routes.
All other routes: any authenticated user.
"""
import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.database import get_db
from app.core.security import get_current_user, require_roles
from app.models.alert import Alert
from app.models.audit import AuditLog
from app.models.email import Email
from app.models.header import HeaderAnalysis
from app.models.ip_reputation import IPReputation
from app.models.threat import ThreatAnalysis, ThreatScore
from app.services.siem import siem_client

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/siem", tags=["SIEM / Elasticsearch"])

ADMIN_ONLY = require_roles(["admin"])


# ── Request / response schemas ─────────────────────────────────────────────────

class SIEMSearchRequest(BaseModel):
    index: str = "emails"           # emails | alerts | audit
    query: Dict[str, Any] = {"match_all": {}}
    size: int = 50
    sort: Optional[List[Any]] = [{"@timestamp": {"order": "desc"}}]


class ReindexResponse(BaseModel):
    indexed: int
    errors: int
    message: str


# ── GET /api/siem/health ──────────────────────────────────────────────────────

@router.get("/health")
async def siem_health(
    current_user: dict = Depends(get_current_user),
):
    """
    Elasticsearch cluster health and index doc counts.
    Use this to verify the SIEM integration is working.
    """
    return await siem_client.health()


# ── POST /api/siem/search ─────────────────────────────────────────────────────

@router.post("/search")
async def siem_search(
    body: SIEMSearchRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Run an Elasticsearch query against a ThreatShield index.

    Example — find all critical alerts in the last 7 days:
    {
      "index": "alerts",
      "query": {
        "bool": {
          "must": [
            {"term": {"severity": "critical"}},
            {"range": {"@timestamp": {"gte": "now-7d"}}}
          ]
        }
      }
    }

    Example — full-text search emails for a keyword:
    {
      "index": "emails",
      "query": {"match": {"subject": "bomb"}}
    }
    """
    if body.index not in ("emails", "alerts", "audit"):
        raise HTTPException(
            status_code=400,
            detail="index must be one of: emails, alerts, audit",
        )

    return await siem_client.search(
        index=body.index,
        query=body.query,
        size=min(body.size, 200),
        sort=body.sort,
    )


# ── POST /api/siem/reindex/emails ────────────────────────────────────────────

@router.post("/reindex/emails", response_model=ReindexResponse)
async def reindex_emails(
    days: int = Query(90, ge=1, le=3650, description="Back-fill emails from the last N days"),
    current_user: dict = Depends(ADMIN_ONLY),
    db: AsyncSession = Depends(get_db),
):
    """
    Back-fill existing emails from the database into Elasticsearch.
    Admin only. Idempotent — re-running updates existing docs.
    """
    from datetime import datetime, timedelta, timezone
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Fetch emails with their threat/score/header/ip data
    emails = (await db.execute(
        select(Email).where(Email.upload_date >= since)
    )).scalars().all()

    if not emails:
        return ReindexResponse(indexed=0, errors=0, message="No emails found in the given window")

    email_ids = [e.id for e in emails]

    ta_map = {r.email_id: r for r in (await db.execute(
        select(ThreatAnalysis).where(ThreatAnalysis.email_id.in_(email_ids))
    )).scalars().all()}

    ts_map = {r.email_id: r for r in (await db.execute(
        select(ThreatScore).where(ThreatScore.email_id.in_(email_ids))
    )).scalars().all()}

    ha_map = {r.email_id: r for r in (await db.execute(
        select(HeaderAnalysis).where(HeaderAnalysis.email_id.in_(email_ids))
    )).scalars().all()}

    ip_map = {r.email_id: r for r in (await db.execute(
        select(IPReputation).where(IPReputation.email_id.in_(email_ids))
    )).scalars().all()}

    indexed = 0
    errors  = 0

    for email in emails:
        ta = ta_map.get(email.id)
        ts = ts_map.get(email.id)
        ha = ha_map.get(email.id)
        ip = ip_map.get(email.id)

        try:
            await siem_client.index_email(
                email_id=email.id,
                subject=email.subject or "",
                sender_email=email.sender_email or "",
                threat_detected=ta.threat_detected if ta else False,
                threat_type=ta.threat_type if ta else "safe",
                threat_score=ts.overall_score if ts else 0.0,
                severity=ts.category if ts else "safe",
                action_taken=email.action_taken or "allow",
                upload_date=email.upload_date,
                originating_ip=ha.originating_ip if ha else None,
                originating_country=ha.originating_country if ha else (ip.country if ip else None),
                is_vpn=ip.is_vpn if ip else False,
                is_tor=ip.is_tor if ip else False,
                is_proxy=ip.is_proxy if ip else False,
            )
            indexed += 1
        except Exception as e:
            logger.error(f"Reindex error for email {email.id}: {e}")
            errors += 1

    return ReindexResponse(
        indexed=indexed,
        errors=errors,
        message=f"Reindexed {indexed} emails ({errors} errors)",
    )


# ── POST /api/siem/reindex/alerts ────────────────────────────────────────────

@router.post("/reindex/alerts", response_model=ReindexResponse)
async def reindex_alerts(
    days: int = Query(90, ge=1, le=3650),
    current_user: dict = Depends(ADMIN_ONLY),
    db: AsyncSession = Depends(get_db),
):
    """Back-fill existing alerts from the database into Elasticsearch. Admin only."""
    from datetime import datetime, timedelta, timezone
    since = datetime.now(timezone.utc) - timedelta(days=days)

    alerts = (await db.execute(
        select(Alert).where(Alert.created_at >= since)
    )).scalars().all()

    indexed = 0
    errors  = 0

    for alert in alerts:
        try:
            await siem_client.index_alert(
                alert_id=alert.id,
                email_id=alert.email_id,
                alert_type=alert.alert_type,
                severity=alert.severity,
                title=alert.title,
                message=alert.message,
                details=alert.details,
            )
            indexed += 1
        except Exception as e:
            logger.error(f"Reindex error for alert {alert.id}: {e}")
            errors += 1

    return ReindexResponse(
        indexed=indexed,
        errors=errors,
        message=f"Reindexed {indexed} alerts ({errors} errors)",
    )


# ── POST /api/siem/reindex/audit ─────────────────────────────────────────────

@router.post("/reindex/audit", response_model=ReindexResponse)
async def reindex_audit(
    days: int = Query(90, ge=1, le=3650),
    current_user: dict = Depends(ADMIN_ONLY),
    db: AsyncSession = Depends(get_db),
):
    """Back-fill existing audit logs into Elasticsearch. Admin only."""
    from datetime import datetime, timedelta, timezone
    since = datetime.now(timezone.utc) - timedelta(days=days)

    logs = (await db.execute(
        select(AuditLog).where(AuditLog.created_at >= since)
    )).scalars().all()

    indexed = 0
    errors  = 0

    for log in logs:
        try:
            await siem_client.index_audit(
                audit_id=log.id,
                user_id=log.user_id,
                action=log.action,
                resource_type=log.resource_type,
                resource_id=log.resource_id,
                ip_address=getattr(log, "ip_address", None),
                details=log.details,
                created_at=log.created_at,
            )
            indexed += 1
        except Exception as e:
            logger.error(f"Reindex error for audit {log.id}: {e}")
            errors += 1

    return ReindexResponse(
        indexed=indexed,
        errors=errors,
        message=f"Reindexed {indexed} audit logs ({errors} errors)",
    )