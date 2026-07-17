"""
LOCATION: threatshield-ai/backend/app/api/dashboard.py

ThreatShield AI - Dashboard & Analytics API Routes

New endpoints added:
  GET /api/dashboard/stats              — existing (unchanged logic, extended response)
  GET /api/dashboard/top-threat-domains — top sender domains by threat count
  GET /api/dashboard/timeline           — threat count per day for the selected window
  GET /api/dashboard/location-map       — threat counts grouped by country
"""
import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, desc, cast, Date
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.database import get_db
from app.core.security import get_current_user, is_admin
from app.models.alert import Alert
from app.models.case import Case
from app.models.email import Email
from app.models.header import HeaderAnalysis
from app.models.ip_reputation import IPReputation
from app.models.sender_intelligence import SenderIntelligence
from app.models.threat import ThreatAnalysis, ThreatScore
from app.schemas import (
    AlertResponse,
    DashboardResponse,
    DashboardStats,
    ThreatTrend,
)

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


# ── Extra response schemas (dashboard-only, not in shared schemas) ─────────────

class TopDomainEntry(BaseModel):
    domain: str
    threat_count: int
    avg_threat_score: float
    is_known_malicious: bool
    is_repeat_offender: bool


class TimelineEntry(BaseModel):
    date: str           # ISO date string YYYY-MM-DD
    total: int
    critical: int
    high: int
    warning: int


class LocationEntry(BaseModel):
    country: str
    city: Optional[str] = None
    threat_count: int
    lat: Optional[float] = None
    lng: Optional[float] = None


# Approximate centroids for the most common countries — used to let the
# frontend render a dot map without a paid geocoding API.
_COUNTRY_CENTROIDS: dict = {
    "United States": (37.09, -95.71),
    "China": (35.86, 104.19),
    "Russia": (61.52, 105.31),
    "Germany": (51.16, 10.45),
    "United Kingdom": (55.37, -3.43),
    "India": (20.59, 78.96),
    "Brazil": (-14.23, -51.92),
    "Nigeria": (9.08, 8.67),
    "Ukraine": (48.37, 31.16),
    "Iran": (32.42, 53.68),
    "France": (46.22, 2.21),
    "South Korea": (35.90, 127.76),
    "Japan": (36.20, 138.25),
    "Canada": (56.13, -106.34),
    "Australia": (-25.27, 133.77),
    "Netherlands": (52.13, 5.29),
    "Pakistan": (30.37, 69.34),
    "Turkey": (38.96, 35.24),
    "Indonesia": (-0.78, 113.92),
    "South Africa": (-30.55, 22.93),
    "Mexico": (23.63, -102.55),
    "Egypt": (26.82, 30.80),
    "Saudi Arabia": (23.88, 45.07),
    "Argentina": (-38.41, -63.61),
    "Italy": (41.87, 12.56),
    "Spain": (40.46, -3.74),
    "Poland": (51.91, 19.14),
    "Romania": (45.94, 24.96),
    "North Korea": (40.33, 127.51),
    "Vietnam": (14.05, 108.27),
}


def _get_centroid(country: str):
    """Return (lat, lng) centroid for a country name, or (None, None) if unknown."""
    return _COUNTRY_CENTROIDS.get(country, (None, None))


# ── Ownership helpers ──────────────────────────────────────────────────────────

def _email_owned(user_id: int):
    return (Email.source_type == "gmail_watch") | (Email.uploaded_by == user_id)


def _case_owned(user_id: int):
    return (Case.created_by == user_id) | (Case.assigned_to == user_id)


def _alert_owned_join(query, user_id: int):
    return query.outerjoin(Email, Alert.email_id == Email.id).where(
        (Alert.email_id.is_(None)) | _email_owned(user_id)
    )


# ── /stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=DashboardResponse)
async def get_dashboard_stats(
    days: int = Query(30, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get comprehensive dashboard statistics.

    Admins see org-wide numbers. Analysts/investigators see their own emails
    plus anything from the shared mailbox watcher.
    """
    admin_view = is_admin(current_user)
    user_id    = current_user["id"]

    async def _count(q):
        return (await db.execute(q)).scalar() or 0

    # Total emails
    total_q = select(func.count(Email.id))
    if not admin_view:
        total_q = total_q.where(_email_owned(user_id))
    total_emails = await _count(total_q)

    # Threat emails
    threat_q = select(func.count(ThreatAnalysis.id)).where(ThreatAnalysis.threat_detected == True)
    if not admin_view:
        threat_q = threat_q.join(Email, ThreatAnalysis.email_id == Email.id).where(_email_owned(user_id))
    threat_emails = await _count(threat_q)

    safe_emails = total_emails - threat_emails

    # Blocked / quarantined / pending
    for action, attr in [("block", "blocked"), ("quarantine", "quarantined")]:
        q = select(func.count(Email.id)).where(Email.action_taken == action)
        if not admin_view:
            q = q.where(_email_owned(user_id))
        locals()[f"{attr}_emails"] = await _count(q)

    blocked_emails    = await _count(select(func.count(Email.id)).where(
        Email.action_taken == "block", *([_email_owned(user_id)] if not admin_view else [])))
    quarantined_emails = await _count(select(func.count(Email.id)).where(
        Email.action_taken == "quarantine", *([_email_owned(user_id)] if not admin_view else [])))
    pending_emails    = await _count(select(func.count(Email.id)).where(
        Email.status == "pending", *([_email_owned(user_id)] if not admin_view else [])))

    # Critical / unacknowledged alerts
    critical_q = select(func.count(Alert.id)).where(Alert.severity == "critical")
    unack_q    = select(func.count(Alert.id)).where(Alert.is_acknowledged == False)
    if not admin_view:
        critical_q = _alert_owned_join(critical_q.select_from(Alert), user_id)
        unack_q    = _alert_owned_join(unack_q.select_from(Alert), user_id)
    critical_alerts       = await _count(critical_q)
    unacknowledged_alerts = await _count(unack_q)

    # Active cases
    cases_q = select(func.count(Case.id)).where(Case.status.in_(["open", "in_progress"]))
    if not admin_view:
        cases_q = cases_q.where(_case_owned(user_id))
    active_cases = await _count(cases_q)

    stats = DashboardStats(
        total_emails=total_emails,
        threat_emails=threat_emails,
        safe_emails=safe_emails,
        blocked_emails=blocked_emails,
        quarantined_emails=quarantined_emails,
        pending_emails=pending_emails,
        critical_alerts=critical_alerts,
        unacknowledged_alerts=unacknowledged_alerts,
        active_cases=active_cases,
    )

    # Recent alerts
    alerts_q = select(Alert).order_by(desc(Alert.created_at)).limit(10)
    if not admin_view:
        alerts_q = _alert_owned_join(alerts_q, user_id)
    alerts_result  = await db.execute(alerts_q)
    recent_alerts  = [AlertResponse.model_validate(a) for a in alerts_result.scalars().all()]

    # Severity distribution
    sev_q = select(ThreatScore.category, func.count(ThreatScore.id))
    if not admin_view:
        sev_q = sev_q.join(Email, ThreatScore.email_id == Email.id).where(_email_owned(user_id))
    sev_q = sev_q.group_by(ThreatScore.category)
    severity_distribution = dict((await db.execute(sev_q)).all())

    # Top threat types
    type_q = (
        select(ThreatAnalysis.threat_type, func.count(ThreatAnalysis.id))
        .where(ThreatAnalysis.threat_detected == True)
    )
    if not admin_view:
        type_q = type_q.join(Email, ThreatAnalysis.email_id == Email.id).where(_email_owned(user_id))
    type_q = type_q.group_by(ThreatAnalysis.threat_type).order_by(
        desc(func.count(ThreatAnalysis.id))
    ).limit(10)
    top_threat_types = dict((await db.execute(type_q)).all())

    return DashboardResponse(
        stats=stats,
        recent_alerts=recent_alerts,
        threat_trends=[],
        severity_distribution=severity_distribution,
        top_threat_types=top_threat_types,
    )


# ── /top-threat-domains ────────────────────────────────────────────────────────

@router.get("/top-threat-domains", response_model=List[TopDomainEntry])
async def get_top_threat_domains(
    limit: int = Query(10, ge=1, le=50),
    days: int = Query(90, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Top sender domains ranked by number of threat emails.

    Pulls from sender_intelligence table which is updated every time an
    email is processed. Returns domain, threat count, average threat score,
    and whether the domain is flagged as malicious or a repeat offender.
    """
    admin_view = is_admin(current_user)
    user_id    = current_user["id"]
    since      = datetime.now(timezone.utc) - timedelta(days=days)

    q = (
        select(
            SenderIntelligence.sender_domain,
            SenderIntelligence.threat_emails_count,
            SenderIntelligence.avg_threat_score,
            SenderIntelligence.is_known_malicious,
            SenderIntelligence.is_repeat_offender,
        )
        .where(
            SenderIntelligence.threat_emails_count > 0,
            SenderIntelligence.last_seen >= since,
        )
    )

    # Non-admins: only domains seen in emails they own
    if not admin_view:
        owned_domains = (
            select(func.lower(func.split_part(Email.sender_email, "@", 2)))
            .where(_email_owned(user_id))
            .scalar_subquery()
        )
        q = q.where(
            func.lower(SenderIntelligence.sender_domain).in_(owned_domains)
        )

    q = q.order_by(
        desc(SenderIntelligence.threat_emails_count),
        desc(SenderIntelligence.avg_threat_score),
    ).limit(limit)

    rows = (await db.execute(q)).all()

    return [
        TopDomainEntry(
            domain=row.sender_domain,
            threat_count=row.threat_emails_count,
            avg_threat_score=round(row.avg_threat_score or 0.0, 1),
            is_known_malicious=row.is_known_malicious or False,
            is_repeat_offender=row.is_repeat_offender or False,
        )
        for row in rows
    ]


# ── /timeline ──────────────────────────────────────────────────────────────────

@router.get("/timeline", response_model=List[TimelineEntry])
async def get_threat_timeline(
    days: int = Query(30, ge=1, le=365),
    threat_type: Optional[str] = Query(None, description="Filter by threat type e.g. bomb_threat"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Threat count per day broken down by severity band (critical / high / warning).

    Returns one entry per day that had at least one threat, sorted oldest→newest.
    Days with zero threats are omitted (frontend can fill gaps).
    """
    admin_view = is_admin(current_user)
    user_id    = current_user["id"]
    since      = datetime.now(timezone.utc) - timedelta(days=days)

    # Base join: ThreatAnalysis → Email (for ownership + date)
    base = (
        select(
            func.strftime("%Y-%m-%d", Email.upload_date).label("day"),
            ThreatScore.category.label("severity"),
            func.count(ThreatAnalysis.id).label("cnt"),
        )
        .join(Email, ThreatAnalysis.email_id == Email.id)
        .join(ThreatScore, ThreatScore.email_id == Email.id)
        .where(
            ThreatAnalysis.threat_detected == True,
            Email.upload_date >= since,
        )
    )

    if threat_type:
        base = base.where(ThreatAnalysis.threat_type == threat_type)

    if not admin_view:
        base = base.where(_email_owned(user_id))

    base = base.group_by("day", ThreatScore.category).order_by("day")
    rows = (await db.execute(base)).all()

    # Aggregate into per-day buckets
    buckets: dict = {}
    for row in rows:
        day_str = str(row.day)
        if day_str not in buckets:
            buckets[day_str] = {"total": 0, "critical": 0, "high": 0, "warning": 0}
        sev = row.severity or "warning"
        if sev in buckets[day_str]:
            buckets[day_str][sev] += row.cnt
        buckets[day_str]["total"] += row.cnt

    return [
        TimelineEntry(date=day, **counts)
        for day, counts in sorted(buckets.items())
    ]


# ── /location-map ──────────────────────────────────────────────────────────────

@router.get("/location-map", response_model=List[LocationEntry])
async def get_location_map(
    days: int = Query(90, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Threat counts grouped by originating country (and city where available).

    Data source priority:
      1. header.originating_country / originating_city  (most accurate — from
         Received headers parsed during ingestion)
      2. ip_reputation.country / city                   (VPN/proxy detection
         lookup result, used as fallback)

    Each entry includes approximate lat/lng centroids for the country so the
    frontend can render a dot map without a geocoding API.
    """
    admin_view = is_admin(current_user)
    user_id    = current_user["id"]
    since      = datetime.now(timezone.utc) - timedelta(days=days)

    # ── Source 1: Header originating country ──────────────────────────────────
    header_q = (
        select(
            HeaderAnalysis.originating_country.label("country"),
            HeaderAnalysis.originating_city.label("city"),
            func.count(HeaderAnalysis.id).label("cnt"),
        )
        .join(Email, HeaderAnalysis.email_id == Email.id)
        .join(ThreatAnalysis, ThreatAnalysis.email_id == Email.id)
        .where(
            ThreatAnalysis.threat_detected == True,
            Email.upload_date >= since,
            HeaderAnalysis.originating_country.isnot(None),
            HeaderAnalysis.originating_country != "",
        )
    )
    if not admin_view:
        header_q = header_q.where(_email_owned(user_id))
    header_q = header_q.group_by(
        HeaderAnalysis.originating_country,
        HeaderAnalysis.originating_city,
    )
    header_rows = (await db.execute(header_q)).all()

    # ── Source 2: IP reputation country (fallback for emails without headers) ─
    ip_q = (
        select(
            IPReputation.country.label("country"),
            IPReputation.city.label("city"),
            func.count(IPReputation.id).label("cnt"),
        )
        .join(Email, IPReputation.email_id == Email.id)
        .join(ThreatAnalysis, ThreatAnalysis.email_id == Email.id)
        .where(
            ThreatAnalysis.threat_detected == True,
            Email.upload_date >= since,
            IPReputation.country.isnot(None),
            IPReputation.country != "",
            # Only use IP-rep rows where header didn't already provide a country
            ~Email.id.in_(
                select(HeaderAnalysis.email_id).where(
                    HeaderAnalysis.originating_country.isnot(None),
                    HeaderAnalysis.originating_country != "",
                )
            ),
        )
    )
    if not admin_view:
        ip_q = ip_q.where(_email_owned(user_id))
    ip_q = ip_q.group_by(IPReputation.country, IPReputation.city)
    ip_rows = (await db.execute(ip_q)).all()

    # ── Merge both sources ─────────────────────────────────────────────────────
    merged: dict = {}
    for row in list(header_rows) + list(ip_rows):
        country = (row.country or "Unknown").strip()
        city    = (row.city or "").strip() or None
        key     = (country, city)
        merged[key] = merged.get(key, 0) + (row.cnt or 0)

    results = []
    for (country, city), count in sorted(merged.items(), key=lambda x: -x[1]):
        lat, lng = _get_centroid(country)
        results.append(
            LocationEntry(
                country=country,
                city=city,
                threat_count=count,
                lat=lat,
                lng=lng,
            )
        )

    return results
