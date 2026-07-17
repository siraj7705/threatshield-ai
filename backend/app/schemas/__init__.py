"""
ThreatShield AI - Pydantic Schemas
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime


# ============================================
# AUTH SCHEMAS
# ============================================
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = None
    role: str = Field(default="analyst", pattern="^(admin|analyst|investigator)$")


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: Optional[datetime]
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenRefresh(BaseModel):
    refresh_token: str


# ============================================
# EMAIL SCHEMAS
# ============================================
class EmailResponse(BaseModel):
    id: int
    message_id: Optional[str]
    subject: Optional[str]
    sender_email: Optional[str]
    sender_name: Optional[str]
    recipient_email: Optional[str]
    body_text: Optional[str]
    received_date: Optional[datetime]
    upload_date: Optional[datetime]
    source_type: str
    file_name: Optional[str]
    file_size: Optional[int]
    status: str
    action_taken: str

    class Config:
        from_attributes = True


class EmailListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    emails: List[EmailResponse]


# ============================================
# THREAT ANALYSIS SCHEMAS
# ============================================
class ThreatAnalysisResponse(BaseModel):
    id: int
    email_id: int
    threat_detected: bool
    threat_type: Optional[str]
    threat_target: Optional[str]
    threat_description: Optional[str]
    confidence_score: float
    severity: str
    intent_score: float
    urgency_score: float
    keywords_found: Optional[str]
    entities_found: Optional[str]
    nlp_model_used: Optional[str]
    analysis_duration_ms: Optional[int]
    analyzed_at: Optional[datetime]

    class Config:
        from_attributes = True


class ThreatScoreResponse(BaseModel):
    id: int
    email_id: int
    overall_score: float
    nlp_score: float
    keyword_score: float
    sender_score: float
    header_score: float
    urgency_score: float
    attachment_score: float
    category: str
    explanation: Optional[str]
    recommended_action: str
    scored_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================
# HEADER ANALYSIS SCHEMAS
# ============================================
class HeaderAnalysisResponse(BaseModel):
    id: int
    email_id: int
    return_path: Optional[str]
    received_chain: Optional[str]
    originating_ip: Optional[str]
    originating_country: Optional[str]
    originating_city: Optional[str]
    spf_result: Optional[str]
    dkim_result: Optional[str]
    dmarc_result: Optional[str]
    message_id_valid: Optional[bool]
    from_domain: Optional[str]
    return_path_domain: Optional[str]
    domain_match: Optional[bool]
    spoofing_detected: bool
    routing_anomalies: Optional[str]
    mail_client: Optional[str]
    header_risk_score: float
    analyzed_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================
# ALERT SCHEMAS
# ============================================
class AlertResponse(BaseModel):
    id: int
    email_id: Optional[int]
    alert_type: str
    severity: str
    title: str
    message: str
    details: Optional[str]
    is_acknowledged: bool
    acknowledged_by: Optional[int]
    acknowledged_at: Optional[datetime]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    total: int
    alerts: List[AlertResponse]


# ============================================
# CASE SCHEMAS
# ============================================
class CaseCreate(BaseModel):
    title: str = Field(..., max_length=255)
    description: Optional[str] = None
    priority: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    email_ids: Optional[List[int]] = None


class CaseResponse(BaseModel):
    id: int
    case_number: str
    title: str
    description: Optional[str]
    status: str
    priority: str
    assigned_to: Optional[int]
    created_by: Optional[int]
    email_ids: Optional[str]
    notes: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    closed_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================
# DASHBOARD SCHEMAS
# ============================================
class DashboardStats(BaseModel):
    total_emails: int
    threat_emails: int
    safe_emails: int
    blocked_emails: int
    quarantined_emails: int
    pending_emails: int
    critical_alerts: int
    unacknowledged_alerts: int
    active_cases: int


class ThreatTrend(BaseModel):
    date: str
    count: int
    threat_type: Optional[str] = None


class DashboardResponse(BaseModel):
    stats: DashboardStats
    recent_alerts: List[AlertResponse]
    threat_trends: List[ThreatTrend]
    severity_distribution: dict
    top_threat_types: dict


# ============================================
# URL ANALYSIS SCHEMAS
# ============================================
class URLAnalysisResponse(BaseModel):
    id: int
    email_id: int
    urls_found: Optional[str]           # JSON array
    malicious_urls: Optional[str]       # JSON array
    suspicious_urls: Optional[str]      # JSON array
    url_risk_score: float
    url_threat_types: Optional[str]     # JSON array
    safe_browsing_checked: bool
    analysis_details: Optional[str]     # JSON array
    domain_age_checked_url: Optional[str] = None
    domain_age_days: Optional[int] = None
    domain_is_newly_registered: Optional[bool] = False
    analyzed_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================
# ATTACHMENT SCAN SCHEMAS
# ============================================
class AttachmentScanResponse(BaseModel):
    id: int
    email_id: int
    filename: Optional[str]
    content_type: Optional[str]
    file_size: Optional[int]

    extraction_ok: bool
    extraction_method: Optional[str]
    extraction_error: Optional[str]
    extracted_text_preview: Optional[str]

    threat_detected: bool
    threat_type: Optional[str]
    threat_target: Optional[str]
    threat_description: Optional[str]
    confidence_score: float
    severity: str
    intent_score: float
    urgency_score: float
    keywords_found: Optional[str]   # JSON array string

    attachment_risk_score: float
    risk_reasons: Optional[str]     # JSON array string

    scanned_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================
# SENDER INTELLIGENCE SCHEMAS
# ============================================
class SenderIntelligenceResponse(BaseModel):
    id: int
    sender_email: str
    sender_domain: str

    total_emails_seen: int
    threat_emails_count: int
    safe_emails_count: int
    blocked_count: int
    quarantined_count: int

    avg_threat_score: float
    max_threat_score: float
    last_threat_score: float

    reputation_score: float
    reputation_label: str

    is_known_malicious: bool
    is_repeat_offender: bool
    is_trusted: bool

    domain_is_disposable: bool
    domain_is_typosquat: bool
    domain_is_lookalike: bool
    domain_is_suspicious_tld: bool
    impersonated_brand: Optional[str]

    domain_age_checked: Optional[bool] = False
    domain_registered_at: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    domain_is_newly_registered: Optional[bool] = False
    domain_registrar: Optional[str] = None

    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    last_threat_at: Optional[datetime]

    notes: Optional[str]

    class Config:
        from_attributes = True


# ============================================
# IP REPUTATION SCHEMAS
# ============================================
class IPReputationResponse(BaseModel):
    id: int
    email_id: int
    ip: Optional[str]
    checked: bool

    is_vpn: bool
    is_tor: bool
    is_proxy: bool
    is_hosting: bool

    isp: Optional[str]
    org: Optional[str]
    country: Optional[str]
    city: Optional[str]

    ip_risk_score: float
    risk_reasons: Optional[str]   # JSON array string
    error: Optional[str]

    checked_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================
# FULL EMAIL ANALYSIS
# ============================================
class FullEmailAnalysis(BaseModel):
    email: EmailResponse
    threat_analysis: Optional[ThreatAnalysisResponse]
    threat_score: Optional[ThreatScoreResponse]
    header_analysis: Optional[HeaderAnalysisResponse]
    url_analysis: Optional[URLAnalysisResponse]
    attachment_scans: List[AttachmentScanResponse] = []
    sender_intelligence: Optional[SenderIntelligenceResponse] = None
    ip_reputation: Optional[IPReputationResponse] = None


# ============================================
# GMAIL ACCOUNT (per-user OAuth connection) SCHEMAS
# ============================================
class GmailAccountResponse(BaseModel):
    """
    Connection status for the current user's linked Gmail account.
    Never includes any token values — those stay server-side, encrypted.
    """
    id: int
    gmail_address: str
    is_active: bool
    is_watching: bool
    last_synced_at: Optional[datetime]
    last_error: Optional[str]
    connected_at: Optional[datetime]

    class Config:
        from_attributes = True


class GmailConnectResponse(BaseModel):
    """Returned by GET /api/gmail/oauth/connect — where to send the browser."""
    authorization_url: str

# ============================================
# DASHBOARD EXTENDED SCHEMAS (#15)
# ============================================
class TopDomainEntry(BaseModel):
    domain: str
    threat_count: int
    avg_threat_score: float
    is_known_malicious: bool
    is_repeat_offender: bool


class TimelineEntry(BaseModel):
    date: str
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