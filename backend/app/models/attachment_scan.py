"""
ThreatShield AI - Attachment Scan Model
Stores per-attachment content-scanning results linked to an email.
"""
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey
)
from sqlalchemy.sql import func
from app.core.database import Base


class AttachmentScan(Base):
    __tablename__ = "attachment_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(
        Integer,
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── File identity ────────────────────────────────────────────────────────
    filename = Column(String(255))
    content_type = Column(String(100))
    file_size = Column(Integer, default=0)

    # ── Extraction ───────────────────────────────────────────────────────────
    extraction_ok = Column(Boolean, default=False)
    extraction_method = Column(String(30))   # pypdf | python-docx | plaintext | unsupported | error
    extraction_error = Column(Text)          # null when ok
    extracted_text_preview = Column(Text)    # first 500 chars (for UI/debug; not full text)

    # ── NLP result ───────────────────────────────────────────────────────────
    threat_detected = Column(Boolean, default=False)
    threat_type = Column(String(50))
    threat_target = Column(Text)
    threat_description = Column(Text)
    confidence_score = Column(Float, default=0.0)
    severity = Column(String(20), default="safe")
    intent_score = Column(Float, default=0.0)
    urgency_score = Column(Float, default=0.0)
    keywords_found = Column(Text)            # JSON array

    # ── Risk ─────────────────────────────────────────────────────────────────
    attachment_risk_score = Column(Float, default=0.0)
    risk_reasons = Column(Text)              # JSON array

    scanned_at = Column(DateTime(timezone=True), server_default=func.now())