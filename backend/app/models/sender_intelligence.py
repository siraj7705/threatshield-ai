"""
ThreatShield AI - Sender Intelligence Model

One row per unique sender email address, updated on every scan.
Tracks historical behaviour so reputation improves over time rather
than being recalculated from scratch each time.
"""
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, Text, DateTime, Index
)
from sqlalchemy.sql import func
from app.core.database import Base


class SenderIntelligence(Base):
    __tablename__ = "sender_intelligence"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Identity
    sender_email = Column(String(255), nullable=False, unique=True, index=True)
    sender_domain = Column(String(255), nullable=False, index=True)

    # Volume history
    total_emails_seen = Column(Integer, default=0, nullable=False)
    threat_emails_count = Column(Integer, default=0, nullable=False)   # emails where threat_detected=True
    safe_emails_count = Column(Integer, default=0, nullable=False)
    blocked_count = Column(Integer, default=0, nullable=False)         # action_taken == "block"
    quarantined_count = Column(Integer, default=0, nullable=False)     # action_taken == "quarantine"

    # Score history
    avg_threat_score = Column(Float, default=0.0)   # rolling average of overall_score
    max_threat_score = Column(Float, default=0.0)   # worst score ever seen from this sender
    last_threat_score = Column(Float, default=0.0)  # most recent overall_score

    # Derived reputation (0-100, higher = more dangerous)
    reputation_score = Column(Float, default=0.0, nullable=False)
    reputation_label = Column(String(20), default="unknown")
    # "trusted" | "clean" | "neutral" | "suspicious" | "malicious"

    # Flags
    is_known_malicious = Column(Boolean, default=False)   # ever scored ≥ 80
    is_repeat_offender = Column(Boolean, default=False)   # ≥ 3 threats
    is_trusted = Column(Boolean, default=False)           # manually whitelisted or consistently clean

    # Domain-level signals (cached from domain_checker)
    domain_is_disposable = Column(Boolean, default=False)
    domain_is_typosquat = Column(Boolean, default=False)
    domain_is_lookalike = Column(Boolean, default=False)
    domain_is_suspicious_tld = Column(Boolean, default=False)
    impersonated_brand = Column(String(100))

    # Domain age (cached from domain_age_checker / RDAP) — checked once per
    # sender at first sighting, since registration date never changes.
    domain_age_checked = Column(Boolean, default=False)   # False if RDAP lookup failed/skipped
    domain_registered_at = Column(DateTime(timezone=True), nullable=True)
    domain_age_days = Column(Integer, nullable=True)
    domain_is_newly_registered = Column(Boolean, default=False)
    domain_registrar = Column(String(255))

    # Timestamps
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_threat_at = Column(DateTime(timezone=True))     # when last threat email arrived

    # Notes (manual analyst annotation)
    notes = Column(Text)