"""
ThreatShield AI - URL Analysis Model
"""
from sqlalchemy import Column, Integer, Text, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.core.database import Base


class URLAnalysis(Base):
    __tablename__ = "url_analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    urls_found = Column(Text)           # JSON array of all URLs extracted
    malicious_urls = Column(Text)       # JSON array of confirmed malicious URLs
    suspicious_urls = Column(Text)      # JSON array of suspicious URLs
    url_risk_score = Column(Float, default=0.0)
    url_threat_types = Column(Text)     # JSON array e.g. ["MALWARE","SOCIAL_ENGINEERING"]
    safe_browsing_checked = Column(Boolean, default=False)
    analysis_details = Column(Text)     # JSON array of per-url heuristic details

    # Domain age check — limited to ONE url domain per email (the first
    # whose domain differs from the sender's, to avoid hammering the free
    # RDAP service on emails with many links). NULL if no qualifying url
    # was found, or the lookup wasn't run/failed.
    domain_age_checked_url = Column(Text, nullable=True)     # which url's domain we checked
    domain_age_days = Column(Integer, nullable=True)
    domain_is_newly_registered = Column(Boolean, nullable=True, default=False)

    analyzed_at = Column(DateTime(timezone=True), server_default=func.now())