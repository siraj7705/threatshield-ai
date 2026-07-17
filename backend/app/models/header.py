"""
ThreatShield AI - Header Analysis Model
"""
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.core.database import Base


class HeaderAnalysis(Base):
    __tablename__ = "header_analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    return_path = Column(String(255))
    received_chain = Column(Text)  # JSON array
    originating_ip = Column(String(45))
    originating_country = Column(String(100))
    originating_city = Column(String(100))
    spf_result = Column(String(20))  # pass, fail, softfail, none
    dkim_result = Column(String(20))
    dmarc_result = Column(String(20))
    message_id_valid = Column(Boolean)
    from_domain = Column(String(255))
    return_path_domain = Column(String(255))
    domain_match = Column(Boolean)
    spoofing_detected = Column(Boolean, default=False)
    routing_anomalies = Column(Text)  # JSON array
    mail_client = Column(String(255))
    header_risk_score = Column(Float, default=0.0)
    analyzed_at = Column(DateTime(timezone=True), server_default=func.now())