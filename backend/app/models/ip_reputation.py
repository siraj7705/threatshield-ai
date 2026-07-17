"""
ThreatShield AI - IP Reputation Model
Stores VPN/Tor/Proxy detection results per email.
"""
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.core.database import Base


class IPReputation(Base):
    __tablename__ = "ip_reputations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)

    ip = Column(String(45))          # IPv4 or IPv6
    checked = Column(Boolean, default=False)   # False = private IP / skipped

    is_vpn = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    is_hosting = Column(Boolean, default=False)

    isp = Column(String(255))
    org = Column(String(255))
    country = Column(String(100))
    city = Column(String(100))

    ip_risk_score = Column(Float, default=0.0)
    risk_reasons = Column(Text)      # JSON array of human-readable reasons
    error = Column(String(255))      # Set when lookup failed

    checked_at = Column(DateTime(timezone=True), server_default=func.now())