"""
ThreatShield AI - Threat Analysis & Scoring Models
"""
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.core.database import Base


class ThreatAnalysis(Base):
    __tablename__ = "threat_analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    threat_detected = Column(Boolean, default=False)
    threat_type = Column(String(50))  # bomb_threat, violence, terror, extortion, harassment, safe
    threat_target = Column(Text)
    threat_description = Column(Text)
    confidence_score = Column(Float, default=0.0)
    severity = Column(String(20), default="safe")  # safe, low, medium, high, critical
    intent_score = Column(Float, default=0.0)
    urgency_score = Column(Float, default=0.0)
    keywords_found = Column(Text)  # JSON array
    entities_found = Column(Text)  # JSON array
    nlp_model_used = Column(String(100))
    analysis_duration_ms = Column(Integer)
    analyzed_at = Column(DateTime(timezone=True), server_default=func.now())


class ThreatScore(Base):
    __tablename__ = "threat_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    overall_score = Column(Float, nullable=False, default=0.0)
    nlp_score = Column(Float, default=0.0)
    keyword_score = Column(Float, default=0.0)
    sender_score = Column(Float, default=0.0)
    header_score = Column(Float, default=0.0)
    urgency_score = Column(Float, default=0.0)
    attachment_score = Column(Float, default=0.0)
    category = Column(String(20), nullable=False, default="safe", index=True)
    explanation = Column(Text)  # JSON array of reasons
    recommended_action = Column(String(20), default="allow")
    scored_at = Column(DateTime(timezone=True), server_default=func.now())