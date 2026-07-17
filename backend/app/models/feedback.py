"""
ThreatShield AI - Feedback Model
Stores analyst corrections for continuous learning.
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.sql import func
from app.core.database import Base


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    analyst_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # What the model predicted
    original_label = Column(String(50), nullable=False)
    original_confidence = Column(String(10))

    # What the analyst says it actually is
    correct_label = Column(String(50), nullable=False)

    # Was this a false positive (model said threat, analyst says safe)?
    is_false_positive = Column(Boolean, default=False)

    # Email text snapshot at time of feedback (for retraining)
    email_text_snapshot = Column(Text)

    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Whether this feedback has been used in a retrain
    used_in_training = Column(Boolean, default=False)