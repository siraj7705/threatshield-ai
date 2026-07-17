"""
ThreatShield AI - Trusted Sender Model
Per-user whitelist of trusted email senders.
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.sql import func
from app.core.database import Base


class TrustedSender(Base):
    __tablename__ = "trusted_senders"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False)        # exact email OR domain (e.g. @company.com)
    name = Column(String(100), nullable=True)          # display label
    added_at = Column(DateTime(timezone=True), server_default=func.now())

    # each user can only add each email once
    __table_args__ = (UniqueConstraint("user_id", "email", name="uq_trusted_sender_user_email"),)