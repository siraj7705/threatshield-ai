"""
ThreatShield AI - Gmail Account Model
Per-user Gmail OAuth connection. Each user can connect their own Gmail
account (via Google's OAuth consent screen) to have their inbox monitored.

Token fields store ENCRYPTED values (see app/core/crypto.py) — never store
raw OAuth tokens in the database.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, UniqueConstraint
from sqlalchemy.sql import func
from app.core.database import Base


class GmailAccount(Base):
    __tablename__ = "gmail_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Owner — the ThreatShield user who connected this Gmail account.
    # One user can connect at most one Gmail account at a time (see
    # UniqueConstraint below); they can disconnect and reconnect a
    # different one later.
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    gmail_address = Column(String(255), nullable=False, index=True)

    # OAuth tokens — encrypted at rest with Fernet (app/core/crypto.py).
    # access_token is short-lived and refreshed automatically; refresh_token
    # is long-lived and is what actually matters for ongoing access.
    encrypted_access_token = Column(Text, nullable=True)
    encrypted_refresh_token = Column(Text, nullable=False)
    token_expiry = Column(DateTime(timezone=True), nullable=True)
    granted_scopes = Column(Text, nullable=True)  # JSON array of granted OAuth scopes

    # Gmail push-notification (Pub/Sub) watch state — used for live monitoring.
    watch_history_id = Column(String(50), nullable=True)
    watch_expiry = Column(DateTime(timezone=True), nullable=True)
    is_watching = Column(Boolean, default=False)

    # Connection lifecycle
    is_active = Column(Boolean, default=True)  # False once user disconnects
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)   # last OAuth/refresh error, for "reconnect" UI prompts

    connected_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("user_id", "gmail_address", name="uq_gmail_account_user_address"),
    )