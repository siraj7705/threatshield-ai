"""
ThreatShield AI - Email Model
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.core.database import Base


class Email(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, autoincrement=True)
    message_id = Column(String(500))
    subject = Column(Text)
    sender_email = Column(String(255), index=True)
    sender_name = Column(String(255))
    recipient_email = Column(Text)
    cc_emails = Column(Text)
    bcc_emails = Column(Text)
    body_text = Column(Text)
    body_html = Column(Text)
    raw_headers = Column(Text)
    raw_content = Column(Text)
    received_date = Column(DateTime(timezone=True))
    upload_date = Column(DateTime(timezone=True), server_default=func.now())
    uploaded_by = Column(Integer, ForeignKey("users.id"))
    # For source_type == "gmail_watch"/"gmail_scan": which user's connected
    # Gmail account this email was pulled from. NULL for manually uploaded
    # emails (those use uploaded_by instead).
    gmail_account_id = Column(Integer, ForeignKey("gmail_accounts.id", ondelete="SET NULL"), nullable=True, index=True)
    source_type = Column(String(20), default="upload")
    file_name = Column(String(255))
    file_size = Column(Integer)
    status = Column(String(20), default="pending", index=True)
    action_taken = Column(String(20), default="none")