"""
ThreatShield AI - Email Parser Service
Parses EML, MSG, and raw email content into structured data.
"""
import email
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr, parsedate_to_datetime
from typing import Optional, Dict, List, Any
import re
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)


class EmailParserService:
    """Parses various email formats into structured data."""

    # Common text content types
    TEXT_TYPES = {"text/plain", "text/html"}

    def parse_eml(self, content: bytes) -> Dict[str, Any]:
        """Parse .eml file content."""
        try:
            msg = BytesParser(policy=policy.default).parsebytes(content)
            return self._extract_email_data(msg)
        except Exception as e:
            logger.error(f"Error parsing EML: {e}")
            raise ValueError(f"Failed to parse EML file: {str(e)}")

    def parse_raw(self, raw_content: str) -> Dict[str, Any]:
        """Parse raw email string content."""
        try:
            msg = Parser(policy=policy.default).parsestr(raw_content)
            return self._extract_email_data(msg)
        except Exception as e:
            logger.error(f"Error parsing raw email: {e}")
            raise ValueError(f"Failed to parse raw email: {str(e)}")

    def _extract_email_data(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract structured data from parsed email message."""
        # Parse sender
        sender_name, sender_email = parseaddr(msg.get("From", ""))

        # Parse recipients
        to_addresses = msg.get("To", "")
        cc_addresses = msg.get("Cc", "")
        bcc_addresses = msg.get("Bcc", "")

        # Parse date
        received_date = None
        date_str = msg.get("Date")
        if date_str:
            try:
                received_date = parsedate_to_datetime(date_str)
            except Exception:
                received_date = None

        # Extract body
        body_text = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    raw_data = part.get_payload(decode=True) or b""
                    attachments.append({
                        "filename": part.get_filename() or "unnamed",
                        "content_type": content_type,
                        "size": len(raw_data),
                        "data": raw_data,   # raw bytes for attachment_scanner
                    })
                elif content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text = payload.decode("utf-8", errors="replace")
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html = payload.decode("utf-8", errors="replace")
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                decoded = payload.decode("utf-8", errors="replace")
                if content_type == "text/html":
                    body_html = decoded
                else:
                    body_text = decoded

        # If no plain text but have HTML, strip HTML for text version
        if not body_text and body_html:
            body_text = self._strip_html(body_html)

        # Extract raw headers
        raw_headers = ""
        for key, value in msg.items():
            raw_headers += f"{key}: {value}\n"

        # Extract URLs from body
        urls = self._extract_urls(body_text + " " + body_html)

        return {
            "message_id": msg.get("Message-ID", ""),
            "subject": msg.get("Subject", ""),
            "sender_email": sender_email,
            "sender_name": sender_name,
            "recipient_email": to_addresses,
            "cc_emails": cc_addresses,
            "bcc_emails": bcc_addresses,
            "body_text": body_text,
            "body_html": body_html,
            "raw_headers": raw_headers,
            "raw_content": msg.as_string(),
            "received_date": received_date,
            "attachments": attachments,
            "urls": urls,
        }

    def _strip_html(self, html: str) -> str:
        """Strip HTML tags to get plain text."""
        clean = re.sub(r'<[^>]+>', ' ', html)
        clean = re.sub(r'\s+', ' ', clean).strip()
        return clean

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text content."""
        url_pattern = re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"\']*',
            re.IGNORECASE
        )
        urls = list(set(url_pattern.findall(text)))
        return urls


# Singleton instance
email_parser = EmailParserService()