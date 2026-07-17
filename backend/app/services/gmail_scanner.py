"""
ThreatShield AI - Gmail Scanner Service
Fetches emails from Gmail, runs them through the ThreatShield analysis
pipeline, quarantines threats, and notifies the admin.
"""
import base64
import json
import logging
import smtplib
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional, Dict, Any

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from app.core.gmail_auth import get_credentials
from app.core.config import settings
from app.services.email_parser import email_parser
from app.services.nlp_engine import nlp_engine
from app.services.header_analyzer import header_analyzer
from app.services.threat_scorer import threat_scorer
from app.services.alert_engine import alert_engine
from app.services.url_analyzer import url_analyzer
from app.services.domain_checker import domain_checker

logger = logging.getLogger(__name__)

QUARANTINE_LABEL = "ThreatShield-Quarantine"
SAFE_LABEL = "ThreatShield-Safe"


class GmailScannerService:
    """
    Core Gmail integration service.
    Handles fetching, scanning, labeling, and admin notification.
    """

    def __init__(self):
        self._service = None
        self._quarantine_label_id: Optional[str] = None
        self._safe_label_id: Optional[str] = None
        self._notified_ids: set = set()  # Track already-notified gmail IDs

    def _get_service(self):
        """Get or create authenticated Gmail API service."""
        if not self._service:
            creds = get_credentials()
            self._service = build("gmail", "v1", credentials=creds)
        return self._service

    # ─────────────────────────────────────────────
    # LABEL MANAGEMENT
    # ─────────────────────────────────────────────

    def _ensure_labels(self):
        """Create ThreatShield labels in Gmail if they don't exist."""
        service = self._get_service()
        try:
            existing = service.users().labels().list(userId="me").execute()
            label_map = {l["name"]: l["id"] for l in existing.get("labels", [])}

            for name, attr in [
                (QUARANTINE_LABEL, "_quarantine_label_id"),
                (SAFE_LABEL, "_safe_label_id"),
            ]:
                if name in label_map:
                    setattr(self, attr, label_map[name])
                else:
                    created = service.users().labels().create(
                        userId="me",
                        body={
                            "name": name,
                            "labelListVisibility": "labelShow",
                            "messageListVisibility": "show",
                            "color": {
                                "backgroundColor": "#cc3a21" if "Quarantine" in name else "#16a766",
                                "textColor": "#ffffff",
                            },
                        }
                    ).execute()
                    setattr(self, attr, created["id"])
                    logger.info(f"Created Gmail label: {name}")
        except HttpError as e:
            logger.error(f"Failed to ensure labels: {e}")

    # ─────────────────────────────────────────────
    # EMAIL FETCHING
    # ─────────────────────────────────────────────

    def fetch_email_by_id(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single email from Gmail by message ID."""
        service = self._get_service()
        try:
            msg = service.users().messages().get(
                userId="me",
                id=message_id,
                format="raw"
            ).execute()

            raw = base64.urlsafe_b64decode(msg["raw"])
            return {"raw": raw, "gmail_id": message_id, "thread_id": msg.get("threadId")}
        except HttpError as e:
            logger.error(f"Failed to fetch email {message_id}: {e}")
            return None

    def fetch_unscanned_emails(self, max_results: int = 10) -> list:
        """Fetch recent inbox emails that haven't been scanned yet."""
        service = self._get_service()
        try:
            # Query inbox emails not yet labeled by ThreatShield
            query = f"in:inbox -label:{QUARANTINE_LABEL} -label:{SAFE_LABEL}"
            result = service.users().messages().list(
                userId="me",
                q=query,
                maxResults=max_results
            ).execute()
            return result.get("messages", [])
        except HttpError as e:
            logger.error(f"Failed to list emails: {e}")
            return []

    # ─────────────────────────────────────────────
    # ANALYSIS PIPELINE
    # ─────────────────────────────────────────────

    def scan_email(self, gmail_id: str) -> Dict[str, Any]:
        """
        Full scan pipeline for a single Gmail message.
        Returns analysis result dict.
        """
        start = time.time()

        # 1. Fetch raw email
        email_data = self.fetch_email_by_id(gmail_id)
        if not email_data:
            return {"error": "Could not fetch email", "gmail_id": gmail_id}

        raw_bytes: bytes = email_data["raw"]

        # 2. Parse email
        try:
            parsed = email_parser.parse_eml(raw_bytes)
        except Exception as e:
            try:
                parsed = email_parser.parse_raw(raw_bytes.decode("utf-8", errors="replace"))
            except Exception:
                return {"error": f"Parse failed: {e}", "gmail_id": gmail_id}

        subject = parsed.get("subject", "")
        sender = parsed.get("sender_email", "")
        body = parsed.get("body_text", "") or parsed.get("body_html", "")
        body_html = parsed.get("body_html", "")
        raw_headers = parsed.get("raw_headers", "")

        # 3. NLP threat detection
        nlp_result = nlp_engine.analyze(body, subject)

        # 4. Header forensics
        header_result = header_analyzer.analyze(raw_headers)

        # 5. URL analysis (Google Safe Browsing + heuristics)
        url_result = url_analyzer.analyze(body, body_html)

        # 6. Domain / sender reputation check
        domain_result = domain_checker.check(sender)

        # 7. Composite threat scoring
        score_result = threat_scorer.score(
            nlp_confidence=nlp_result.confidence_score,
            nlp_threat_type=nlp_result.threat_type,
            keywords_found=nlp_result.keywords_found,
            sender_domain=sender,
            header_risk_score=header_result.header_risk_score if header_result else 0.0,
            urgency_score=nlp_result.urgency_score,
            has_attachments=bool(parsed.get("attachments")),
            spoofing_detected=header_result.spoofing_detected if header_result else False,
        )

        duration_ms = int((time.time() - start) * 1000)

        result = {
            "gmail_id": gmail_id,
            "subject": subject,
            "sender": sender,
            "threat_detected": nlp_result.threat_detected,
            "threat_type": nlp_result.threat_type,
            "threat_target": nlp_result.threat_target,
            "confidence": nlp_result.confidence_score,
            "severity": nlp_result.severity,
            "overall_score": score_result.overall_score,
            "category": score_result.category,
            "recommended_action": score_result.recommended_action,
            "keywords_found": nlp_result.keywords_found,
            "spoofing_detected": header_result.spoofing_detected if header_result else False,
            "duration_ms": duration_ms,
            "body_text": body[:2000] if body else "",  # Include email body (max 2000 chars)
            # URL analysis results
            "urls_found": url_result.urls_found,
            "malicious_urls": url_result.malicious_urls,
            "suspicious_urls": url_result.suspicious_urls,
            "url_risk_score": url_result.url_risk_score,
            "safe_browsing_checked": url_result.safe_browsing_checked,
            # Domain analysis results
            "domain_is_lookalike": domain_result.is_lookalike,
            "domain_is_typosquat": domain_result.is_typosquatting,
            "domain_impersonates": domain_result.impersonated_brand,
            "domain_risk_score": domain_result.domain_risk_score,
        }
        # Auto-upgrade threat detection if URLs or domain are confirmed malicious.
        # IMPORTANT: domain lookalike alone is not enough — require NLP signal too,
        # or a confirmed malicious URL, to avoid false positives on legitimate
        # marketing emails from real brands.
        has_nlp_signal = nlp_result.threat_detected or nlp_result.confidence_score >= 0.3
        has_malicious_url = bool(url_result.malicious_urls)

        # Phishing body: lookalike domain + credential-harvesting language
        phishing_words = {"verify", "suspended", "confirm", "validate",
                          "update your", "click here", "login", "sign in",
                          "locked", "unusual activity", "reactivate"}
        body_lower = (body + " " + subject).lower()
        has_phishing_language = any(w in body_lower for w in phishing_words)

        has_confirmed_domain_threat = (
            domain_result.is_typosquatting or
            (domain_result.is_lookalike and (has_nlp_signal or has_phishing_language))
        )

        if has_malicious_url or has_confirmed_domain_threat:
            result["threat_detected"] = True
            if not result["threat_type"] or result["threat_type"] == "safe":
                result["threat_type"] = "phishing"
            # Boost overall score
            boost = max(url_result.url_risk_score, domain_result.domain_risk_score)
            result["overall_score"] = min(max(result["overall_score"], boost), 100.0)
            result["category"] = "high_risk" if result["overall_score"] <= 80 else "critical"
            result["recommended_action"] = "quarantine" if result["overall_score"] > 40 else result["recommended_action"]

        logger.info(
            f"Scanned [{gmail_id}] '{subject[:60]}' | "
            f"score={score_result.overall_score:.0f} | "
            f"type={nlp_result.threat_type} | "
            f"action={score_result.recommended_action}"
        )

        return result

    # ─────────────────────────────────────────────
    # QUARANTINE
    # ─────────────────────────────────────────────

    def quarantine_email(self, gmail_id: str):
        """Move email to quarantine: apply label + remove from inbox."""
        self._ensure_labels()
        service = self._get_service()
        try:
            service.users().messages().modify(
                userId="me",
                id=gmail_id,
                body={
                    "addLabelIds": [self._quarantine_label_id],
                    "removeLabelIds": ["INBOX"],
                }
            ).execute()
            logger.warning(f"Email {gmail_id} quarantined.")
        except HttpError as e:
            logger.error(f"Failed to quarantine {gmail_id}: {e}")

    def label_safe(self, gmail_id: str):
        """Apply safe label to email."""
        self._ensure_labels()
        service = self._get_service()
        try:
            service.users().messages().modify(
                userId="me",
                id=gmail_id,
                body={"addLabelIds": [self._safe_label_id]}
            ).execute()
        except HttpError as e:
            logger.error(f"Failed to label safe {gmail_id}: {e}")

    # ─────────────────────────────────────────────
    # ADMIN NOTIFICATION
    # ─────────────────────────────────────────────

    def notify_admin(self, scan_result: Dict[str, Any]):
        """Send threat alert email to the admin via Gmail API."""
        admin_email = settings.GMAIL_ADMIN_EMAIL
        if not admin_email:
            logger.warning("GMAIL_ADMIN_EMAIL not set — skipping admin notification.")
            return

        subject = f"🚨 ThreatShield Alert: {scan_result['threat_type'].replace('_', ' ').title()} Detected"

        keywords = ", ".join(scan_result.get("keywords_found", [])[:10]) or "N/A"
        html_body = f"""
        <html><body style="font-family:Arial,sans-serif;background:#0a0f1e;color:#e2e8f0;padding:24px;">
        <div style="max-width:600px;margin:0 auto;background:#1e293b;border-radius:12px;padding:24px;border:1px solid #334155;">
            <h2 style="color:#ef4444;margin-top:0;">🛡️ ThreatShield AI — Threat Detected</h2>

            <table style="width:100%;border-collapse:collapse;">
                <tr><td style="padding:8px;color:#94a3b8;width:140px;">Threat Type</td>
                    <td style="padding:8px;color:#f97316;font-weight:bold;">{scan_result['threat_type'].replace('_',' ').title()}</td></tr>
                <tr><td style="padding:8px;color:#94a3b8;">Risk Score</td>
                    <td style="padding:8px;color:#ef4444;font-weight:bold;">{scan_result['overall_score']:.0f} / 100</td></tr>
                <tr><td style="padding:8px;color:#94a3b8;">Severity</td>
                    <td style="padding:8px;">{scan_result['severity'].upper()}</td></tr>
                <tr><td style="padding:8px;color:#94a3b8;">From</td>
                    <td style="padding:8px;font-family:monospace;">{scan_result['sender']}</td></tr>
                <tr><td style="padding:8px;color:#94a3b8;">Subject</td>
                    <td style="padding:8px;">{scan_result['subject']}</td></tr>
                <tr><td style="padding:8px;color:#94a3b8;">Keywords</td>
                    <td style="padding:8px;color:#fbbf24;">{keywords}</td></tr>
                <tr><td style="padding:8px;color:#94a3b8;">Spoofing</td>
                    <td style="padding:8px;">{'⚠️ Yes' if scan_result.get('spoofing_detected') else '✅ No'}</td></tr>
                <tr><td style="padding:8px;color:#94a3b8;">Action Taken</td>
                    <td style="padding:8px;color:#22c55e;font-weight:bold;">📦 QUARANTINED</td></tr>
                <tr><td style="padding:8px;color:#94a3b8;">Time</td>
                    <td style="padding:8px;">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
            </table>

            <div style="margin-top:16px;background:#0f172a;border-radius:8px;padding:16px;border-left:4px solid #ef4444;">
                <p style="color:#94a3b8;margin:0 0 8px 0;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Email Content</p>
                <p style="color:#e2e8f0;margin:0;font-size:14px;white-space:pre-wrap;">{scan_result.get('body_text', 'N/A')[:1000]}</p>
            </div>

            <p style="margin-top:20px;color:#64748b;font-size:12px;">
                This alert was generated automatically by ThreatShield AI.<br>
                Log in to <a href="http://localhost:5173" style="color:#3b82f6;">ThreatShield Dashboard</a> to investigate.
            </p>
        </div>
        </body></html>
        """

        try:
            service = self._get_service()
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"ThreatShield AI <{settings.GMAIL_WATCHER_EMAIL}>"
            msg["To"] = admin_email
            msg.attach(MIMEText(html_body, "html"))

            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
            service.users().messages().send(
                userId="me",
                body={"raw": raw}
            ).execute()
            logger.info(f"Admin notified at {admin_email}")
        except Exception as e:
            logger.error(f"Failed to send admin notification: {e}")

    # ─────────────────────────────────────────────
    # MAIN SCAN + ACT
    # ─────────────────────────────────────────────

    def scan_and_act(self, gmail_id: str) -> Dict[str, Any]:
        """
        Full scan pipeline + quarantine + notify for a single email.
        Called by the Pub/Sub webhook and the polling watcher.
        """
        result = self.scan_email(gmail_id)

        if "error" in result:
            return result

        if result["threat_detected"] and result["overall_score"] >= 40:
            # Quarantine the email
            self.quarantine_email(gmail_id)
            result["action_taken"] = "quarantined"

            # Notify admin only once per gmail_id
            if gmail_id not in self._notified_ids:
                self.notify_admin(result)
                self._notified_ids.add(gmail_id)
                result["admin_notified"] = True
                logger.info(f"Alert sent for {gmail_id}")
            else:
                result["admin_notified"] = False
                logger.info(f"Skipping duplicate alert for {gmail_id}")
        else:
            self.label_safe(gmail_id)
            result["action_taken"] = "labeled_safe"
            result["admin_notified"] = False

        return result


# Singleton
gmail_scanner = GmailScannerService()