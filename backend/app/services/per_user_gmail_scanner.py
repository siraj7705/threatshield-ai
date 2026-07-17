"""
ThreatShield AI - Per-User Gmail Scanner

Scans a SPECIFIC connected GmailAccount's inbox on demand. This is
intentionally separate from app/services/gmail_scanner.py (the legacy
GmailScannerService), which is a singleton caching ONE Gmail API service
object built from the single shared mailbox's credentials
(app/core/gmail_auth.get_credentials()). Reusing that singleton across
different users' connected accounts would leak one user's authenticated
Gmail client into another user's request — there is no per-call account
switch in that design.

Instead, every function here takes the already-built `service` (a
googleapiclient Resource) as an explicit argument, built fresh per request
from that specific user's stored, decrypted OAuth credentials
(see app/core/gmail_oauth.py). Nothing is cached across users.

The actual threat-analysis pipeline (NLP, header forensics, URL/domain
checks, scoring) is reused as-is from the existing stateless service
singletons — those hold no Gmail credential state, so sharing them is safe.
"""
import base64
import logging
import time
from typing import Any, Dict, Optional

from googleapiclient.errors import HttpError

from app.services.email_parser import email_parser
from app.services.nlp_engine import nlp_engine
from app.services.header_analyzer import header_analyzer
from app.services.threat_scorer import threat_scorer
from app.services.url_analyzer import url_analyzer
from app.services.domain_checker import domain_checker

logger = logging.getLogger(__name__)


def fetch_email_by_id(service, message_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single raw email from a specific user's Gmail via their service client."""
    try:
        msg = service.users().messages().get(userId="me", id=message_id, format="raw").execute()
        raw = base64.urlsafe_b64decode(msg["raw"])
        return {"raw": raw, "gmail_id": message_id, "thread_id": msg.get("threadId")}
    except HttpError as e:
        logger.error(f"Failed to fetch email {message_id}: {e}")
        return None


def list_recent_inbox_messages(service, max_results: int = 10) -> list:
    """List recent inbox message IDs for a specific user's connected account."""
    try:
        result = service.users().messages().list(
            userId="me", q="in:inbox", maxResults=max_results
        ).execute()
        return result.get("messages", [])
    except HttpError as e:
        logger.error(f"Failed to list inbox messages: {e}")
        return []


def scan_email(service, gmail_id: str) -> Dict[str, Any]:
    """
    Run the full ThreatShield analysis pipeline against one Gmail message
    belonging to the connected account behind `service`. Mirrors
    GmailScannerService.scan_email() exactly, but takes the service as an
    argument instead of relying on a cached singleton credential.
    """
    start = time.time()

    email_data = fetch_email_by_id(service, gmail_id)
    if not email_data:
        return {"error": "Could not fetch email", "gmail_id": gmail_id}

    raw_bytes: bytes = email_data["raw"]

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

    nlp_result = nlp_engine.analyze(body, subject)
    header_result = header_analyzer.analyze(raw_headers)
    url_result = url_analyzer.analyze(body, body_html)
    domain_result = domain_checker.check(sender)

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
        "body_text": body[:2000] if body else "",
        "urls_found": url_result.urls_found,
        "malicious_urls": url_result.malicious_urls,
        "suspicious_urls": url_result.suspicious_urls,
        "url_risk_score": url_result.url_risk_score,
        "safe_browsing_checked": url_result.safe_browsing_checked,
        "domain_is_lookalike": domain_result.is_lookalike,
        "domain_is_typosquat": domain_result.is_typosquatting,
        "domain_impersonates": domain_result.impersonated_brand,
        "domain_risk_score": domain_result.domain_risk_score,
    }

    has_nlp_signal = nlp_result.threat_detected or nlp_result.confidence_score >= 0.3
    has_malicious_url = bool(url_result.malicious_urls)
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
        boost = max(url_result.url_risk_score, domain_result.domain_risk_score)
        result["overall_score"] = min(max(result["overall_score"], boost), 100.0)
        result["category"] = "high_risk" if result["overall_score"] <= 80 else "critical"
        result["recommended_action"] = "quarantine" if result["overall_score"] > 40 else result["recommended_action"]

    logger.info(
        f"[per-user scan] '{subject[:60]}' | score={result['overall_score']:.0f} | "
        f"type={result['threat_type']} | action={result['recommended_action']}"
    )
    return result


QUARANTINE_LABEL = "ThreatShield-Quarantine"
SAFE_LABEL = "ThreatShield-Safe"


def _ensure_labels(service) -> Dict[str, str]:
    """Create ThreatShield labels in this user's Gmail if they don't exist yet."""
    label_ids = {}
    try:
        existing = service.users().labels().list(userId="me").execute()
        label_map = {l["name"]: l["id"] for l in existing.get("labels", [])}
        for name in (QUARANTINE_LABEL, SAFE_LABEL):
            if name in label_map:
                label_ids[name] = label_map[name]
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
                    },
                ).execute()
                label_ids[name] = created["id"]
    except HttpError as e:
        logger.error(f"Failed to ensure labels: {e}")
    return label_ids


def quarantine_email(service, gmail_id: str):
    """Label + move a message out of inbox in this user's connected mailbox."""
    label_ids = _ensure_labels(service)
    if QUARANTINE_LABEL not in label_ids:
        return
    try:
        service.users().messages().modify(
            userId="me", id=gmail_id,
            body={"addLabelIds": [label_ids[QUARANTINE_LABEL]], "removeLabelIds": ["INBOX"]},
        ).execute()
    except HttpError as e:
        logger.error(f"Failed to quarantine {gmail_id}: {e}")


def label_safe(service, gmail_id: str):
    """Apply the safe label in this user's connected mailbox."""
    label_ids = _ensure_labels(service)
    if SAFE_LABEL not in label_ids:
        return
    try:
        service.users().messages().modify(
            userId="me", id=gmail_id, body={"addLabelIds": [label_ids[SAFE_LABEL]]},
        ).execute()
    except HttpError as e:
        logger.error(f"Failed to label safe {gmail_id}: {e}")


def scan_and_act(service, gmail_id: str) -> Dict[str, Any]:
    """Scan one message and quarantine/label it in the connected account, no admin email side-effect."""
    result = scan_email(service, gmail_id)
    if "error" in result:
        return result

    if result["threat_detected"] and result["overall_score"] >= 40:
        quarantine_email(service, gmail_id)
        result["action_taken"] = "quarantined"
    else:
        label_safe(service, gmail_id)
        result["action_taken"] = "labeled_safe"

    return result