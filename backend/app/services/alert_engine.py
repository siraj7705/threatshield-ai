"""
LOCATION: threatshield-ai/backend/app/services/alert_engine.py

ThreatShield AI - Alert Engine

Generates security alerts and dispatches real-time notifications via:
  - Dashboard alerts (always, saved to DB by the caller)
  - SMS via Twilio (when TWILIO_ENABLED=true and severity >= sms_threshold)
  - Voice call via Twilio (critical threats only, when TWILIO_VOICE_ENABLED=true)

Twilio setup:
  1. Create a free account at https://www.twilio.com
  2. Get your Account SID, Auth Token, and a Twilio phone number
  3. Add to .env:
       TWILIO_ENABLED=true
       TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
       TWILIO_AUTH_TOKEN=your_auth_token
       TWILIO_FROM_NUMBER=+1xxxxxxxxxx
       TWILIO_TO_NUMBERS=+1xxxxxxxxxx,+1xxxxxxxxxx   # comma-separated recipients
       TWILIO_SMS_SEVERITY_THRESHOLD=high             # critical|high|warning
       TWILIO_VOICE_ENABLED=true                      # voice calls for critical only
"""
import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ── Twilio SMS/Voice dispatcher ───────────────────────────────────────────────

class TwilioNotifier:
    """
    Handles real-time SMS and voice call notifications via Twilio REST API.
    Initialised lazily — only imports twilio when actually enabled, so the
    rest of the app works even if the twilio package is not installed.
    """

    SEVERITY_ORDER = {"warning": 1, "high": 2, "critical": 3}

    def __init__(self):
        self._client = None
        self._ready = False
        self._account_sid: str = ""
        self._auth_token: str = ""
        self._from_number: str = ""
        self._to_numbers: List[str] = []
        self._sms_enabled: bool = False
        self._voice_enabled: bool = False
        self._sms_threshold: str = "high"
        self._twiml_url: str = ""
        self._load_config()

    def _load_config(self):
        """Load Twilio config from app settings. Fails silently if not configured."""
        try:
            from app.core.config import settings

            self._sms_enabled   = getattr(settings, "TWILIO_ENABLED", False)
            self._voice_enabled = getattr(settings, "TWILIO_VOICE_ENABLED", False)

            if not self._sms_enabled and not self._voice_enabled:
                logger.info("Twilio notifications disabled (TWILIO_ENABLED=false)")
                return

            self._account_sid   = getattr(settings, "TWILIO_ACCOUNT_SID", "")
            self._auth_token    = getattr(settings, "TWILIO_AUTH_TOKEN", "")
            self._from_number   = getattr(settings, "TWILIO_FROM_NUMBER", "")
            self._sms_threshold = getattr(settings, "TWILIO_SMS_SEVERITY_THRESHOLD", "high")
            self._twiml_url     = getattr(settings, "TWILIO_TWIML_URL", "")

            raw_to = getattr(settings, "TWILIO_TO_NUMBERS", "")
            self._to_numbers = [n.strip() for n in raw_to.split(",") if n.strip()]

            if not all([self._account_sid, self._auth_token, self._from_number, self._to_numbers]):
                logger.warning(
                    "Twilio is enabled but missing config. "
                    "Check TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, "
                    "TWILIO_FROM_NUMBER, TWILIO_TO_NUMBERS in .env"
                )
                return

            # Import twilio lazily
            try:
                from twilio.rest import Client
                self._client = Client(self._account_sid, self._auth_token)
                self._ready = True
                logger.info(
                    f"Twilio notifier ready — SMS: {self._sms_enabled}, "
                    f"Voice: {self._voice_enabled}, "
                    f"Recipients: {len(self._to_numbers)}, "
                    f"SMS threshold: {self._sms_threshold}"
                )
            except ImportError:
                logger.warning(
                    "Twilio package not installed. Run: pip install twilio\n"
                    "SMS/Voice alerts will be skipped until installed."
                )

        except Exception as e:
            logger.error(f"TwilioNotifier config error: {e}")

    def _severity_meets_threshold(self, severity: str) -> bool:
        """Return True if severity >= configured SMS threshold."""
        return (
            self.SEVERITY_ORDER.get(severity, 0)
            >= self.SEVERITY_ORDER.get(self._sms_threshold, 2)
        )

    def _build_sms_body(
        self,
        severity: str,
        threat_type: str,
        score: float,
        sender: str,
        subject: str,
    ) -> str:
        """Build a concise SMS body (Twilio caps at 1600 chars; we stay <160 for single segment)."""
        type_label = threat_type.replace("_", " ").upper()
        body = (
            f"[ThreatShield] {severity.upper()} ALERT\n"
            f"Type: {type_label}\n"
            f"Score: {score:.0f}/100\n"
        )
        if sender:
            body += f"From: {sender[:40]}\n"
        if subject:
            body += f"Subj: {subject[:40]}\n"
        body += "Login to ThreatShield to investigate."
        return body

    def _build_twiml_say(self, severity: str, threat_type: str, score: float) -> str:
        """
        Build inline TwiML for voice calls.
        Used when TWILIO_TWIML_URL is not set.
        """
        type_label = threat_type.replace("_", " ")
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f"<Response>"
            f"<Say voice=\"alice\">"
            f"ThreatShield AI security alert. "
            f"A {severity} threat has been detected. "
            f"Threat type: {type_label}. "
            f"Risk score: {score:.0f} out of 100. "
            f"Please log in to ThreatShield immediately to investigate. "
            f"This message will repeat once."
            f"</Say>"
            f"<Pause length=\"1\"/>"
            f"<Say voice=\"alice\">"
            f"ThreatShield AI alert. {severity} {type_label} detected. "
            f"Risk score {score:.0f} out of 100. Please investigate immediately."
            f"</Say>"
            f"</Response>"
        )

    async def send_sms(
        self,
        severity: str,
        threat_type: str,
        score: float,
        sender: str = "",
        subject: str = "",
    ) -> List[str]:
        """
        Send SMS to all configured recipients.
        Returns list of message SIDs (empty on failure/disabled).
        """
        if not self._ready or not self._sms_enabled:
            return []
        if not self._severity_meets_threshold(severity):
            logger.debug(f"SMS skipped — severity '{severity}' below threshold '{self._sms_threshold}'")
            return []

        body = self._build_sms_body(severity, threat_type, score, sender, subject)
        sids = []

        for to_number in self._to_numbers:
            try:
                msg = self._client.messages.create(
                    body=body,
                    from_=self._from_number,
                    to=to_number,
                )
                sids.append(msg.sid)
                logger.info(f"SMS sent to {to_number} — SID: {msg.sid}")
            except Exception as e:
                logger.error(f"SMS failed to {to_number}: {e}")

        return sids

    async def send_voice_call(
        self,
        severity: str,
        threat_type: str,
        score: float,
    ) -> List[str]:
        """
        Place voice calls to all configured recipients for critical alerts.
        Returns list of call SIDs (empty on failure/disabled).
        """
        if not self._ready or not self._voice_enabled:
            return []
        if severity != "critical":
            logger.debug("Voice call skipped — only triggered for critical severity")
            return []

        sids = []
        for to_number in self._to_numbers:
            try:
                call_kwargs: Dict[str, Any] = {
                    "from_": self._from_number,
                    "to": to_number,
                }
                if self._twiml_url:
                    call_kwargs["url"] = self._twiml_url
                else:
                    call_kwargs["twiml"] = self._build_twiml_say(severity, threat_type, score)

                call = self._client.calls.create(**call_kwargs)
                sids.append(call.sid)
                logger.info(f"Voice call placed to {to_number} — SID: {call.sid}")
            except Exception as e:
                logger.error(f"Voice call failed to {to_number}: {e}")

        return sids

    async def notify(
        self,
        severity: str,
        threat_type: str,
        score: float,
        sender: str = "",
        subject: str = "",
    ) -> Dict[str, Any]:
        """
        Dispatch all configured notification channels for an alert.
        Returns a summary dict with which channels were triggered.
        """
        if not self._ready:
            return {"sms": [], "voice": [], "skipped": True}

        sms_sids   = await self.send_sms(severity, threat_type, score, sender, subject)
        voice_sids = await self.send_voice_call(severity, threat_type, score)

        return {
            "sms_sent": len(sms_sids),
            "sms_sids": sms_sids,
            "voice_calls": len(voice_sids),
            "voice_sids": voice_sids,
            "skipped": False,
        }


# ── Alert Engine ──────────────────────────────────────────────────────────────

class AlertEngine:
    """
    Generates security alerts based on threat scoring results and dispatches
    real-time notifications via Twilio SMS and voice call.
    """

    CRITICAL_THRESHOLD = 80
    HIGH_THRESHOLD     = 60
    WARNING_THRESHOLD  = 40

    CRITICAL_THREAT_TYPES = {"bomb_threat", "terror", "school_threat"}

    def __init__(self):
        self.notifier = TwilioNotifier()

    def generate_alert(
        self,
        email_id: int,
        threat_score: float,
        threat_type: str,
        threat_target: str = "",
        confidence: float = 0.0,
        sender: str = "",
        subject: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Generate an alert dict based on threat analysis results.
        Returns alert dict or None if no alert is warranted.
        The caller is responsible for saving this to the DB.
        """
        if (
            threat_score < self.WARNING_THRESHOLD
            and threat_type not in self.CRITICAL_THREAT_TYPES
        ):
            return None

        severity   = self._determine_severity(threat_score, threat_type)
        alert_type = self._determine_alert_type(threat_type, threat_score)
        title      = self._generate_title(threat_type, severity, threat_target)
        message    = self._generate_message(
            threat_type, threat_score, confidence, sender, subject, threat_target
        )

        details = {
            "threat_score": threat_score,
            "threat_type":  threat_type,
            "confidence":   confidence,
            "sender":       sender,
            "subject":      subject[:200] if subject else "",
            "target":       threat_target,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
        }

        alert = {
            "email_id":   email_id,
            "alert_type": alert_type,
            "severity":   severity,
            "title":      title,
            "message":    message,
            "details":    json.dumps(details),
        }

        logger.warning(
            f"ALERT GENERATED: [{severity.upper()}] {title} "
            f"(email_id={email_id}, score={threat_score:.1f})"
        )

        return alert

    async def generate_and_notify(
        self,
        email_id: int,
        threat_score: float,
        threat_type: str,
        threat_target: str = "",
        confidence: float = 0.0,
        sender: str = "",
        subject: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Generate an alert AND dispatch Twilio SMS/voice notifications.
        Returns the alert dict (same as generate_alert) with an extra
        'notifications' key showing what was sent.
        """
        alert = self.generate_alert(
            email_id=email_id,
            threat_score=threat_score,
            threat_type=threat_type,
            threat_target=threat_target,
            confidence=confidence,
            sender=sender,
            subject=subject,
        )

        if alert is None:
            return None

        # Fire Twilio notifications
        notification_result = await self.notifier.notify(
            severity=alert["severity"],
            threat_type=threat_type,
            score=threat_score,
            sender=sender,
            subject=subject,
        )

        alert["notifications"] = notification_result
        return alert

    # ── Private helpers ───────────────────────────────────────────────────────

    def _determine_severity(self, score: float, threat_type: str) -> str:
        if score >= self.CRITICAL_THRESHOLD or threat_type in self.CRITICAL_THREAT_TYPES:
            return "critical"
        if score >= self.HIGH_THRESHOLD:
            return "high"
        if score >= self.WARNING_THRESHOLD:
            return "warning"
        return "info"

    def _determine_alert_type(self, threat_type: str, score: float) -> str:
        type_mapping = {
            "bomb_threat":  "bomb_threat",
            "terror":       "terror_threat",
            "school_threat":"school_threat",
            "violence":     "violence_threat",
            "extortion":    "extortion_threat",
            "harassment":   "harassment_threat",
        }
        if threat_type in type_mapping:
            return type_mapping[threat_type]
        if score >= self.CRITICAL_THRESHOLD:
            return "critical_threat"
        return "suspicious_email"

    def _generate_title(self, threat_type: str, severity: str, target: str = "") -> str:
        type_labels = {
            "bomb_threat":  "🚨 BOMB THREAT DETECTED",
            "terror":       "🚨 TERROR THREAT DETECTED",
            "school_threat":"🚨 SCHOOL THREAT DETECTED",
            "violence":     "⚠️ VIOLENCE THREAT DETECTED",
            "extortion":    "⚠️ EXTORTION ATTEMPT DETECTED",
            "harassment":   "⚠️ HARASSMENT DETECTED",
        }
        title = type_labels.get(threat_type, f"⚠️ {severity.upper()} THREAT DETECTED")
        if target:
            title += f" — Target: {target}"
        return title

    def _generate_message(
        self,
        threat_type: str,
        score: float,
        confidence: float,
        sender: str,
        subject: str,
        target: str,
    ) -> str:
        severity_label = (
            "CRITICAL" if score >= 80 else
            "HIGH"     if score >= 60 else
            "MODERATE"
        )
        lines = [
            f"A {severity_label} threat has been detected in an incoming email.",
            "",
            f"Threat Type: {threat_type.replace('_', ' ').title()}",
            f"Risk Score:  {score:.1f}/100",
            f"Confidence:  {confidence:.0%}",
        ]
        if sender:
            lines.append(f"Sender:  {sender}")
        if subject:
            lines.append(f"Subject: {subject[:100]}")
        if target:
            lines.append(f"Target:  {target}")
        lines.extend([
            "",
            f"Recommended Action: {'BLOCK & INVESTIGATE' if score >= 80 else 'QUARANTINE' if score >= 60 else 'REVIEW'}",
            "",
            "This alert was generated automatically by ThreatShield AI.",
        ])
        return "\n".join(lines)

    def should_auto_block(self, threat_score: float, threat_type: str) -> bool:
        return (
            threat_score >= self.CRITICAL_THRESHOLD
            or threat_type in self.CRITICAL_THREAT_TYPES
        )

    def get_recommended_action(self, threat_score: float) -> str:
        if threat_score <= 30:
            return "allow"
        if threat_score <= 60:
            return "spam"
        if threat_score <= 80:
            return "quarantine"
        return "block"


# Singleton — loaded once at startup
alert_engine = AlertEngine()