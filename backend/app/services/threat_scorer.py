"""
ThreatShield AI - Threat Risk Scoring Engine
Computes composite risk scores from multiple analysis signals.
"""
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ScoreResult:
    """Result of threat risk scoring."""
    overall_score: float = 0.0
    nlp_score: float = 0.0
    keyword_score: float = 0.0
    sender_score: float = 0.0
    header_score: float = 0.0
    urgency_score: float = 0.0
    attachment_score: float = 0.0
    category: str = "safe"
    explanation: List[str] = None
    recommended_action: str = "allow"

    def __post_init__(self):
        if self.explanation is None:
            self.explanation = []

    def to_dict(self) -> dict:
        result = asdict(self)
        result["explanation"] = json.dumps(self.explanation)
        return result


class ThreatScorer:
    """
    Computes composite threat risk scores (0-100) from multiple analysis signals.

    Score Categories:
    - 0-30: Safe (Allow)
    - 31-60: Suspicious (Spam)
    - 61-80: High Risk (Quarantine)
    - 81-100: Critical Threat (Block)
    """

    # Scoring weights
    WEIGHTS = {
        "nlp": 0.40,       # NLP threat detection
        "keyword": 0.15,   # Keyword density
        "sender": 0.15,    # Sender reputation
        "header": 0.15,    # Header anomalies
        "urgency": 0.10,   # Urgency indicators
        "attachment": 0.05, # Attachment risk
    }

    def score(
        self,
        nlp_confidence: float = 0.0,
        nlp_threat_type: str = "safe",
        keywords_found: List[str] = None,
        header_risk_score: float = 0.0,
        urgency_score: float = 0.0,
        sender_domain: str = "",
        has_attachments: bool = False,
        spoofing_detected: bool = False,
        sender_reputation_score: float = 0.0,  # NEW: from SenderIntelligence (0-100)
        sender_reputation_label: str = "unknown",  # NEW: "trusted"|"clean"|"neutral"|"suspicious"|"malicious"
    ) -> ScoreResult:
        """
        Compute composite threat risk score.

        Args:
            nlp_confidence: Confidence from NLP engine (0-1)
            nlp_threat_type: Type of threat detected
            keywords_found: List of threat keywords found
            header_risk_score: Risk score from header analysis (0-100)
            urgency_score: Urgency score (0-1)
            sender_domain: Sender's email domain
            has_attachments: Whether email has attachments
            spoofing_detected: Whether spoofing was detected

        Returns:
            ScoreResult with composite score and explanations
        """
        keywords_found = keywords_found or []
        explanations = []

        # 1. NLP Score (0-100)
        nlp_score = nlp_confidence * 100
        if nlp_score > 60:
            explanations.append(f"Threatening language detected ({nlp_threat_type}): {nlp_score:.0f}% confidence")

        # 2. Keyword Score (0-100)
        keyword_count = len(keywords_found)
        if keyword_count == 0:
            keyword_score = 0.0
        elif keyword_count <= 2:
            keyword_score = 30.0
        elif keyword_count <= 5:
            keyword_score = 60.0
        elif keyword_count <= 10:
            keyword_score = 80.0
        else:
            keyword_score = 95.0

        if keyword_count > 0:
            sample_keywords = keywords_found[:5]
            explanations.append(f"Threat-related keywords found ({keyword_count}): {', '.join(sample_keywords)}")

        # 3. Sender Score (0-100)
        # If a real reputation score is provided (from SenderIntelligence), use it.
        # Fall back to the domain heuristic only when no history exists yet.
        if sender_reputation_score > 0 or sender_reputation_label not in ("unknown", ""):
            sender_score = sender_reputation_score
            if sender_reputation_label == "malicious":
                explanations.append(
                    f"Sender is flagged as malicious based on history (score {sender_score:.0f})"
                )
            elif sender_reputation_label == "suspicious":
                explanations.append(
                    f"Sender has a suspicious reputation history (score {sender_score:.0f})"
                )
            elif sender_score > 40:
                explanations.append(
                    f"Sender reputation risk: {sender_reputation_label} (score {sender_score:.0f})"
                )
        else:
            sender_score = self._score_sender(sender_domain)
            if sender_score > 40:
                explanations.append(f"Sender risk indicators: domain={sender_domain}, score={sender_score:.0f}")

        # 4. Header Score (0-100)
        header_score = header_risk_score
        if spoofing_detected:
            header_score = max(header_score, 75.0)
            explanations.append("Email spoofing detected in headers")
        elif header_score > 30:
            explanations.append(f"Header anomalies detected: risk={header_score:.0f}")

        # 5. Urgency Score (0-100)
        urgency_100 = urgency_score * 100
        if urgency_100 > 50:
            explanations.append(f"Urgent/threatening tone detected: {urgency_100:.0f}%")

        # 6. Attachment Score (0-100)
        attachment_score = 30.0 if has_attachments else 0.0
        if has_attachments:
            explanations.append("Email contains attachments (potential risk)")

        # Calculate weighted overall score
        overall_score = (
            nlp_score * self.WEIGHTS["nlp"] +
            keyword_score * self.WEIGHTS["keyword"] +
            sender_score * self.WEIGHTS["sender"] +
            header_score * self.WEIGHTS["header"] +
            urgency_100 * self.WEIGHTS["urgency"] +
            attachment_score * self.WEIGHTS["attachment"]
        )

        # Boost score for critical threats
        if nlp_threat_type in ("bomb_threat", "terror", "school_threat") and nlp_confidence > 0.7:
            overall_score = max(overall_score, 80.0)
            explanations.append(f"Critical threat type ({nlp_threat_type}) - score boosted")

        # Cap at 100
        overall_score = min(round(overall_score, 2), 100.0)

        # Determine category and action
        category, action = self._categorize_score(overall_score)

        if not explanations:
            explanations.append("No significant threat indicators detected")

        return ScoreResult(
            overall_score=overall_score,
            nlp_score=round(nlp_score, 2),
            keyword_score=round(keyword_score, 2),
            sender_score=round(sender_score, 2),
            header_score=round(header_score, 2),
            urgency_score=round(urgency_100, 2),
            attachment_score=round(attachment_score, 2),
            category=category,
            explanation=explanations,
            recommended_action=action,
        )

    def _score_sender(self, domain: str) -> float:
        """Score sender domain reputation."""
        if not domain:
            return 30.0  # Unknown sender is somewhat suspicious

        domain = domain.lower()
        score = 0.0

        # Check for disposable email providers
        disposable_domains = {
            "tempmail.com", "throwaway.email", "guerrillamail.com",
            "mailinator.com", "10minutemail.com", "yopmail.com",
            "trashmail.com", "maildrop.cc", "sharklasers.com",
        }
        if domain in disposable_domains:
            score += 70
            return min(score, 100.0)

        # Check for suspicious TLDs
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz"]
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                score += 40
                break

        # Well-known providers get lower scores
        trusted_domains = {
            "gmail.com", "outlook.com", "yahoo.com", "hotmail.com",
            "protonmail.com", "icloud.com", "aol.com", "live.com",
        }
        if domain in trusted_domains:
            score = max(score - 20, 0)

        return min(score, 100.0)

    def _categorize_score(self, score: float) -> tuple:
        """Categorize score and determine recommended action."""
        if score <= 30:
            return "safe", "allow"
        elif score <= 60:
            return "suspicious", "spam"
        elif score <= 80:
            return "high_risk", "quarantine"
        else:
            return "critical", "block"


# Singleton instance
threat_scorer = ThreatScorer()