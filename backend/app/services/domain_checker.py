"""
ThreatShield AI - Domain Checker Service
Detects fake/spoofed sender domains, typosquatting, and lookalike domains.
"""
import re
import logging
from typing import Dict, List, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class DomainCheckResult:
    """Result of domain reputation check."""
    sender_domain: str = ""
    is_typosquatting: bool = False
    is_lookalike: bool = False
    is_disposable: bool = False
    is_suspicious_tld: bool = False
    impersonated_brand: str = ""
    domain_risk_score: float = 0.0
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class DomainChecker:
    """
    Detects fake sender domains used in phishing attacks.

    Checks:
    1. Typosquatting (paypa1.com, g00gle.com)
    2. Lookalike domains (paypal-secure.com, sbi-bank-login.com)
    3. Disposable email providers
    4. Suspicious TLDs
    5. Free email used for brand impersonation
    """

    # Major brands commonly impersonated in phishing
    BRAND_DOMAINS = {
        "paypal": "paypal.com",
        "amazon": "amazon.com",
        "google": "google.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "facebook": "facebook.com",
        "netflix": "netflix.com",
        "instagram": "instagram.com",
        "twitter": "twitter.com",
        "linkedin": "linkedin.com",
        "dropbox": "dropbox.com",
        "chase": "chase.com",
        "bank of america": "bankofamerica.com",
        "wellsfargo": "wellsfargo.com",
        "hsbc": "hsbc.com",
        "barclays": "barclays.com",
        "sbi": "sbi.co.in",
        "hdfc": "hdfcbank.com",
        "icici": "icicibank.com",
        "axis": "axisbank.com",
        "dhl": "dhl.com",
        "fedex": "fedex.com",
        "ups": "ups.com",
        "usps": "usps.com",
        "irs": "irs.gov",
        "ebay": "ebay.com",
        "steam": "store.steampowered.com",
        "coinbase": "coinbase.com",
        "binance": "binance.com",
    }

    # Legitimate official sending domains used by real companies for email delivery.
    # These should NEVER be flagged as lookalikes or typosquats.
    LEGITIMATE_SENDING_DOMAINS = {
        # Facebook / Meta
        "facebookmail.com", "meta.com", "fb.com",
        # Google
        "google.com", "googlemail.com", "accounts.google.com",
        # Amazon / AWS
        "amazon.com", "amazonses.com", "amazonaws.com",
        "mail.amazon.com", "gc.email.amazon.com",
        # Microsoft
        "microsoft.com", "live.com", "outlook.com", "hotmail.com",
        "email.microsoft.com",
        # LinkedIn
        "linkedin.com", "e.linkedin.com", "em.linkedin.com",
        # Twitter / X
        "twitter.com", "e.twitter.com",
        # Apple
        "apple.com", "email.apple.com",
        # Netflix
        "netflix.com", "mailer.netflix.com",
        # PayPal
        "paypal.com", "e.paypal.com",
        # Udemy
        "udemy.com", "students.udemy.com", "e.udemymail.com",
        # Truecaller
        "truecaller.com",
        # Common ESPs used by legit businesses
        "mailchimp.com", "sendgrid.net", "amazonses.com",
        "mandrillapp.com", "sparkpostmail.com", "mailgun.org",
        "em.service-now.com", "bounce.linkedin.com",
    }

    # Disposable / temporary email providers
    DISPOSABLE_DOMAINS = {
        "tempmail.com", "throwaway.email", "guerrillamail.com",
        "mailinator.com", "10minutemail.com", "yopmail.com",
        "trashmail.com", "maildrop.cc", "sharklasers.com",
        "dispostable.com", "tempr.email", "spamgourmet.com",
        "fakeinbox.com", "discard.email", "mailnull.com",
        "spambox.us", "getonemail.com", "trashmail.at",
        "mohmal.com", "spamotron.com", "filzmail.com",
    }

    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
        ".buzz", ".click", ".link", ".work", ".loan", ".win",
        ".party", ".racing", ".bid", ".trade", ".accountant",
    ]

    # Free email providers (suspicious when impersonating brands)
    FREE_EMAIL_PROVIDERS = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "live.com", "aol.com", "protonmail.com", "icloud.com",
        "mail.com", "yandex.com", "gmx.com",
    }

    def check(self, sender_email: str) -> DomainCheckResult:
        """
        Check sender domain for phishing/spoofing indicators.

        Args:
            sender_email: Full sender email address (e.g. support@paypal-secure.com)

        Returns:
            DomainCheckResult with risk assessment
        """
        result = DomainCheckResult(sender_domain=sender_email)

        if not sender_email or "@" not in sender_email:
            return result

        domain = sender_email.split("@")[-1].lower().strip()
        result.sender_domain = domain

        # Early exit: known legitimate sending domains are never threats
        if domain in self.LEGITIMATE_SENDING_DOMAINS:
            return result
        # Also skip subdomains of legitimate sending domains
        # e.g. pageupdates@facebookmail.com, security@facebookmail.com
        for legit in self.LEGITIMATE_SENDING_DOMAINS:
            if domain.endswith("." + legit) or domain == legit:
                return result

        # 1. Disposable email check
        if domain in self.DISPOSABLE_DOMAINS:
            result.is_disposable = True
            result.reasons.append(f"Disposable/temporary email provider: {domain}")

        # 2. Suspicious TLD check
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result.is_suspicious_tld = True
                result.reasons.append(f"High-risk TLD used: {tld}")
                break

        # 3. Brand impersonation checks
        brand_result = self._check_brand_impersonation(domain)
        if brand_result:
            brand_name, impersonation_type = brand_result
            result.impersonated_brand = brand_name
            if impersonation_type == "typosquatting":
                result.is_typosquatting = True
                result.reasons.append(
                    f"Possible typosquatting of '{brand_name}' (real: {self.BRAND_DOMAINS[brand_name]})"
                )
            elif impersonation_type == "lookalike":
                result.is_lookalike = True
                result.reasons.append(
                    f"Lookalike domain impersonating '{brand_name}' (real: {self.BRAND_DOMAINS[brand_name]})"
                )

        # 4. Free email used with brand-like display name
        # (This is flagged when free email providers send "official" looking emails)
        # Handled in header_analyzer; here we just note if it's a free provider
        # sending something that looks important
        if domain in self.FREE_EMAIL_PROVIDERS:
            # Not inherently suspicious — but note it for context
            pass

        # Calculate domain risk score
        result.domain_risk_score = self._calculate_domain_risk(result)

        if result.reasons:
            logger.warning(
                f"Domain risk detected for {domain}: {result.reasons}"
            )

        return result

    def _check_brand_impersonation(self, domain: str) -> Tuple[str, str]:
        """
        Check if domain is impersonating a known brand.

        Returns:
            (brand_name, impersonation_type) or None
        """
        domain_base = domain.split('.')[0]  # e.g. "paypal-secure" from "paypal-secure.com"

        for brand, official_domain in self.BRAND_DOMAINS.items():
            official_base = official_domain.split('.')[0]  # e.g. "paypal"

            # Skip if it IS the official domain
            if domain == official_domain or domain.endswith(f".{official_domain}"):
                continue

            # Check for lookalike: brand name appears in domain but isn't the real domain
            # e.g. paypal-secure.com, sbi-netbanking.com, amazon-support.net
            if official_base in domain_base or brand in domain_base:
                # Common lookalike patterns
                lookalike_patterns = [
                    f"{official_base}-", f"-{official_base}",
                    f"{official_base}.", f"{brand}-", f"-{brand}",
                ]
                for pattern in lookalike_patterns:
                    if pattern in domain:
                        return (brand, "lookalike")
                # If brand name is just present (without being the real domain)
                if official_base in domain:
                    return (brand, "lookalike")

            # Check for typosquatting: character substitution/addition
            if self._is_typosquat(domain_base, official_base):
                return (brand, "typosquatting")

        return None

    def _is_typosquat(self, domain_base: str, official_base: str) -> bool:
        """
        Detect typosquatting using edit distance.
        Returns True if domain_base looks like a typo of official_base.
        Only checks brands with base names >= 5 chars to avoid false positives.
        """
        if len(official_base) < 5:
            return False
        if domain_base == official_base:
            return False

        # Common substitution patterns
        substitutions = {
            'o': ['0'], 'a': ['@', '4'], 'e': ['3'],
            'i': ['1', 'l'], 'l': ['1', 'i'], 's': ['5', '$'],
        }

        # Check simple character substitutions
        if len(domain_base) == len(official_base):
            diffs = sum(1 for a, b in zip(domain_base, official_base) if a != b)
            if diffs == 1:
                return True

        # Check for one character insertion/deletion (within 1 edit distance)
        if abs(len(domain_base) - len(official_base)) == 1:
            # Check if one is a substring of the other (with 1 char diff)
            shorter = min(domain_base, official_base, key=len)
            longer = max(domain_base, official_base, key=len)
            for i in range(len(longer)):
                if longer[:i] + longer[i+1:] == shorter:
                    return True

        return False

    def _calculate_domain_risk(self, result: DomainCheckResult) -> float:
        """Calculate domain risk score (0-100)."""
        score = 0.0

        if result.is_disposable:
            score = max(score, 70.0)
        if result.is_typosquatting:
            score = max(score, 85.0)
        if result.is_lookalike:
            score = max(score, 75.0)
        if result.is_suspicious_tld:
            score = max(score, 45.0)

        # Multiple flags compound the risk
        flag_count = sum([
            result.is_disposable, result.is_typosquatting,
            result.is_lookalike, result.is_suspicious_tld
        ])
        if flag_count >= 2:
            score = min(score + 10.0, 100.0)

        return round(score, 2)


# Singleton instance
domain_checker = DomainChecker()