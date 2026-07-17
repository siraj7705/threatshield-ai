"""
ThreatShield AI - Domain Age / WHOIS (RDAP) Lookup Service

Detects newly-registered domains — a strong phishing signal, since attackers
frequently register a fresh lookalike domain shortly before a campaign and
abandon it shortly after.

Uses RDAP (RFC 9083), the modern structured-JSON replacement for legacy
WHOIS, via the free rdap.org public redirector (no API key, no bootstrap
logic needed on our side — rdap.org resolves the correct registry for us).

This is a SEPARATE async service from domain_checker.py (which stays
synchronous, in-memory, heuristic-only) and from sender_intelligence.py.
Callers that want domain-age data call this directly, the same way
emails.py already calls ip_reputation_checker — not nested inside the
existing synchronous checks, to avoid turning sync code paths async.
"""
import logging
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_RDAP_URL = "https://rdap.org/domain/{domain}"

# Matches a bare registrable domain, e.g. "example.com" — used to strip
# subdomains before querying RDAP, since RDAP registration data is recorded
# against the registrable domain, not a specific subdomain.
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


@dataclass
class DomainAgeResult:
    """Result of a domain age / RDAP registration lookup."""
    domain: str = ""
    checked: bool = False              # False if lookup was skipped or failed
    registered_at: Optional[str] = None  # ISO date string, or None if unknown
    age_days: Optional[int] = None
    is_newly_registered: bool = False  # younger than settings.DOMAIN_AGE_NEW_DOMAIN_DAYS
    registrar: str = ""
    domain_risk_score: float = 0.0     # 0-100
    risk_reasons: list = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class DomainAgeChecker:
    """
    Async RDAP-based domain age lookup.

    Threat model: a domain registered days or weeks ago sending "urgent"
    financial or security emails is a meaningful signal — legitimate
    businesses rarely operate from brand-new domains. This is a SEPARATE
    signal from domain_checker's typosquat/lookalike heuristics; a domain
    can be old AND a lookalike, or new AND not a lookalike (e.g. a
    freshly-registered throwaway domain with no brand impersonation at all).
    """

    # Registrable-domain suffixes we never bother querying — RDAP has no
    # useful registration data for these (internal/test/reserved names).
    _SKIP_SUFFIXES = (".local", ".internal", ".test", ".invalid", ".localhost")

    def _extract_registrable_domain(self, domain: str) -> Optional[str]:
        """
        Best-effort reduction of a possibly-subdomained address to its
        registrable domain, e.g. "mail.billing.example.co.uk" -> best
        guess "example.co.uk". We don't ship a full public-suffix list,
        so this is a heuristic: take the last two labels, unless the
        TLD itself looks like a known multi-part suffix, in which case
        take three.
        """
        domain = domain.strip().lower().rstrip(".")
        if not domain or not _DOMAIN_RE.match(domain):
            return None

        labels = domain.split(".")
        if len(labels) <= 2:
            return domain

        # Common multi-part public suffixes where we need 3 labels, not 2
        # (not exhaustive — good enough to avoid the most common false splits)
        two_part_tlds = {
            "co.uk", "org.uk", "ac.uk", "gov.uk",
            "co.in", "co.jp", "co.kr", "com.au", "com.br",
            "co.za", "com.cn", "com.sg",
        }
        last_two = ".".join(labels[-2:])
        if last_two in two_part_tlds and len(labels) >= 3:
            return ".".join(labels[-3:])

        return last_two

    async def check(self, sender_email_or_domain: str) -> DomainAgeResult:
        """
        Look up domain registration age via RDAP.

        Args:
            sender_email_or_domain: either a full email address
                ("user@example.com") or a bare domain ("example.com").

        Returns:
            DomainAgeResult — always returns a result, never raises.
        """
        raw = sender_email_or_domain.strip().lower()
        domain = raw.split("@")[-1] if "@" in raw else raw

        registrable = self._extract_registrable_domain(domain)
        if not registrable:
            return DomainAgeResult(domain=domain, checked=False, error="invalid domain")

        if registrable.endswith(self._SKIP_SUFFIXES):
            return DomainAgeResult(domain=registrable, checked=False)

        if settings.DOMAIN_AGE_PROVIDER != "rdap":
            # Future: plug in other providers here
            return DomainAgeResult(domain=registrable, checked=False)

        url = _RDAP_URL.format(domain=registrable)
        try:
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 404:
                    # Domain not found in RDAP — could be unregistered or a
                    # registry RDAP didn't respond. Not an error, just unknown.
                    return DomainAgeResult(domain=registrable, checked=True, error="not found")
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.warning(f"RDAP lookup failed for {registrable}: {e}")
            return DomainAgeResult(domain=registrable, checked=False, error=str(e))

        return self._parse_rdap(registrable, data)

    def _parse_rdap(self, domain: str, data: dict) -> DomainAgeResult:
        result = DomainAgeResult(domain=domain, checked=True)

        events = data.get("events", []) or []
        registration_event = next(
            (e for e in events if e.get("eventAction") == "registration"), None
        )

        if registration_event and registration_event.get("eventDate"):
            try:
                reg_date = self._parse_iso(registration_event["eventDate"])
                result.registered_at = reg_date.isoformat()
                age = (datetime.now(timezone.utc) - reg_date).days
                result.age_days = age
                if age < settings.DOMAIN_AGE_NEW_DOMAIN_DAYS:
                    result.is_newly_registered = True
            except (ValueError, TypeError) as e:
                logger.debug(f"Could not parse RDAP registration date for {domain}: {e}")

        # Registrar name, if present (varies by registry — entities array
        # with role "registrar" is the RDAP-standard location)
        for entity in data.get("entities", []) or []:
            if "registrar" in (entity.get("roles") or []):
                vcard = entity.get("vcardArray")
                if vcard and len(vcard) > 1:
                    for field_entry in vcard[1]:
                        if field_entry[0] == "fn":
                            result.registrar = field_entry[3]
                            break
                break

        result.domain_risk_score = self._calculate_risk(result)

        if result.is_newly_registered:
            age_str = f"{result.age_days} day(s)" if result.age_days is not None else "an unknown but short time"
            result.risk_reasons.append(
                f"Domain {domain} was registered {age_str} ago — newly registered domains are commonly used in phishing campaigns"
            )
            logger.warning(f"Newly registered domain detected: {domain} (age_days={result.age_days})")

        return result

    @staticmethod
    def _parse_iso(date_str: str) -> datetime:
        """Parse an RDAP ISO-8601 datetime string into an aware UTC datetime."""
        normalized = date_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _calculate_risk(self, r: DomainAgeResult) -> float:
        """Risk score 0-100. Newer domains are riskier, on a sliding scale."""
        if r.age_days is None:
            return 0.0
        if r.age_days < 0:
            return 0.0  # clock skew / bad data — don't penalize

        new_threshold = settings.DOMAIN_AGE_NEW_DOMAIN_DAYS
        if r.age_days >= new_threshold:
            return 0.0
        if r.age_days <= 1:
            return 90.0
        if r.age_days <= 7:
            return 75.0
        if r.age_days <= 14:
            return 55.0
        # Linearly taper from 55 -> 0 between 14 days and new_threshold
        remaining = new_threshold - 14
        if remaining <= 0:
            return 0.0
        fraction = max(0.0, (new_threshold - r.age_days) / remaining)
        return round(55.0 * fraction, 2)


# Singleton
domain_age_checker = DomainAgeChecker()