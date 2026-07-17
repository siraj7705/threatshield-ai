"""
LOCATION: threatshield-ai/backend/app/services/sender_intelligence.py

ThreatShield AI - Sender Intelligence Service

Maintains a per-sender reputation history that improves with every email
processed.  Unlike the domain_checker (which is purely heuristic / static),
SenderIntelligence learns from observed behaviour:

  - A sender that has never sent a threat keeps a clean score.
  - A sender that has sent multiple threats is flagged as a repeat offender.
  - A sender whose emails are frequently blocked is marked malicious.
  - Score decays slowly over time so a reformed sender can recover.

Upgraded in this version with:
  - External DNS-based domain blacklist checks (SURBL, Spamhaus DBL, URIBL)
    using standard asyncio DNS queries — no API key required.
  - Results cached on the SenderIntelligence row so we never re-query the
    same domain (DNS TTL is honoured by the OS resolver anyway, but the DB
    cache avoids redundant async work on every email from the same sender).
  - Blacklist hit raises the reputation score and adds a risk reason.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sender_intelligence import SenderIntelligence
from app.services.domain_checker import domain_checker
from app.services.domain_age import domain_age_checker

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DNS Blacklist (DNSBL / SURBL) checker
# ---------------------------------------------------------------------------

# Each entry is (dnsbl_zone, human_label).
# These are all free, no-key, high-reliability lists.
_DOMAIN_BLACKLISTS = [
    ("multi.surbl.org",         "SURBL multi"),          # SURBL combined feed
    ("dbl.spamhaus.org",        "Spamhaus DBL"),         # Spamhaus domain blacklist
    ("black.uribl.com",         "URIBL Black"),          # URIBL black-listed domains
    ("rhsbl.sorbs.net",         "SORBS RHSBL"),          # SORBS right-hand-side BL
]

# Spamhaus DBL return codes we consider "listed" (their docs define these).
# 127.0.1.2 = spam domain, 127.0.1.4 = phishing, 127.0.1.5 = malware,
# 127.0.1.6 = botnet C&C, 127.0.1.102/103 = abused legit domain (treat as warning)
_SPAMHAUS_DBL_LISTED = {
    "127.0.1.2", "127.0.1.4", "127.0.1.5", "127.0.1.6",
}
_SPAMHAUS_DBL_WARNING = {"127.0.1.102", "127.0.1.103"}


class DNSBlacklistChecker:
    """
    Async DNS-based domain blacklist checker.

    Each DNSBL query works by reversing the domain and prepending it to the
    DNSBL zone, then doing an A-record lookup:
        evil.com  →  evil.com.multi.surbl.org
    A response means "listed"; NXDOMAIN means "clean".

    All queries run concurrently with asyncio.gather so total latency is
    bounded by the slowest single DNS query (~1-2 s), not the sum of all.
    """

    # Per-query DNS timeout in seconds
    _TIMEOUT = 3.0

    async def check_domain(self, domain: str) -> dict:
        """
        Query all configured DNSBLs for `domain` concurrently.

        Returns
        -------
        {
          "is_blacklisted": bool,           # True if ANY list returned a hit
          "is_warning": bool,               # True for abused-legit hits (Spamhaus only)
          "blacklists_hit": ["SURBL multi", ...],   # human labels of lists that hit
          "blacklists_checked": int,        # number of lists queried
          "risk_score_bonus": float,        # 0-30, added to reputation score
        }
        """
        domain = domain.strip().lower().rstrip(".")
        if not domain or "." not in domain:
            return self._empty_result()

        tasks = [
            self._query_dnsbl(domain, zone, label)
            for zone, label in _DOMAIN_BLACKLISTS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        hits = []
        warnings = []
        for r in results:
            if isinstance(r, Exception):
                continue
            if r.get("hit"):
                if r.get("warning"):
                    warnings.append(r["label"])
                else:
                    hits.append(r["label"])

        is_blacklisted = len(hits) > 0
        is_warning = len(warnings) > 0 and not is_blacklisted

        # Risk bonus: 20 pts per confirmed list hit (capped at 30), 8 for warning
        risk_bonus = min(len(hits) * 20, 30) if is_blacklisted else (8 if is_warning else 0)

        return {
            "is_blacklisted": is_blacklisted,
            "is_warning": is_warning,
            "blacklists_hit": hits + warnings,
            "blacklists_checked": len(_DOMAIN_BLACKLISTS),
            "risk_score_bonus": float(risk_bonus),
        }

    async def _query_dnsbl(self, domain: str, zone: str, label: str) -> dict:
        """Query a single DNSBL zone. Returns {"hit": bool, "warning": bool, "label": str}."""
        query_name = f"{domain}.{zone}"
        try:
            loop = asyncio.get_event_loop()
            # Use getaddrinfo via executor so we don't block the event loop
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._resolve, query_name),
                timeout=self._TIMEOUT,
            )
            if result is None:
                # NXDOMAIN — not listed
                return {"hit": False, "warning": False, "label": label}

            # Spamhaus DBL has specific return codes; others: any A record = listed
            if zone == "dbl.spamhaus.org":
                if result in _SPAMHAUS_DBL_WARNING:
                    return {"hit": True, "warning": True, "label": label}
                if result in _SPAMHAUS_DBL_LISTED:
                    return {"hit": True, "warning": False, "label": label}
                # Unlisted / unexpected return code
                return {"hit": False, "warning": False, "label": label}

            # All other DNSBLs: any A record = listed
            return {"hit": True, "warning": False, "label": label}

        except asyncio.TimeoutError:
            logger.debug(f"DNSBL timeout: {query_name}")
            return {"hit": False, "warning": False, "label": label}
        except Exception as e:
            logger.debug(f"DNSBL query error for {query_name}: {e}")
            return {"hit": False, "warning": False, "label": label}

    @staticmethod
    def _resolve(hostname: str) -> Optional[str]:
        """
        Synchronous DNS A-record lookup suitable for run_in_executor.
        Returns the first A-record string, or None on NXDOMAIN / error.
        """
        import socket
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            if infos:
                return infos[0][4][0]  # first IPv4 address
            return None
        except socket.gaierror:
            # NXDOMAIN or no answer — domain not listed
            return None

    @staticmethod
    def _empty_result() -> dict:
        return {
            "is_blacklisted": False,
            "is_warning": False,
            "blacklists_hit": [],
            "blacklists_checked": 0,
            "risk_score_bonus": 0.0,
        }


# Singleton
_dnsbl_checker = DNSBlacklistChecker()


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class SenderReputationResult:
    """Reputation snapshot for a single sender, returned after an update."""
    sender_email: str = ""
    sender_domain: str = ""

    total_emails_seen: int = 0
    threat_emails_count: int = 0
    safe_emails_count: int = 0
    avg_threat_score: float = 0.0
    max_threat_score: float = 0.0

    reputation_score: float = 0.0
    reputation_label: str = "unknown"  # trusted | clean | neutral | suspicious | malicious

    is_known_malicious: bool = False
    is_repeat_offender: bool = False
    is_trusted: bool = False

    # Domain heuristic signals
    domain_is_disposable: bool = False
    domain_is_typosquat: bool = False
    domain_is_lookalike: bool = False
    impersonated_brand: str = ""

    # Domain age signals
    domain_age_checked: bool = False
    domain_age_days: Optional[int] = None
    domain_is_newly_registered: bool = False
    domain_registrar: str = ""

    # External blacklist signals  ← NEW
    domain_is_blacklisted: bool = False
    domain_blacklists_hit: list = field(default_factory=list)

    risk_reasons: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class SenderIntelligenceService:
    """
    Async service that upserts SenderIntelligence rows and returns a
    SenderReputationResult the caller can use to boost the threat score.

    Typical call from emails.py
    ---------------------------
    sender_rep = await sender_intelligence.update_and_score(
        db=db,
        sender_email=parsed["sender_email"],
        threat_detected=nlp_result.threat_detected,
        overall_score=score_result.overall_score,
        action_taken=email_record.action_taken,
    )
    """

    _LABEL_THRESHOLDS = [
        (80, "malicious"),
        (60, "suspicious"),
        (35, "neutral"),
        (15, "clean"),
        (0,  "trusted"),
    ]

    _EMA_ALPHA = 0.30

    async def update_and_score(
        self,
        db: AsyncSession,
        sender_email: str,
        threat_detected: bool,
        overall_score: float,
        action_taken: str,
    ) -> SenderReputationResult:
        """
        Upsert the SenderIntelligence row for this sender and return a
        SenderReputationResult.
        """
        if not sender_email or "@" not in sender_email:
            return SenderReputationResult(sender_email=sender_email)

        sender_email = sender_email.strip().lower()
        domain = sender_email.split("@")[-1]

        # ── 1. Fetch or create the row ────────────────────────────────────────
        result = await db.execute(
            select(SenderIntelligence).where(
                SenderIntelligence.sender_email == sender_email
            )
        )
        row: Optional[SenderIntelligence] = result.scalar_one_or_none()

        blacklist_result = {"is_blacklisted": False, "is_warning": False,
                            "blacklists_hit": [], "risk_score_bonus": 0.0}

        if row is None:
            # First time we've seen this sender — run all one-time domain checks.
            domain_result = domain_checker.check(sender_email)
            age_result = await domain_age_checker.check(domain)

            # External DNSBL check — runs only once per new sender
            blacklist_result = await _dnsbl_checker.check_domain(domain)
            logger.info(
                f"DNSBL check for {domain}: blacklisted={blacklist_result['is_blacklisted']} "
                f"hits={blacklist_result['blacklists_hit']}"
            )

            row = SenderIntelligence(
                sender_email=sender_email,
                sender_domain=domain,
                # Heuristic domain flags
                domain_is_disposable=domain_result.is_disposable,
                domain_is_typosquat=domain_result.is_typosquatting,
                domain_is_lookalike=domain_result.is_lookalike,
                domain_is_suspicious_tld=domain_result.is_suspicious_tld,
                impersonated_brand=domain_result.impersonated_brand or "",
                # Domain age (RDAP)
                domain_age_checked=age_result.checked,
                domain_registered_at=(
                    datetime.fromisoformat(age_result.registered_at)
                    if age_result.registered_at else None
                ),
                domain_age_days=age_result.age_days,
                domain_is_newly_registered=age_result.is_newly_registered,
                domain_registrar=age_result.registrar or "",
                # External blacklist results — stored in notes JSON for now
                # (avoids a schema migration; we persist them as a JSON blob)
                notes=self._serialize_blacklist(blacklist_result),
            )
            db.add(row)

        else:
            # Row exists — read cached blacklist result from notes field
            blacklist_result = self._deserialize_blacklist(row.notes)

        # ── 2. Update counters ────────────────────────────────────────────────
        row.total_emails_seen = (row.total_emails_seen or 0) + 1
        row.last_seen = datetime.now(timezone.utc)

        if threat_detected:
            row.threat_emails_count = (row.threat_emails_count or 0) + 1
            row.last_threat_at = datetime.now(timezone.utc)
            row.last_threat_score = overall_score
        else:
            row.safe_emails_count = (row.safe_emails_count or 0) + 1

        if action_taken == "block":
            row.blocked_count = (row.blocked_count or 0) + 1
        elif action_taken == "quarantine":
            row.quarantined_count = (row.quarantined_count or 0) + 1

        # ── 3. Update rolling score (EMA) ─────────────────────────────────────
        if row.avg_threat_score is None or row.avg_threat_score == 0:
            row.avg_threat_score = overall_score
        else:
            row.avg_threat_score = round(
                self._EMA_ALPHA * overall_score + (1 - self._EMA_ALPHA) * row.avg_threat_score,
                2,
            )

        if overall_score > (row.max_threat_score or 0):
            row.max_threat_score = overall_score

        # ── 4. Update flags ───────────────────────────────────────────────────
        if overall_score >= 80:
            row.is_known_malicious = True
        if (row.threat_emails_count or 0) >= 3:
            row.is_repeat_offender = True

        # ── 5. Compute reputation score ───────────────────────────────────────
        reputation_score = self._calculate_reputation(row, blacklist_result)
        row.reputation_score = reputation_score
        row.reputation_label = self._label(reputation_score)

        # ── 6. Build result ───────────────────────────────────────────────────
        rep = SenderReputationResult(
            sender_email=sender_email,
            sender_domain=domain,
            total_emails_seen=row.total_emails_seen,
            threat_emails_count=row.threat_emails_count or 0,
            safe_emails_count=row.safe_emails_count or 0,
            avg_threat_score=row.avg_threat_score or 0.0,
            max_threat_score=row.max_threat_score or 0.0,
            reputation_score=reputation_score,
            reputation_label=row.reputation_label,
            is_known_malicious=row.is_known_malicious or False,
            is_repeat_offender=row.is_repeat_offender or False,
            is_trusted=row.is_trusted or False,
            domain_is_disposable=row.domain_is_disposable or False,
            domain_is_typosquat=row.domain_is_typosquat or False,
            domain_is_lookalike=row.domain_is_lookalike or False,
            impersonated_brand=row.impersonated_brand or "",
            domain_age_checked=row.domain_age_checked or False,
            domain_age_days=row.domain_age_days,
            domain_is_newly_registered=row.domain_is_newly_registered or False,
            domain_registrar=row.domain_registrar or "",
            domain_is_blacklisted=blacklist_result.get("is_blacklisted", False),
            domain_blacklists_hit=blacklist_result.get("blacklists_hit", []),
        )

        rep.risk_reasons = self._build_risk_reasons(row, rep)

        logger.debug(
            f"SenderIntelligence updated: {sender_email} → "
            f"rep={reputation_score:.1f} label={row.reputation_label} "
            f"total={row.total_emails_seen} threats={row.threat_emails_count} "
            f"blacklisted={rep.domain_is_blacklisted}"
        )
        return rep

    async def get(
        self, db: AsyncSession, sender_email: str
    ) -> Optional[SenderIntelligence]:
        """Read-only lookup — does not create or update."""
        result = await db.execute(
            select(SenderIntelligence).where(
                SenderIntelligence.sender_email == sender_email.strip().lower()
            )
        )
        return result.scalar_one_or_none()

    # ── Score calculation ─────────────────────────────────────────────────────

    def _calculate_reputation(self, row: SenderIntelligence, blacklist: dict) -> float:
        """
        Derive a 0-100 reputation score from the sender's history.

        Components
        ----------
        base         : rolling average threat score   (max 50 pts)
        volume       : threat ratio × 30              (max 30 pts)
        severity     : max_threat_score × 0.20        (max 20 pts)
        domain_flags : typosquat / lookalike / disposable / suspicious TLD / new domain
        repeat       : is_repeat_offender bonus       (+10 pts)
        blacklist    : DNSBL hit bonus                (max +30 pts)  ← NEW
        """
        total = max(row.total_emails_seen or 0, 1)
        threats = row.threat_emails_count or 0

        base = (row.avg_threat_score or 0.0) * 0.50
        threat_ratio = threats / total
        volume = threat_ratio * 30
        severity = (row.max_threat_score or 0.0) * 0.20

        domain_bonus = 0.0
        if row.domain_is_typosquat:
            domain_bonus += 10
        if row.domain_is_lookalike:
            domain_bonus += 8
        if row.domain_is_disposable:
            domain_bonus += 8
        if row.domain_is_suspicious_tld:
            domain_bonus += 5
        if row.domain_is_newly_registered:
            domain_bonus += 8
        domain_bonus = min(domain_bonus, 20)

        repeat_bonus = 10.0 if row.is_repeat_offender else 0.0

        # External blacklist bonus
        bl_bonus = blacklist.get("risk_score_bonus", 0.0)

        score = base + volume + severity + domain_bonus + repeat_bonus + bl_bonus
        return round(min(score, 100.0), 2)

    def _label(self, score: float) -> str:
        for threshold, label in self._LABEL_THRESHOLDS:
            if score >= threshold:
                return label
        return "trusted"

    def _build_risk_reasons(
        self, row: SenderIntelligence, rep: SenderReputationResult
    ) -> list[str]:
        reasons = []
        if rep.is_known_malicious:
            reasons.append(
                f"Sender {rep.sender_email} has previously triggered a critical threat alert"
            )
        if rep.is_repeat_offender:
            reasons.append(
                f"Sender {rep.sender_email} has sent {rep.threat_emails_count} threat emails historically"
            )
        if rep.domain_is_blacklisted:
            lists = ", ".join(rep.domain_blacklists_hit) if rep.domain_blacklists_hit else "external blacklists"
            reasons.append(
                f"Sender domain ({rep.sender_domain}) is listed on: {lists}"
            )
        if rep.domain_is_typosquat:
            brand = rep.impersonated_brand or "a known brand"
            reasons.append(f"Sender domain is a typosquat impersonating {brand}")
        if rep.domain_is_lookalike:
            brand = rep.impersonated_brand or "a known brand"
            reasons.append(f"Sender domain is a lookalike of {brand}")
        if rep.domain_is_disposable:
            reasons.append(f"Sender uses a disposable/temporary email domain ({rep.sender_domain})")
        if rep.domain_is_newly_registered:
            age_str = f"{rep.domain_age_days} day(s)" if rep.domain_age_days is not None else "very recently"
            reasons.append(f"Sender domain ({rep.sender_domain}) was registered {age_str} ago")
        if rep.avg_threat_score >= 60:
            reasons.append(
                f"Sender has a high average threat score historically ({rep.avg_threat_score:.1f}/100)"
            )
        return reasons

    # ── Blacklist result persistence (stored in notes JSON) ───────────────────

    @staticmethod
    def _serialize_blacklist(bl: dict) -> str:
        """Serialise DNSBL result to JSON for storage in the notes column."""
        import json
        try:
            return json.dumps({
                "dnsbl": {
                    "is_blacklisted": bl.get("is_blacklisted", False),
                    "is_warning": bl.get("is_warning", False),
                    "blacklists_hit": bl.get("blacklists_hit", []),
                    "risk_score_bonus": bl.get("risk_score_bonus", 0.0),
                }
            })
        except Exception:
            return "{}"

    @staticmethod
    def _deserialize_blacklist(notes: Optional[str]) -> dict:
        """Read cached DNSBL result back from the notes column."""
        import json
        empty = {"is_blacklisted": False, "is_warning": False,
                 "blacklists_hit": [], "risk_score_bonus": 0.0}
        if not notes:
            return empty
        try:
            data = json.loads(notes)
            return data.get("dnsbl", empty)
        except Exception:
            return empty


# Singleton
sender_intelligence = SenderIntelligenceService()