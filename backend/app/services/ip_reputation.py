"""
ThreatShield AI - IP Reputation & VPN/Tor/Proxy Detection Service

Uses ip-api.com (free tier, no key required, 45 req/min).
Falls back gracefully if the request fails or the IP is private/internal.
"""
import logging
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# ip-api fields we care about — only request what we need to stay lean
_FIELDS = "status,message,proxy,vpn,tor,hosting,isp,org,country,city,query"

# ip-api endpoint
_IP_API_URL = "http://ip-api.com/json/{ip}?fields={fields}"


@dataclass
class IPReputationResult:
    """Result of an IP reputation check."""
    ip: str = ""
    checked: bool = False          # False if IP was skipped (private/loopback/empty)
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_hosting: bool = False       # Datacenter/cloud — often used by bots
    isp: str = ""
    org: str = ""
    country: str = ""
    city: str = ""
    ip_risk_score: float = 0.0     # 0-100
    risk_reasons: list = field(default_factory=list)
    error: Optional[str] = None    # Set when the lookup failed

    def to_dict(self) -> dict:
        return asdict(self)


class IPReputationChecker:
    """
    Checks the originating IP of an email against ip-api.com to detect
    VPN, Tor, proxy, and datacenter traffic.

    Threat model: an attacker routing email through Tor or a commercial VPN
    to hide their real location is a meaningful signal on top of the existing
    header and NLP scores.

    Rate limit: ip-api free tier allows 45 requests/min from a single IP.
    We skip private/loopback IPs immediately so we never waste quota on
    internal infrastructure.
    """

    # Private / reserved ranges — never worth checking
    _PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
    ]

    def _is_private(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._PRIVATE_NETWORKS)
        except ValueError:
            return True  # malformed IP → treat as private, skip

    async def check(self, ip: str) -> IPReputationResult:
        """
        Async IP reputation lookup.

        Args:
            ip: IPv4 or IPv6 address extracted from email headers.

        Returns:
            IPReputationResult — always returns a result, never raises.
        """
        if not ip or not ip.strip():
            return IPReputationResult(ip=ip, checked=False)

        ip = ip.strip()

        if self._is_private(ip):
            logger.debug(f"IP {ip} is private/loopback — skipping reputation check")
            return IPReputationResult(ip=ip, checked=False)

        if settings.IP_REPUTATION_PROVIDER != "ip-api":
            # Future: plug in other providers here
            return IPReputationResult(ip=ip, checked=False)

        url = _IP_API_URL.format(ip=ip, fields=_FIELDS)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.warning(f"IP reputation check failed for {ip}: {e}")
            return IPReputationResult(ip=ip, checked=False, error=str(e))

        if data.get("status") != "success":
            msg = data.get("message", "unknown error")
            logger.warning(f"ip-api returned non-success for {ip}: {msg}")
            return IPReputationResult(ip=ip, checked=False, error=msg)

        result = IPReputationResult(
            ip=ip,
            checked=True,
            is_vpn=bool(data.get("vpn", False)),
            is_tor=bool(data.get("tor", False)),
            is_proxy=bool(data.get("proxy", False)),
            is_hosting=bool(data.get("hosting", False)),
            isp=data.get("isp", ""),
            org=data.get("org", ""),
            country=data.get("country", ""),
            city=data.get("city", ""),
        )

        result.ip_risk_score = self._calculate_risk(result)

        if result.is_tor:
            result.risk_reasons.append(f"Originating IP {ip} is a known Tor exit node")
        if result.is_vpn:
            result.risk_reasons.append(f"Originating IP {ip} is a VPN endpoint ({result.isp})")
        if result.is_proxy:
            result.risk_reasons.append(f"Originating IP {ip} is an open proxy")
        if result.is_hosting and not result.is_vpn and not result.is_tor:
            result.risk_reasons.append(
                f"Originating IP {ip} belongs to a datacenter/hosting provider ({result.org})"
            )

        if result.risk_reasons:
            logger.warning(f"IP risk detected: {result.risk_reasons}")

        return result

    def _calculate_risk(self, r: IPReputationResult) -> float:
        """Risk score 0-100 based on detection flags."""
        score = 0.0
        if r.is_tor:
            score = max(score, 90.0)   # Tor is the strongest signal
        if r.is_proxy:
            score = max(score, 75.0)
        if r.is_vpn:
            score = max(score, 55.0)
        if r.is_hosting:
            score = max(score, 30.0)   # Hosting alone is weak — bots, not always humans

        # Multiple flags compound
        flags = sum([r.is_tor, r.is_proxy, r.is_vpn, r.is_hosting])
        if flags >= 2:
            score = min(score + 10.0, 100.0)

        return round(score, 2)


# Singleton
ip_reputation_checker = IPReputationChecker()