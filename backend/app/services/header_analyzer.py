"""
ThreatShield AI - Email Header Forensics Analyzer
Analyzes email headers for authentication, spoofing, and routing anomalies.
"""
import re
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field

logger = logging.getLogger(__name__)


@dataclass
class HeaderResult:
    """Result of email header forensic analysis."""
    return_path: str = ""
    received_chain: List[Dict] = field(default_factory=list)
    originating_ip: str = ""
    originating_country: str = ""
    originating_city: str = ""
    spf_result: str = "none"
    dkim_result: str = "none"
    dmarc_result: str = "none"
    message_id_valid: bool = True
    from_domain: str = ""
    return_path_domain: str = ""
    domain_match: bool = True
    spoofing_detected: bool = False
    routing_anomalies: List[str] = field(default_factory=list)
    mail_client: str = ""
    header_risk_score: float = 0.0

    def to_dict(self) -> dict:
        result = asdict(self)
        result["received_chain"] = json.dumps(self.received_chain)
        result["routing_anomalies"] = json.dumps(self.routing_anomalies)
        return result


class HeaderAnalyzer:
    """Analyzes email headers for security indicators."""

    # Known disposable email domains
    DISPOSABLE_DOMAINS = {
        "tempmail.com", "throwaway.email", "guerrillamail.com", "mailinator.com",
        "10minutemail.com", "guerrillamail.info", "grr.la", "guerrillamail.biz",
        "guerrillamail.de", "guerrillamail.net", "yopmail.com", "yopmail.fr",
        "cool.fr.nf", "jetable.fr.nf", "nospam.ze.tc", "nomail.xl.cx",
        "mega.zik.dj", "speed.1s.fr", "courriel.fr.nf", "moncourrier.fr.nf",
        "trashmail.com", "trashmail.net", "trashmail.org", "trashmail.me",
        "sharklasers.com", "guerrillamailblock.com", "tempinbox.com",
        "dispostable.com", "maildrop.cc", "mailnesia.com",
    }

    # Known suspicious TLDs
    SUSPICIOUS_TLDS = {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz",
        ".work", ".click", ".link", ".info", ".biz", ".icu",
    }

    def analyze(self, raw_headers: str) -> HeaderResult:
        """
        Perform full header forensic analysis.

        Args:
            raw_headers: Raw email headers as string

        Returns:
            HeaderResult with all analysis details
        """
        result = HeaderResult()

        if not raw_headers:
            result.header_risk_score = 50.0
            result.routing_anomalies.append("No headers available for analysis")
            return result

        try:
            # Parse individual headers
            headers = self._parse_headers(raw_headers)

            # Extract Return-Path
            result.return_path = headers.get("Return-Path", "").strip("<>")

            # Parse Received chain
            result.received_chain = self._parse_received_chain(raw_headers)

            # Extract originating IP
            result.originating_ip = self._extract_originating_ip(result.received_chain)

            # Check SPF
            result.spf_result = self._check_spf(raw_headers)

            # Check DKIM
            result.dkim_result = self._check_dkim(raw_headers)

            # Check DMARC
            result.dmarc_result = self._check_dmarc(raw_headers)

            # Extract domains
            from_header = headers.get("From", "")
            result.from_domain = self._extract_domain(from_header)
            result.return_path_domain = self._extract_domain(result.return_path)

            # Check Message-ID validity
            message_id = headers.get("Message-ID", "")
            result.message_id_valid = self._validate_message_id(message_id)

            # Check domain match (From vs Return-Path)
            if result.from_domain and result.return_path_domain:
                result.domain_match = result.from_domain.lower() == result.return_path_domain.lower()
            else:
                result.domain_match = True  # Can't determine

            # Detect spoofing
            result.spoofing_detected = self._detect_spoofing(result, headers)

            # Check for routing anomalies
            result.routing_anomalies = self._check_routing_anomalies(result, headers)

            # Extract mail client
            result.mail_client = self._extract_mail_client(headers)

            # Calculate risk score
            result.header_risk_score = self._calculate_risk_score(result)

        except Exception as e:
            logger.error(f"Header analysis error: {e}")
            result.header_risk_score = 50.0
            result.routing_anomalies.append(f"Analysis error: {str(e)}")

        return result

    def _parse_headers(self, raw_headers: str) -> Dict[str, str]:
        """Parse raw headers into key-value dict."""
        headers = {}
        current_key = None
        current_value = ""

        for line in raw_headers.split("\n"):
            if ":" in line and not line.startswith((" ", "\t")):
                if current_key:
                    headers[current_key] = current_value.strip()
                parts = line.split(":", 1)
                current_key = parts[0].strip()
                current_value = parts[1].strip() if len(parts) > 1 else ""
            elif current_key and line.startswith((" ", "\t")):
                current_value += " " + line.strip()

        if current_key:
            headers[current_key] = current_value.strip()

        return headers

    def _parse_received_chain(self, raw_headers: str) -> List[Dict]:
        """Parse Received headers into structured chain."""
        chain = []
        received_pattern = re.compile(
            r'Received:\s*(.*?)(?=\nReceived:|\n[A-Z][\w-]*:|\Z)',
            re.DOTALL | re.IGNORECASE
        )
        matches = received_pattern.findall(raw_headers)

        for i, match in enumerate(matches):
            hop = {
                "hop": i + 1,
                "raw": match.strip()[:500],
            }

            # Extract 'from' server
            from_match = re.search(r'from\s+([\w.\-]+)', match)
            if from_match:
                hop["from"] = from_match.group(1)

            # Extract 'by' server
            by_match = re.search(r'by\s+([\w.\-]+)', match)
            if by_match:
                hop["by"] = by_match.group(1)

            # Extract IP
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', match)
            if ip_match:
                hop["ip"] = ip_match.group(1)

            chain.append(hop)

        return chain

    def _extract_originating_ip(self, received_chain: List[Dict]) -> str:
        """Extract the originating IP from the received chain."""
        if received_chain:
            # Last hop in chain is typically the originator
            last_hop = received_chain[-1] if received_chain else {}
            return last_hop.get("ip", "")
        return ""

    def _check_spf(self, raw_headers: str) -> str:
        """Check SPF authentication result."""
        # Look for Authentication-Results or Received-SPF
        spf_patterns = [
            r'spf=(\w+)',
            r'Received-SPF:\s*(\w+)',
        ]
        for pattern in spf_patterns:
            match = re.search(pattern, raw_headers, re.IGNORECASE)
            if match:
                result = match.group(1).lower()
                if result in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
                    return result
        return "none"

    def _check_dkim(self, raw_headers: str) -> str:
        """Check DKIM authentication result."""
        match = re.search(r'dkim=(\w+)', raw_headers, re.IGNORECASE)
        if match:
            result = match.group(1).lower()
            if result in ("pass", "fail", "none"):
                return result
        # Check for DKIM-Signature header existence
        if "DKIM-Signature:" in raw_headers:
            return "present"
        return "none"

    def _check_dmarc(self, raw_headers: str) -> str:
        """Check DMARC authentication result."""
        match = re.search(r'dmarc=(\w+)', raw_headers, re.IGNORECASE)
        if match:
            result = match.group(1).lower()
            if result in ("pass", "fail", "none"):
                return result
        return "none"

    def _extract_domain(self, email_str: str) -> str:
        """Extract domain from an email address string."""
        match = re.search(r'@([\w.\-]+)', email_str)
        return match.group(1) if match else ""

    def _validate_message_id(self, message_id: str) -> bool:
        """Validate Message-ID format."""
        if not message_id:
            return False
        # Message-ID should be in format <unique@domain>
        pattern = r'^<[\w.\-+]+@[\w.\-]+>$'
        return bool(re.match(pattern, message_id.strip()))

    def _detect_spoofing(self, result: HeaderResult, headers: Dict) -> bool:
        """Detect potential email spoofing."""
        indicators = []

        # Domain mismatch between From and Return-Path
        if not result.domain_match and result.return_path_domain:
            indicators.append("domain_mismatch")

        # SPF fail
        if result.spf_result in ("fail", "softfail"):
            indicators.append("spf_failure")

        # DKIM fail
        if result.dkim_result == "fail":
            indicators.append("dkim_failure")

        # Invalid Message-ID
        if not result.message_id_valid:
            indicators.append("invalid_message_id")

        # From domain is disposable
        if result.from_domain and result.from_domain.lower() in self.DISPOSABLE_DOMAINS:
            indicators.append("disposable_domain")

        return len(indicators) >= 2

    def _check_routing_anomalies(self, result: HeaderResult, headers: Dict) -> List[str]:
        """Check for routing anomalies in headers."""
        anomalies = []

        # Private IP in received chain (not always bad but noteworthy)
        for hop in result.received_chain:
            ip = hop.get("ip", "")
            if ip and self._is_private_ip(ip):
                anomalies.append(f"Private IP {ip} found in routing chain")

        # SPF failure
        if result.spf_result in ("fail", "softfail"):
            anomalies.append(f"SPF check {result.spf_result}: sender may not be authorized")

        # DKIM failure
        if result.dkim_result == "fail":
            anomalies.append("DKIM signature verification failed")

        # DMARC failure
        if result.dmarc_result == "fail":
            anomalies.append("DMARC policy check failed")

        # Domain mismatch
        if not result.domain_match and result.return_path_domain:
            anomalies.append(
                f"From domain ({result.from_domain}) does not match "
                f"Return-Path domain ({result.return_path_domain})"
            )

        # Suspicious TLD
        if result.from_domain:
            for tld in self.SUSPICIOUS_TLDS:
                if result.from_domain.endswith(tld):
                    anomalies.append(f"Suspicious TLD: {tld}")
                    break

        # Too many hops
        if len(result.received_chain) > 8:
            anomalies.append(f"Unusual number of hops: {len(result.received_chain)}")

        return anomalies

    def _extract_mail_client(self, headers: Dict) -> str:
        """Extract mail client from X-Mailer or User-Agent headers."""
        mailer = headers.get("X-Mailer", "")
        if mailer:
            return mailer
        user_agent = headers.get("User-Agent", "")
        if user_agent:
            return user_agent
        return "Unknown"

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            a, b = int(parts[0]), int(parts[1])
            return (
                a == 10 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168) or
                a == 127
            )
        except ValueError:
            return False

    def _calculate_risk_score(self, result: HeaderResult) -> float:
        """Calculate header-based risk score (0-100)."""
        score = 0.0

        # SPF failures
        if result.spf_result == "fail":
            score += 25
        elif result.spf_result == "softfail":
            score += 15
        elif result.spf_result == "none":
            score += 10

        # DKIM failures
        if result.dkim_result == "fail":
            score += 20
        elif result.dkim_result == "none":
            score += 10

        # DMARC failures
        if result.dmarc_result == "fail":
            score += 20
        elif result.dmarc_result == "none":
            score += 5

        # Spoofing detected
        if result.spoofing_detected:
            score += 25

        # Domain mismatch
        if not result.domain_match and result.return_path_domain:
            score += 15

        # Invalid Message-ID
        if not result.message_id_valid:
            score += 10

        # Routing anomalies
        anomaly_count = len(result.routing_anomalies)
        score += min(anomaly_count * 5, 20)

        return min(score, 100.0)


# Singleton instance
header_analyzer = HeaderAnalyzer()
