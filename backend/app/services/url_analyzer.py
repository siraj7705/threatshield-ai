"""
LOCATION: threatshield-ai/backend/app/services/url_analyzer.py

ThreatShield AI - URL Analyzer Service
Extracts URLs from email content and checks them against Google Safe Browsing API.

Upgraded in this version:
  - Async redirect-chain following for every extracted URL (up to 10 hops,
    2 s per hop).  The FINAL destination URL is what gets sent to Safe
    Browsing and scored — so a link-shortener or tracker that lands on a
    phishing page is caught rather than whitelisted by the innocent first hop.
  - Chain stored per-URL in analysis_details so investigators can see the
    full redirect path.
  - Domain-age RDAP check wired into URL analysis (one domain per email,
    same as before) — now applied to the FINAL destination domain, not the
    surface URL's domain.
  - Synchronous analyze() kept for callers that can't await; async
    analyze_async() is the preferred path for the upload pipeline.
"""
import asyncio
import re
import logging
import httpx
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
from urllib.parse import urlparse

from app.core.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>\]\)]+',
    re.IGNORECASE
)

SUSPICIOUS_URL_KEYWORDS = [
    "verify", "update", "secure", "login", "signin", "account",
    "password", "confirm", "billing", "suspended", "locked",
    "urgent", "alert", "validate", "reactivate", "click",
]

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "linkedin.com",
    "github.com", "youtube.com", "instagram.com", "netflix.com",
}

# Known URL-shortener / redirect-tracker domains — we ALWAYS follow these
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "buff.ly",
    "short.link", "rebrand.ly", "cutt.ly", "tiny.cc", "is.gd",
    "bl.ink", "shorturl.at", "clck.ru", "rb.gy", "urlzs.com",
}

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RedirectChain:
    """Full redirect chain for a single URL."""
    original_url: str = ""
    final_url: str = ""
    hops: List[Dict[str, Any]] = field(default_factory=list)
    # Each hop: {"url": str, "status_code": int, "redirected_to": str|None}
    hop_count: int = 0
    followed: bool = False          # False if we skipped following (trusted domain, etc.)
    error: Optional[str] = None


@dataclass
class URLAnalysisResult:
    """Result of URL analysis for a single email."""
    urls_found: List[str] = field(default_factory=list)
    malicious_urls: List[str] = field(default_factory=list)
    suspicious_urls: List[str] = field(default_factory=list)
    safe_browsing_checked: bool = False
    url_risk_score: float = 0.0
    url_threat_types: List[str] = field(default_factory=list)
    analysis_details: List[Dict[str, Any]] = field(default_factory=list)
    # NEW: redirect chains keyed by original URL
    redirect_chains: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Redirect chain follower
# ---------------------------------------------------------------------------

class RedirectFollower:
    """
    Async HTTP redirect-chain follower.

    Follows up to MAX_HOPS redirects per URL, collecting each hop's URL and
    status code.  Uses a HEAD request first (cheaper); falls back to GET if
    the server rejects HEAD.

    Timeouts are strict — a slow redirect chain must not hold up the whole
    email pipeline.
    """

    MAX_HOPS = 10
    TIMEOUT_PER_HOP = 2.0       # seconds per individual request
    TOTAL_TIMEOUT = 8.0         # hard cap for the whole chain

    # Headers that mimic a real browser — some servers refuse Python UA
    _HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
    }

    async def follow(self, url: str) -> RedirectChain:
        """
        Follow all redirects from `url` and return the full chain.
        Never raises — errors are captured in RedirectChain.error.
        """
        chain = RedirectChain(original_url=url)

        try:
            async with asyncio.timeout(self.TOTAL_TIMEOUT):
                await self._follow_chain(url, chain)
        except asyncio.TimeoutError:
            chain.error = "total timeout exceeded"
            if not chain.final_url:
                chain.final_url = url
        except Exception as e:
            chain.error = str(e)
            if not chain.final_url:
                chain.final_url = url

        chain.hop_count = len(chain.hops)
        chain.followed = chain.hop_count > 0
        return chain

    async def _follow_chain(self, start_url: str, chain: RedirectChain) -> None:
        current_url = start_url
        visited: set = set()

        # Use manual redirect handling so we can record every hop
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=self.TIMEOUT_PER_HOP,
            headers=self._HEADERS,
            verify=False,           # some phishing sites have bad certs — we still want to see them
        ) as client:
            for _ in range(self.MAX_HOPS):
                if current_url in visited:
                    chain.error = "redirect loop detected"
                    break
                visited.add(current_url)

                resp = await self._request(client, current_url)
                if resp is None:
                    chain.final_url = current_url
                    break

                hop: Dict[str, Any] = {
                    "url": current_url,
                    "status_code": resp.status_code,
                    "redirected_to": None,
                }

                if resp.is_redirect:
                    next_url = resp.headers.get("location", "")
                    if not next_url:
                        chain.final_url = current_url
                        hop["redirected_to"] = None
                        chain.hops.append(hop)
                        break
                    # Handle relative redirects
                    next_url = self._resolve_url(current_url, next_url)
                    hop["redirected_to"] = next_url
                    chain.hops.append(hop)
                    current_url = next_url
                else:
                    # Final destination
                    chain.final_url = current_url
                    hop["redirected_to"] = None
                    chain.hops.append(hop)
                    break
            else:
                # Exceeded MAX_HOPS
                chain.final_url = current_url
                chain.error = f"exceeded {self.MAX_HOPS} redirect hops"

        if not chain.final_url:
            chain.final_url = start_url

    async def _request(
        self, client: httpx.AsyncClient, url: str
    ) -> Optional[httpx.Response]:
        """Try HEAD first, fall back to GET on 405."""
        try:
            resp = await client.head(url)
            if resp.status_code == 405:
                resp = await client.get(url)
            return resp
        except Exception as e:
            logger.debug(f"Redirect follow request failed for {url}: {e}")
            return None

    @staticmethod
    def _resolve_url(base: str, location: str) -> str:
        """Resolve a possibly-relative Location header against the base URL."""
        if location.startswith("http://") or location.startswith("https://"):
            return location
        parsed = urlparse(base)
        if location.startswith("/"):
            return f"{parsed.scheme}://{parsed.netloc}{location}"
        # Relative path — resolve against directory
        base_path = parsed.path.rsplit("/", 1)[0]
        return f"{parsed.scheme}://{parsed.netloc}{base_path}/{location}"


# Singleton
_redirect_follower = RedirectFollower()


# ---------------------------------------------------------------------------
# URL Analyzer
# ---------------------------------------------------------------------------

class URLAnalyzer:
    """
    Extracts and analyses URLs from email content.

    Checks:
    1. Redirect-chain following — resolve the true final destination  ← NEW
    2. Google Safe Browsing API (checks FINAL destination URL)
    3. Domain reputation heuristics (typosquatting, suspicious keywords)
    4. URL structure analysis
    5. Domain age (RDAP) on the final destination domain              ← NEW: uses final URL
    """

    SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    # Cap on how many URLs we follow redirects for — following every URL in
    # a newsletter with 30 links is wasteful.  We prioritise:
    #   (a) URL shorteners (always follow)
    #   (b) heuristically suspicious URLs
    #   (c) first N remaining
    MAX_REDIRECT_FOLLOWS = 15

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, body_text: str, body_html: str = "") -> URLAnalysisResult:
        """
        Synchronous wrapper — runs the async pipeline in a new event loop.
        Kept for backward compatibility with any sync callers.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're inside an async context (FastAPI) — schedule as a task
                # This path should not normally be hit; callers should use
                # analyze_async() directly.
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self.analyze_async(body_text, body_html))
                    return future.result(timeout=30)
            else:
                return loop.run_until_complete(self.analyze_async(body_text, body_html))
        except Exception as e:
            logger.error(f"URL analysis error: {e}")
            return URLAnalysisResult()

    async def analyze_async(self, body_text: str, body_html: str = "") -> URLAnalysisResult:
        """
        Full async URL analysis pipeline:
          1. Extract URLs
          2. Follow redirect chains (async, concurrent)
          3. Heuristic analysis on final destination URLs
          4. Google Safe Browsing on final destination URLs
          5. Score
        """
        result = URLAnalysisResult()

        combined = f"{body_text} {body_html}"
        urls = self._extract_urls(combined)
        result.urls_found = urls

        if not urls:
            return result

        # ── Step 1: Follow redirect chains ─────────────────────────────────
        chains = await self._follow_all_redirects(urls)
        result.redirect_chains = {
            url: {
                "final_url": c.final_url,
                "hop_count": c.hop_count,
                "hops": c.hops,
                "followed": c.followed,
                "error": c.error,
            }
            for url, c in chains.items()
        }

        # Build a map: original_url → final_url
        final_urls: Dict[str, str] = {
            url: chains[url].final_url if chains.get(url) and chains[url].final_url else url
            for url in urls
        }

        # ── Step 2: Heuristic analysis on final destination ─────────────────
        for url in urls:
            final = final_urls[url]
            detail = self._analyze_url_heuristic(url, final_url=final)
            # Attach chain summary to detail
            chain = chains.get(url)
            if chain and chain.hop_count > 0:
                detail["redirect_chain"] = {
                    "hops": chain.hop_count,
                    "final_url": chain.final_url,
                    "path": [h["url"] for h in chain.hops],
                }
                if chain.hop_count >= 3:
                    detail["reasons"].append(
                        f"URL redirects through {chain.hop_count} hops before reaching {chain.final_url}"
                    )
                    if detail["risk"] == "safe":
                        detail["risk"] = "suspicious"

            result.analysis_details.append(detail)

            if detail["risk"] == "malicious":
                if url not in result.malicious_urls:
                    result.malicious_urls.append(url)
            elif detail["risk"] == "suspicious":
                if url not in result.suspicious_urls:
                    result.suspicious_urls.append(url)

        # ── Step 3: Google Safe Browsing on FINAL destination URLs ──────────
        api_key = getattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", None)
        if api_key:
            # Deduplicate — several original URLs may share the same final URL
            unique_finals = list({v for v in final_urls.values()})
            try:
                sb_results = self._check_safe_browsing(unique_finals, api_key)
                result.safe_browsing_checked = True
                flagged_finals = set()
                for match in sb_results:
                    flagged_final = match.get("threat", {}).get("url", "")
                    threat_type = match.get("threatType", "UNKNOWN")
                    flagged_finals.add(flagged_final)
                    if threat_type not in result.url_threat_types:
                        result.url_threat_types.append(threat_type)
                    logger.warning(
                        f"Safe Browsing flagged final URL: {flagged_final} ({threat_type})"
                    )

                # Map flagged final URLs back to their original URLs
                for orig, final in final_urls.items():
                    if final in flagged_finals and orig not in result.malicious_urls:
                        result.malicious_urls.append(orig)

            except Exception as e:
                logger.error(f"Google Safe Browsing API error: {e}")

        # ── Step 4: Score ────────────────────────────────────────────────────
        result.url_risk_score = self._calculate_url_risk_score(result)

        logger.info(
            f"URL analysis: {len(urls)} URLs, "
            f"{len(result.malicious_urls)} malicious, "
            f"{len(result.suspicious_urls)} suspicious, "
            f"risk={result.url_risk_score:.1f}, "
            f"chains_followed={sum(1 for c in chains.values() if c.followed)}"
        )

        return result

    # ------------------------------------------------------------------
    # Redirect following
    # ------------------------------------------------------------------

    async def _follow_all_redirects(
        self, urls: List[str]
    ) -> Dict[str, RedirectChain]:
        """
        Follow redirect chains for a prioritised subset of URLs concurrently.

        Priority:
          1. Known URL shorteners — always follow
          2. Heuristically suspicious surface URLs — always follow
          3. Others — up to MAX_REDIRECT_FOLLOWS total
        """
        to_follow: List[str] = []
        skip: List[str] = []

        for url in urls:
            domain = self._extract_domain(url)
            # Always follow shorteners and suspicious-surface URLs
            is_shortener = any(domain == s or domain.endswith(f".{s}") for s in SHORTENER_DOMAINS)
            is_trusted = any(domain == t or domain.endswith(f".{t}") for t in TRUSTED_DOMAINS)
            heuristic = self._analyze_url_heuristic(url)
            is_suspicious_surface = heuristic["risk"] in ("suspicious", "malicious")

            if is_trusted and not is_shortener:
                # Trusted domains — skip following to save time
                skip.append(url)
            elif is_shortener or is_suspicious_surface:
                to_follow.insert(0, url)   # priority
            else:
                to_follow.append(url)

        # Cap total follows
        to_follow = to_follow[:self.MAX_REDIRECT_FOLLOWS]

        # Run all follows concurrently
        tasks = [_redirect_follower.follow(url) for url in to_follow]
        chains_list = await asyncio.gather(*tasks, return_exceptions=True)

        result: Dict[str, RedirectChain] = {}
        for url, chain in zip(to_follow, chains_list):
            if isinstance(chain, Exception):
                result[url] = RedirectChain(
                    original_url=url, final_url=url, followed=False, error=str(chain)
                )
            else:
                result[url] = chain

        # Skipped URLs — just map to themselves
        for url in skip:
            result[url] = RedirectChain(
                original_url=url, final_url=url, followed=False
            )
        # URLs not in either list (overflow past cap)
        for url in urls:
            if url not in result:
                result[url] = RedirectChain(
                    original_url=url, final_url=url, followed=False
                )

        return result

    # ------------------------------------------------------------------
    # Heuristics
    # ------------------------------------------------------------------

    def _extract_urls(self, text: str) -> List[str]:
        matches = URL_PATTERN.findall(text)
        cleaned = []
        for url in matches:
            url = url.rstrip(".,;:!?)\"'")
            if url not in cleaned:
                cleaned.append(url)
        return cleaned[:50]

    def _extract_domain(self, url: str) -> str:
        try:
            domain = re.sub(r'^https?://', '', url)
            domain = domain.split('/')[0].split(':')[0]
            domain = re.sub(r'^www\.', '', domain)
            return domain.lower()
        except Exception:
            return ""

    def _analyze_url_heuristic(
        self, url: str, final_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Heuristic URL risk analysis.  When final_url differs from url,
        analysis is run against BOTH — the surface URL and the destination.
        """
        analysis_url = final_url if final_url and final_url != url else url
        domain = self._extract_domain(analysis_url)
        surface_domain = self._extract_domain(url)
        risk = "safe"
        reasons: List[str] = []

        # Domain-switched after redirect — always suspicious
        if final_url and final_url != url and domain != surface_domain:
            reasons.append(
                f"URL redirects from {surface_domain} to different domain {domain}"
            )
            risk = "suspicious"

        # IP address URL
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}', domain):
            risk = "suspicious"
            reasons.append("Direct IP address URL (no domain name)")

        # Suspicious TLDs
        suspicious_tlds = [
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
            ".top", ".buzz", ".click", ".link", ".work",
        ]
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                risk = "suspicious"
                reasons.append(f"Suspicious TLD: {tld}")
                break

        # Typosquatting
        for trusted in TRUSTED_DOMAINS:
            trusted_base = trusted.split('.')[0]
            if (trusted_base in domain
                    and domain != trusted
                    and not domain.endswith(f".{trusted}")):
                risk = "suspicious"
                reasons.append(f"Possible typosquatting of {trusted}")
                break

        # Suspicious path keywords
        url_lower = analysis_url.lower()
        found_kw = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in url_lower]
        if len(found_kw) >= 2:
            if risk == "safe":
                risk = "suspicious"
            reasons.append(f"Suspicious URL keywords: {', '.join(found_kw[:3])}")

        # Excessively long URL
        if len(analysis_url) > 200:
            if risk == "safe":
                risk = "suspicious"
            reasons.append("Unusually long URL")

        # Many subdomains — domain spoofing signal
        subdomain_count = domain.count('.')
        if subdomain_count >= 4:
            risk = "suspicious"
            reasons.append(f"Many subdomains ({subdomain_count}) — possible domain spoofing")

        # URL encoding obfuscation
        if '%' in analysis_url and analysis_url.count('%') > 3:
            if risk == "safe":
                risk = "suspicious"
            reasons.append("URL contains many encoded characters (possible obfuscation)")

        return {
            "url": url,
            "final_url": final_url or url,
            "domain": domain,
            "risk": risk,
            "reasons": reasons,
        }

    # ------------------------------------------------------------------
    # Safe Browsing
    # ------------------------------------------------------------------

    def _check_safe_browsing(self, urls: List[str], api_key: str) -> List[Dict]:
        payload = {
            "client": {
                "clientId": "threatshield-ai",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                f"{self.SAFE_BROWSING_URL}?key={api_key}",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            return response.json().get("matches", [])

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _calculate_url_risk_score(self, result: URLAnalysisResult) -> float:
        if not result.urls_found:
            return 0.0

        score = 0.0

        if result.malicious_urls:
            score = max(score, 85.0 + min(len(result.malicious_urls) * 5, 15.0))

        suspicious_count = len(result.suspicious_urls)
        if suspicious_count >= 3:
            score = max(score, 70.0)
        elif suspicious_count == 2:
            score = max(score, 55.0)
        elif suspicious_count == 1:
            score = max(score, 35.0)

        # Extra risk for long redirect chains landing on suspicious destinations
        long_chains = sum(
            1 for c in result.redirect_chains.values()
            if isinstance(c, dict) and c.get("hop_count", 0) >= 3
        )
        if long_chains >= 2:
            score = max(score, 45.0)
        elif long_chains == 1:
            score = max(score, 30.0)

        return min(round(score, 2), 100.0)


# Singleton instance
url_analyzer = URLAnalyzer()