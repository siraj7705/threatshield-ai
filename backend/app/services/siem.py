"""
LOCATION: threatshield-ai/backend/app/services/siem.py

ThreatShield AI - SIEM / Elasticsearch Integration

Indexes threat events, alerts, and audit logs into Elasticsearch so they
can be consumed by Kibana, ELK-based SIEMs, or any tool that speaks the
Elasticsearch REST API (Splunk ES, OpenSearch, etc.)

Index layout:
  threatshield-emails   — one doc per analysed email (threat score, type, sender…)
  threatshield-alerts   — one doc per generated alert
  threatshield-audit    — one doc per audit log entry

Setup:
  1. Ensure Elasticsearch is running (Docker: already in docker-compose.yml)
  2. Set in .env:
       ELASTICSEARCH_ENABLED=true
       ELASTICSEARCH_URL=http://elasticsearch:9200   (or your ES host)
       ELASTICSEARCH_API_KEY=                        (optional, for secured clusters)
       ELASTICSEARCH_USERNAME=                       (optional)
       ELASTICSEARCH_PASSWORD=                       (optional)
  3. Install client:
       pip install elasticsearch

The client is initialised lazily — if the package is missing or ES is
unreachable the rest of the app works fine; events are just not indexed.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Index names
INDEX_EMAILS  = "threatshield-emails"
INDEX_ALERTS  = "threatshield-alerts"
INDEX_AUDIT   = "threatshield-audit"


class SIEMClient:
    """
    Async-friendly wrapper around the official elasticsearch-py client.

    All public methods are fire-and-forget coroutines — they log errors
    but never raise, so a broken ES connection never breaks email processing.
    """

    def __init__(self):
        self._es = None
        self._enabled = False
        self._ready = False
        self._load_config()

    def _load_config(self):
        try:
            from app.core.config import settings

            self._enabled = getattr(settings, "ELASTICSEARCH_ENABLED", False)
            if not self._enabled:
                logger.info("Elasticsearch integration disabled (ELASTICSEARCH_ENABLED=false)")
                return

            url      = getattr(settings, "ELASTICSEARCH_URL", "http://elasticsearch:9200")
            api_key  = getattr(settings, "ELASTICSEARCH_API_KEY", "") or None
            username = getattr(settings, "ELASTICSEARCH_USERNAME", "") or None
            password = getattr(settings, "ELASTICSEARCH_PASSWORD", "") or None

            try:
                from elasticsearch import AsyncElasticsearch

                kwargs: Dict[str, Any] = {"hosts": [url]}
                if api_key:
                    kwargs["api_key"] = api_key
                elif username and password:
                    kwargs["basic_auth"] = (username, password)

                self._es = AsyncElasticsearch(**kwargs)
                self._ready = True
                logger.info(f"Elasticsearch SIEM client initialised → {url}")

            except ImportError:
                logger.warning(
                    "elasticsearch package not installed — SIEM indexing disabled.\n"
                    "Run: pip install elasticsearch"
                )

        except Exception as e:
            logger.error(f"SIEMClient config error: {e}")

    # ── Index bootstrap ───────────────────────────────────────────────────────

    async def ensure_indices(self):
        """
        Create index templates if they don't exist yet.
        Called once at app startup via lifespan.
        Safe to call multiple times (no-op if indices exist).
        """
        if not self._ready:
            return

        mappings = {
            INDEX_EMAILS: {
                "mappings": {
                    "properties": {
                        "email_id":      {"type": "integer"},
                        "subject":       {"type": "text"},
                        "sender_email":  {"type": "keyword"},
                        "sender_domain": {"type": "keyword"},
                        "threat_detected": {"type": "boolean"},
                        "threat_type":   {"type": "keyword"},
                        "threat_score":  {"type": "float"},
                        "severity":      {"type": "keyword"},
                        "action_taken":  {"type": "keyword"},
                        "originating_ip":      {"type": "ip"},
                        "originating_country": {"type": "keyword"},
                        "is_vpn":    {"type": "boolean"},
                        "is_tor":    {"type": "boolean"},
                        "is_proxy":  {"type": "boolean"},
                        "upload_date":   {"type": "date"},
                        "@timestamp":    {"type": "date"},
                    }
                }
            },
            INDEX_ALERTS: {
                "mappings": {
                    "properties": {
                        "alert_id":    {"type": "integer"},
                        "email_id":    {"type": "integer"},
                        "alert_type":  {"type": "keyword"},
                        "severity":    {"type": "keyword"},
                        "title":       {"type": "text"},
                        "message":     {"type": "text"},
                        "threat_score": {"type": "float"},
                        "threat_type": {"type": "keyword"},
                        "sender":      {"type": "keyword"},
                        "sms_sent":    {"type": "integer"},
                        "voice_calls": {"type": "integer"},
                        "@timestamp":  {"type": "date"},
                    }
                }
            },
            INDEX_AUDIT: {
                "mappings": {
                    "properties": {
                        "audit_id":      {"type": "integer"},
                        "user_id":       {"type": "integer"},
                        "action":        {"type": "keyword"},
                        "resource_type": {"type": "keyword"},
                        "resource_id":   {"type": "integer"},
                        "ip_address":    {"type": "ip"},
                        "details":       {"type": "object", "dynamic": True},
                        "@timestamp":    {"type": "date"},
                    }
                }
            },
        }

        for index, body in mappings.items():
            try:
                exists = await self._es.indices.exists(index=index)
                if not exists:
                    await self._es.indices.create(index=index, body=body)
                    logger.info(f"Elasticsearch index created: {index}")
            except Exception as e:
                logger.warning(f"Could not create index '{index}': {e}")

    # ── Public indexing methods ───────────────────────────────────────────────

    async def index_email(
        self,
        email_id: int,
        subject: str,
        sender_email: str,
        threat_detected: bool,
        threat_type: str,
        threat_score: float,
        severity: str,
        action_taken: str,
        upload_date: Optional[datetime] = None,
        originating_ip: Optional[str] = None,
        originating_country: Optional[str] = None,
        is_vpn: bool = False,
        is_tor: bool = False,
        is_proxy: bool = False,
        **extra,
    ):
        """Index a processed email event into threatshield-emails."""
        if not self._ready:
            return

        sender_domain = ""
        if sender_email and "@" in sender_email:
            sender_domain = sender_email.split("@")[1].lower()

        doc = {
            "@timestamp":    _now_iso(),
            "email_id":      email_id,
            "subject":       subject or "",
            "sender_email":  (sender_email or "").lower(),
            "sender_domain": sender_domain,
            "threat_detected": threat_detected,
            "threat_type":   threat_type or "safe",
            "threat_score":  round(threat_score, 2),
            "severity":      severity or "safe",
            "action_taken":  action_taken or "allow",
            "upload_date":   upload_date.isoformat() if upload_date else _now_iso(),
            "originating_ip":      originating_ip,
            "originating_country": originating_country,
            "is_vpn":   is_vpn,
            "is_tor":   is_tor,
            "is_proxy": is_proxy,
            **extra,
        }

        await self._index(INDEX_EMAILS, doc, doc_id=f"email-{email_id}")

    async def index_alert(
        self,
        alert_id: int,
        email_id: Optional[int],
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        details: Optional[str] = None,
        sms_sent: int = 0,
        voice_calls: int = 0,
    ):
        """Index an alert event into threatshield-alerts."""
        if not self._ready:
            return

        parsed_details: Dict[str, Any] = {}
        if details:
            try:
                parsed_details = json.loads(details)
            except Exception:
                pass

        doc = {
            "@timestamp":  _now_iso(),
            "alert_id":    alert_id,
            "email_id":    email_id,
            "alert_type":  alert_type,
            "severity":    severity,
            "title":       title,
            "message":     message,
            "threat_score": parsed_details.get("threat_score"),
            "threat_type":  parsed_details.get("threat_type"),
            "sender":       parsed_details.get("sender"),
            "sms_sent":    sms_sent,
            "voice_calls": voice_calls,
            **{k: v for k, v in parsed_details.items()
               if k not in ("threat_score", "threat_type", "sender")},
        }

        await self._index(INDEX_ALERTS, doc, doc_id=f"alert-{alert_id}")

    async def index_audit(
        self,
        audit_id: int,
        user_id: Optional[int],
        action: str,
        resource_type: str,
        resource_id: Optional[int],
        ip_address: Optional[str] = None,
        details: Optional[str] = None,
        created_at: Optional[datetime] = None,
    ):
        """Index an audit log entry into threatshield-audit."""
        if not self._ready:
            return

        parsed_details: Any = {}
        if details:
            try:
                parsed_details = json.loads(details)
            except Exception:
                parsed_details = details

        doc = {
            "@timestamp":    created_at.isoformat() if created_at else _now_iso(),
            "audit_id":      audit_id,
            "user_id":       user_id,
            "action":        action,
            "resource_type": resource_type,
            "resource_id":   resource_id,
            "ip_address":    ip_address or None,
            "details":       parsed_details,
        }

        await self._index(INDEX_AUDIT, doc, doc_id=f"audit-{audit_id}")

    async def bulk_index_emails(self, docs: List[Dict[str, Any]]):
        """Bulk index multiple email docs — faster than individual calls."""
        if not self._ready or not docs:
            return
        operations = []
        for doc in docs:
            doc_id = f"email-{doc.get('email_id', '')}"
            operations.append({"index": {"_index": INDEX_EMAILS, "_id": doc_id}})
            operations.append(doc)
        await self._bulk(operations)

    # ── Search helper (used by /api/siem/search) ──────────────────────────────

    async def search(
        self,
        index: str,
        query: Dict[str, Any],
        size: int = 50,
        sort: Optional[List] = None,
    ) -> Dict[str, Any]:
        """
        Run an ES query and return hits.
        index: one of 'emails', 'alerts', 'audit' (prefix added automatically)
        """
        if not self._ready:
            return {"hits": [], "total": 0, "error": "Elasticsearch not available"}

        index_map = {
            "emails": INDEX_EMAILS,
            "alerts": INDEX_ALERTS,
            "audit":  INDEX_AUDIT,
        }
        es_index = index_map.get(index, index)

        body: Dict[str, Any] = {"query": query, "size": size}
        if sort:
            body["sort"] = sort

        try:
            resp = await self._es.search(index=es_index, body=body)
            hits = resp["hits"]["hits"]
            return {
                "total": resp["hits"]["total"]["value"],
                "hits": [{"_id": h["_id"], **h["_source"]} for h in hits],
            }
        except Exception as e:
            logger.error(f"ES search error on {es_index}: {e}")
            return {"hits": [], "total": 0, "error": str(e)}

    async def health(self) -> Dict[str, Any]:
        """Return ES cluster health — used by /api/siem/health."""
        if not self._ready:
            return {
                "available": False,
                "reason": "elasticsearch package not installed or ELASTICSEARCH_ENABLED=false",
            }
        try:
            h = await self._es.cluster.health()
            info = await self._es.info()
            return {
                "available": True,
                "status": h["status"],
                "cluster_name": h["cluster_name"],
                "number_of_nodes": h["number_of_nodes"],
                "version": info["version"]["number"],
                "indices": {
                    INDEX_EMAILS: await self._index_doc_count(INDEX_EMAILS),
                    INDEX_ALERTS: await self._index_doc_count(INDEX_ALERTS),
                    INDEX_AUDIT:  await self._index_doc_count(INDEX_AUDIT),
                },
            }
        except Exception as e:
            return {"available": False, "reason": str(e)}

    # ── Private helpers ───────────────────────────────────────────────────────

    async def _index(self, index: str, doc: Dict[str, Any], doc_id: Optional[str] = None):
        """Index a single document. Errors are caught and logged, never raised."""
        try:
            kwargs: Dict[str, Any] = {"index": index, "body": doc}
            if doc_id:
                kwargs["id"] = doc_id
            await self._es.index(**kwargs)
        except Exception as e:
            logger.error(f"ES index error ({index}): {e}")

    async def _bulk(self, operations: List[Any]):
        try:
            from elasticsearch.helpers import async_bulk
            await async_bulk(self._es, operations)
        except Exception as e:
            logger.error(f"ES bulk index error: {e}")

    async def _index_doc_count(self, index: str) -> int:
        try:
            resp = await self._es.count(index=index)
            return resp["count"]
        except Exception:
            return -1

    async def close(self):
        if self._es:
            try:
                await self._es.close()
            except Exception:
                pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Singleton — imported by emails.py, alerts.py, audit hooks, and siem API
siem_client = SIEMClient()