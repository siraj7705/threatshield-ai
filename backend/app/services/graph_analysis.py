"""
LOCATION: threatshield-ai/backend/app/services/graph_analysis.py

ThreatShield AI - Graph-Based Threat Analysis

Builds a relationship graph over emails, senders, domains, IPs, URLs,
cases, and alert clusters using networkx. Exposes methods used by the
/api/graph endpoints.

Node types:
  - email        (id, subject, threat_score, threat_type)
  - sender       (email address)
  - domain       (sender domain)
  - ip           (originating IP)
  - url          (extracted URLs)
  - case         (linked case)

Edge types:
  - SENT_BY      email → sender
  - BELONGS_TO   sender → domain
  - ORIGINATED_FROM  email → ip
  - CONTAINS_URL email → url
  - LINKED_TO    email → case

Install:  pip install networkx
"""
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False
    logger.warning(
        "networkx not installed — graph analysis disabled. "
        "Run: pip install networkx"
    )


def _require_nx():
    if not _NX_AVAILABLE:
        raise RuntimeError(
            "networkx is not installed. Run: pip install networkx"
        )


class ThreatGraphBuilder:
    """
    Builds and queries a networkx DiGraph from ThreatShield data.

    Typical call sequence (from the API layer):
        builder = ThreatGraphBuilder()
        G = await builder.build(db, email_ids=[...])   # or build_full(db)
        summary  = builder.summary(G)
        nodes    = builder.export_nodes(G)
        edges    = builder.export_edges(G)
        clusters = builder.find_clusters(G)
        paths    = builder.find_paths(G, source, target)
        central  = builder.top_central_nodes(G)
    """

    # ── Graph construction ────────────────────────────────────────────────────

    async def build(
        self,
        db,
        email_ids: Optional[List[int]] = None,
        days: int = 90,
        threat_only: bool = True,
    ):
        """
        Build a threat relationship graph.

        Args:
            db:          AsyncSession
            email_ids:   limit graph to these email IDs (None = all in window)
            days:        look-back window when email_ids is None
            threat_only: if True, only include emails where threat_detected=True

        Returns a networkx DiGraph.
        """
        _require_nx()

        from datetime import datetime, timedelta, timezone
        from sqlalchemy.future import select
        from app.models.email import Email
        from app.models.threat import ThreatAnalysis, ThreatScore
        from app.models.header import HeaderAnalysis
        from app.models.ip_reputation import IPReputation
        from app.models.url_analysis import URLAnalysis
        from app.models.case import Case

        G = nx.DiGraph()
        since = datetime.now(timezone.utc) - timedelta(days=days)

        # ── Fetch emails ──────────────────────────────────────────────────────
        eq = select(Email)
        if email_ids:
            eq = eq.where(Email.id.in_(email_ids))
        else:
            eq = eq.where(Email.upload_date >= since)
        emails = (await db.execute(eq)).scalars().all()

        if not emails:
            return G

        all_ids = [e.id for e in emails]

        # ── Fetch related data in bulk ────────────────────────────────────────
        ta_map: Dict[int, Any] = {}
        ts_map: Dict[int, Any] = {}
        ha_map: Dict[int, Any] = {}
        ip_map: Dict[int, Any] = {}
        url_map: Dict[int, List] = {}
        case_email_map: Dict[int, List[int]] = {}  # case_id → [email_id]

        ta_rows = (await db.execute(
            select(ThreatAnalysis).where(ThreatAnalysis.email_id.in_(all_ids))
        )).scalars().all()
        for row in ta_rows:
            ta_map[row.email_id] = row

        ts_rows = (await db.execute(
            select(ThreatScore).where(ThreatScore.email_id.in_(all_ids))
        )).scalars().all()
        for row in ts_rows:
            ts_map[row.email_id] = row

        ha_rows = (await db.execute(
            select(HeaderAnalysis).where(HeaderAnalysis.email_id.in_(all_ids))
        )).scalars().all()
        for row in ha_rows:
            ha_map[row.email_id] = row

        ip_rows = (await db.execute(
            select(IPReputation).where(IPReputation.email_id.in_(all_ids))
        )).scalars().all()
        for row in ip_rows:
            ip_map[row.email_id] = row

        url_rows = (await db.execute(
            select(URLAnalysis).where(URLAnalysis.email_id.in_(all_ids))
        )).scalars().all()
        for row in url_rows:
            url_map[row.email_id] = url_map.get(row.email_id, [])
            try:
                urls = json.loads(row.urls_found or "[]")
                url_map[row.email_id].extend(urls[:5])  # cap at 5 URLs per email
            except Exception:
                pass

        case_rows = (await db.execute(select(Case))).scalars().all()
        for case in case_rows:
            try:
                ids = json.loads(case.email_ids or "[]")
                for eid in ids:
                    if eid in all_ids:
                        case_email_map.setdefault(case.id, []).append(eid)
            except Exception:
                pass

        # ── Build graph ───────────────────────────────────────────────────────
        for email in emails:
            ta  = ta_map.get(email.id)
            ts  = ts_map.get(email.id)
            ha  = ha_map.get(email.id)
            ip  = ip_map.get(email.id)

            if threat_only and (not ta or not ta.threat_detected):
                continue

            threat_score = ts.overall_score if ts else 0.0
            threat_type  = ta.threat_type if ta else "unknown"
            severity     = ts.category if ts else "safe"

            # Email node
            email_node = f"email:{email.id}"
            G.add_node(
                email_node,
                node_type="email",
                label=f"Email #{email.id}",
                subject=(email.subject or "")[:80],
                threat_score=round(threat_score, 1),
                threat_type=threat_type,
                severity=severity,
                upload_date=email.upload_date.isoformat() if email.upload_date else None,
            )

            # Sender node
            if email.sender_email:
                sender_node = f"sender:{email.sender_email.lower()}"
                if not G.has_node(sender_node):
                    G.add_node(
                        sender_node,
                        node_type="sender",
                        label=email.sender_email.lower(),
                        email=email.sender_email.lower(),
                    )
                G.add_edge(email_node, sender_node, edge_type="SENT_BY")

                # Domain node
                parts = email.sender_email.split("@")
                if len(parts) == 2:
                    domain = parts[1].lower()
                    domain_node = f"domain:{domain}"
                    if not G.has_node(domain_node):
                        G.add_node(domain_node, node_type="domain", label=domain, domain=domain)
                    G.add_edge(sender_node, domain_node, edge_type="BELONGS_TO")

            # IP node
            if ha and ha.originating_ip:
                ip_node = f"ip:{ha.originating_ip}"
                if not G.has_node(ip_node):
                    is_vpn     = ip.is_vpn if ip else False
                    is_tor     = ip.is_tor if ip else False
                    is_proxy   = ip.is_proxy if ip else False
                    country    = (ha.originating_country or (ip.country if ip else None) or "Unknown")
                    G.add_node(
                        ip_node,
                        node_type="ip",
                        label=ha.originating_ip,
                        ip=ha.originating_ip,
                        country=country,
                        is_vpn=is_vpn,
                        is_tor=is_tor,
                        is_proxy=is_proxy,
                    )
                G.add_edge(email_node, ip_node, edge_type="ORIGINATED_FROM")

            # URL nodes
            for url in url_map.get(email.id, []):
                if not url:
                    continue
                url_node = f"url:{url[:200]}"
                if not G.has_node(url_node):
                    G.add_node(url_node, node_type="url", label=url[:80], url=url)
                G.add_edge(email_node, url_node, edge_type="CONTAINS_URL")

        # Case nodes
        for case_id, linked_email_ids in case_email_map.items():
            case_node = f"case:{case_id}"
            if not G.has_node(case_node):
                G.add_node(case_node, node_type="case", label=f"Case #{case_id}")
            for eid in linked_email_ids:
                email_node = f"email:{eid}"
                if G.has_node(email_node):
                    G.add_edge(email_node, case_node, edge_type="LINKED_TO")

        logger.info(
            f"Graph built: {G.number_of_nodes()} nodes, "
            f"{G.number_of_edges()} edges"
        )
        return G

    # ── Analysis methods ──────────────────────────────────────────────────────

    def summary(self, G) -> Dict[str, Any]:
        """High-level graph statistics."""
        _require_nx()
        if G.number_of_nodes() == 0:
            return {"nodes": 0, "edges": 0, "clusters": 0, "node_types": {}}

        node_types: Dict[str, int] = {}
        for _, data in G.nodes(data=True):
            t = data.get("node_type", "unknown")
            node_types[t] = node_types.get(t, 0) + 1

        undirected = G.to_undirected()
        components = list(nx.connected_components(undirected))

        return {
            "nodes": G.number_of_nodes(),
            "edges": G.number_of_edges(),
            "clusters": len(components),
            "largest_cluster_size": max(len(c) for c in components) if components else 0,
            "node_types": node_types,
            "density": round(nx.density(G), 4),
            "is_dag": nx.is_directed_acyclic_graph(G),
        }

    def export_nodes(self, G) -> List[Dict[str, Any]]:
        """Export all nodes as a list of dicts for the frontend."""
        _require_nx()
        return [
            {"id": node_id, **data}
            for node_id, data in G.nodes(data=True)
        ]

    def export_edges(self, G) -> List[Dict[str, Any]]:
        """Export all edges as a list of dicts for the frontend."""
        _require_nx()
        return [
            {"source": u, "target": v, **data}
            for u, v, data in G.edges(data=True)
        ]

    def find_clusters(self, G) -> List[Dict[str, Any]]:
        """
        Find connected components (threat clusters).
        Returns clusters sorted by size descending.
        Each cluster includes its member node IDs and a brief summary.
        """
        _require_nx()
        undirected = G.to_undirected()
        clusters = []
        for i, component in enumerate(
            sorted(nx.connected_components(undirected), key=len, reverse=True)
        ):
            subgraph   = G.subgraph(component)
            node_types: Dict[str, int] = {}
            severities: List[str] = []

            for _, data in subgraph.nodes(data=True):
                t = data.get("node_type", "unknown")
                node_types[t] = node_types.get(t, 0) + 1
                if data.get("node_type") == "email":
                    severities.append(data.get("severity", "safe"))

            dominant_severity = _dominant_severity(severities)

            clusters.append({
                "cluster_id": i + 1,
                "size": len(component),
                "nodes": list(component),
                "node_types": node_types,
                "dominant_severity": dominant_severity,
                "email_count": node_types.get("email", 0),
                "domain_count": node_types.get("domain", 0),
                "ip_count": node_types.get("ip", 0),
            })

        return clusters

    def top_central_nodes(
        self, G, top_n: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find the most central nodes using degree centrality.
        High centrality = connected to many other nodes = likely pivot point
        (shared sender, shared IP, shared domain across many threat emails).
        """
        _require_nx()
        if G.number_of_nodes() == 0:
            return []

        centrality = nx.degree_centrality(G)
        sorted_nodes = sorted(centrality.items(), key=lambda x: -x[1])[:top_n]

        result = []
        for node_id, score in sorted_nodes:
            data = G.nodes[node_id]
            result.append({
                "id": node_id,
                "centrality_score": round(score, 4),
                "node_type": data.get("node_type", "unknown"),
                "label": data.get("label", node_id),
                "degree": G.degree(node_id),
                **{k: v for k, v in data.items() if k not in ("node_type", "label")},
            })

        return result

    def find_paths(
        self, G, source: str, target: str, max_paths: int = 3
    ) -> List[List[str]]:
        """
        Find shortest paths between two nodes.
        Useful for tracing how two threats are connected (shared sender, IP, etc.)
        """
        _require_nx()
        try:
            paths = list(nx.all_simple_paths(G.to_undirected(), source, target, cutoff=6))
            paths.sort(key=len)
            return paths[:max_paths]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def sender_co_occurrence(self, G) -> List[Dict[str, Any]]:
        """
        Find sender addresses that appear together across multiple threat emails.
        Returns pairs of senders with the count of emails they share (via domain or IP).
        """
        _require_nx()
        # Find all domain nodes and their connected senders
        co: Dict[tuple, int] = {}
        for node, data in G.nodes(data=True):
            if data.get("node_type") != "domain":
                continue
            senders = [
                n for n in G.predecessors(node)
                if G.nodes[n].get("node_type") == "sender"
            ]
            for i, s1 in enumerate(senders):
                for s2 in senders[i + 1:]:
                    pair = tuple(sorted([s1, s2]))
                    co[pair] = co.get(pair, 0) + 1

        return [
            {"sender_a": a, "sender_b": b, "shared_domains": count}
            for (a, b), count in sorted(co.items(), key=lambda x: -x[1])
        ][:20]


# ── Helpers ───────────────────────────────────────────────────────────────────

_SEVERITY_RANK = {"critical": 4, "high": 3, "warning": 2, "low": 1, "safe": 0}


def _dominant_severity(severities: List[str]) -> str:
    if not severities:
        return "safe"
    return max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0))


# Singleton
graph_builder = ThreatGraphBuilder()