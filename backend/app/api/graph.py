"""
LOCATION: threatshield-ai/backend/app/api/graph.py

ThreatShield AI - Graph-Based Threat Analysis API

Endpoints:
  GET  /api/graph/build           build graph, return summary + nodes + edges
  GET  /api/graph/clusters        connected threat clusters
  GET  /api/graph/central-nodes   most connected/central nodes
  GET  /api/graph/paths           shortest path between two nodes
  GET  /api/graph/co-occurrence   senders sharing domains/IPs

All endpoints require authentication. Admin role gets full org-wide graph;
analysts/investigators get a graph scoped to their own emails.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, is_admin
from app.services.graph_analysis import graph_builder

router = APIRouter(prefix="/api/graph", tags=["Graph Analysis"])


async def _build_scoped_graph(
    current_user: dict,
    db: AsyncSession,
    days: int = 90,
    threat_only: bool = True,
    email_ids: Optional[List[int]] = None,
):
    """Build graph scoped to the current user's accessible emails."""
    from sqlalchemy.future import select
    from app.models.email import Email
    from app.models.threat import ThreatAnalysis

    if not is_admin(current_user):
        user_id = current_user["id"]
        owned_q = select(Email.id).where(
            (Email.source_type == "gmail_watch") | (Email.uploaded_by == user_id)
        )
        if email_ids:
            owned_q = owned_q.where(Email.id.in_(email_ids))
        result = await db.execute(owned_q)
        email_ids = [row[0] for row in result.all()]
        if not email_ids:
            return None

    return await graph_builder.build(
        db=db,
        email_ids=email_ids,
        days=days,
        threat_only=threat_only,
    )


# ── GET /api/graph/build ──────────────────────────────────────────────────────

@router.get("/build")
async def build_graph(
    days: int = Query(90, ge=1, le=365, description="Look-back window in days"),
    threat_only: bool = Query(True, description="Only include emails where threat_detected=True"),
    email_ids: Optional[str] = Query(None, description="Comma-separated email IDs to limit graph"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Build the threat relationship graph and return:
      - summary    : node/edge counts, cluster count, density
      - nodes      : list of all graph nodes with attributes
      - edges      : list of all edges with type labels
      - central    : top 10 most central nodes

    Pass this directly to a frontend graph renderer (e.g. react-force-graph,
    vis-network, or cytoscape.js).
    """
    ids = None
    if email_ids:
        try:
            ids = [int(x.strip()) for x in email_ids.split(",") if x.strip()]
        except ValueError:
            raise HTTPException(status_code=400, detail="email_ids must be comma-separated integers")

    G = await _build_scoped_graph(current_user, db, days=days, threat_only=threat_only, email_ids=ids)
    if G is None or G.number_of_nodes() == 0:
        return {"summary": {"nodes": 0, "edges": 0, "clusters": 0}, "nodes": [], "edges": [], "central": []}

    return {
        "summary":  graph_builder.summary(G),
        "nodes":    graph_builder.export_nodes(G),
        "edges":    graph_builder.export_edges(G),
        "central":  graph_builder.top_central_nodes(G, top_n=10),
    }


# ── GET /api/graph/clusters ───────────────────────────────────────────────────

@router.get("/clusters")
async def get_clusters(
    days: int = Query(90, ge=1, le=365),
    threat_only: bool = Query(True),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """
    Return connected threat clusters — groups of emails/senders/IPs/domains
    that are linked to each other.

    Large clusters often indicate coordinated campaigns (same sender
    infrastructure used across multiple threat emails).
    """
    G = await _build_scoped_graph(current_user, db, days=days, threat_only=threat_only)
    if G is None or G.number_of_nodes() == 0:
        return []
    return graph_builder.find_clusters(G)


# ── GET /api/graph/central-nodes ─────────────────────────────────────────────

@router.get("/central-nodes")
async def get_central_nodes(
    days: int = Query(90, ge=1, le=365),
    top_n: int = Query(10, ge=1, le=50),
    threat_only: bool = Query(True),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """
    Return the most central nodes in the threat graph.

    High centrality = connected to many other nodes. These are the most
    important pivot points — shared senders, IPs, or domains that link
    multiple threat emails together.
    """
    G = await _build_scoped_graph(current_user, db, days=days, threat_only=threat_only)
    if G is None or G.number_of_nodes() == 0:
        return []
    return graph_builder.top_central_nodes(G, top_n=top_n)


# ── GET /api/graph/paths ──────────────────────────────────────────────────────

@router.get("/paths")
async def find_paths(
    source: str = Query(..., description="Source node ID e.g. email:42"),
    target: str = Query(..., description="Target node ID e.g. domain:evil.com"),
    days: int = Query(90, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Find shortest paths between two nodes in the threat graph.

    Use this to answer questions like:
      - "How is email #42 connected to email #87?"
      - "Does sender A share any infrastructure with sender B?"

    Returns up to 3 shortest paths, each as an ordered list of node IDs.
    """
    G = await _build_scoped_graph(current_user, db, days=days)
    if G is None or G.number_of_nodes() == 0:
        return {"paths": [], "source": source, "target": target}

    if not G.has_node(source):
        raise HTTPException(status_code=404, detail=f"Node '{source}' not found in graph")
    if not G.has_node(target):
        raise HTTPException(status_code=404, detail=f"Node '{target}' not found in graph")

    paths = graph_builder.find_paths(G, source, target)
    return {
        "source": source,
        "target": target,
        "path_count": len(paths),
        "paths": paths,
    }


# ── GET /api/graph/co-occurrence ──────────────────────────────────────────────

@router.get("/co-occurrence")
async def get_co_occurrence(
    days: int = Query(90, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """
    Find sender pairs that share domains or IPs.

    High co-occurrence between two senders suggests they use the same
    sending infrastructure — a strong indicator of coordinated campaigns
    or the same threat actor operating multiple aliases.
    """
    G = await _build_scoped_graph(current_user, db, days=days)
    if G is None or G.number_of_nodes() == 0:
        return []
    return graph_builder.sender_co_occurrence(G)