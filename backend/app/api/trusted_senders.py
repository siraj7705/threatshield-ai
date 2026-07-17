"""
ThreatShield AI - Trusted Senders API
Per-user whitelist management.

Endpoints:
  GET    /api/trusted-senders          — list current user's trusted senders
  POST   /api/trusted-senders          — add a trusted sender
  DELETE /api/trusted-senders/{id}     — remove a trusted sender
  GET    /api/trusted-senders/check    — check if a given email is trusted
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.trusted_sender import TrustedSender

router = APIRouter(prefix="/api/trusted-senders", tags=["Trusted Senders"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class TrustedSenderCreate(BaseModel):
    email: str          # full email (user@domain.com) or domain (@domain.com)
    name: Optional[str] = None


class TrustedSenderResponse(BaseModel):
    id: int
    user_id: int
    email: str
    name: Optional[str]
    added_at: Optional[datetime]

    class Config:
        from_attributes = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_trusted(sender_email: str, trusted_list: list[TrustedSender]) -> bool:
    """
    Check if a sender email matches any entry in the trusted list.
    Supports:
      - Exact email match:  user@domain.com
      - Domain wildcard:    @domain.com  (matches any email at that domain)
    """
    sender_email = sender_email.lower().strip()
    sender_domain = "@" + sender_email.split("@")[-1] if "@" in sender_email else ""

    for entry in trusted_list:
        entry_val = entry.email.lower().strip()
        if entry_val == sender_email:
            return True
        if entry_val.startswith("@") and entry_val == sender_domain:
            return True
    return False


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("", response_model=list[TrustedSenderResponse])
async def list_trusted_senders(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all trusted senders for the current user."""
    result = await db.execute(
        select(TrustedSender)
        .where(TrustedSender.user_id == current_user["id"])
        .order_by(TrustedSender.added_at.desc())
    )
    return result.scalars().all()


@router.post("", response_model=TrustedSenderResponse, status_code=201)
async def add_trusted_sender(
    data: TrustedSenderCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add an email or domain to the current user's trusted list."""
    email = data.email.lower().strip()

    # Validate format
    if not email:
        raise HTTPException(status_code=400, detail="Email cannot be empty")
    if not ("@" in email):
        raise HTTPException(status_code=400, detail="Must be an email (user@domain.com) or domain (@domain.com)")

    # Check duplicate
    existing = await db.execute(
        select(TrustedSender).where(
            TrustedSender.user_id == current_user["id"],
            TrustedSender.email == email,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Already in your trusted list")

    entry = TrustedSender(
        user_id=current_user["id"],
        email=email,
        name=data.name,
    )
    db.add(entry)
    await db.flush()
    return entry


@router.delete("/{entry_id}", status_code=204)
async def remove_trusted_sender(
    entry_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a trusted sender entry."""
    result = await db.execute(
        select(TrustedSender).where(
            TrustedSender.id == entry_id,
            TrustedSender.user_id == current_user["id"],
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    await db.delete(entry)


@router.get("/check")
async def check_trusted(
    email: str = Query(...),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Check whether a given email is in the current user's trusted list."""
    result = await db.execute(
        select(TrustedSender).where(TrustedSender.user_id == current_user["id"])
    )
    trusted_list = result.scalars().all()
    trusted = _is_trusted(email, trusted_list)
    return {"email": email, "trusted": trusted}
