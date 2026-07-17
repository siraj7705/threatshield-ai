"""
LOCATION: threatshield-ai/backend/app/api/users.py

ThreatShield AI - User Management API (Admin Only)
Handles listing, updating roles, and deactivating users.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.security import get_current_user, require_roles
from app.models.user import User
from app.models.audit import AuditLog
from app.schemas import UserResponse

router = APIRouter(prefix="/api/users", tags=["User Management"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class UserUpdateRole(BaseModel):
    role: str = Field(..., pattern="^(admin|analyst|investigator)$")


class UserUpdateStatus(BaseModel):
    is_active: bool


class UserListResponse(BaseModel):
    total: int
    users: List[UserResponse]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=UserListResponse)
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_roles(["admin"])),
):
    """List all users. Admin only."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    return UserListResponse(
        total=len(users),
        users=[UserResponse.model_validate(u) for u in users],
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_roles(["admin"])),
):
    """Get a specific user by ID. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)


@router.patch("/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: int,
    body: UserUpdateRole,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_roles(["admin"])),
):
    """Update a user's role. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent admin from demoting themselves
    if user.id == current_user["id"] and body.role != "admin":
        raise HTTPException(status_code=400, detail="Cannot change your own admin role")

    old_role = user.role
    user.role = body.role

    audit = AuditLog(
        user_id=current_user["id"],
        action="update_role",
        resource_type="user",
        resource_id=user_id,
        details=f"Role changed from {old_role} to {body.role}",
    )
    db.add(audit)

    return UserResponse.model_validate(user)


@router.patch("/{user_id}/status", response_model=UserResponse)
async def update_user_status(
    user_id: int,
    body: UserUpdateStatus,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_roles(["admin"])),
):
    """Activate or deactivate a user. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    user.is_active = body.is_active

    audit = AuditLog(
        user_id=current_user["id"],
        action="update_status",
        resource_type="user",
        resource_id=user_id,
        details=f"Account {'activated' if body.is_active else 'deactivated'}",
    )
    db.add(audit)

    return UserResponse.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_roles(["admin"])),
):
    """Delete a user permanently. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    audit = AuditLog(
        user_id=current_user["id"],
        action="delete_user",
        resource_type="user",
        resource_id=user_id,
        details=f"Deleted user: {user.username}",
    )
    db.add(audit)
    await db.delete(user)