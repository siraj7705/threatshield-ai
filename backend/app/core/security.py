"""
LOCATION: threatshield-ai/backend/app/core/security.py

ThreatShield AI - Security Utilities (JWT, Hashing, RBAC)
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from functools import wraps
import secrets

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ── Role Constants ─────────────────────────────────────────────────────────────
ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_INVESTIGATOR = "investigator"

ALL_ROLES = [ROLE_ADMIN, ROLE_ANALYST, ROLE_INVESTIGATOR]
ADMIN_ONLY = [ROLE_ADMIN]
ADMIN_AND_ANALYST = [ROLE_ADMIN, ROLE_ANALYST]
ADMIN_AND_INVESTIGATOR = [ROLE_ADMIN, ROLE_INVESTIGATOR]

# ── Role Permissions ───────────────────────────────────────────────────────────
# Admin        → full access: manage users, delete emails, change settings
# Analyst      → analyze emails, manage alerts, create cases, generate reports
# Investigator → read-only + case notes, cannot upload/delete emails


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_oauth_state_token(user_id: int) -> str:
    """
    Create a short-lived, signed 'state' token to carry the initiating
    user's identity through a third-party OAuth redirect (Google's consent
    screen) and back to our callback.

    This exists because a top-level browser redirect can't carry an
    Authorization header, so we can't just use the normal access token to
    know "who clicked Connect Gmail" when Google redirects back to us.
    Google echoes the `state` query param back unmodified, and because this
    token is signed with our JWT secret, a forged/tampered state value will
    fail to decode — this also doubles as CSRF protection for the OAuth flow.

    A random `nonce` is included so two state tokens for the same user are
    never identical, and a short 10-minute expiry limits the window in which
    a leaked/intercepted state value could be replayed.
    """
    to_encode = {
        "sub": str(user_id),
        "nonce": secrets.token_urlsafe(16),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        "type": "gmail_oauth_state",
    }
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def verify_oauth_state_token(state: str) -> int:
    """
    Decode and validate a Gmail OAuth state token, returning the user_id
    that initiated the connection. Raises HTTPException if the state is
    missing, expired, tampered with, or of the wrong type.
    """
    payload = decode_token(state)
    if payload.get("type") != "gmail_oauth_state":
        raise HTTPException(status_code=400, detail="Invalid OAuth state token")
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=400, detail="Invalid OAuth state token")
    return int(user_id)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    return {
        "id": int(user_id),
        "username": payload.get("username"),
        "role": payload.get("role", "analyst"),
    }


def require_roles(allowed_roles: List[str]):
    """Dependency factory for role-based access control."""
    async def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {', '.join(allowed_roles)}",
            )
        return current_user
    return role_checker


# ── Multi-User Data Ownership Helpers ──────────────────────────────────────────
#
# ThreatShield AI is multi-user (separate logins, JWTs, RBAC roles), but data
# rows (emails, cases, alerts, ...) must also be scoped to whoever owns them —
# otherwise any logged-in analyst/investigator could read or act on every other
# user's emails and cases. These helpers centralize that ownership logic so
# every router applies it the same way:
#
#   - Admins always see/manage everything (org-wide visibility is intentional
#     for a SOC admin role).
#   - Analysts/Investigators only see their own data (uploaded_by / created_by),
#     plus anything that genuinely has no single owner — e.g. emails captured
#     by the shared Gmail-watch mailbox (source_type == "gmail_watch"), which
#     belong to the team as a whole rather than to one uploader.

def is_admin(current_user: dict) -> bool:
    """True if the current user has the admin role (org-wide visibility)."""
    return current_user.get("role") == ROLE_ADMIN


def can_access_owned_resource(current_user: dict, owner_id: Optional[int]) -> bool:
    """
    True if current_user is allowed to view/act on a resource owned by owner_id.
    Admins can access anything. Everyone else only their own (owner_id == their id).
    A None/missing owner_id (e.g. legacy or shared-mailbox rows) is treated as
    accessible to all authenticated users, matching the "no single owner" case.
    """
    if is_admin(current_user):
        return True
    if owner_id is None:
        return True
    return int(owner_id) == int(current_user["id"])