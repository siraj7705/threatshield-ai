# LOCATION: threatshield-ai/backend/app/core/gmail_oauth.py

"""
ThreatShield AI - Per-User Gmail OAuth (Web Application flow)
"""
import logging
from datetime import datetime, timezone
from typing import Optional

import requests as http_requests
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build

from app.core.config import settings

logger = logging.getLogger(__name__)

GMAIL_OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]


def is_configured() -> bool:
    return bool(settings.GMAIL_OAUTH_CLIENT_ID and settings.GMAIL_OAUTH_CLIENT_SECRET)


def build_authorization_url(state: str) -> str:
    if not is_configured():
        raise RuntimeError(
            "Gmail OAuth is not configured. Set GMAIL_OAUTH_CLIENT_ID and "
            "GMAIL_OAUTH_CLIENT_SECRET in .env."
        )

    import urllib.parse
    params = {
        "client_id": settings.GMAIL_OAUTH_CLIENT_ID,
        "redirect_uri": settings.GMAIL_OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(GMAIL_OAUTH_SCOPES),
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
        "state": state,
    }
    return "https://accounts.google.com/o/oauth2/auth?" + urllib.parse.urlencode(params)


def exchange_code_for_credentials(authorization_code: str) -> Credentials:
    resp = http_requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": authorization_code,
            "client_id": settings.GMAIL_OAUTH_CLIENT_ID,
            "client_secret": settings.GMAIL_OAUTH_CLIENT_SECRET,
            "redirect_uri": settings.GMAIL_OAUTH_REDIRECT_URI,
            "grant_type": "authorization_code",
        },
    )
    resp.raise_for_status()
    token_data = resp.json()

    if "error" in token_data:
        raise RuntimeError(f"{token_data['error']}: {token_data.get('error_description', '')}")

    expiry = None
    if "expires_in" in token_data:
        from datetime import timedelta
        expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=token_data["expires_in"])

    creds = Credentials(
        token=token_data.get("access_token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GMAIL_OAUTH_CLIENT_ID,
        client_secret=settings.GMAIL_OAUTH_CLIENT_SECRET,
        scopes=GMAIL_OAUTH_SCOPES,
    )
    creds.expiry = expiry
    return creds


def get_gmail_address(creds: Credentials) -> str:
    service = build("gmail", "v1", credentials=creds)
    profile = service.users().getProfile(userId="me").execute()
    return profile.get("emailAddress", "")


def credentials_from_stored_tokens(
    access_token: Optional[str],
    refresh_token: str,
    expiry: Optional[datetime],
) -> Credentials:
    creds = Credentials(
        token=access_token,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GMAIL_OAUTH_CLIENT_ID,
        client_secret=settings.GMAIL_OAUTH_CLIENT_SECRET,
        scopes=GMAIL_OAUTH_SCOPES,
    )
    if expiry:
        creds.expiry = expiry.astimezone(timezone.utc).replace(tzinfo=None)
    return creds


def refresh_if_needed(creds: Credentials) -> Credentials:
    if not creds.valid and creds.refresh_token:
        creds.refresh(GoogleAuthRequest())
    return creds


def build_gmail_service(creds: Credentials):
    return build("gmail", "v1", credentials=creds)