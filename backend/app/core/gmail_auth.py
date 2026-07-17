"""
ThreatShield AI - Gmail OAuth2 Authentication Handler
Manages Google API credentials and token refresh.
"""
import os
import json
import logging
from pathlib import Path
from typing import Optional

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow

logger = logging.getLogger(__name__)

# Scopes required for Gmail read + label management
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",  # for labeling/moving
    "https://www.googleapis.com/auth/gmail.send",    # for admin notifications
]

CREDENTIALS_FILE = os.getenv("GMAIL_CREDENTIALS_FILE", "credentials.json")
TOKEN_FILE = os.getenv("GMAIL_TOKEN_FILE", "gmail_token.json")


def get_credentials() -> Credentials:
    """
    Load or refresh Gmail OAuth2 credentials.
    On first run, opens browser for user consent.
    On subsequent runs, loads from token file and refreshes if expired.
    """
    creds: Optional[Credentials] = None

    # Load existing token
    if Path(TOKEN_FILE).exists():
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
            logger.info("Loaded existing Gmail token.")
        except Exception as e:
            logger.warning(f"Could not load token file: {e}")

    # Refresh or re-authenticate
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logger.info("Gmail token refreshed.")
            except Exception as e:
                logger.error(f"Token refresh failed: {e}")
                creds = None

        if not creds:
            if not Path(CREDENTIALS_FILE).exists():
                raise FileNotFoundError(
                    f"Gmail credentials file not found: {CREDENTIALS_FILE}\n"
                    "Download it from Google Cloud Console → APIs & Services → Credentials."
                )
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
            logger.info("Gmail authenticated via browser consent.")

        # Save token for next run
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
        logger.info(f"Gmail token saved to {TOKEN_FILE}")

    return creds
