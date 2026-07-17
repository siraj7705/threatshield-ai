"""
ThreatShield AI - Gmail Pub/Sub Watcher
Sets up Gmail push notifications via Google Cloud Pub/Sub.
When a new email arrives, Gmail pushes a notification to our webhook.
"""
import logging
import os
from typing import Optional

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from app.core.gmail_auth import get_credentials
from app.core.config import settings

logger = logging.getLogger(__name__)


class GmailWatcherService:
    """
    Manages Gmail watch subscription via Pub/Sub.
    Must be renewed every 7 days (Gmail requirement).
    """

    def __init__(self):
        self._service = None

    def _get_service(self):
        if not self._service:
            creds = get_credentials()
            self._service = build("gmail", "v1", credentials=creds)
        return self._service

    def start_watch(self) -> dict:
        """
        Register Gmail push notifications to our Pub/Sub topic.
        Gmail will POST to our webhook whenever a new email arrives.
        """
        topic = settings.GMAIL_PUBSUB_TOPIC
        if not topic:
            raise ValueError("GMAIL_PUBSUB_TOPIC not set in .env")

        service = self._get_service()
        try:
            response = service.users().watch(
                userId="me",
                body={
                    "topicName": topic,
                    "labelIds": ["INBOX"],
                    "labelFilterAction": "include",
                }
            ).execute()

            expiry_ms = int(response.get("expiration", 0))
            expiry_sec = expiry_ms // 1000
            logger.info(
                f"Gmail watch started. "
                f"historyId={response.get('historyId')} "
                f"expires in ~7 days."
            )
            return response
        except HttpError as e:
            logger.error(f"Failed to start Gmail watch: {e}")
            raise

    def stop_watch(self):
        """Stop Gmail push notifications."""
        service = self._get_service()
        try:
            service.users().stop(userId="me").execute()
            logger.info("Gmail watch stopped.")
        except HttpError as e:
            logger.error(f"Failed to stop Gmail watch: {e}")

    def get_history(self, start_history_id: str) -> list:
        """
        Fetch Gmail history since a given historyId.
        Returns list of new message IDs added to inbox.
        """
        service = self._get_service()
        new_message_ids = []
        page_token = None

        try:
            while True:
                kwargs = {
                    "userId": "me",
                    "startHistoryId": start_history_id,
                    "historyTypes": ["messageAdded"],
                    "labelId": "INBOX",
                }
                if page_token:
                    kwargs["pageToken"] = page_token

                response = service.users().history().list(**kwargs).execute()

                for history in response.get("history", []):
                    for msg_added in history.get("messagesAdded", []):
                        msg_id = msg_added["message"]["id"]
                        label_ids = msg_added["message"].get("labelIds", [])
                        # Only process inbox emails
                        if "INBOX" in label_ids:
                            new_message_ids.append(msg_id)

                page_token = response.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            if "Invalid startHistoryId" in str(e):
                logger.warning("Invalid historyId — skipping history fetch.")
            else:
                logger.error(f"History fetch error: {e}")

        return list(set(new_message_ids))  # deduplicate


# Singleton
gmail_watcher = GmailWatcherService()
