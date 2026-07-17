"""
ThreatShield AI - Per-User Gmail Watch (live push monitoring)

Manages the Gmail Pub/Sub "watch" subscription for an individual user's
connected account. Like per_user_gmail_scanner.py, every function here is
stateless and takes an already-built `service` client as an argument
rather than caching one in a singleton (see that module's docstring for
why — the legacy GmailWatcherService singleton cannot safely be reused
across multiple users' accounts).

Multi-user Pub/Sub design:
  All connected accounts share ONE Pub/Sub topic (GMAIL_PUBSUB_TOPIC) — this
  is how Gmail's API is meant to be used; you do not need a separate topic
  per user. When any watched mailbox changes, Google POSTs a notification
  to our single /api/gmail/webhook containing an `emailAddress` field. The
  webhook looks up which GmailAccount that address belongs to and processes
  the change using THAT account's stored watch_history_id as the starting
  point — never the historyId from the notification itself (that's the
  *current* state, not the cursor; using it as startHistoryId would skip
  everything between the last processed point and now).

Renewal:
  Gmail watches expire after 7 days and must be renewed before then (Google
  recommends renewing daily). renew_expiring_watches() in this module loops
  over all active GmailAccounts and renews any that are close to expiry.
  This needs to be invoked periodically — e.g. by a cron job, a systemd
  timer, or an APScheduler job wired up in main.py's startup — see the
  module-level note at the bottom for a suggested wiring snippet.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from googleapiclient.errors import HttpError

from app.core.config import settings

logger = logging.getLogger(__name__)

# Gmail watches are valid for 7 days; renew with some safety margin so a
# missed cron run doesn't let the watch lapse entirely.
WATCH_RENEWAL_MARGIN = timedelta(days=1)


def start_watch(service) -> dict:
    """
    Register Gmail push notifications for this account to our shared
    Pub/Sub topic. Returns the raw watch() response:
      {"historyId": "...", "expiration": "<epoch millis>"}
    """
    topic = settings.GMAIL_PUBSUB_TOPIC
    if not topic:
        raise ValueError(
            "GMAIL_PUBSUB_TOPIC is not set in .env — live monitoring requires "
            "a Google Cloud Pub/Sub topic. See app/services/per_user_gmail_watcher.py "
            "module docstring for the multi-user design."
        )
    try:
        response = service.users().watch(
            userId="me",
            body={
                "topicName": topic,
                "labelIds": ["INBOX"],
                "labelFilterAction": "include",
            },
        ).execute()
        logger.info(f"Gmail watch started: historyId={response.get('historyId')}")
        return response
    except HttpError as e:
        logger.error(f"Failed to start Gmail watch: {e}")
        raise


def stop_watch(service):
    """Stop push notifications for this account."""
    try:
        service.users().stop(userId="me").execute()
        logger.info("Gmail watch stopped.")
    except HttpError as e:
        logger.error(f"Failed to stop Gmail watch: {e}")
        raise


def get_history(service, start_history_id: str) -> list:
    """
    Fetch new inbox message IDs added since start_history_id.

    IMPORTANT: start_history_id must be the PREVIOUSLY stored historyId for
    this account (from the last watch() call or the last successfully
    processed notification) — never the historyId from the notification
    that triggered this call. That field reflects the mailbox state at
    notification time, not a cursor; using it directly would skip any
    changes between the last sync and now.

    Raises a ValueError with a special marker if Gmail reports the
    startHistoryId is too old (>7 days) — callers should catch this and
    fall back to a fresh watch() + messages.list() resync.
    """
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
                    if "INBOX" in label_ids:
                        new_message_ids.append(msg_id)

            page_token = response.get("nextPageToken")
            if not page_token:
                break

    except HttpError as e:
        if "Invalid startHistoryId" in str(e) or getattr(e, "status_code", None) == 404:
            # The stored historyId is stale (>7 days, or watch was reset).
            # Caller should resync: list current inbox messages directly,
            # then start a fresh watch() to get a new baseline historyId.
            raise ValueError("STALE_HISTORY_ID") from e
        logger.error(f"History fetch error: {e}")

    return list(set(new_message_ids))


def needs_renewal(watch_expiry: Optional[datetime]) -> bool:
    """True if a watch's expiry is within the renewal margin (or already passed/unset)."""
    if not watch_expiry:
        return True
    now = datetime.now(timezone.utc)
    expiry = watch_expiry if watch_expiry.tzinfo else watch_expiry.replace(tzinfo=timezone.utc)
    return expiry - now <= WATCH_RENEWAL_MARGIN


def expiration_ms_to_datetime(expiration_ms: str) -> datetime:
    """Convert the watch() response's epoch-millis expiration field to a datetime."""
    return datetime.fromtimestamp(int(expiration_ms) / 1000, tz=timezone.utc)