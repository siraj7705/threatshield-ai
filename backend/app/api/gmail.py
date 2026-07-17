"""
ThreatShield AI - Gmail Integration API Routes

LEGACY (single shared mailbox, admin-configured):
  POST /api/gmail/webhook        — receives Pub/Sub push notifications from Gmail
  POST /api/gmail/watch/start    — start Gmail push watch
  POST /api/gmail/watch/stop     — stop Gmail push watch
  POST /api/gmail/scan/{id}      — manually scan a Gmail message
  GET  /api/gmail/status         — integration status
  POST /api/gmail/scan/batch     — scan recent unscanned emails

PER-USER OAUTH (each user connects their own Gmail account):
  GET    /api/gmail/oauth/connect   — get the Google consent screen URL
  GET    /api/gmail/oauth/callback  — Google redirects here after consent
  GET    /api/gmail/oauth/status    — current user's connection status
  DELETE /api/gmail/oauth/disconnect — unlink the current user's Gmail account
"""
import base64
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.security import (
    get_current_user, require_roles, ADMIN_ONLY, ADMIN_AND_ANALYST,
    create_oauth_state_token, verify_oauth_state_token,
)
from app.core.config import settings
from app.core import gmail_oauth
from app.core.crypto import encrypt_token, decrypt_token
from app.services.gmail_watcher import gmail_watcher
from app.services.gmail_scanner import gmail_scanner
from app.services import per_user_gmail_scanner
from app.services import per_user_gmail_watcher
from app.models.email import Email
from app.models.threat import ThreatAnalysis, ThreatScore
from app.models.alert import Alert
from app.models.trusted_sender import TrustedSender
from app.models.gmail_account import GmailAccount
from app.schemas import GmailAccountResponse, GmailConnectResponse
from app.api.trusted_senders import _is_trusted

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/gmail", tags=["Gmail Integration"])

# Track last known historyId (in production, store this in DB)
_last_history_id: Optional[str] = None


# ─────────────────────────────────────────────────────────
# PER-USER OAUTH — Connect / Callback / Status / Disconnect
# ─────────────────────────────────────────────────────────

@router.get("/oauth/connect", response_model=GmailConnectResponse)
async def gmail_oauth_connect(
    current_user: dict = Depends(get_current_user),
):
    """
    Step 1 of the per-user Gmail connection flow.

    Returns the Google consent screen URL for the frontend to redirect the
    browser to. The `state` parameter embeds a short-lived, signed token
    identifying which ThreatShield user initiated this — Google will echo
    it back unmodified to /oauth/callback, since a top-level browser
    redirect can't carry our normal Authorization header.
    """
    if not gmail_oauth.is_configured():
        raise HTTPException(
            status_code=503,
            detail=(
                "Gmail OAuth is not configured on this server. "
                "An administrator needs to set GMAIL_OAUTH_CLIENT_ID and "
                "GMAIL_OAUTH_CLIENT_SECRET in the backend .env file."
            ),
        )

    state = create_oauth_state_token(current_user["id"])
    auth_url = gmail_oauth.build_authorization_url(state)
    return GmailConnectResponse(authorization_url=auth_url)


@router.get("/oauth/callback")
async def gmail_oauth_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Step 2 — Google redirects the user's browser here after they Allow/Deny
    on the consent screen. This endpoint has NO auth dependency, because the
    browser arriving here is just following a redirect — it does not carry
    our JWT. Instead, we recover "who initiated this" from the signed
    `state` param (see create_oauth_state_token).

    On success, redirects the browser back to the frontend with a status
    flag so the UI can show "Gmail connected" without needing this endpoint
    to render HTML itself.
    """
    error = request.query_params.get("error")
    frontend_settings_url = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/settings"

    if error:
        # User clicked "Deny", or some other OAuth error occurred.
        logger.info(f"Gmail OAuth consent declined or errored: {error}")
        return RedirectResponse(url=f"{frontend_settings_url}?gmail_connected=0&reason={error}")

    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing 'code' or 'state' in OAuth callback")

    # Validates signature + expiry; raises HTTPException if tampered/expired.
    user_id = verify_oauth_state_token(state)

    try:
        creds = gmail_oauth.exchange_code_for_credentials(code)
        gmail_address = gmail_oauth.get_gmail_address(creds)
    except Exception as e:
        logger.error(f"Gmail OAuth token exchange failed for user {user_id}: {e}")
        return RedirectResponse(url=f"{frontend_settings_url}?gmail_connected=0&reason=token_exchange_failed")

    if not creds.refresh_token:
        # Google only sends a refresh_token on the FIRST consent for a given
        # client+account, or when prompt=consent forces re-issue (which we
        # already pass in build_authorization_url). If it's still missing,
        # something is misconfigured rather than a normal user error.
        logger.error(f"No refresh_token returned for user {user_id} / {gmail_address}")
        return RedirectResponse(url=f"{frontend_settings_url}?gmail_connected=0&reason=no_refresh_token")

    # Upsert: a user may reconnect the same address, or connect a different
    # one after disconnecting their previous account.
    existing = await db.execute(
        select(GmailAccount).where(
            GmailAccount.user_id == user_id,
            GmailAccount.gmail_address == gmail_address,
        )
    )
    account = existing.scalar_one_or_none()

    expiry = None
    if creds.expiry:
        expiry = creds.expiry.replace(tzinfo=timezone.utc)

    if account:
        account.encrypted_access_token = encrypt_token(creds.token) if creds.token else None
        account.encrypted_refresh_token = encrypt_token(creds.refresh_token)
        account.token_expiry = expiry
        account.granted_scopes = json.dumps(list(creds.scopes or []))
        account.is_active = True
        account.last_error = None
    else:
        account = GmailAccount(
            user_id=user_id,
            gmail_address=gmail_address,
            encrypted_access_token=encrypt_token(creds.token) if creds.token else None,
            encrypted_refresh_token=encrypt_token(creds.refresh_token),
            token_expiry=expiry,
            granted_scopes=json.dumps(list(creds.scopes or [])),
            is_active=True,
        )
        db.add(account)

    await db.flush()
    logger.info(f"Gmail account connected: user_id={user_id} gmail_address={gmail_address}")

    # Auto-start live monitoring right after connecting — the user
    # shouldn't have to click Connect AND a separate Start button.
    # If this fails (most commonly: GMAIL_PUBSUB_TOPIC isn't configured
    # yet), the connection itself still succeeds; we just tell the
    # frontend monitoring didn't start so it can show a clear message
    # instead of silently leaving it off.
    watch_started = False
    watch_error = None
    try:
        service = gmail_oauth.build_gmail_service(creds)
        watch_response = per_user_gmail_watcher.start_watch(service)
        account.watch_history_id = str(watch_response.get("historyId", ""))
        expiration_ms = watch_response.get("expiration")
        if expiration_ms:
            account.watch_expiry = per_user_gmail_watcher.expiration_ms_to_datetime(expiration_ms)
        account.is_watching = True
        account.last_error = None
        await db.flush()
        watch_started = True
        logger.info(f"Live monitoring auto-started for {gmail_address}")
    except Exception as e:
        watch_error = str(e)
        account.last_error = f"Connected, but live monitoring could not start automatically: {e}"
        await db.flush()
        logger.warning(f"Auto-start watch failed for {gmail_address}: {e}")

    redirect_url = f"{frontend_settings_url}?gmail_connected=1&address={gmail_address}&watching={'1' if watch_started else '0'}"
    return RedirectResponse(url=redirect_url)


@router.get("/oauth/status", response_model=Optional[GmailAccountResponse])
async def gmail_oauth_status(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the current user's own Gmail connection status (or null if never connected)."""
    result = await db.execute(
        select(GmailAccount).where(
            GmailAccount.user_id == current_user["id"],
            GmailAccount.is_active == True,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        return None
    return GmailAccountResponse.model_validate(account)


@router.delete("/oauth/disconnect", status_code=204)
async def gmail_oauth_disconnect(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Disconnect the current user's Gmail account. Stops any active watch,
    marks the connection inactive, and discards the stored tokens — the
    user would need to go through the consent screen again to reconnect.
    Past scanned emails from this account are kept (for case history).
    """
    result = await db.execute(
        select(GmailAccount).where(
            GmailAccount.user_id == current_user["id"],
            GmailAccount.is_active == True,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="No connected Gmail account")

    if account.is_watching:
        try:
            creds = gmail_oauth.credentials_from_stored_tokens(
                access_token=decrypt_token(account.encrypted_access_token) if account.encrypted_access_token else None,
                refresh_token=decrypt_token(account.encrypted_refresh_token),
                expiry=account.token_expiry,
            )
            creds = gmail_oauth.refresh_if_needed(creds)
            service = gmail_oauth.build_gmail_service(creds)
            service.users().stop(userId="me").execute()
        except Exception as e:
            # Don't block disconnect on a failed watch-stop call — the
            # account is being unlinked either way.
            logger.warning(f"Failed to stop Gmail watch on disconnect for user {current_user['id']}: {e}")

    account.is_active = False
    account.is_watching = False
    account.encrypted_access_token = None
    account.encrypted_refresh_token = ""
    return None


async def _get_active_account_and_service(current_user: dict, db: AsyncSession):
    """
    Shared helper: load the current user's active GmailAccount, rebuild
    Google credentials from the encrypted, stored tokens, refresh the
    access token if it's expired, and persist any refreshed token back to
    the DB. Returns (account, service). Raises HTTPException(404) if the
    user has no connected account, or HTTPException(401) if the stored
    refresh token is no longer valid (user must reconnect).
    """
    result = await db.execute(
        select(GmailAccount).where(
            GmailAccount.user_id == current_user["id"],
            GmailAccount.is_active == True,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(
            status_code=404,
            detail="No connected Gmail account. Connect one via /api/gmail/oauth/connect first.",
        )

    try:
        creds = gmail_oauth.credentials_from_stored_tokens(
            access_token=decrypt_token(account.encrypted_access_token) if account.encrypted_access_token else None,
            refresh_token=decrypt_token(account.encrypted_refresh_token),
            expiry=account.token_expiry,
        )
        creds = gmail_oauth.refresh_if_needed(creds)
    except Exception as e:
        account.last_error = str(e)
        account.is_active = False
        await db.flush()
        logger.error(f"Gmail credential refresh failed for user {current_user['id']}: {e}")
        raise HTTPException(
            status_code=401,
            detail="Gmail connection expired or revoked. Please reconnect your Gmail account.",
        )

    # Persist a refreshed access token so we don't have to refresh again
    # on every single call within its validity window.
    account.encrypted_access_token = encrypt_token(creds.token) if creds.token else None
    if creds.expiry:
        account.token_expiry = creds.expiry.replace(tzinfo=timezone.utc)
    account.last_synced_at = datetime.now(timezone.utc)
    account.last_error = None
    await db.flush()

    service = gmail_oauth.build_gmail_service(creds)
    return account, service


# ─────────────────────────────────────────────────────────
# PER-USER MANUAL SCAN — scan the current user's own inbox
# ─────────────────────────────────────────────────────────

@router.post("/oauth/scan/batch")
async def scan_my_inbox_batch(
    background_tasks: BackgroundTasks,
    max_emails: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Scan recent inbox emails from the CURRENT USER's own connected Gmail
    account (up to max_emails). Any authenticated user with a connected
    account can do this for themselves — no special role required, since
    it only ever touches their own mailbox.
    """
    account, service = await _get_active_account_and_service(current_user, db)
    messages = per_user_gmail_scanner.list_recent_inbox_messages(service, max_results=max_emails)

    if not messages:
        return {"status": "done", "scanned": 0, "message": "No emails to scan."}

    account_id = account.id
    user_id = current_user["id"]

    async def run_batch():
        # Background tasks need their own DB session — `db` above is tied
        # to this request and will be closed by the time this runs.
        from app.core.database import async_session
        async with async_session() as bg_db:
            for msg in messages:
                result = per_user_gmail_scanner.scan_and_act(service, msg["id"])
                await _persist_scan_result(result, bg_db, gmail_account_id=account_id, owner_user_id=user_id)

    background_tasks.add_task(run_batch)

    return {
        "status": "scanning",
        "queued": len(messages),
        "gmail_address": account.gmail_address,
        "message": f"{len(messages)} emails from {account.gmail_address} queued for background scanning.",
    }


@router.post("/oauth/scan/{gmail_id}")
async def scan_my_inbox_single(
    gmail_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Manually scan one message from the CURRENT USER's own connected Gmail account."""
    account, service = await _get_active_account_and_service(current_user, db)
    result = per_user_gmail_scanner.scan_and_act(service, gmail_id)

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    await _persist_scan_result(result, db, gmail_account_id=account.id, owner_user_id=current_user["id"])
    return result


# ─────────────────────────────────────────────────────────
# HELPER: persist scan result to DB
# ─────────────────────────────────────────────────────────

async def _persist_scan_result(
    result: dict,
    db: AsyncSession,
    gmail_account_id: Optional[int] = None,
    owner_user_id: Optional[int] = None,
):
    """
    Save Gmail scan result into ThreatShield database.

    gmail_account_id / owner_user_id are set when this scan came from a
    user's own per-user connected account (Phase C) — the resulting Email
    row is tagged with source_type="gmail_personal" and linked to that
    GmailAccount, so it's correctly scoped to that one user instead of
    being treated as shared organization-wide data.

    When both are None (the legacy webhook / admin shared-mailbox scan
    paths), behavior is unchanged: source_type="gmail_watch", no owner —
    those emails remain visible to the whole team, which is correct for a
    single shared monitored mailbox.
    """
    try:
        # Check if this gmail_id already exists — prevent duplicate alerts
        existing = await db.execute(
            select(Email).where(Email.message_id == result["gmail_id"])
        )
        if existing.scalar_one_or_none():
            logger.info(f"Skipping duplicate scan for Gmail ID {result['gmail_id']}")
            return

        # Save email record
        email_record = Email(
            message_id=result["gmail_id"],
            subject=result.get("subject", ""),
            sender_email=result.get("sender", ""),
            source_type="gmail_personal" if gmail_account_id else "gmail_watch",
            gmail_account_id=gmail_account_id,
            uploaded_by=owner_user_id,
            status="analyzed",
            action_taken=result.get("action_taken", "none"),
            upload_date=datetime.now(timezone.utc),
        )
        db.add(email_record)
        await db.flush()

        # Save threat analysis
        if result.get("threat_detected"):
            threat = ThreatAnalysis(
                email_id=email_record.id,
                threat_detected=result["threat_detected"],
                threat_type=result.get("threat_type"),
                threat_target=result.get("threat_target"),
                confidence_score=result.get("confidence", 0.0),
                severity=result.get("severity", "low"),
                intent_score=result.get("confidence", 0.0),
                urgency_score=0.0,
                analyzed_at=datetime.now(timezone.utc),
            )
            db.add(threat)

            # Save alert
            if result["overall_score"] >= 40:
                alert = Alert(
                    email_id=email_record.id,
                    alert_type=result.get("threat_type", "suspicious_email"),
                    severity=result.get("severity", "medium"),
                    title=f"Gmail Threat: {result.get('threat_type','').replace('_',' ').title()}",
                    message=(
                        f"Threat detected in email from {result.get('sender','')}. "
                        f"Score: {result['overall_score']:.0f}/100. "
                        f"Action: {result.get('action_taken','quarantined').upper()}"
                    ),
                    is_acknowledged=False,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(alert)

        await db.commit()
        logger.info(f"Persisted scan result for Gmail ID {result['gmail_id']}")

    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to persist scan result: {e}")


# ─────────────────────────────────────────────────────────
# WEBHOOK — called by Google Pub/Sub
# ─────────────────────────────────────────────────────────

@router.post("/webhook")
async def gmail_pubsub_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Receives Pub/Sub push notifications from Gmail.

    Both the legacy shared mailbox AND every per-user connected account
    publish to this SAME webhook URL (they all use one Pub/Sub topic —
    this is the normal way to use Gmail's API across many accounts; each
    account's watch() call is independent even though the topic is shared).

    Google's notification tells us WHICH mailbox changed via the
    `emailAddress` field, so we route accordingly:
      - emailAddress == GMAIL_WATCHER_EMAIL (the legacy shared mailbox)
        -> existing single-mailbox handling, unchanged.
      - emailAddress matches an active GmailAccount.gmail_address
        -> per-user handling: use THAT account's own stored
           watch_history_id as the sync cursor, scan with THAT user's
           credentials, and persist with gmail_account_id/uploaded_by set.
      - emailAddress matches neither
        -> ignored (e.g. a stale watch from a disconnected account).
    """
    global _last_history_id

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    pubsub_message = body.get("message", {})
    encoded_data = pubsub_message.get("data", "")

    if not encoded_data:
        return {"status": "ignored", "reason": "no data"}

    try:
        decoded = base64.b64decode(encoded_data).decode("utf-8")
        notification = json.loads(decoded)
    except Exception as e:
        logger.error(f"Failed to decode Pub/Sub message: {e}")
        raise HTTPException(status_code=400, detail="Could not decode message")

    email_address = notification.get("emailAddress", "")
    history_id = str(notification.get("historyId", ""))

    logger.info(f"Gmail push received: email={email_address} historyId={history_id}")

    # ── Route 1: legacy shared mailbox (unchanged behavior) ──
    if email_address and email_address == settings.GMAIL_WATCHER_EMAIL:
        if _last_history_id and history_id:
            new_ids = gmail_watcher.get_history(_last_history_id)
            logger.info(f"New emails from shared mailbox history: {new_ids}")

            for gmail_id in new_ids:
                async def scan_task(gid=gmail_id):
                    existing = await db.execute(select(Email).where(Email.message_id == gid))
                    if existing.scalar_one_or_none():
                        logger.info(f"Already scanned {gid} — skipping")
                        return
                    try:
                        from app.services.gmail_scanner import gmail_scanner as gs
                        email_data = gs.fetch_email_by_id(gid)
                        if email_data:
                            from app.services.email_parser import email_parser
                            parsed_check = email_parser.parse_eml(email_data["raw"])
                            subject_check = parsed_check.get("subject", "")
                            sender_check = parsed_check.get("sender_email", "")
                            if "ThreatShield Alert" in subject_check or "ThreatShield" in subject_check:
                                logger.info(f"Skipping ThreatShield alert email {gid}")
                                return
                            if sender_check == settings.GMAIL_WATCHER_EMAIL:
                                logger.info(f"Skipping self-sent email {gid}")
                                return
                    except Exception as e:
                        logger.warning(f"Pre-check failed for {gid}: {e}")

                    result = gmail_scanner.scan_and_act(gid)
                    await _persist_scan_result(result, db)

                background_tasks.add_task(scan_task)

        _last_history_id = history_id
        return {"status": "accepted", "route": "shared_mailbox", "historyId": history_id}

    # ── Route 2: per-user connected account ──
    if email_address:
        result = await db.execute(
            select(GmailAccount).where(
                GmailAccount.gmail_address == email_address,
                GmailAccount.is_active == True,
            )
        )
        account = result.scalar_one_or_none()

        if account:
            account_id = account.id
            owner_user_id = account.user_id
            previous_history_id = account.watch_history_id

            # Always advance the stored cursor to this notification's
            # historyId for NEXT time, but use the PREVIOUS value as the
            # starting point for fetching what's new right now.
            account.watch_history_id = history_id
            await db.flush()

            if previous_history_id:
                async def per_user_scan_task(
                    gid_account_id=account_id,
                    gid_owner_user_id=owner_user_id,
                    gid_prev_history=previous_history_id,
                ):
                    from app.core.database import async_session
                    async with async_session() as bg_db:
                        acct_result = await bg_db.execute(
                            select(GmailAccount).where(GmailAccount.id == gid_account_id)
                        )
                        acct = acct_result.scalar_one_or_none()
                        if not acct or not acct.is_active:
                            return

                        try:
                            creds = gmail_oauth.credentials_from_stored_tokens(
                                access_token=decrypt_token(acct.encrypted_access_token) if acct.encrypted_access_token else None,
                                refresh_token=decrypt_token(acct.encrypted_refresh_token),
                                expiry=acct.token_expiry,
                            )
                            creds = gmail_oauth.refresh_if_needed(creds)
                        except Exception as e:
                            logger.error(f"Webhook: credential refresh failed for account {gid_account_id}: {e}")
                            acct.last_error = str(e)
                            await bg_db.commit()
                            return

                        service = gmail_oauth.build_gmail_service(creds)

                        try:
                            new_ids = per_user_gmail_watcher.get_history(service, gid_prev_history)
                        except ValueError as e:
                            if str(e) == "STALE_HISTORY_ID":
                                logger.warning(
                                    f"Stale historyId for account {gid_account_id} — "
                                    f"needs a manual resync via /oauth/watch/start."
                                )
                                acct.last_error = "Watch history expired — please restart monitoring."
                                acct.is_watching = False
                                await bg_db.commit()
                            return

                        logger.info(f"New emails for account {gid_account_id}: {new_ids}")
                        for gmail_id in new_ids:
                            existing = await bg_db.execute(select(Email).where(Email.message_id == gmail_id))
                            if existing.scalar_one_or_none():
                                continue
                            scan_result = per_user_gmail_scanner.scan_and_act(service, gmail_id)
                            if "error" not in scan_result:
                                await _persist_scan_result(
                                    scan_result, bg_db,
                                    gmail_account_id=gid_account_id,
                                    owner_user_id=gid_owner_user_id,
                                )

                background_tasks.add_task(per_user_scan_task)
            else:
                logger.info(f"No previous historyId for account {account_id} yet — skipping this notification's diff.")

            return {"status": "accepted", "route": "per_user_account", "account_id": account_id, "historyId": history_id}

    # Neither the shared mailbox nor any active connected account matched.
    logger.info(f"Webhook notification for unrecognized address '{email_address}' — ignored.")
    return {"status": "ignored", "reason": "unrecognized emailAddress"}


# ─────────────────────────────────────────────────────────
# WATCH MANAGEMENT
# ─────────────────────────────────────────────────────────

@router.post("/watch/start")
async def start_watch(current_user: dict = Depends(require_roles(ADMIN_ONLY))):
    """Start Gmail push watch. Admin only — this changes a system-wide setting."""
    global _last_history_id
    try:
        response = gmail_watcher.start_watch()
        _last_history_id = str(response.get("historyId", ""))
        return {
            "status": "watching",
            "historyId": _last_history_id,
            "message": "Gmail is now being monitored. Every new inbox email will be auto-scanned.",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/watch/stop")
async def stop_watch(current_user: dict = Depends(require_roles(ADMIN_ONLY))):
    """Stop Gmail push watch. Admin only."""
    try:
        gmail_watcher.stop_watch()
        return {"status": "stopped", "message": "Gmail monitoring stopped."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────
# PER-USER WATCH MANAGEMENT — live monitoring of your own inbox
# ─────────────────────────────────────────────────────────

@router.post("/oauth/watch/start")
async def start_my_watch(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Start live push monitoring of the CURRENT USER's own connected Gmail
    account. New inbox emails will be auto-scanned in near real-time via
    the shared /api/gmail/webhook (see that endpoint's docstring for how
    notifications are routed to the right account).
    """
    account, service = await _get_active_account_and_service(current_user, db)
    try:
        response = per_user_gmail_watcher.start_watch(service)
    except ValueError as e:
        # GMAIL_PUBSUB_TOPIC not configured
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start watch: {e}")

    account.watch_history_id = str(response.get("historyId", ""))
    expiration_ms = response.get("expiration")
    if expiration_ms:
        account.watch_expiry = per_user_gmail_watcher.expiration_ms_to_datetime(expiration_ms)
    account.is_watching = True
    account.last_error = None
    await db.flush()

    return {
        "status": "watching",
        "gmail_address": account.gmail_address,
        "history_id": account.watch_history_id,
        "watch_expires_at": account.watch_expiry,
        "message": (
            f"Live monitoring started for {account.gmail_address}. "
            "New inbox emails will be auto-scanned."
        ),
    }


@router.post("/oauth/watch/stop")
async def stop_my_watch(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Stop live push monitoring of the CURRENT USER's own connected Gmail account."""
    account, service = await _get_active_account_and_service(current_user, db)
    try:
        per_user_gmail_watcher.stop_watch(service)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop watch: {e}")

    account.is_watching = False
    await db.flush()
    return {"status": "stopped", "gmail_address": account.gmail_address}


async def renew_expiring_watches(db: AsyncSession):
    """
    Loop over every active, currently-watching GmailAccount and renew any
    whose watch is close to its 7-day expiry. Intended to be called once a
    day by a scheduler — see the note below for how to wire that up, since
    this process does not run a background scheduler on its own.

    Wiring suggestion (pick one):
      1. Cron / systemd timer that runs once daily and calls a small script
         which opens a DB session and calls this function, e.g.:
             python -m app.scripts.renew_gmail_watches
      2. APScheduler inside the FastAPI app — add to app/main.py's startup:
             from apscheduler.schedulers.asyncio import AsyncIOScheduler
             scheduler = AsyncIOScheduler()
             scheduler.add_job(renew_job, "interval", hours=24)
             scheduler.start()
         (requires `pip install apscheduler`, not currently in requirements.txt)
    """
    result = await db.execute(
        select(GmailAccount).where(
            GmailAccount.is_active == True,
            GmailAccount.is_watching == True,
        )
    )
    accounts = result.scalars().all()

    renewed, failed = 0, 0
    for account in accounts:
        if not per_user_gmail_watcher.needs_renewal(account.watch_expiry):
            continue
        try:
            creds = gmail_oauth.credentials_from_stored_tokens(
                access_token=decrypt_token(account.encrypted_access_token) if account.encrypted_access_token else None,
                refresh_token=decrypt_token(account.encrypted_refresh_token),
                expiry=account.token_expiry,
            )
            creds = gmail_oauth.refresh_if_needed(creds)
            service = gmail_oauth.build_gmail_service(creds)
            response = per_user_gmail_watcher.start_watch(service)

            account.watch_history_id = str(response.get("historyId", ""))
            expiration_ms = response.get("expiration")
            if expiration_ms:
                account.watch_expiry = per_user_gmail_watcher.expiration_ms_to_datetime(expiration_ms)
            account.last_error = None
            renewed += 1
            logger.info(f"Renewed Gmail watch for account {account.id} ({account.gmail_address})")
        except Exception as e:
            account.last_error = f"Watch renewal failed: {e}"
            account.is_watching = False
            failed += 1
            logger.error(f"Failed to renew watch for account {account.id}: {e}")

    await db.commit()
    return {"renewed": renewed, "failed": failed, "checked": len(accounts)}


@router.post("/oauth/watch/renew-all")
async def renew_all_watches_endpoint(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_roles(ADMIN_ONLY)),
):
    """
    Admin-triggered renewal sweep across ALL users' watches that are close
    to expiry. Exposed as an endpoint so it CAN be triggered by an external
    cron job (e.g. `curl -X POST .../oauth/watch/renew-all` with an admin
    token) if you don't want to run a scheduler inside the app process.
    """
    return await renew_expiring_watches(db)


# ─────────────────────────────────────────────────────────
# MANUAL SCAN
# ─────────────────────────────────────────────────────────

@router.post("/scan/batch")
async def scan_batch(
    background_tasks: BackgroundTasks,
    max_emails: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_roles(ADMIN_AND_ANALYST)),
):
    """Scan recent unscanned inbox emails (up to max_emails). Admin/analyst only."""
    messages = gmail_watcher._get_service().users().messages().list(
        userId="me",
        q="in:inbox",
        maxResults=max_emails
    ).execute().get("messages", [])

    if not messages:
        return {"status": "done", "scanned": 0, "message": "No emails to scan."}

    async def run_batch():
        for msg in messages:
            result = gmail_scanner.scan_and_act(msg["id"])
            await _persist_scan_result(result, db)

    background_tasks.add_task(run_batch)

    return {
        "status": "scanning",
        "queued": len(messages),
        "message": f"{len(messages)} emails queued for background scanning.",
    }


@router.post("/scan/{gmail_id}")
async def scan_single_email(
    gmail_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_roles(ADMIN_AND_ANALYST)),
):
    """Manually trigger scan + quarantine for a specific Gmail message ID. Admin/analyst only."""
    result = gmail_scanner.scan_and_act(gmail_id)

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    await _persist_scan_result(result, db)
    return result


# ─────────────────────────────────────────────────────────
# STATUS
# ─────────────────────────────────────────────────────────

@router.get("/status")
async def gmail_status(current_user: dict = Depends(get_current_user)):
    """Check Gmail integration status."""
    token_exists = __import__("pathlib").Path(
        __import__("os").getenv("GMAIL_TOKEN_FILE", "gmail_token.json")
    ).exists()

    creds_exists = __import__("pathlib").Path(
        __import__("os").getenv("GMAIL_CREDENTIALS_FILE", "credentials.json")
    ).exists()

    return {
        "credentials_file": creds_exists,
        "token_file": token_exists,
        "authenticated": token_exists,
        "watching": _last_history_id is not None,
        "last_history_id": _last_history_id,
        "pubsub_topic": settings.GMAIL_PUBSUB_TOPIC or "not configured",
        "admin_email": settings.GMAIL_ADMIN_EMAIL or "not configured",
        "webhook_url": f"{settings.APP_BASE_URL}/api/gmail/webhook",
    }