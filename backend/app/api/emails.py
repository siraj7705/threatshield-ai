"""
ThreatShield AI - Email Upload & Analysis API Routes
"""
import json
import time
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.core.security import get_current_user, require_roles, ADMIN_AND_ANALYST, ADMIN_ONLY, is_admin, can_access_owned_resource
from app.models.email import Email
from app.models.threat import ThreatAnalysis, ThreatScore
from app.models.header import HeaderAnalysis
from app.models.alert import Alert
from app.models.audit import AuditLog
from app.models.url_analysis import URLAnalysis
from app.schemas import EmailResponse, EmailListResponse, FullEmailAnalysis, AttachmentScanResponse, SenderIntelligenceResponse, IPReputationResponse
from app.services.email_parser import email_parser
from app.services.nlp_engine import nlp_engine
from app.services.header_analyzer import header_analyzer
from app.services.threat_scorer import threat_scorer
from app.services.alert_engine import alert_engine
from app.services.url_analyzer import url_analyzer
from app.models.trusted_sender import TrustedSender
from app.api.trusted_senders import _is_trusted
from app.models.ip_reputation import IPReputation
from app.services.ip_reputation import ip_reputation_checker
from app.models.attachment_scan import AttachmentScan
from app.services.attachment_scanner import attachment_scanner
from app.models.sender_intelligence import SenderIntelligence
from app.services.sender_intelligence import sender_intelligence
from app.services.domain_age import domain_age_checker
from app.services.siem import siem_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/emails", tags=["Emails"])


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_email(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_roles(ADMIN_AND_ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload and analyze a single email file (.eml or .txt).
    Performs full analysis pipeline: parsing → NLP → header forensics → scoring → alerting.

    Requires admin or analyst role — investigators are read-only and
    cannot upload or delete emails.
    """
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    allowed_ext = (".eml", ".txt", ".msg")
    if not any(file.filename.lower().endswith(ext) for ext in allowed_ext):
        raise HTTPException(status_code=400, detail=f"Unsupported file type. Allowed: {allowed_ext}")

    # Read file content
    content = await file.read()
    if len(content) > 25 * 1024 * 1024:  # 25MB limit
        raise HTTPException(status_code=400, detail="File too large (max 25MB)")

    try:
        # Parse email
        parsed = email_parser.parse_eml(content)
    except ValueError as e:
        # Try raw text parsing
        try:
            parsed = email_parser.parse_raw(content.decode("utf-8", errors="replace"))
        except Exception:
            raise HTTPException(status_code=400, detail=f"Failed to parse email: {str(e)}")

    # Store email in database
    email_record = Email(
        message_id=parsed.get("message_id", ""),
        subject=parsed.get("subject", ""),
        sender_email=parsed.get("sender_email", ""),
        sender_name=parsed.get("sender_name", ""),
        recipient_email=parsed.get("recipient_email", ""),
        cc_emails=parsed.get("cc_emails", ""),
        bcc_emails=parsed.get("bcc_emails", ""),
        body_text=parsed.get("body_text", ""),
        body_html=parsed.get("body_html", ""),
        raw_headers=parsed.get("raw_headers", ""),
        raw_content=parsed.get("raw_content", ""),
        received_date=parsed.get("received_date"),
        uploaded_by=current_user["id"],
        source_type="upload",
        file_name=file.filename,
        file_size=len(content),
        status="analyzing",
    )
    db.add(email_record)
    await db.flush()

    # ===== ANALYSIS PIPELINE =====
    start_time = time.time()

    # 0. Trusted Sender Check
    sender_email = parsed.get("sender_email", "")
    trusted_result = await db.execute(
        select(TrustedSender).where(TrustedSender.user_id == current_user["id"])
    )
    trusted_list = trusted_result.scalars().all()
    sender_is_trusted = _is_trusted(sender_email, trusted_list)

    # 1. NLP Threat Detection
    nlp_result = nlp_engine.analyze(
        subject=parsed.get("subject", ""),
        body=parsed.get("body_text", ""),
        sender=parsed.get("sender_email", ""),
    )

    threat_analysis = ThreatAnalysis(
        email_id=email_record.id,
        threat_detected=nlp_result.threat_detected,
        threat_type=nlp_result.threat_type,
        threat_target=nlp_result.threat_target,
        threat_description=nlp_result.threat_description,
        confidence_score=nlp_result.confidence_score,
        severity=nlp_result.severity,
        intent_score=nlp_result.intent_score,
        urgency_score=nlp_result.urgency_score,
        keywords_found=json.dumps(nlp_result.keywords_found),
        entities_found=json.dumps([e for e in nlp_result.entities_found]),
        nlp_model_used=nlp_result.model_used,
        analysis_duration_ms=int((time.time() - start_time) * 1000),
    )
    db.add(threat_analysis)

    # 2. Header Forensics
    header_result = header_analyzer.analyze(parsed.get("raw_headers", ""))

    header_analysis = HeaderAnalysis(
        email_id=email_record.id,
        **header_result.to_dict(),
    )
    db.add(header_analysis)

    # 3. IP Reputation — VPN / Tor / Proxy detection
    originating_ip = header_result.originating_ip if hasattr(header_result, "originating_ip") else ""
    ip_rep_result = await ip_reputation_checker.check(originating_ip or "")
    db.add(IPReputation(
        email_id=email_record.id,
        ip=ip_rep_result.ip,
        checked=ip_rep_result.checked,
        is_vpn=ip_rep_result.is_vpn,
        is_tor=ip_rep_result.is_tor,
        is_proxy=ip_rep_result.is_proxy,
        is_hosting=ip_rep_result.is_hosting,
        isp=ip_rep_result.isp,
        org=ip_rep_result.org,
        country=ip_rep_result.country,
        city=ip_rep_result.city,
        ip_risk_score=ip_rep_result.ip_risk_score,
        risk_reasons=json.dumps(ip_rep_result.risk_reasons),
        error=ip_rep_result.error,
    ))

    # 5. URL Analysis (Google Safe Browsing + heuristics)
    url_result = await url_analyzer.analyze_async(
        body_text=parsed.get("body_text", ""),
        body_html=parsed.get("body_html", ""),
    )

    # Domain age check on ONE url domain (the first that differs from the
    # sender's own domain). Deliberately limited to a single lookup per
    # email — most phishing links share one attacker domain, and checking
    # every link in every email would risk hammering the free RDAP service
    # on newsletter-style emails with many unrelated links.
    url_domain_age_checked_url = None
    url_domain_age_days = None
    url_domain_is_newly_registered = False
    _sender_domain_for_url_check = sender_email.split("@")[-1] if "@" in sender_email else ""
    for detail in url_result.analysis_details:
        candidate_domain = detail.get("domain", "")
        if candidate_domain and candidate_domain != _sender_domain_for_url_check:
            age_result = await domain_age_checker.check(candidate_domain)
            if age_result.checked:
                url_domain_age_checked_url = detail.get("url", candidate_domain)
                url_domain_age_days = age_result.age_days
                url_domain_is_newly_registered = age_result.is_newly_registered
            break  # only ever check the first qualifying domain

    url_analysis = URLAnalysis(
        email_id=email_record.id,
        urls_found=json.dumps(url_result.urls_found),
        malicious_urls=json.dumps(url_result.malicious_urls),
        suspicious_urls=json.dumps(url_result.suspicious_urls),
        url_risk_score=url_result.url_risk_score,
        url_threat_types=json.dumps(url_result.url_threat_types),
        safe_browsing_checked=url_result.safe_browsing_checked,
        analysis_details=json.dumps(url_result.analysis_details),
        domain_age_checked_url=url_domain_age_checked_url,
        domain_age_days=url_domain_age_days,
        domain_is_newly_registered=url_domain_is_newly_registered,
    )
    db.add(url_analysis)

    # 4. Attachment Content Scanning (PDF / DOCX / TXT)
    attachment_results = attachment_scanner.scan_all(
        parsed.get("attachments", []), nlp_engine
    )
    for att_result in attachment_results:
        db.add(AttachmentScan(
            email_id=email_record.id,
            filename=att_result.filename,
            content_type=att_result.content_type,
            file_size=att_result.file_size,
            extraction_ok=att_result.extraction_ok,
            extraction_method=att_result.extraction_method,
            extraction_error=att_result.extraction_error,
            extracted_text_preview=att_result.extracted_text[:500] if att_result.extracted_text else None,
            threat_detected=att_result.threat_detected,
            threat_type=att_result.threat_type,
            threat_target=att_result.threat_target,
            threat_description=att_result.threat_description,
            confidence_score=att_result.confidence_score,
            severity=att_result.severity,
            intent_score=att_result.intent_score,
            urgency_score=att_result.urgency_score,
            keywords_found=json.dumps(att_result.keywords_found),
            attachment_risk_score=att_result.attachment_risk_score,
            risk_reasons=json.dumps(att_result.risk_reasons),
        ))
    att_risk_score, att_risk_reasons = attachment_scanner.aggregate_risk(attachment_results)
    att_threats_detected = [r for r in attachment_results if r.threat_detected]

    # 5. Sender Reputation — look up existing history before scoring
    existing_sender_rep = await sender_intelligence.get(db, sender_email)
    sender_rep_score = existing_sender_rep.reputation_score if existing_sender_rep else 0.0
    sender_rep_label = existing_sender_rep.reputation_label if existing_sender_rep else "unknown"

    # 6. Threat Scoring
    score_result = threat_scorer.score(
        nlp_confidence=nlp_result.confidence_score,
        nlp_threat_type=nlp_result.threat_type,
        keywords_found=nlp_result.keywords_found,
        header_risk_score=header_result.header_risk_score,
        urgency_score=nlp_result.urgency_score,
        sender_domain=parsed.get("sender_email", "").split("@")[-1] if "@" in parsed.get("sender_email", "") else "",
        has_attachments=len(parsed.get("attachments", [])) > 0,
        spoofing_detected=header_result.spoofing_detected,
        sender_reputation_score=sender_rep_score,
        sender_reputation_label=sender_rep_label,
    )

    # Boost score if IP is Tor / proxy / VPN
    if ip_rep_result.checked and ip_rep_result.ip_risk_score > 0:
        boosted = min(score_result.overall_score + ip_rep_result.ip_risk_score * 0.15, 100.0)
        score_result.overall_score = round(boosted, 2)
        existing_explanation = score_result.explanation if isinstance(score_result.explanation, list) else json.loads(score_result.explanation or "[]")
        existing_explanation.extend(ip_rep_result.risk_reasons)
        score_result.explanation = existing_explanation
        if score_result.overall_score >= 80:
            score_result.category = "critical"
            score_result.recommended_action = "block"
        elif score_result.overall_score >= 61:
            score_result.category = "high_risk"
            score_result.recommended_action = "quarantine"

    # Boost score if malicious URLs confirmed by Safe Browsing
    if url_result.malicious_urls:
        boosted = min(max(score_result.overall_score, url_result.url_risk_score), 100.0)
        score_result.overall_score = boosted
        score_result.category = "critical" if boosted >= 80 else "high_risk"
        score_result.recommended_action = "block"
        existing_explanation = json.loads(score_result.explanation) if isinstance(score_result.explanation, str) else (score_result.explanation or [])
        existing_explanation.append(f"Malicious URLs detected by Google Safe Browsing: {url_result.malicious_urls}")
        score_result.explanation = json.dumps(existing_explanation)

    # Boost score if attachment content scanning found threats
    if att_risk_score > 0:
        boosted = min(score_result.overall_score + att_risk_score * 0.25, 100.0)
        score_result.overall_score = round(boosted, 2)
        existing_explanation = json.loads(score_result.explanation) if isinstance(score_result.explanation, str) else (score_result.explanation or [])
        existing_explanation.extend(att_risk_reasons)
        score_result.explanation = json.dumps(existing_explanation)
        if score_result.overall_score >= 80:
            score_result.category = "critical"
            score_result.recommended_action = "block"
        elif score_result.overall_score >= 61:
            score_result.category = "high_risk"
            score_result.recommended_action = "quarantine"

    threat_score = ThreatScore(
        email_id=email_record.id,
        **score_result.to_dict(),
    )
    db.add(threat_score)

    # 5. Update email status and action — trusted senders are never quarantined/blocked
    email_record.status = "analyzed"
    if sender_is_trusted:
        # Trusted sender: always allow, never quarantine
        email_record.action_taken = "allow"
    else:
        email_record.action_taken = score_result.recommended_action

    # 6. Generate alert — different logic for trusted senders
    if sender_is_trusted:
        # Trusted sender with phishing URLs → still alert (possible compromised link)
        if url_result.malicious_urls:
            alert = Alert(
                email_id=email_record.id,
                alert_type="phishing",
                severity="high",
                title=f"⭐ Trusted Sender — Malicious URL Detected",
                message=(
                    f"Email from trusted sender {sender_email} contains malicious URLs.\n"
                    f"This may indicate a compromised account or forwarded phishing link.\n"
                    f"URLs: {', '.join(url_result.malicious_urls[:3])}"
                ),
                details=json.dumps({"sender": sender_email, "trusted": True, "malicious_urls": url_result.malicious_urls}),
            )
            db.add(alert)
        # Trusted sender with high-confidence threat phrases → low-severity notice
        elif nlp_result.threat_detected and nlp_result.confidence_score >= 0.7:
            alert = Alert(
                email_id=email_record.id,
                alert_type="trusted_sender_notice",
                severity="low",
                title=f"⭐ Trusted Sender — Suspicious Content Notice",
                message=(
                    f"Email from trusted sender {sender_email} contains potentially harmful language.\n"
                    f"Threat type: {nlp_result.threat_type} (confidence: {nlp_result.confidence_score:.0%})\n"
                    f"No action taken — sender is trusted. Review manually if needed."
                ),
                details=json.dumps({"sender": sender_email, "trusted": True, "threat_type": nlp_result.threat_type}),
            )
            db.add(alert)
    else:
        # Normal sender — generate full alert if needed
        alert_data = alert_engine.generate_alert(
            email_id=email_record.id,
            threat_score=score_result.overall_score,
            threat_type=nlp_result.threat_type,
            threat_target=nlp_result.threat_target,
            confidence=nlp_result.confidence_score,
            sender=sender_email,
            subject=parsed.get("subject", ""),
        )
        if alert_data:
            db.add(Alert(**alert_data))

    # 7. Update Sender Intelligence (record this email's verdict into history)
    await sender_intelligence.update_and_score(
        db=db,
        sender_email=sender_email,
        threat_detected=nlp_result.threat_detected,
        overall_score=score_result.overall_score,
        action_taken=email_record.action_taken,
    )

    # 8. Audit log
    audit = AuditLog(
        resource_type="email",
        resource_id=email_record.id,
        details=json.dumps({
            "filename": file.filename,
            "threat_detected": nlp_result.threat_detected,
            "threat_score": score_result.overall_score,
        }),
    )
    db.add(audit)

    # 9. SIEM / Elasticsearch indexing (fire-and-forget — never breaks email processing)
    await siem_client.index_email(
        email_id=email_record.id,
        subject=email_record.subject or "",
        sender_email=email_record.sender_email or "",
        threat_detected=nlp_result.threat_detected,
        threat_type=nlp_result.threat_type,
        threat_score=score_result.overall_score,
        severity=score_result.category,
        action_taken=email_record.action_taken,
        upload_date=email_record.upload_date,
        originating_ip=getattr(header_result, "originating_ip", None),
        originating_country=getattr(header_result, "originating_country", None),
        is_vpn=ip_rep_result.is_vpn,
        is_tor=ip_rep_result.is_tor,
        is_proxy=ip_rep_result.is_proxy,
    )

    elapsed_ms = int((time.time() - start_time) * 1000)
    logger.info(f"Email analysis completed in {elapsed_ms}ms - email_id={email_record.id}")

    return {
        "id": email_record.id,
        "subject": email_record.subject,
        "sender": email_record.sender_email,
        "status": email_record.status,
        "action_taken": email_record.action_taken,
        "trusted_sender": sender_is_trusted,
        "threat_detected": nlp_result.threat_detected,
        "threat_type": nlp_result.threat_type,
        "threat_score": score_result.overall_score,
        "severity": nlp_result.severity,
        "confidence": nlp_result.confidence_score,
        "analysis_time_ms": elapsed_ms,
        # URL analysis summary
        "urls_found": len(url_result.urls_found),
        "malicious_urls": url_result.malicious_urls,
        "suspicious_urls": url_result.suspicious_urls,
        "url_risk_score": url_result.url_risk_score,
        # Attachment scan summary
        "attachments_scanned": len(attachment_results),
        "attachment_threats": len(att_threats_detected),
        "attachment_risk_score": att_risk_score,
    }


@router.post("/upload-batch", status_code=status.HTTP_207_MULTI_STATUS)
async def upload_emails_batch(
    files: list[UploadFile] = File(...),
    current_user: dict = Depends(require_roles(ADMIN_AND_ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload and analyze multiple email files in a single request.
    Returns a 207 Multi-Status response with per-file results.

    Each file runs through the same full analysis pipeline as /upload.
    Accepts up to 50 files per batch; total payload capped at 100MB.
    """
    MAX_FILES = 50
    MAX_TOTAL_BYTES = 100 * 1024 * 1024  # 100 MB

    if not files:
        raise HTTPException(status_code=400, detail="No files provided")
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=400, detail=f"Too many files (max {MAX_FILES})")

    allowed_ext = (".eml", ".txt", ".msg")
    results = []
    total_bytes = 0

    for file in files:
        # ---- per-file validation ----
        if not file.filename:
            results.append({"file": "(unnamed)", "ok": False, "error": "No filename"})
            continue

        if not any(file.filename.lower().endswith(ext) for ext in allowed_ext):
            results.append({
                "file": file.filename,
                "ok": False,
                "error": f"Unsupported file type. Allowed: {allowed_ext}",
            })
            continue

        content = await file.read()
        if len(content) > 25 * 1024 * 1024:
            results.append({"file": file.filename, "ok": False, "error": "File too large (max 25MB)"})
            continue

        total_bytes += len(content)
        if total_bytes > MAX_TOTAL_BYTES:
            results.append({"file": file.filename, "ok": False, "error": "Batch total size exceeded (max 100MB)"})
            continue

        # ---- parse ----
        try:
            parsed = email_parser.parse_eml(content)
        except ValueError:
            try:
                parsed = email_parser.parse_raw(content.decode("utf-8", errors="replace"))
            except Exception as e:
                results.append({"file": file.filename, "ok": False, "error": f"Parse failed: {e}"})
                continue

        # ---- store ----
        email_record = Email(
            message_id=parsed.get("message_id", ""),
            subject=parsed.get("subject", ""),
            sender_email=parsed.get("sender_email", ""),
            sender_name=parsed.get("sender_name", ""),
            recipient_email=parsed.get("recipient_email", ""),
            cc_emails=parsed.get("cc_emails", ""),
            bcc_emails=parsed.get("bcc_emails", ""),
            body_text=parsed.get("body_text", ""),
            body_html=parsed.get("body_html", ""),
            raw_headers=parsed.get("raw_headers", ""),
            raw_content=parsed.get("raw_content", ""),
            received_date=parsed.get("received_date"),
            uploaded_by=current_user["id"],
            source_type="upload",
            file_name=file.filename,
            file_size=len(content),
            status="analyzing",
        )
        db.add(email_record)
        await db.flush()

        # ---- analysis pipeline (same as /upload) ----
        start_time = time.time()

        trusted_result = await db.execute(
            select(TrustedSender).where(TrustedSender.user_id == current_user["id"])
        )
        trusted_list = trusted_result.scalars().all()
        sender_is_trusted = _is_trusted(parsed.get("sender_email", ""), trusted_list)

        nlp_result = nlp_engine.analyze(
            subject=parsed.get("subject", ""),
            body=parsed.get("body_text", ""),
            sender=parsed.get("sender_email", ""),
        )
        db.add(ThreatAnalysis(
            email_id=email_record.id,
            threat_detected=nlp_result.threat_detected,
            threat_type=nlp_result.threat_type,
            threat_target=nlp_result.threat_target,
            threat_description=nlp_result.threat_description,
            confidence_score=nlp_result.confidence_score,
            severity=nlp_result.severity,
            intent_score=nlp_result.intent_score,
            urgency_score=nlp_result.urgency_score,
            keywords_found=json.dumps(nlp_result.keywords_found),
            entities_found=json.dumps([e for e in nlp_result.entities_found]),
            nlp_model_used=nlp_result.model_used,
            analysis_duration_ms=int((time.time() - start_time) * 1000),
        ))

        header_result = header_analyzer.analyze(parsed.get("raw_headers", ""))
        db.add(HeaderAnalysis(email_id=email_record.id, **header_result.to_dict()))

        # IP Reputation — VPN / Tor / Proxy detection
        batch_ip = header_result.originating_ip if hasattr(header_result, "originating_ip") else ""
        ip_rep_result = await ip_reputation_checker.check(batch_ip or "")
        db.add(IPReputation(
            email_id=email_record.id,
            ip=ip_rep_result.ip,
            checked=ip_rep_result.checked,
            is_vpn=ip_rep_result.is_vpn,
            is_tor=ip_rep_result.is_tor,
            is_proxy=ip_rep_result.is_proxy,
            is_hosting=ip_rep_result.is_hosting,
            isp=ip_rep_result.isp,
            org=ip_rep_result.org,
            country=ip_rep_result.country,
            city=ip_rep_result.city,
            ip_risk_score=ip_rep_result.ip_risk_score,
            risk_reasons=json.dumps(ip_rep_result.risk_reasons),
            error=ip_rep_result.error,
        ))

        url_result = await url_analyzer.analyze_async(
            body_text=parsed.get("body_text", ""),
            body_html=parsed.get("body_html", ""),
        )

        # Domain age check on ONE url domain — same conservative approach
        # as the single-upload path, to avoid hammering RDAP on batches.
        batch_url_domain_age_checked_url = None
        batch_url_domain_age_days = None
        batch_url_domain_is_newly_registered = False
        _batch_sender_domain_for_url_check = (
            parsed.get("sender_email", "").split("@")[-1]
            if "@" in parsed.get("sender_email", "") else ""
        )
        for detail in url_result.analysis_details:
            candidate_domain = detail.get("domain", "")
            if candidate_domain and candidate_domain != _batch_sender_domain_for_url_check:
                age_result = await domain_age_checker.check(candidate_domain)
                if age_result.checked:
                    batch_url_domain_age_checked_url = detail.get("url", candidate_domain)
                    batch_url_domain_age_days = age_result.age_days
                    batch_url_domain_is_newly_registered = age_result.is_newly_registered
                break

        db.add(URLAnalysis(
            email_id=email_record.id,
            urls_found=json.dumps(url_result.urls_found),
            malicious_urls=json.dumps(url_result.malicious_urls),
            suspicious_urls=json.dumps(url_result.suspicious_urls),
            url_risk_score=url_result.url_risk_score,
            url_threat_types=json.dumps(url_result.url_threat_types),
            safe_browsing_checked=url_result.safe_browsing_checked,
            analysis_details=json.dumps(url_result.analysis_details),
            domain_age_checked_url=batch_url_domain_age_checked_url,
            domain_age_days=batch_url_domain_age_days,
            domain_is_newly_registered=batch_url_domain_is_newly_registered,
        ))

        # Attachment content scanning
        batch_att_results = attachment_scanner.scan_all(
            parsed.get("attachments", []), nlp_engine
        )
        for att_result in batch_att_results:
            db.add(AttachmentScan(
                email_id=email_record.id,
                filename=att_result.filename,
                content_type=att_result.content_type,
                file_size=att_result.file_size,
                extraction_ok=att_result.extraction_ok,
                extraction_method=att_result.extraction_method,
                extraction_error=att_result.extraction_error,
                extracted_text_preview=att_result.extracted_text[:500] if att_result.extracted_text else None,
                threat_detected=att_result.threat_detected,
                threat_type=att_result.threat_type,
                threat_target=att_result.threat_target,
                threat_description=att_result.threat_description,
                confidence_score=att_result.confidence_score,
                severity=att_result.severity,
                intent_score=att_result.intent_score,
                urgency_score=att_result.urgency_score,
                keywords_found=json.dumps(att_result.keywords_found),
                attachment_risk_score=att_result.attachment_risk_score,
                risk_reasons=json.dumps(att_result.risk_reasons),
            ))
        batch_att_risk, batch_att_reasons = attachment_scanner.aggregate_risk(batch_att_results)
        batch_att_threats = [r for r in batch_att_results if r.threat_detected]

        # Sender reputation — look up existing history before scoring
        batch_sender_email = parsed.get("sender_email", "")
        batch_sender_row = await sender_intelligence.get(db, batch_sender_email)
        batch_rep_score = batch_sender_row.reputation_score if batch_sender_row else 0.0
        batch_rep_label = batch_sender_row.reputation_label if batch_sender_row else "unknown"

        score_result = threat_scorer.score(
            nlp_confidence=nlp_result.confidence_score,
            nlp_threat_type=nlp_result.threat_type,
            keywords_found=nlp_result.keywords_found,
            header_risk_score=header_result.header_risk_score,
            urgency_score=nlp_result.urgency_score,
            sender_domain=batch_sender_email.split("@")[-1] if "@" in batch_sender_email else "",
            has_attachments=len(parsed.get("attachments", [])) > 0,
            spoofing_detected=header_result.spoofing_detected,
            sender_reputation_score=batch_rep_score,
            sender_reputation_label=batch_rep_label,
        )
        if ip_rep_result.checked and ip_rep_result.ip_risk_score > 0:
            boosted = min(score_result.overall_score + ip_rep_result.ip_risk_score * 0.15, 100.0)
            score_result.overall_score = round(boosted, 2)
            existing_explanation = score_result.explanation if isinstance(score_result.explanation, list) else json.loads(score_result.explanation or "[]")
            existing_explanation.extend(ip_rep_result.risk_reasons)
            score_result.explanation = existing_explanation
            if score_result.overall_score >= 80:
                score_result.category = "critical"
                score_result.recommended_action = "block"
            elif score_result.overall_score >= 61:
                score_result.category = "high_risk"
                score_result.recommended_action = "quarantine"
        if url_result.malicious_urls:
            boosted = min(max(score_result.overall_score, url_result.url_risk_score), 100.0)
            score_result.overall_score = boosted
            score_result.category = "critical" if boosted >= 80 else "high_risk"
            score_result.recommended_action = "block"

        if batch_att_risk > 0:
            boosted = min(score_result.overall_score + batch_att_risk * 0.25, 100.0)
            score_result.overall_score = round(boosted, 2)
            existing_explanation = score_result.explanation if isinstance(score_result.explanation, list) else json.loads(score_result.explanation or "[]")
            existing_explanation.extend(batch_att_reasons)
            score_result.explanation = existing_explanation
            if score_result.overall_score >= 80:
                score_result.category = "critical"
                score_result.recommended_action = "block"
            elif score_result.overall_score >= 61:
                score_result.category = "high_risk"
                score_result.recommended_action = "quarantine"

        db.add(ThreatScore(email_id=email_record.id, **score_result.to_dict()))

        email_record.status = "analyzed"
        email_record.action_taken = "allow" if sender_is_trusted else score_result.recommended_action

        # alert
        alert_data = alert_engine.generate_alert(
            email_id=email_record.id,
            threat_score=score_result.overall_score,
            threat_type=nlp_result.threat_type,
            threat_target=nlp_result.threat_target,
            confidence=nlp_result.confidence_score,
            sender=parsed.get("sender_email", ""),
            subject=parsed.get("subject", ""),
        )
        if alert_data:
            db.add(Alert(**alert_data))

        db.add(AuditLog(
            user_id=current_user["id"],
            action="upload_email_batch",
            resource_type="email",
            resource_id=email_record.id,
            details=json.dumps({"filename": file.filename, "threat_score": score_result.overall_score}),
        ))

        # SIEM / Elasticsearch indexing (fire-and-forget)
        await siem_client.index_email(
            email_id=email_record.id,
            subject=email_record.subject or "",
            sender_email=email_record.sender_email or "",
            threat_detected=nlp_result.threat_detected,
            threat_type=nlp_result.threat_type,
            threat_score=score_result.overall_score,
            severity=score_result.category,
            action_taken=email_record.action_taken,
            upload_date=email_record.upload_date,
            originating_ip=getattr(header_result, "originating_ip", None),
            originating_country=getattr(header_result, "originating_country", None),
            is_vpn=ip_rep_result.is_vpn,
            is_tor=ip_rep_result.is_tor,
            is_proxy=ip_rep_result.is_proxy,
        )

        # Update sender intelligence with this email's verdict
        await sender_intelligence.update_and_score(
            db=db,
            sender_email=batch_sender_email,
            threat_detected=nlp_result.threat_detected,
            overall_score=score_result.overall_score,
            action_taken=email_record.action_taken,
        )

        results.append({
            "file": file.filename,
            "ok": True,
            "id": email_record.id,
            "subject": email_record.subject,
            "sender": email_record.sender_email,
            "threat_detected": nlp_result.threat_detected,
            "threat_type": nlp_result.threat_type,
            "threat_score": score_result.overall_score,
            "severity": nlp_result.severity,
            "action_taken": email_record.action_taken,
            "trusted_sender": sender_is_trusted,
            "malicious_urls": url_result.malicious_urls,
            "analysis_time_ms": int((time.time() - start_time) * 1000),
            "attachments_scanned": len(batch_att_results),
            "attachment_threats": len(batch_att_threats),
            "attachment_risk_score": batch_att_risk,
        })

    succeeded = sum(1 for r in results if r.get("ok"))
    failed = len(results) - succeeded
    return {
        "total": len(results),
        "succeeded": succeeded,
        "failed": failed,
        "results": results,
    }


@router.post("/upload-raw", status_code=status.HTTP_201_CREATED)
async def upload_raw_email(
    raw_content: str,
    current_user: dict = Depends(require_roles(ADMIN_AND_ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Upload raw email text content for analysis. Admin/analyst only."""
    if not raw_content.strip():
        raise HTTPException(status_code=400, detail="Empty content provided")

    try:
        parsed = email_parser.parse_raw(raw_content)
    except ValueError as e:
        # Treat as plain text body (not a full email)
        parsed = {
            "message_id": "",
            "subject": "",
            "sender_email": "",
            "sender_name": "",
            "recipient_email": "",
            "cc_emails": "",
            "bcc_emails": "",
            "body_text": raw_content,
            "body_html": "",
            "raw_headers": "",
            "raw_content": raw_content,
            "received_date": None,
            "attachments": [],
            "urls": [],
        }

    # Store and analyze (same pipeline as file upload)
    email_record = Email(
        message_id=parsed.get("message_id", ""),
        subject=parsed.get("subject", "") or "Raw Email Content",
        sender_email=parsed.get("sender_email", ""),
        sender_name=parsed.get("sender_name", ""),
        recipient_email=parsed.get("recipient_email", ""),
        body_text=parsed.get("body_text", ""),
        body_html=parsed.get("body_html", ""),
        raw_headers=parsed.get("raw_headers", ""),
        raw_content=parsed.get("raw_content", ""),
        received_date=parsed.get("received_date"),
        uploaded_by=current_user["id"],
        source_type="raw",
        file_name="raw_input",
        file_size=len(raw_content.encode("utf-8")),
        status="analyzing",
    )
    db.add(email_record)
    await db.flush()

    # Run analysis pipeline
    nlp_result = nlp_engine.analyze(
        subject=parsed.get("subject", ""),
        body=parsed.get("body_text", ""),
    )

    header_result = header_analyzer.analyze(parsed.get("raw_headers", ""))

    score_result = threat_scorer.score(
        nlp_confidence=nlp_result.confidence_score,
        nlp_threat_type=nlp_result.threat_type,
        keywords_found=nlp_result.keywords_found,
        header_risk_score=header_result.header_risk_score,
        urgency_score=nlp_result.urgency_score,
    )

    # Store results
    db.add(ThreatAnalysis(
        email_id=email_record.id,
        threat_detected=nlp_result.threat_detected,
        threat_type=nlp_result.threat_type,
        threat_target=nlp_result.threat_target,
        threat_description=nlp_result.threat_description,
        confidence_score=nlp_result.confidence_score,
        severity=nlp_result.severity,
        intent_score=nlp_result.intent_score,
        urgency_score=nlp_result.urgency_score,
        keywords_found=json.dumps(nlp_result.keywords_found),
        entities_found=json.dumps(nlp_result.entities_found),
        nlp_model_used=nlp_result.model_used,
    ))

    db.add(HeaderAnalysis(email_id=email_record.id, **header_result.to_dict()))
    db.add(ThreatScore(email_id=email_record.id, **score_result.to_dict()))

    email_record.status = "analyzed"
    email_record.action_taken = score_result.recommended_action

    # Generate alert
    alert_data = alert_engine.generate_alert(
        email_id=email_record.id,
        threat_score=score_result.overall_score,
        threat_type=nlp_result.threat_type,
        threat_target=nlp_result.threat_target,
        confidence=nlp_result.confidence_score,
        sender=parsed.get("sender_email", ""),
        subject=parsed.get("subject", ""),
    )
    if alert_data:
        db.add(Alert(**alert_data))

    # SIEM / Elasticsearch indexing (fire-and-forget)
    await siem_client.index_email(
        email_id=email_record.id,
        subject=email_record.subject or "",
        sender_email=email_record.sender_email or "",
        threat_detected=nlp_result.threat_detected,
        threat_type=nlp_result.threat_type,
        threat_score=score_result.overall_score,
        severity=score_result.category,
        action_taken=email_record.action_taken,
    )

    return {
        "id": email_record.id,
        "threat_detected": nlp_result.threat_detected,
        "threat_type": nlp_result.threat_type,
        "threat_score": score_result.overall_score,
        "severity": nlp_result.severity,
        "action_taken": score_result.recommended_action,
    }


@router.get("", response_model=EmailListResponse)
async def list_emails(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    action: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List emails with pagination and filtering.

    Admins see every email. Analysts/investigators only see emails they
    personally uploaded or scanned from their own connected Gmail account
    (Email.uploaded_by == them), plus emails captured by the legacy SHARED
    mailbox watcher (source_type == "gmail_watch"), which has no single
    owner and is meant to be visible to the whole team.
    """
    query = select(Email)
    count_query = select(func.count(Email.id))

    if not is_admin(current_user):
        ownership_filter = (Email.uploaded_by == current_user["id"]) | (Email.source_type == "gmail_watch")
        query = query.where(ownership_filter)
        count_query = count_query.where(ownership_filter)

    if status:
        query = query.where(Email.status == status)
        count_query = count_query.where(Email.status == status)
    if action:
        query = query.where(Email.action_taken == action)
        count_query = count_query.where(Email.action_taken == action)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Fetch page
    query = query.order_by(desc(Email.upload_date)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    emails = result.scalars().all()

    return EmailListResponse(
        total=total,
        page=page,
        per_page=per_page,
        emails=[EmailResponse.model_validate(e) for e in emails],
    )


@router.get("/{email_id}", response_model=FullEmailAnalysis)
async def get_email_detail(
    email_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get full email details with all analysis results — only if the current user owns it (or is admin)."""
    # Get email
    result = await db.execute(select(Email).where(Email.id == email_id))
    email_record = result.scalar_one_or_none()
    if not email_record:
        raise HTTPException(status_code=404, detail="Email not found")

    # Ownership check: shared-mailbox emails (source_type == "gmail_watch")
    # have no single owner and are visible to everyone; anything else is
    # restricted to its uploader unless the caller is an admin.
    owner_id = None if email_record.source_type == "gmail_watch" else email_record.uploaded_by
    if not can_access_owned_resource(current_user, owner_id):
        # 404 rather than 403 — avoids confirming to a non-owner that an
        # email with this ID exists at all.
        raise HTTPException(status_code=404, detail="Email not found")

    # Get threat analysis
    result = await db.execute(select(ThreatAnalysis).where(ThreatAnalysis.email_id == email_id))
    threat = result.scalar_one_or_none()

    # Get threat score
    result = await db.execute(select(ThreatScore).where(ThreatScore.email_id == email_id))
    score = result.scalar_one_or_none()

    # Get header analysis
    result = await db.execute(select(HeaderAnalysis).where(HeaderAnalysis.email_id == email_id))
    header = result.scalar_one_or_none()

    # Get URL analysis
    result = await db.execute(select(URLAnalysis).where(URLAnalysis.email_id == email_id))
    url_analysis = result.scalar_one_or_none()

    # Get attachment scan results (one row per attachment on this email)
    result = await db.execute(
        select(AttachmentScan)
        .where(AttachmentScan.email_id == email_id)
        .order_by(AttachmentScan.id)
    )
    attachment_scans = result.scalars().all()

    # Get sender reputation — looked up by sender_email, same as the
    # upload pipeline. This is intentionally NOT scoped to the current
    # user: reputation is sender-level history shared across the whole
    # deployment, not per-tenant data, mirroring how the scorer already
    # uses it in app/api/emails.py.
    sender_rep = None
    if email_record.sender_email:
        sender_rep = await sender_intelligence.get(db, email_record.sender_email)

    # Get IP reputation (VPN/Tor/proxy/hosting detection on the
    # originating IP) — one row per email, written during upload.
    result = await db.execute(select(IPReputation).where(IPReputation.email_id == email_id))
    ip_rep = result.scalar_one_or_none()

    # Audit log
    audit = AuditLog(
        user_id=current_user["id"],
        action="view_email",
        resource_type="email",
        resource_id=email_id,
    )
    db.add(audit)

    return FullEmailAnalysis(
        email=EmailResponse.model_validate(email_record),
        threat_analysis=threat,
        threat_score=score,
        header_analysis=header,
        url_analysis=url_analysis,
        attachment_scans=[AttachmentScanResponse.model_validate(a) for a in attachment_scans],
        sender_intelligence=SenderIntelligenceResponse.model_validate(sender_rep) if sender_rep else None,
        ip_reputation=IPReputationResponse.model_validate(ip_rep) if ip_rep else None,
    )


@router.delete("/{email_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_email(
    email_id: int,
    current_user: dict = Depends(require_roles(ADMIN_ONLY)),
    db: AsyncSession = Depends(get_db),
):
    """
    Permanently delete an email and its associated analysis records.
    Admin only — analysts and investigators cannot delete evidence.
    """
    result = await db.execute(select(Email).where(Email.id == email_id))
    email_record = result.scalar_one_or_none()
    if not email_record:
        raise HTTPException(status_code=404, detail="Email not found")

    # Clean up related rows that don't cascade automatically.
    for model in (ThreatAnalysis, ThreatScore, HeaderAnalysis, URLAnalysis, AttachmentScan, IPReputation):
        rel_result = await db.execute(select(model).where(model.email_id == email_id))
        for row in rel_result.scalars().all():
            await db.delete(row)

    alert_result = await db.execute(select(Alert).where(Alert.email_id == email_id))
    for alert_row in alert_result.scalars().all():
        await db.delete(alert_row)

    audit = AuditLog(
        user_id=current_user["id"],
        action="delete_email",
        resource_type="email",
        resource_id=email_id,
        details=f"Deleted email '{email_record.subject}' from {email_record.sender_email}",
    )
    db.add(audit)

    await db.delete(email_record)
    return None