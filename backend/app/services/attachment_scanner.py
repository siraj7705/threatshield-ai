"""
ThreatShield AI - Attachment Content Scanner

Extracts plain text from email attachments (PDF, DOCX, TXT) and runs
the NLP threat-detection pipeline on that text.  This is how phishing
kits and malware often hide their payload — inside an attached document
rather than the email body.

Supported formats
-----------------
  .pdf        — pypdf (text layer only; scanned/image PDFs return empty)
  .docx       — python-docx (body paragraphs + tables)
  .doc        — fallback: raw byte decode (best-effort, often messy)
  .txt / .csv — direct UTF-8 decode

Dependencies (add to requirements.txt):
  pypdf>=4.0
  python-docx>=1.1
"""
import io
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# ── Optional imports — degrade gracefully if libs missing ────────────────────
try:
    import pypdf                         # type: ignore
    _PYPDF_OK = True
except ImportError:
    _PYPDF_OK = False
    logger.warning("pypdf not installed — PDF extraction disabled")

try:
    import docx as _docx                 # type: ignore  (python-docx)
    _DOCX_OK = True
except ImportError:
    _DOCX_OK = False
    logger.warning("python-docx not installed — DOCX extraction disabled")


# ── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class AttachmentScanResult:
    """Scan result for a single attachment."""
    filename: str = ""
    content_type: str = ""
    file_size: int = 0

    # Extraction
    extracted_text: str = ""
    extraction_ok: bool = False
    extraction_error: Optional[str] = None
    extraction_method: str = ""          # "pypdf" | "python-docx" | "plaintext" | "unsupported"

    # NLP result (mirrors ThreatAnalysis fields we care about)
    threat_detected: bool = False
    threat_type: Optional[str] = None
    threat_target: Optional[str] = None
    threat_description: Optional[str] = None
    confidence_score: float = 0.0
    severity: str = "safe"
    intent_score: float = 0.0
    urgency_score: float = 0.0
    keywords_found: list = field(default_factory=list)

    # Risk
    attachment_risk_score: float = 0.0  # 0-100
    risk_reasons: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ── Scanner ──────────────────────────────────────────────────────────────────

class AttachmentScanner:
    """
    Scans email attachment bytes for threat content.

    Usage
    -----
    results = await attachment_scanner.scan_all(parsed_attachments, nlp_engine)
    # parsed_attachments is the list produced by the updated email_parser.
    """

    # Max text we feed to NLP — keeps inference time bounded
    _MAX_TEXT_CHARS = 20_000

    # Extensions we can handle
    _PDF_EXT = {".pdf"}
    _DOCX_EXT = {".docx"}
    _DOC_EXT = {".doc"}
    _TEXT_EXT = {".txt", ".csv", ".eml", ".msg", ".rtf", ".html", ".htm"}

    def _extension(self, filename: str) -> str:
        lower = filename.lower()
        for ext in self._PDF_EXT | self._DOCX_EXT | self._DOC_EXT | self._TEXT_EXT:
            if lower.endswith(ext):
                return ext
        return ""

    # ── Text extractors ──────────────────────────────────────────────────────

    def _extract_pdf(self, data: bytes) -> tuple[str, str]:
        """Return (text, method_name). Raises on failure."""
        if not _PYPDF_OK:
            raise RuntimeError("pypdf not installed")
        reader = pypdf.PdfReader(io.BytesIO(data))
        pages = []
        for page in reader.pages:
            pages.append(page.extract_text() or "")
        return "\n".join(pages), "pypdf"

    def _extract_docx(self, data: bytes) -> tuple[str, str]:
        """Return (text, method_name). Raises on failure."""
        if not _DOCX_OK:
            raise RuntimeError("python-docx not installed")
        doc = _docx.Document(io.BytesIO(data))
        parts = []
        for para in doc.paragraphs:
            if para.text.strip():
                parts.append(para.text)
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    if cell.text.strip():
                        parts.append(cell.text)
        return "\n".join(parts), "python-docx"

    def _extract_text(self, data: bytes) -> tuple[str, str]:
        """Best-effort UTF-8 decode for plain-text formats."""
        text = data.decode("utf-8", errors="replace")
        return text, "plaintext"

    def _extract_doc_fallback(self, data: bytes) -> tuple[str, str]:
        """
        .doc files (old binary format) — python-docx can't read them.
        Extract printable ASCII runs as a rough fallback.
        This is lossy but better than nothing for keyword detection.
        """
        import re
        raw = data.decode("latin-1", errors="replace")
        # Keep runs of printable ASCII that are ≥4 chars long
        runs = re.findall(r'[ -~]{4,}', raw)
        text = " ".join(runs)
        return text, "doc-fallback"

    # ── Main entry ───────────────────────────────────────────────────────────

    def extract_text(self, filename: str, data: bytes) -> tuple[str, str, Optional[str]]:
        """
        Extract text from attachment bytes.

        Returns
        -------
        (text, method, error_or_None)
        """
        ext = self._extension(filename)
        try:
            if ext in self._PDF_EXT:
                text, method = self._extract_pdf(data)
            elif ext in self._DOCX_EXT:
                text, method = self._extract_docx(data)
            elif ext in self._DOC_EXT:
                text, method = self._extract_doc_fallback(data)
            elif ext in self._TEXT_EXT:
                text, method = self._extract_text(data)
            else:
                return "", "unsupported", f"Unsupported extension: '{ext or filename}'"
        except Exception as e:
            logger.warning(f"Attachment extraction failed for '{filename}': {e}")
            return "", "error", str(e)

        # Truncate to NLP budget
        if len(text) > self._MAX_TEXT_CHARS:
            text = text[: self._MAX_TEXT_CHARS]

        return text.strip(), method, None

    def scan_one(self, filename: str, content_type: str, data: bytes, nlp_engine) -> AttachmentScanResult:
        """
        Scan a single attachment synchronously.

        Parameters
        ----------
        filename     : original filename from the email
        content_type : MIME type string
        data         : raw attachment bytes
        nlp_engine   : the existing NLP engine singleton (nlp_engine.analyze())
        """
        result = AttachmentScanResult(
            filename=filename,
            content_type=content_type,
            file_size=len(data),
        )

        # Step 1 — Extract text
        text, method, error = self.extract_text(filename, data)
        result.extraction_method = method

        if error:
            result.extraction_ok = False
            result.extraction_error = error
            return result

        result.extraction_ok = True
        result.extracted_text = text

        if not text.strip():
            # Successfully parsed but the document is empty (scanned image PDF, etc.)
            result.extraction_error = "No extractable text found (may be image-only)"
            return result

        # Step 2 — NLP analysis on the extracted text
        try:
            nlp_result = nlp_engine.analyze(
                subject=f"[ATTACHMENT] {filename}",
                body=text,
                sender="",
            )
            result.threat_detected = nlp_result.threat_detected
            result.threat_type = nlp_result.threat_type
            result.threat_target = nlp_result.threat_target
            result.threat_description = nlp_result.threat_description
            result.confidence_score = nlp_result.confidence_score
            result.severity = nlp_result.severity
            result.intent_score = nlp_result.intent_score
            result.urgency_score = nlp_result.urgency_score
            result.keywords_found = nlp_result.keywords_found
        except Exception as e:
            logger.error(f"NLP failed on attachment '{filename}': {e}")
            result.extraction_error = f"NLP error: {e}"
            return result

        # Step 3 — Calculate attachment risk score
        result.attachment_risk_score, result.risk_reasons = self._calculate_risk(result, filename)

        return result

    def scan_all(self, attachments: list[dict], nlp_engine) -> list[AttachmentScanResult]:
        """
        Scan a list of attachment dicts (from email_parser).

        Each dict must have: filename, content_type, data (bytes).

        Returns a list of AttachmentScanResult, one per attachment.
        """
        results = []
        for att in attachments:
            if not att.get("data"):
                # No bytes — metadata-only attachment (pre-existing behaviour)
                results.append(AttachmentScanResult(
                    filename=att.get("filename", ""),
                    content_type=att.get("content_type", ""),
                    file_size=att.get("size", 0),
                    extraction_ok=False,
                    extraction_error="No attachment data available",
                ))
                continue

            result = self.scan_one(
                filename=att.get("filename", "unnamed"),
                content_type=att.get("content_type", ""),
                data=att["data"],
                nlp_engine=nlp_engine,
            )
            results.append(result)

        return results

    # ── Risk scoring ─────────────────────────────────────────────────────────

    def _calculate_risk(self, r: AttachmentScanResult, filename: str) -> tuple[float, list[str]]:
        """
        Derive an attachment risk score (0-100) from the NLP result
        and the file extension.
        """
        score = 0.0
        reasons: list[str] = []

        if r.threat_detected:
            # Scale by confidence
            nlp_contribution = r.confidence_score * 70  # max 70 pts from NLP
            score = max(score, nlp_contribution)
            reasons.append(
                f"Attachment '{filename}' contains {r.threat_type} content "
                f"(confidence {r.confidence_score:.0%})"
            )

        # Keyword density boost
        if len(r.keywords_found) >= 5:
            score = min(score + 10, 100.0)
            reasons.append(f"High keyword density in attachment ({len(r.keywords_found)} threat keywords)")

        # Urgency boost
        if r.urgency_score >= 0.6:
            score = min(score + 8, 100.0)
            reasons.append(f"High urgency language detected in attachment (score {r.urgency_score:.2f})")

        # Suspicious file types
        ext = self._extension(filename)
        suspicious_doc_types = {".doc", ".docx"}  # macro-capable
        if ext in suspicious_doc_types and r.threat_detected:
            score = min(score + 5, 100.0)
            reasons.append(f"Threat content inside macro-capable document type ({ext})")

        return round(score, 2), reasons

    def aggregate_risk(self, results: list[AttachmentScanResult]) -> tuple[float, list[str]]:
        """
        Roll up per-attachment risk scores into a single score + reason list
        for use in the email-level threat scorer boost.
        """
        if not results:
            return 0.0, []
        top_score = max(r.attachment_risk_score for r in results)
        all_reasons: list[str] = []
        for r in results:
            all_reasons.extend(r.risk_reasons)
        return top_score, all_reasons


# Singleton
attachment_scanner = AttachmentScanner()