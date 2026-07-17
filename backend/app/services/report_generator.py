"""
ThreatShield AI - PDF Report Generator
Generates forensic analysis reports in PDF format.
"""
import io
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, Image
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates PDF forensic reports for email threat analysis."""

    # Brand colors
    BRAND_PRIMARY = colors.HexColor("#0ea5e9")
    BRAND_DARK = colors.HexColor("#0f172a")
    BRAND_DANGER = colors.HexColor("#ef4444")
    BRAND_WARNING = colors.HexColor("#f59e0b")
    BRAND_SUCCESS = colors.HexColor("#22c55e")
    BRAND_GRAY = colors.HexColor("#64748b")

    SEVERITY_COLORS = {
        "critical": colors.HexColor("#ef4444"),
        "high": colors.HexColor("#f97316"),
        "medium": colors.HexColor("#f59e0b"),
        "low": colors.HexColor("#3b82f6"),
        "safe": colors.HexColor("#22c55e"),
    }

    def generate_email_report(self, analysis_data: Dict[str, Any]) -> bytes:
        """
        Generate a PDF forensic report for a single email analysis.

        Args:
            analysis_data: Dict containing email, threat_analysis, threat_score, header_analysis

        Returns:
            PDF bytes
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            topMargin=20*mm, bottomMargin=20*mm,
            leftMargin=20*mm, rightMargin=20*mm,
        )

        styles = self._get_styles()
        elements = []

        # Header / Title
        elements.append(Paragraph("THREATSHIELD AI", styles["brand_title"]))
        elements.append(Paragraph("Email Threat Analysis Report", styles["report_subtitle"]))
        elements.append(Spacer(1, 5*mm))
        elements.append(HRFlowable(
            width="100%", thickness=2,
            color=self.BRAND_PRIMARY, spaceAfter=10
        ))
        elements.append(Spacer(1, 3*mm))

        # Report metadata
        report_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        elements.append(Paragraph(f"Generated: {report_time}", styles["meta_text"]))
        elements.append(Paragraph(
            f"Report ID: TSA-{analysis_data.get('email', {}).get('id', 'N/A')}-{datetime.now().strftime('%Y%m%d%H%M')}",
            styles["meta_text"]
        ))
        elements.append(Spacer(1, 8*mm))

        # Email Summary Section
        email = analysis_data.get("email", {})
        elements.append(Paragraph("1. EMAIL SUMMARY", styles["section_header"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=self.BRAND_GRAY))
        elements.append(Spacer(1, 3*mm))

        email_data = [
            ["Field", "Value"],
            ["Subject", str(email.get("subject", "N/A"))[:80]],
            ["Sender", str(email.get("sender_email", "N/A"))],
            ["Recipient", str(email.get("recipient_email", "N/A"))[:80]],
            ["Date", str(email.get("received_date", "N/A"))],
            ["Status", str(email.get("status", "N/A")).upper()],
            ["Action Taken", str(email.get("action_taken", "none")).upper()],
        ]
        elements.append(self._create_table(email_data, styles))
        elements.append(Spacer(1, 8*mm))

        # Threat Analysis Section
        threat = analysis_data.get("threat_analysis", {})
        if threat:
            elements.append(Paragraph("2. THREAT ANALYSIS", styles["section_header"]))
            elements.append(HRFlowable(width="100%", thickness=1, color=self.BRAND_GRAY))
            elements.append(Spacer(1, 3*mm))

            severity = str(threat.get("severity", "safe"))
            severity_color = self.SEVERITY_COLORS.get(severity, self.BRAND_GRAY)

            threat_data = [
                ["Field", "Value"],
                ["Threat Detected", "YES ⚠️" if threat.get("threat_detected") else "NO ✅"],
                ["Threat Type", str(threat.get("threat_type", "N/A")).replace("_", " ").title()],
                ["Severity", severity.upper()],
                ["Confidence", f"{float(threat.get('confidence_score', 0)) * 100:.1f}%"],
                ["Intent Score", f"{float(threat.get('intent_score', 0)) * 100:.1f}%"],
                ["Urgency Score", f"{float(threat.get('urgency_score', 0)) * 100:.1f}%"],
                ["Target", str(threat.get("threat_target", "N/A")) or "N/A"],
            ]
            elements.append(self._create_table(threat_data, styles))
            elements.append(Spacer(1, 3*mm))

            # Description
            desc = threat.get("threat_description", "")
            if desc:
                elements.append(Paragraph(f"<b>Analysis:</b> {desc}", styles["body_text"]))

            # Keywords
            keywords = threat.get("keywords_found", "")
            if keywords:
                if isinstance(keywords, str):
                    try:
                        keywords = json.loads(keywords)
                    except json.JSONDecodeError:
                        keywords = [keywords]
                if keywords:
                    kw_str = ", ".join(keywords[:10])
                    elements.append(Paragraph(f"<b>Keywords Found:</b> {kw_str}", styles["body_text"]))

            elements.append(Spacer(1, 8*mm))

        # Threat Score Section
        score_data = analysis_data.get("threat_score", {})
        if score_data:
            elements.append(Paragraph("3. RISK SCORE BREAKDOWN", styles["section_header"]))
            elements.append(HRFlowable(width="100%", thickness=1, color=self.BRAND_GRAY))
            elements.append(Spacer(1, 3*mm))

            overall = float(score_data.get("overall_score", 0))
            category = str(score_data.get("category", "safe"))

            score_table_data = [
                ["Component", "Score", "Weight"],
                ["NLP Analysis", f"{float(score_data.get('nlp_score', 0)):.1f}", "40%"],
                ["Keyword Density", f"{float(score_data.get('keyword_score', 0)):.1f}", "15%"],
                ["Sender Reputation", f"{float(score_data.get('sender_score', 0)):.1f}", "15%"],
                ["Header Anomalies", f"{float(score_data.get('header_score', 0)):.1f}", "15%"],
                ["Urgency Level", f"{float(score_data.get('urgency_score', 0)):.1f}", "10%"],
                ["Attachment Risk", f"{float(score_data.get('attachment_score', 0)):.1f}", "5%"],
                ["", "", ""],
                ["OVERALL SCORE", f"{overall:.1f}/100", category.upper()],
            ]
            elements.append(self._create_score_table(score_table_data, styles))
            elements.append(Spacer(1, 3*mm))

            # Explanations
            explanation = score_data.get("explanation", "")
            if explanation:
                if isinstance(explanation, str):
                    try:
                        reasons = json.loads(explanation)
                    except json.JSONDecodeError:
                        reasons = [explanation]
                else:
                    reasons = explanation

                elements.append(Paragraph("<b>Score Explanation:</b>", styles["body_text"]))
                for reason in reasons:
                    elements.append(Paragraph(f"• {reason}", styles["body_text"]))

            elements.append(Spacer(1, 3*mm))
            elements.append(Paragraph(
                f"<b>Recommended Action:</b> {str(score_data.get('recommended_action', 'N/A')).upper()}",
                styles["body_text"]
            ))
            elements.append(Spacer(1, 8*mm))

        # Header Analysis Section
        header = analysis_data.get("header_analysis", {})
        if header:
            elements.append(Paragraph("4. EMAIL HEADER FORENSICS", styles["section_header"]))
            elements.append(HRFlowable(width="100%", thickness=1, color=self.BRAND_GRAY))
            elements.append(Spacer(1, 3*mm))

            header_table_data = [
                ["Check", "Result"],
                ["SPF", str(header.get("spf_result", "N/A")).upper()],
                ["DKIM", str(header.get("dkim_result", "N/A")).upper()],
                ["DMARC", str(header.get("dmarc_result", "N/A")).upper()],
                ["From Domain", str(header.get("from_domain", "N/A"))],
                ["Return-Path Domain", str(header.get("return_path_domain", "N/A"))],
                ["Domain Match", "YES ✅" if header.get("domain_match") else "NO ❌"],
                ["Spoofing Detected", "YES ⚠️" if header.get("spoofing_detected") else "NO ✅"],
                ["Originating IP", str(header.get("originating_ip", "N/A")) or "N/A"],
                ["Mail Client", str(header.get("mail_client", "N/A"))[:50]],
                ["Header Risk Score", f"{float(header.get('header_risk_score', 0)):.1f}/100"],
            ]
            elements.append(self._create_table(header_table_data, styles))
            elements.append(Spacer(1, 3*mm))

            # Routing anomalies
            anomalies = header.get("routing_anomalies", "")
            if anomalies:
                if isinstance(anomalies, str):
                    try:
                        anomalies = json.loads(anomalies)
                    except json.JSONDecodeError:
                        anomalies = [anomalies]
                if anomalies:
                    elements.append(Paragraph("<b>Routing Anomalies:</b>", styles["body_text"]))
                    for anomaly in anomalies:
                        elements.append(Paragraph(f"• {anomaly}", styles["body_text"]))

        elements.append(Spacer(1, 10*mm))

        # Footer
        elements.append(HRFlowable(width="100%", thickness=2, color=self.BRAND_PRIMARY))
        elements.append(Spacer(1, 3*mm))
        elements.append(Paragraph(
            "This report was generated by ThreatShield AI — Intelligent Threat Email Detection Platform",
            styles["footer_text"]
        ))
        elements.append(Paragraph(
            "CONFIDENTIAL — For authorized personnel only",
            styles["footer_text"]
        ))

        # Build PDF
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        return pdf_bytes

    def generate_executive_summary(self, stats: Dict[str, Any], recent_threats: List[Dict]) -> bytes:
        """Generate an executive summary PDF report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            topMargin=20*mm, bottomMargin=20*mm,
            leftMargin=20*mm, rightMargin=20*mm,
        )

        styles = self._get_styles()
        elements = []

        # Header
        elements.append(Paragraph("THREATSHIELD AI", styles["brand_title"]))
        elements.append(Paragraph("Executive Summary Report", styles["report_subtitle"]))
        elements.append(Spacer(1, 5*mm))
        elements.append(HRFlowable(width="100%", thickness=2, color=self.BRAND_PRIMARY))
        elements.append(Spacer(1, 5*mm))

        report_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        elements.append(Paragraph(f"Generated: {report_time}", styles["meta_text"]))
        elements.append(Spacer(1, 8*mm))

        # Overview Stats
        elements.append(Paragraph("OVERVIEW", styles["section_header"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=self.BRAND_GRAY))
        elements.append(Spacer(1, 3*mm))

        stats_data = [
            ["Metric", "Value"],
            ["Total Emails Processed", str(stats.get("total_emails", 0))],
            ["Threat Emails Detected", str(stats.get("threat_emails", 0))],
            ["Safe Emails", str(stats.get("safe_emails", 0))],
            ["Blocked Emails", str(stats.get("blocked_emails", 0))],
            ["Quarantined Emails", str(stats.get("quarantined_emails", 0))],
            ["Active Alerts", str(stats.get("critical_alerts", 0))],
            ["Open Cases", str(stats.get("active_cases", 0))],
        ]
        elements.append(self._create_table(stats_data, styles))
        elements.append(Spacer(1, 8*mm))

        # Recent Threats
        if recent_threats:
            elements.append(Paragraph("RECENT THREATS", styles["section_header"]))
            elements.append(HRFlowable(width="100%", thickness=1, color=self.BRAND_GRAY))
            elements.append(Spacer(1, 3*mm))

            threats_table = [["#", "Type", "Severity", "Score", "Sender"]]
            for i, threat in enumerate(recent_threats[:20], 1):
                threats_table.append([
                    str(i),
                    str(threat.get("threat_type", "N/A")).replace("_", " ").title(),
                    str(threat.get("severity", "N/A")).upper(),
                    f"{float(threat.get('overall_score', 0)):.1f}",
                    str(threat.get("sender", "N/A"))[:30],
                ])
            elements.append(self._create_table(threats_table, styles, col_widths=[30, 100, 80, 60, 180]))

        # Footer
        elements.append(Spacer(1, 10*mm))
        elements.append(HRFlowable(width="100%", thickness=2, color=self.BRAND_PRIMARY))
        elements.append(Spacer(1, 3*mm))
        elements.append(Paragraph(
            "CONFIDENTIAL — ThreatShield AI Executive Report",
            styles["footer_text"]
        ))

        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    def _get_styles(self):
        """Get custom report styles."""
        base_styles = getSampleStyleSheet()
        styles = {}

        styles["brand_title"] = ParagraphStyle(
            "brand_title", parent=base_styles["Title"],
            fontSize=24, textColor=self.BRAND_PRIMARY,
            fontName="Helvetica-Bold", spaceAfter=2*mm,
            alignment=TA_CENTER,
        )
        styles["report_subtitle"] = ParagraphStyle(
            "report_subtitle", parent=base_styles["Title"],
            fontSize=14, textColor=self.BRAND_DARK,
            fontName="Helvetica", spaceAfter=2*mm,
            alignment=TA_CENTER,
        )
        styles["section_header"] = ParagraphStyle(
            "section_header", parent=base_styles["Heading2"],
            fontSize=13, textColor=self.BRAND_DARK,
            fontName="Helvetica-Bold", spaceBefore=5*mm,
            spaceAfter=2*mm,
        )
        styles["body_text"] = ParagraphStyle(
            "body_text", parent=base_styles["Normal"],
            fontSize=10, textColor=self.BRAND_DARK,
            fontName="Helvetica", spaceAfter=2*mm,
            leading=14,
        )
        styles["meta_text"] = ParagraphStyle(
            "meta_text", parent=base_styles["Normal"],
            fontSize=9, textColor=self.BRAND_GRAY,
            fontName="Helvetica", alignment=TA_CENTER,
        )
        styles["footer_text"] = ParagraphStyle(
            "footer_text", parent=base_styles["Normal"],
            fontSize=8, textColor=self.BRAND_GRAY,
            fontName="Helvetica", alignment=TA_CENTER,
        )

        return styles

    def _create_table(self, data, styles, col_widths=None):
        """Create a styled table."""
        if not col_widths:
            col_widths = [150, 300]

        table = Table(data, colWidths=col_widths)
        table.setStyle(TableStyle([
            # Header row
            ("BACKGROUND", (0, 0), (-1, 0), self.BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("ALIGN", (0, 0), (-1, 0), "LEFT"),
            # Data rows
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("TEXTCOLOR", (0, 1), (-1, -1), self.BRAND_DARK),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, self.BRAND_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        return table

    def _create_score_table(self, data, styles):
        """Create a score breakdown table with color coding."""
        table = Table(data, colWidths=[200, 120, 80])
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), self.BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("FONTNAME", (0, 1), (-1, -2), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, -1), (-1, -1), 11),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f0f9ff")),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, self.BRAND_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f8fafc")]),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]
        table.setStyle(TableStyle(style_commands))
        return table


# Singleton instance
report_generator = ReportGenerator()
