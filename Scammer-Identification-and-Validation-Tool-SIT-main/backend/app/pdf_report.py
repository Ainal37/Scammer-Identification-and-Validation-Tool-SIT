"""PDF report generation for scan results using ReportLab.
Customer-friendly, non-technical layout.
"""

import html
import json
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Preformatted,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from .models import Scan, Report, AuditLog


# Rule -> (human-readable title, why it matters)
RULE_MAP: Dict[str, Tuple[str, str]] = {
    "HTTPS missing": ("Unencrypted Connection", "Data can be intercepted by others on the network."),
    "URL shortener": ("URL Shortener", "Shorteners hide the real destination and are often used in scams."),
    "IP-based URL": ("IP Address as Domain", "Legitimate sites usually use domain names, not raw IPs."),
    "IP Address Hostname": ("IP Address Hostname", "IP-based links are common in phishing."),
    "URL Userinfo (@) Trick": ("URL Userinfo (@) Trick", "Attackers hide the real destination."),
    "High keyword concentration": ("High Keyword Concentration", "Multiple phishing keywords indicate targeted phishing."),
    "Suspicious TLD": ("Suspicious Domain Extension", "Free TLDs are often abused for phishing."),
    "Suspicious keywords": ("Suspicious Keywords", "Login/verify/password prompts are common in phishing."),
    "Excessive subdomains": ("Too Many Subdomains", "Complex URLs can hide malicious sites."),
    "Long URL": ("Very Long URL", "Long URLs can hide the real destination."),
    "VirusTotal": ("VirusTotal Check", "Security engines flagged this URL."),
    "URLhaus": ("URLhaus Check", "This URL is in a malware database."),
}

PLAIN_MEANING = {
    "safe": "This URL appears low-risk. No major red flags were detected.",
    "caution": "This URL has some warning signs. It may be harmless, but proceed with care.",
    "suspicious": "This URL may be risky. Several security checks raised concerns.",
    "scam": "This URL is likely dangerous. Multiple indicators suggest a scam or phishing attempt.",
}

_ACTIONS_BY_CATEGORY: Dict[str, Dict[str, Any]] = {
    "safe": {
        "bullets": [
            "Proceed normally, but stay alert.",
            "Check the domain spelling (official-looking, no extra letters).",
            "Do not share OTP/password on any site.",
            "Keep your browser and antivirus updated.",
        ],
        "note": (
            "This link looks low-risk based on current checks, but safety can change. "
            "If the page asks for login/payment suddenly, stop and verify."
        ),
    },
    "caution": {
        "bullets": [
            "Avoid logging in unless you fully trust the website.",
            "Verify the domain using official sources.",
            "Avoid clicking downloads or pop-ups.",
            "If it is a bank/gov/service link, open the official website manually.",
        ],
        "note": (
            "Some warning signs exist. It may be harmless, but it is not fully clean. "
            "Treat carefully and avoid sharing personal data."
        ),
    },
    "suspicious": {
        "bullets": [
            "Do not enter passwords, OTP, IC, or banking details.",
            "Close the page if it shows urgency (e.g., \"verify now\", \"account locked\").",
            "Screenshot and report it to admin/IT/security.",
            "Scan the URL using threat intel tools (VirusTotal / URLhaus) before sharing.",
        ],
        "note": (
            "Multiple red flags match scam/phishing patterns. "
            "Best action is to avoid interacting unless verified safe."
        ),
    },
    "scam": {
        "bullets": [
            "Do not open the link again.",
            "If you already clicked: run a malware scan and close the page.",
            "If you entered credentials: change passwords immediately and enable 2FA.",
            "If banking info was involved: contact the bank hotline and freeze the account/card.",
            "Report and block the sender.",
        ],
        "note": (
            "High confidence scam. Assume it is designed to steal credentials or money. "
            "Act quickly to reduce risk."
        ),
    },
}

SAFETY_TIPS: List[str] = [
    "Never share OTP/password.",
    "Verify the domain carefully.",
]


def _score_to_category(score: int) -> str:
    """Map a 0-100 score to a risk category string."""
    score = min(max(score, 0), 100)
    if score <= 25:
        return "safe"
    if score <= 50:
        return "caution"
    if score <= 75:
        return "suspicious"
    return "scam"


def get_recommended_actions(
    score: int,
    verdict: str,
    url: str = "",
    reasons: Optional[Any] = None,
) -> Dict[str, Any]:
    """Return recommended-actions payload based on the scan score.

    Returns dict with keys: title, bullets (list[str]), note (str).
    If the verdict disagrees with the score category an extra bullet is added.
    """
    category = _score_to_category(score)
    entry = _ACTIONS_BY_CATEGORY[category]
    bullets = list(entry["bullets"])

    verdict_norm = (verdict or "").strip().lower()
    if verdict_norm == "scam" and category != "scam":
        bullets.append(
            "This result conflicts with the verdict. "
            "Treat as high-risk and verify with threat intel tools."
        )

    return {
        "title": "Recommended actions",
        "bullets": bullets,
        "note": entry["note"],
    }

RISK_BANDS = [
    (0, 25, "Safe", colors.HexColor("#22c55e")),
    (26, 50, "Caution", colors.HexColor("#fbbf24")),
    (51, 75, "Suspicious", colors.HexColor("#f97316")),
    (76, 100, "Scam", colors.HexColor("#dc2626")),
]


def _parse_breakdown(scan: Scan) -> List[Dict[str, Any]]:
    """Parse breakdown JSON from scan. Returns list of dicts."""
    if not scan.breakdown:
        return []
    try:
        data = json.loads(scan.breakdown)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _parse_intel(scan: Scan) -> Dict[str, Any]:
    """Parse intel_summary JSON from scan."""
    if not scan.intel_summary:
        return {}
    try:
        data = json.loads(scan.intel_summary)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _escape_html(text: str) -> str:
    """Escape text for use in ReportLab Paragraph (HTML subset)."""
    return html.escape(str(text or ""), quote=True)


def _rule_to_human(rule: str) -> Tuple[str, str]:
    """Return (title, why_it_matters) for a rule. Never returns '?'."""
    r = (rule or "").strip()
    if r in RULE_MAP:
        return RULE_MAP[r]
    return (r or "Other check", "This factor contributed to the risk score.")


def _format_intel_virustotal(vt: Dict[str, Any]) -> str:
    if not vt:
        return "Not checked"
    if not vt.get("available"):
        return vt.get("error", "Not checked")
    if vt.get("error"):
        return vt["error"]
    if not vt.get("found"):
        return "Not in database"
    pos = vt.get("positives", 0)
    total = vt.get("total", 0)
    if pos > 0:
        return f"{pos}/{total} engines flagged"
    return "Clean"


def _format_intel_urlhaus(uh: Dict[str, Any]) -> str:
    if not uh:
        return "Not checked"
    if not uh.get("available"):
        return uh.get("error", "Not checked")
    if uh.get("error"):
        return uh["error"]
    if not uh.get("found"):
        return "Clean"
    threat = uh.get("threat", "malicious")
    return f"Threat: {threat}"


def generate_scan_pdf(scan: Scan) -> bytes:
    """Generate a customer-friendly PDF report for a scan. Returns PDF bytes."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    elements = []
    meta_style = styles["Normal"]
    small_style = ParagraphStyle(
        name="Small",
        parent=meta_style,
        fontSize=9,
        spaceBefore=2,
        spaceAfter=2,
    )

    # 1. Title
    title_style = ParagraphStyle(
        name="ReportTitle",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
        alignment=TA_CENTER,
    )
    elements.append(Paragraph("SIT Scan Report", title_style))
    elements.append(Spacer(1, 0.15 * inch))

    # 2. Meta
    created = str(scan.created_at) if scan.created_at else "N/A"
    url_display = (scan.link or "")[:200] + ("..." if len(scan.link or "") > 200 else "")
    elements.append(Paragraph(f"<b>Report ID:</b> #{scan.id}", meta_style))
    elements.append(Paragraph(f"<b>Timestamp:</b> {created}", meta_style))
    elements.append(Paragraph(f"<b>URL:</b> {url_display}", meta_style))
    elements.append(Spacer(1, 0.2 * inch))

    # 3. Executive Summary
    verdict = (scan.verdict or "safe").lower()
    score = min(max(scan.score, 0), 100)
    category = _score_to_category(score)
    verdict_badge = category.upper()
    verdict_color = {
        "safe": "green", "caution": "#b8860b",
        "suspicious": "orange", "scam": "red",
    }.get(category, "black")
    elements.append(Paragraph("<b>Executive Summary</b>", meta_style))
    elements.append(Spacer(1, 0.08 * inch))
    elements.append(Paragraph(
        f"<b>Result:</b> <font color='{verdict_color}' size='12'><b>{verdict_badge}</b></font>",
        meta_style,
    ))
    elements.append(Paragraph(f"<b>Threat Level:</b> {scan.threat_level or 'N/A'} | <b>Score:</b> {score}/100", meta_style))
    elements.append(Spacer(1, 0.05 * inch))
    elements.append(Paragraph(PLAIN_MEANING.get(category, PLAIN_MEANING["safe"]), meta_style))
    elements.append(Spacer(1, 0.08 * inch))

    actions = get_recommended_actions(score, verdict, scan.link or "")
    elements.append(Paragraph(f"<b>{actions['title']}:</b>", meta_style))
    for bullet in actions["bullets"]:
        elements.append(Paragraph(f"&bull; {_escape_html(bullet)}", small_style))
    elements.append(Spacer(1, 0.06 * inch))
    elements.append(Paragraph(_escape_html(actions["note"]), small_style))
    elements.append(Spacer(1, 0.2 * inch))

    # 4. Risk Meter
    elements.append(Paragraph("<b>Risk Meter</b>", meta_style))
    elements.append(Spacer(1, 0.05 * inch))
    band_data = []
    band_col_w = 1.2 * inch
    for lo, hi, label, col in RISK_BANDS:
        in_band = lo <= score <= hi
        cell_text = f"{label}\n({lo}-{hi})"
        band_data.append(cell_text)
    risk_table = Table([band_data], colWidths=[band_col_w] * 4, rowHeights=[0.35 * inch])
    risk_styles = []
    for i, (lo, hi, _, col) in enumerate(RISK_BANDS):
        in_band = lo <= score <= hi
        risk_styles.append(("BACKGROUND", (i, 0), (i, 0), col))
        if in_band:
            risk_styles.append(("BOX", (i, 0), (i, 0), 2, colors.black))
            risk_styles.append(("FONTNAME", (i, 0), (i, 0), "Helvetica-Bold"))
        risk_styles.append(("VALIGN", (i, 0), (i, 0), "MIDDLE"))
        risk_styles.append(("ALIGN", (i, 0), (i, 0), "CENTER"))
        risk_styles.append(("FONTSIZE", (i, 0), (i, 0), 9))
    risk_table.setStyle(TableStyle(risk_styles))
    elements.append(risk_table)
    elements.append(Paragraph(f"<i>Your score: {score}/100</i>", small_style))
    elements.append(Spacer(1, 0.2 * inch))

    # 5. Top Reasons (from breakdown)
    breakdown = _parse_breakdown(scan)
    elements.append(Paragraph("<b>Top Reasons</b>", meta_style))
    elements.append(Spacer(1, 0.08 * inch))
    if breakdown:
        sorted_bd = sorted(breakdown, key=lambda x: (x.get("points") or x.get("score") or 0), reverse=True)[:5]
        for item in sorted_bd:
            if not isinstance(item, dict):
                continue
            rule = item.get("rule") or item.get("factor") or item.get("name") or ""
            title, why = _rule_to_human(rule)
            evidence = str(item.get("detail") or item.get("reason") or item.get("details") or "")[:120]
            elements.append(Paragraph(f"<b>{title}</b>", meta_style))
            elements.append(Paragraph(f"Why it matters: {why}", small_style))
            elements.append(Paragraph(f"Evidence: {evidence or 'N/A'}", small_style))
            elements.append(Spacer(1, 0.06 * inch))
    else:
        elements.append(Paragraph("No risk factors detected.", small_style))
    elements.append(Spacer(1, 0.15 * inch))

    # 6. Breakdown Table (fixed column widths, wrapped text, no overflow)
    # A4 width 595.28 pt, margins 0.75" each = 54 pt, available = 487.28 pt
    # Factor: 110 | Points: 45 | Evidence: 140 | Why it matters: 192.28
    COL_FACTOR = 110
    COL_POINTS = 45
    COL_EVIDENCE = 140
    COL_WHY = 487.28 - COL_FACTOR - COL_POINTS - COL_EVIDENCE  # ~192.28
    WHY_MAX_CHARS = 95  # ~2 lines at col width; full text goes to Notes if truncated

    table_cell_style = ParagraphStyle(
        name="TableCell",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        spaceBefore=0,
        spaceAfter=0,
    )

    if breakdown:
        elements.append(Paragraph("<b>Detailed Breakdown</b>", meta_style))
        elements.append(Spacer(1, 0.08 * inch))
        header_white = '<font color="white">'
        table_data = [
            [
                Paragraph(f"{header_white}<b>Factor</b></font>", table_cell_style),
                Paragraph(f"{header_white}<b>Points</b></font>", table_cell_style),
                Paragraph(f"{header_white}<b>Evidence</b></font>", table_cell_style),
                Paragraph(f"{header_white}<b>Why it matters</b></font>", table_cell_style),
            ]
        ]
        notes_items: List[str] = []

        for item in breakdown[:20]:
            if isinstance(item, dict):
                rule = item.get("rule") or item.get("factor") or item.get("name") or ""
                title, why = _rule_to_human(rule)
                pts = item.get("points") or item.get("score") or ""
                pts_str = str(pts) if pts != "" else ""
                evidence = _escape_html(
                    item.get("detail") or item.get("reason") or item.get("details") or ""
                )
                why_escaped = _escape_html(why)

                # Truncate "Why it matters" if too long; store full for Notes
                if len(why) > WHY_MAX_CHARS:
                    why_display = _escape_html(why[:WHY_MAX_CHARS].rstrip() + "\u2026")
                    notes_items.append(f"{title}: {why}")
                else:
                    why_display = why_escaped

                cell_factor = Paragraph(_escape_html(title), table_cell_style)
                cell_pts = Paragraph(pts_str, table_cell_style)
                cell_evidence = Paragraph(evidence or "—", table_cell_style)
                cell_why = Paragraph(why_display, table_cell_style)
                table_data.append([cell_factor, cell_pts, cell_evidence, cell_why])
            else:
                fallback = "This factor contributed to the risk score."
                table_data.append([
                    Paragraph("Other check", table_cell_style),
                    Paragraph("", table_cell_style),
                    Paragraph("—", table_cell_style),
                    Paragraph(_escape_html(fallback), table_cell_style),
                ])

        t = Table(
            table_data,
            colWidths=[COL_FACTOR, COL_POINTS, COL_EVIDENCE, COL_WHY],
        )
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(t)

        if notes_items:
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph("<b>Notes</b>", small_style))
            for note in notes_items:
                elements.append(Paragraph(f"&bull; {_escape_html(note)}", table_cell_style))

        elements.append(Spacer(1, 0.15 * inch))

    # 7. Intel Summary (readable)
    intel = _parse_intel(scan)
    elements.append(Paragraph("<b>Threat Intelligence</b>", meta_style))
    elements.append(Spacer(1, 0.08 * inch))
    vt = intel.get("virustotal", {}) if intel else {}
    uh = intel.get("urlhaus", {}) if intel else {}
    vt_status = "Checked" if vt.get("available") else "Not checked"
    uh_status = "Checked" if uh.get("available") else "Not checked"
    vt_result = _format_intel_virustotal(vt)
    uh_result = _format_intel_urlhaus(uh)
    elements.append(Paragraph(f"<b>VirusTotal:</b> {vt_status}", meta_style))
    elements.append(Paragraph(f"Result: {vt_result}", small_style))
    elements.append(Spacer(1, 0.05 * inch))
    elements.append(Paragraph(f"<b>URLhaus:</b> {uh_status}", meta_style))
    elements.append(Paragraph(f"Result: {uh_result}", small_style))
    elements.append(Spacer(1, 0.15 * inch))

    # 8. Safety Tips
    elements.append(Paragraph("<b>Safety Tips</b>", meta_style))
    elements.append(Spacer(1, 0.05 * inch))
    for tip in SAFETY_TIPS:
        elements.append(Paragraph(f"&bull; {_escape_html(tip)}", small_style))
    elements.append(Spacer(1, 0.2 * inch))

    # 9. Appendix (raw intel)
    if intel:
        elements.append(Paragraph("<b>Appendix: Raw Intel Data</b>", small_style))
        elements.append(Spacer(1, 0.05 * inch))
        intel_str = json.dumps(intel, indent=2, default=str)[:2000]
        elements.append(Preformatted(intel_str, ParagraphStyle(name="Appendix", fontSize=7, fontName="Courier")))
        elements.append(Spacer(1, 0.15 * inch))

    # 10. Footer
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    footer_style = ParagraphStyle(
        name="Footer",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.grey,
        alignment=TA_CENTER,
    )
    elements.append(Paragraph(
        f"Report ID: #{scan.id} | Generated: {gen_time} | SIT-System v2.0",
        footer_style,
    ))

    doc.build(elements)
    return buffer.getvalue()


def generate_case_pdf(report: Report, scan: Optional[Scan], audit_entries: List[Any]) -> bytes:
    """Generate case PDF: report + linked scan summary + audit entries. Returns PDF bytes."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    elements = []
    meta_style = styles["Normal"]
    small_style = ParagraphStyle(
        name="CaseSmall",
        parent=meta_style,
        fontSize=9,
        spaceBefore=2,
        spaceAfter=2,
    )

    # 1. Title
    title_style = ParagraphStyle(
        name="CaseTitle",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
        alignment=TA_CENTER,
    )
    elements.append(Paragraph("SIT Case Evidence Pack", title_style))
    elements.append(Spacer(1, 0.15 * inch))

    # 2. Report Section
    elements.append(Paragraph("<b>Report Details</b>", meta_style))
    elements.append(Spacer(1, 0.08 * inch))
    elements.append(Paragraph(f"<b>Report ID:</b> #{report.id}", meta_style))
    elements.append(Paragraph(f"<b>Link:</b> {_escape_html((report.link or '—')[:300])}", meta_style))
    elements.append(Paragraph(f"<b>Type:</b> {_escape_html(report.report_type or '—')}", meta_style))
    elements.append(Paragraph(f"<b>Status:</b> {_escape_html(report.status or '—')}", meta_style))
    elements.append(Paragraph(f"<b>Assignee:</b> {_escape_html(report.assignee or '—')}", meta_style))
    elements.append(Paragraph(f"<b>Priority:</b> {_escape_html(report.priority or '—')}", meta_style))
    due_str = str(report.due_at) if report.due_at else "—"
    elements.append(Paragraph(f"<b>Due:</b> {due_str}", meta_style))
    elements.append(Paragraph(f"<b>Created:</b> {str(report.created_at) if report.created_at else '—'}", meta_style))
    elements.append(Paragraph(f"<b>Description:</b> {_escape_html((report.description or '')[:800])}", meta_style))
    if report.notes:
        elements.append(Paragraph(f"<b>Notes:</b> {_escape_html((report.notes or '')[:500])}", meta_style))
    elements.append(Spacer(1, 0.2 * inch))

    # 3. Linked Scan Section (condensed)
    if scan:
        elements.append(Paragraph("<b>Linked Scan Summary</b>", meta_style))
        elements.append(Spacer(1, 0.08 * inch))
        elements.append(Paragraph(f"<b>Scan ID:</b> #{scan.id}", meta_style))
        elements.append(Paragraph(f"<b>URL:</b> {_escape_html((scan.link or '')[:250])}", meta_style))
        elements.append(Paragraph(f"<b>Verdict:</b> {_escape_html(scan.verdict or '—')} | <b>Score:</b> {scan.score}/100", meta_style))
        elements.append(Paragraph(f"<b>Threat Level:</b> {scan.threat_level or '—'}", meta_style))
        elements.append(Paragraph(f"<b>Reason:</b> {_escape_html((scan.reason or '')[:400])}", meta_style))
        breakdown = _parse_breakdown(scan)
        if breakdown:
            sorted_bd = sorted(breakdown, key=lambda x: (x.get("points") or x.get("score") or 0), reverse=True)[:5]
            elements.append(Paragraph("<b>Top factors:</b>", meta_style))
            for item in sorted_bd:
                if isinstance(item, dict):
                    rule = item.get("rule") or item.get("factor") or item.get("name") or ""
                    title, _ = _rule_to_human(rule)
                    elements.append(Paragraph(f"&bull; {_escape_html(title)}", small_style))
        elements.append(Spacer(1, 0.2 * inch))

    # 4. Audit Entries Table
    elements.append(Paragraph("<b>Audit Trail</b>", meta_style))
    elements.append(Spacer(1, 0.08 * inch))
    if audit_entries:
        table_cell = ParagraphStyle(name="AuditCell", parent=meta_style, fontSize=8, spaceBefore=0, spaceAfter=0)
        audit_data = [
            [
                Paragraph('<font color="white"><b>Actor</b></font>', table_cell),
                Paragraph('<font color="white"><b>Action</b></font>', table_cell),
                Paragraph('<font color="white"><b>Target</b></font>', table_cell),
                Paragraph('<font color="white"><b>Time</b></font>', table_cell),
            ]
        ]
        for a in audit_entries[:50]:
            actor = _escape_html((a.actor_email or "—")[:40])
            action = _escape_html((a.action or "—")[:60])
            target = _escape_html((a.target or "—")[:80])
            created = str(a.created_at) if a.created_at else "—"
            audit_data.append([
                Paragraph(actor, table_cell),
                Paragraph(action, table_cell),
                Paragraph(target, table_cell),
                Paragraph(created, table_cell),
            ])
        page_w = A4[0] - 1.5 * inch
        col_w = [page_w * 0.2, page_w * 0.25, page_w * 0.4, page_w * 0.15]
        t = Table(audit_data, colWidths=col_w)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No audit entries for this case.", small_style))
    elements.append(Spacer(1, 0.2 * inch))

    # 5. Footer
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    footer_style = ParagraphStyle(
        name="CaseFooter",
        parent=meta_style,
        fontSize=8,
        textColor=colors.grey,
        alignment=TA_CENTER,
    )
    elements.append(Paragraph(
        f"Case Report #{report.id} | Generated: {gen_time} | SIT-System v2.0",
        footer_style,
    ))

    doc.build(elements)
    return buffer.getvalue()
