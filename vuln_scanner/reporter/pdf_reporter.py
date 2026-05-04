# reporter/pdf_reporter.py
"""
WASP PDF Reporter — Phase 2
Generates a professional penetration testing report in PDF format.

Report sections:
  1. Cover page       — target, date, severity summary
  2. Executive summary — AI-generated or fallback overview
  3. Vulnerability details — each finding with full analysis
  4. Open ports        — port scan results
  5. Crawled URLs      — full list of discovered URLs
  6. Remediation table — quick-reference fix table

Requires: reportlab
Install:  pip install reportlab
"""

import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import (
    HexColor, black, white, red, orange, yellow, green, grey
)
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak, HRFlowable,
)

from config import OUTPUT_DIR
from core.logger import get_logger
from core.models import ScanResult, Vulnerability
from core.utils import sanitize_filename

log = get_logger(__name__)

# ── Colour palette ────────────────────────────────────────────────────────────
WASP_DARK    = HexColor("#1a1a2e")
WASP_BLUE    = HexColor("#16213e")
WASP_ACCENT  = HexColor("#0f3460")
WASP_YELLOW  = HexColor("#e94560")

SEV_CRITICAL = HexColor("#7b0000")
SEV_HIGH     = HexColor("#c0392b")
SEV_MEDIUM   = HexColor("#e67e22")
SEV_LOW      = HexColor("#27ae60")
SEV_INFO     = HexColor("#2980b9")

PAGE_BG      = HexColor("#f8f9fa")
TABLE_HEADER = HexColor("#2c3e50")
TABLE_ALT    = HexColor("#ecf0f1")


def _sev_color(severity: str):
    return {
        "CRITICAL": SEV_CRITICAL,
        "HIGH":     SEV_HIGH,
        "MEDIUM":   SEV_MEDIUM,
        "LOW":      SEV_LOW,
        "INFO":     SEV_INFO,
    }.get(severity.upper(), grey)


def generate(
    scan_result: ScanResult,
    ai_analyses: dict | None = None,
    executive_summary: str = "",
) -> str:
    """
    Generate a professional PDF report from a ScanResult.

    Args:
        scan_result       — the completed scan data
        ai_analyses       — dict of {vuln_index: analysis_dict} from AIAdvisor
        executive_summary — AI-generated or fallback summary string

    Returns path to the generated PDF file.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = sanitize_filename(
        scan_result.target.replace("http://", "").replace("https://", "")
    )
    filename = f"wasp_{safe_name}_{timestamp}.pdf"
    filepath = os.path.join(OUTPUT_DIR, filename)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles  = _build_styles()
    content = []

    # ── 1. Cover page ─────────────────────────────────────────────────────────
    content += _cover_page(scan_result, styles)
    content.append(PageBreak())

    # ── 2. Executive summary ──────────────────────────────────────────────────
    content += _executive_summary_section(
        scan_result, executive_summary, styles
    )
    content.append(PageBreak())

    # ── 3. Vulnerability details ──────────────────────────────────────────────
    if scan_result.vulnerabilities:
        content += _vulnerability_section(
            scan_result.vulnerabilities,
            ai_analyses or {},
            styles,
        )
        content.append(PageBreak())

    # ── 4. Open ports ─────────────────────────────────────────────────────────
    if scan_result.open_ports:
        content += _ports_section(scan_result.open_ports, styles)
        content.append(PageBreak())

    # ── 5. Crawled URLs ───────────────────────────────────────────────────────
    if scan_result.urls_crawled:
        content += _urls_section(scan_result.urls_crawled, styles)

    doc.build(content)
    log.info(f"PDF report saved: {filepath}")
    return filepath


# ── Section builders ──────────────────────────────────────────────────────────

def _cover_page(scan_result: ScanResult, styles: dict) -> list:
    """Build the cover page with target info and severity summary."""
    items = []

    # Top spacer
    items.append(Spacer(1, 3 * cm))

    # Title
    items.append(Paragraph("WASP", styles["cover_title"]))
    items.append(Paragraph(
        "Web Application Security Probe", styles["cover_subtitle"]
    ))
    items.append(Spacer(1, 0.5 * cm))
    items.append(HRFlowable(
        width="100%", thickness=2, color=WASP_YELLOW
    ))
    items.append(Spacer(1, 0.5 * cm))
    items.append(Paragraph(
        "Security Assessment Report", styles["cover_report_type"]
    ))

    items.append(Spacer(1, 2 * cm))

    # Target info table
    info_data = [
        ["Target",    scan_result.target],
        ["Scan Date", scan_result.start_time[:10]],
        ["Duration",  _calc_duration(scan_result)],
        ["URLs Found", str(len(scan_result.urls_crawled))],
    ]
    info_table = Table(info_data, colWidths=[4 * cm, 12 * cm])
    info_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1), TABLE_HEADER),
        ("TEXTCOLOR",   (0, 0), (0, -1), white),
        ("BACKGROUND",  (1, 0), (1, -1), TABLE_ALT),
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 10),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("PADDING",     (0, 0), (-1, -1), 8),
        ("GRID",        (0, 0), (-1, -1), 0.5, grey),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [white, TABLE_ALT]),
    ]))
    items.append(info_table)

    items.append(Spacer(1, 1.5 * cm))

    # Severity summary table
    vulns = scan_result.vulnerabilities
    sev_counts = {
        "CRITICAL": 0, "HIGH": 0,
        "MEDIUM":   0, "LOW":  0, "INFO": 0
    }
    for v in vulns:
        sev_counts[v.severity.value] = \
            sev_counts.get(v.severity.value, 0) + 1

    items.append(Paragraph("Findings Summary", styles["section_title"]))
    items.append(Spacer(1, 0.3 * cm))

    sev_data = [["Severity", "Count", "Risk Level"]]
    sev_rows = [
        ("CRITICAL", "Immediate action required"),
        ("HIGH",     "Urgent remediation needed"),
        ("MEDIUM",   "Fix within 30 days"),
        ("LOW",      "Fix within 90 days"),
        ("INFO",     "Informational only"),
    ]
    for sev, risk in sev_rows:
        sev_data.append([sev, str(sev_counts[sev]), risk])

    sev_table = Table(sev_data, colWidths=[4 * cm, 3 * cm, 9 * cm])
    sev_styles = [
        ("BACKGROUND",  (0, 0), (-1, 0), TABLE_HEADER),
        ("TEXTCOLOR",   (0, 0), (-1, 0), white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("PADDING",     (0, 0), (-1, -1), 7),
        ("GRID",        (0, 0), (-1, -1), 0.5, grey),
        ("ALIGN",       (1, 0), (1, -1), "CENTER"),
    ]
    for i, (sev, _) in enumerate(sev_rows, 1):
        sev_styles.append(
            ("TEXTCOLOR", (0, i), (0, i), _sev_color(sev))
        )
        sev_styles.append(
            ("FONTNAME", (0, i), (0, i), "Helvetica-Bold")
        )
    sev_table.setStyle(TableStyle(sev_styles))
    items.append(sev_table)

    items.append(Spacer(1, 2 * cm))
    items.append(Paragraph(
        "CONFIDENTIAL — For authorized use only",
        styles["footer_note"]
    ))

    return items


def _executive_summary_section(
    scan_result: ScanResult,
    summary_text: str,
    styles: dict,
) -> list:
    items = []
    items.append(Paragraph("Executive Summary", styles["section_title"]))
    items.append(HRFlowable(width="100%", thickness=1, color=WASP_ACCENT))
    items.append(Spacer(1, 0.5 * cm))

    if summary_text:
        for para in summary_text.split("\n\n"):
            if para.strip():
                items.append(Paragraph(para.strip(), styles["body"]))
                items.append(Spacer(1, 0.3 * cm))
    else:
        total = len(scan_result.vulnerabilities)
        high  = sum(
            1 for v in scan_result.vulnerabilities
            if v.severity.value in ("HIGH", "CRITICAL")
        )
        items.append(Paragraph(
            f"WASP scanned {scan_result.target} and discovered "
            f"{total} vulnerabilities, of which {high} are rated "
            f"HIGH or CRITICAL severity. Immediate remediation is "
            f"recommended for all high-severity findings.",
            styles["body"]
        ))

    return items


def _vulnerability_section(
    vulns: list,
    ai_analyses: dict,
    styles: dict,
) -> list:
    items = []
    items.append(Paragraph("Vulnerability Findings", styles["section_title"]))
    items.append(HRFlowable(width="100%", thickness=1, color=WASP_ACCENT))
    items.append(Spacer(1, 0.5 * cm))

    for i, vuln in enumerate(vulns, 1):
        analysis = ai_analyses.get(i - 1, {})
        items += _single_vuln_block(i, vuln, analysis, styles)
        items.append(Spacer(1, 0.5 * cm))

    return items


def _single_vuln_block(
    index: int,
    vuln: Vulnerability,
    analysis: dict,
    styles: dict,
) -> list:
    items = []
    sev_color = _sev_color(vuln.severity.value)

    # Finding header
    items.append(Paragraph(
        f"[{index}] {vuln.vuln_type}",
        styles["vuln_title"]
    ))

    # Metadata table
    meta_data = [
        ["Severity",  vuln.severity.value],
        ["URL",       vuln.url[:80]],
        ["Parameter", vuln.parameter],
        ["Payload",   vuln.payload[:80]],
        ["Evidence",  vuln.evidence[:80]],
    ]
    if analysis.get("cvss_score"):
        meta_data.append(["CVSS Score", str(analysis["cvss_score"])])

    meta_table = Table(meta_data, colWidths=[3.5 * cm, 12.5 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1), WASP_BLUE),
        ("TEXTCOLOR",   (0, 0), (0, -1), white),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",    (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("PADDING",     (0, 0), (-1, -1), 6),
        ("GRID",        (0, 0), (-1, -1), 0.5, grey),
        ("TEXTCOLOR",   (1, 0), (1, 0), sev_color),
        ("FONTNAME",    (1, 0), (1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (1, 1), (1, -1), [white, TABLE_ALT]),
    ]))
    items.append(meta_table)
    items.append(Spacer(1, 0.3 * cm))

    # AI-generated or fallback content
    if analysis.get("explanation"):
        items.append(Paragraph("Description", styles["subsection"]))
        items.append(Paragraph(analysis["explanation"], styles["body"]))
        items.append(Spacer(1, 0.2 * cm))

    if analysis.get("impact"):
        items.append(Paragraph("Impact", styles["subsection"]))
        items.append(Paragraph(analysis["impact"], styles["body"]))
        items.append(Spacer(1, 0.2 * cm))

    if analysis.get("remediation"):
        items.append(Paragraph("Remediation", styles["subsection"]))
        items.append(Paragraph(
            analysis["remediation"].replace("\n", "<br/>"),
            styles["body"]
        ))
        items.append(Spacer(1, 0.2 * cm))

    if analysis.get("code_example"):
        items.append(Paragraph("Secure Code Example", styles["subsection"]))
        items.append(Paragraph(
            analysis["code_example"].replace("\n", "<br/>"),
            styles["code"]
        ))
        items.append(Spacer(1, 0.2 * cm))

    if analysis.get("references"):
        items.append(Paragraph("References", styles["subsection"]))
        for ref in analysis["references"]:
            items.append(Paragraph(f"• {ref}", styles["body_small"]))

    items.append(HRFlowable(width="100%", thickness=0.5, color=grey))
    return items


def _ports_section(ports: list, styles: dict) -> list:
    items = []
    items.append(Paragraph("Open Ports", styles["section_title"]))
    items.append(HRFlowable(width="100%", thickness=1, color=WASP_ACCENT))
    items.append(Spacer(1, 0.5 * cm))

    data = [["Port", "State", "Service"]]
    for p in ports:
        data.append([str(p.port), p.state, p.service])

    table = Table(data, colWidths=[3 * cm, 4 * cm, 9 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), TABLE_HEADER),
        ("TEXTCOLOR",      (0, 0), (-1, 0), white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("PADDING",        (0, 0), (-1, -1), 6),
        ("GRID",           (0, 0), (-1, -1), 0.5, grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, TABLE_ALT]),
    ]))
    items.append(table)
    return items


def _urls_section(urls: list, styles: dict) -> list:
    items = []
    items.append(Paragraph("Crawled URLs", styles["section_title"]))
    items.append(HRFlowable(width="100%", thickness=1, color=WASP_ACCENT))
    items.append(Spacer(1, 0.5 * cm))

    data = [["#", "URL"]]
    for i, url in enumerate(urls, 1):
        data.append([str(i), url])

    table = Table(data, colWidths=[1.5 * cm, 14.5 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), TABLE_HEADER),
        ("TEXTCOLOR",      (0, 0), (-1, 0), white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 8),
        ("PADDING",        (0, 0), (-1, -1), 5),
        ("GRID",           (0, 0), (-1, -1), 0.5, grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, TABLE_ALT]),
    ]))
    items.append(table)
    return items


# ── Style definitions ─────────────────────────────────────────────────────────

def _build_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontSize=48, textColor=WASP_DARK,
            alignment=TA_CENTER, fontName="Helvetica-Bold",
            spaceAfter=6,
        ),
        "cover_subtitle": ParagraphStyle(
            "cover_subtitle",
            fontSize=16, textColor=WASP_ACCENT,
            alignment=TA_CENTER, fontName="Helvetica",
            spaceAfter=12,
        ),
        "cover_report_type": ParagraphStyle(
            "cover_report_type",
            fontSize=20, textColor=WASP_DARK,
            alignment=TA_CENTER, fontName="Helvetica-Bold",
        ),
        "section_title": ParagraphStyle(
            "section_title",
            fontSize=16, textColor=WASP_DARK,
            fontName="Helvetica-Bold", spaceAfter=6,
        ),
        "subsection": ParagraphStyle(
            "subsection",
            fontSize=10, textColor=WASP_ACCENT,
            fontName="Helvetica-Bold", spaceAfter=3,
        ),
        "vuln_title": ParagraphStyle(
            "vuln_title",
            fontSize=12, textColor=WASP_DARK,
            fontName="Helvetica-Bold", spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body",
            fontSize=9, textColor=black,
            fontName="Helvetica",
            leading=14, alignment=TA_JUSTIFY,
        ),
        "body_small": ParagraphStyle(
            "body_small",
            fontSize=8, textColor=black,
            fontName="Helvetica", leading=12,
        ),
        "code": ParagraphStyle(
            "code",
            fontSize=8, textColor=HexColor("#2c3e50"),
            fontName="Courier", leading=12,
            backColor=HexColor("#f4f4f4"),
            leftIndent=10, rightIndent=10,
        ),
        "footer_note": ParagraphStyle(
            "footer_note",
            fontSize=8, textColor=grey,
            alignment=TA_CENTER, fontName="Helvetica-Oblique",
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _calc_duration(scan_result: ScanResult) -> str:
    try:
        from datetime import datetime
        start = datetime.fromisoformat(scan_result.start_time)
        end   = datetime.fromisoformat(scan_result.end_time)
        delta = end - start
        secs  = int(delta.total_seconds())
        if secs < 60:
            return f"{secs} seconds"
        return f"{secs // 60}m {secs % 60}s"
    except Exception:
        return "N/A"