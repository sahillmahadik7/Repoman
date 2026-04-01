# pdf_generator.py — Generates a clean, professional PDF using reportlab
# No system dependencies — works on Windows out of the box
#
# To install: pip install reportlab

import logging
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.platypus import KeepTogether
from datetime import datetime

# ===== LOGGING =====
logger = logging.getLogger(__name__)

# ===== CONSTANTS - DIMENSIONS =====
MARGIN_H = 15 * mm      # Horizontal margins
MARGIN_V_TOP = 18 * mm  # Top margin
MARGIN_V_BOT = 15 * mm  # Bottom margin
HEADER_HEIGHT = 12 * mm
FOOTER_HEIGHT = 10 * mm
SPACER_LARGE = 20 * mm
SPACER_MED = 6 * mm
SPACER_SMALL = 4 * mm
SPACER_TINY = 3 * mm

# ===== CONSTANTS - FONTS =====
FONT_TITLE = 'Helvetica-Bold'
FONT_BODY = 'Helvetica'
FONT_MONO = 'Courier'
SIZE_COVER_TITLE = 26
SIZE_COVER_SUB = 11
SIZE_SECTION = 14
SIZE_BODY = 9
SIZE_LABEL = 8
SIZE_MONO = 8
SIZE_FINDING = 10
SIZE_HEADER = 8
SIZE_FOOTER = 7

# ===== COLORS =====
BLACK = colors.HexColor('#000000')
WHITE = colors.HexColor('#ffffff')
DARK_GRAY = colors.HexColor('#1a1a2e')
MID_GRAY = colors.HexColor('#4a4a6a')
LIGHT_GRAY = colors.HexColor('#f5f5f5')
BORDER_GRAY = colors.HexColor('#cccccc')
ACCENT_GREEN = colors.HexColor('#00cc88')
ACCENT_BLUE = colors.HexColor('#2c5282')
ACCENT_RED = colors.HexColor('#ff4444')
ACCENT_GRAY = colors.HexColor('#eeeeee')

SEV_COLORS = {
    'CRITICAL':      colors.HexColor('#c0392b'),
    'HIGH':          colors.HexColor('#e67e22'),
    'MEDIUM':        colors.HexColor('#f39c12'),
    'LOW':           colors.HexColor('#2980b9'),
    'INFORMATIONAL': colors.HexColor('#7f8c8d'),
}

SEV_BG = {
    'CRITICAL':      colors.HexColor('#fdf0f0'),
    'HIGH':          colors.HexColor('#fef5ec'),
    'MEDIUM':        colors.HexColor('#fefbe6'),
    'LOW':           colors.HexColor('#eaf4fb'),
    'INFORMATIONAL': colors.HexColor('#f4f4f4'),
}

# ===== TABLE COLUMN WIDTHS =====
COL_FULL = 170 * mm
COL_STAT_SEV = 55 * mm
COL_STAT_COUNT = 30 * mm
COL_STAT_RISK = 85 * mm
COL_FINDING_DESC = 130 * mm
COL_FINDING_SEV = 40 * mm


# ===== PAGE TEMPLATE (Header & Footer on every page) =====
def make_page_template(canvas, doc):
    """Adds header and footer to every page."""
    try:
        canvas.saveState()
        width, height = A4

        # --- Top border line ---
        canvas.setStrokeColor(DARK_GRAY)
        canvas.setLineWidth(2)
        canvas.line(MARGIN_H, height - HEADER_HEIGHT, width - MARGIN_H, height - HEADER_HEIGHT)

        # --- Header: left = report title, right = page number ---
        canvas.setFont(FONT_TITLE, SIZE_HEADER)
        canvas.setFillColor(DARK_GRAY)
        canvas.drawString(MARGIN_H, height - 9*mm,
                          'CYBERSECURITY VULNERABILITY ASSESSMENT REPORT')

        canvas.setFont(FONT_BODY, SIZE_HEADER)
        canvas.setFillColor(MID_GRAY)
        canvas.drawRightString(width - MARGIN_H, height - 9*mm, f'Page {doc.page}')

        # --- Bottom border line ---
        canvas.setStrokeColor(BORDER_GRAY)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN_H, FOOTER_HEIGHT, width - MARGIN_H, FOOTER_HEIGHT)

        # --- Footer: left = confidential, right = date ---
        canvas.setFont(FONT_BODY, SIZE_FOOTER)
        canvas.setFillColor(MID_GRAY)
        canvas.drawString(
            MARGIN_H, 6*mm, 'CONFIDENTIAL — For authorized personnel only')
        canvas.drawRightString(
            width - MARGIN_H, 6*mm,
            f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}'
        )

        canvas.restoreState()
    except Exception as e:
        logger.error(f"Error creating page template: {e}")


# ===== STYLES =====
def build_styles():
    """Build and return all paragraph styles for the document."""
    try:
        base = getSampleStyleSheet()

        styles = {
            'cover_title': ParagraphStyle(
                'cover_title',
                fontName=FONT_TITLE,
                fontSize=SIZE_COVER_TITLE,
                textColor=WHITE,
                leading=32,
                alignment=TA_LEFT,
            ),
            'cover_sub': ParagraphStyle(
                'cover_sub',
                fontName=FONT_BODY,
                fontSize=SIZE_COVER_SUB,
                textColor=colors.HexColor('#cccccc'),
                leading=16,
                alignment=TA_LEFT,
            ),
            'cover_meta': ParagraphStyle(
                'cover_meta',
                fontName=FONT_BODY,
                fontSize=SIZE_LABEL,
                textColor=colors.HexColor('#aaaaaa'),
                leading=14,
                alignment=TA_LEFT,
            ),
            'section_heading': ParagraphStyle(
                'section_heading',
                fontName=FONT_TITLE,
                fontSize=SIZE_SECTION,
                textColor=DARK_GRAY,
                leading=18,
                spaceBefore=6,
                spaceAfter=4,
            ),
            'body': ParagraphStyle(
                'body',
                fontName=FONT_BODY,
                fontSize=SIZE_BODY,
                textColor=colors.HexColor('#2c2c2c'),
                leading=14,
                spaceAfter=4,
            ),
            'body_bold': ParagraphStyle(
                'body_bold',
                fontName=FONT_TITLE,
                fontSize=SIZE_BODY,
                textColor=colors.HexColor('#1a1a1a'),
                leading=14,
            ),
            'label': ParagraphStyle(
                'label',
                fontName=FONT_TITLE,
                fontSize=SIZE_LABEL,
                textColor=MID_GRAY,
                leading=12,
                spaceAfter=2,
            ),
            'mono': ParagraphStyle(
                'mono',
                fontName=FONT_MONO,
                fontSize=SIZE_MONO,
                textColor=colors.HexColor('#333333'),
                leading=12,
                spaceAfter=2,
            ),
            'finding_title': ParagraphStyle(
                'finding_title',
                fontName=FONT_TITLE,
                fontSize=SIZE_FINDING,
                textColor=colors.HexColor('#1a1a1a'),
                leading=14,
            ),
        }
        return styles
    except Exception as e:
        logger.error(f"Error building styles: {e}")
        raise


# ===== COVER PAGE =====
def build_cover(report_data, styles):
    """Build the cover page with report metadata."""
    try:
        # Validate required fields
        required_fields = ['targets', 'date', 'title', 'overall_risk', 'total_findings']
        for field in required_fields:
            if field not in report_data:
                logger.warning(f"Missing required field in report_data: {field}")

        elements = []
        width, height = A4

        # Extract data with defaults
        target_str = ', '.join(report_data.get('targets', ['Unknown']))
        date_str = report_data.get('date', 'Unknown')
        title_str = report_data.get('title', 'Untitled Report')
        overall = report_data.get('overall_risk', 'Unknown')
        total = report_data.get('total_findings', 0)

        # Create cover content
        cover_content = [
            [Paragraph('', styles['body'])],  # spacer row
            [Paragraph('CYBERSECURITY', ParagraphStyle('ct', fontName=FONT_BODY, fontSize=SIZE_COVER_SUB,
                                                       textColor=colors.HexColor('#aaaaaa'), leading=14))],
            [Paragraph('Vulnerability Assessment Report', ParagraphStyle('ct2', fontName=FONT_TITLE,
                                                                         fontSize=SIZE_COVER_TITLE, textColor=WHITE, leading=30))],
            [Paragraph('&nbsp;', styles['body'])],
            [Paragraph(title_str, ParagraphStyle('ct3', fontName=FONT_TITLE,
                                                 fontSize=SIZE_SECTION, textColor=ACCENT_GREEN, leading=18))],
            [Paragraph('&nbsp;', styles['body'])],
            [Paragraph(f'Target(s): {target_str}', ParagraphStyle('cm', fontName=FONT_BODY,
                                                                  fontSize=SIZE_BODY, textColor=colors.HexColor('#cccccc'), leading=14))],
            [Paragraph(f'Assessment Date: {date_str}', ParagraphStyle('cm2', fontName=FONT_BODY,
                                                                      fontSize=SIZE_BODY, textColor=colors.HexColor('#cccccc'), leading=14))],
            [Paragraph(f'Total Findings: {total}  |  Overall Risk: {overall}',
                       ParagraphStyle('cm3', fontName=FONT_TITLE,
                                      fontSize=SIZE_BODY, textColor=WHITE, leading=14))],
            [Paragraph('&nbsp;', styles['body'])],
            [Paragraph('CONFIDENTIAL', ParagraphStyle('conf', fontName=FONT_TITLE,
                                                      fontSize=SIZE_LABEL, textColor=ACCENT_RED, leading=12))],
        ]

        cover_table = Table(cover_content, colWidths=[COL_FULL])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND',  (0, 0), (-1, -1), DARK_GRAY),
            ('TOPPADDING',  (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [DARK_GRAY]),
        ]))

        elements.append(Spacer(1, SPACER_LARGE))
        elements.append(cover_table)
        elements.append(PageBreak())
        return elements
    except Exception as e:
        logger.error(f"Error building cover page: {e}")
        raise


# ===== SECTION DIVIDER =====
def section_divider(title, styles):
    """Create a section divider with title and horizontal line."""
    return [
        Spacer(1, SPACER_MED),
        Paragraph(title.upper(), styles['section_heading']),
        HRFlowable(width='100%', thickness=1.5, color=DARK_GRAY, spaceAfter=SPACER_SMALL),
    ]


# ===== EXECUTIVE SUMMARY =====
def build_executive_summary(report_data, styles):
    """Build the executive summary section."""
    try:
        elements = []
        elements += section_divider('1. Executive Summary', styles)
        
        summary_text = report_data.get('executive_summary', 'No summary provided.')
        elements.append(Paragraph(summary_text, styles['body']))
        elements.append(Spacer(1, SPACER_SMALL))
        return elements
    except Exception as e:
        logger.error(f"Error building executive summary: {e}")
        return []


# ===== SEVERITY STATS TABLE =====
def build_stats_table(report_data, styles):
    """Build the findings severity summary table."""
    try:
        elements = []
        elements += section_divider('2. Findings Summary', styles)

        stats = report_data.get('severity_stats', {})
        overall = report_data.get('overall_risk', 'Unknown')

        # Stats table
        data = [['Severity', 'Count', 'Risk Level']]
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']

        for sev in severity_order:
            count = stats.get(sev, 0)
            data.append(
                [sev, str(count), '●' * min(count, 5) if count > 0 else '—'])

        data.append(
            ['TOTAL', str(report_data.get('total_findings', 0)), f'Overall: {overall}'])

        t = Table(data, colWidths=[COL_STAT_SEV, COL_STAT_COUNT, COL_STAT_RISK])
        t.setStyle(TableStyle([
            # Header row
            ('BACKGROUND',   (0, 0), (-1, 0), DARK_GRAY),
            ('TEXTCOLOR',    (0, 0), (-1, 0), WHITE),
            ('FONTNAME',     (0, 0), (-1, 0), FONT_TITLE),
            ('FONTSIZE',     (0, 0), (-1, 0), SIZE_BODY),
            ('ALIGN',        (0, 0), (-1, 0), 'CENTER'),

            # Data rows
            ('FONTNAME',     (0, 1), (-1, -1), FONT_BODY),
            ('FONTSIZE',     (0, 1), (-1, -1), SIZE_BODY),
            ('ALIGN',        (1, 1), (1, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -2), [WHITE, LIGHT_GRAY]),

            # Total row
            ('BACKGROUND',   (0, -1), (-1, -1), colors.HexColor('#e8e8e8')),
            ('FONTNAME',     (0, -1), (-1, -1), FONT_TITLE),

            # Grid
            ('GRID',         (0, 0), (-1, -1), 0.5, BORDER_GRAY),
            ('TOPPADDING',   (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING',  (0, 0), (-1, -1), 8),
        ]))

        elements.append(t)
        elements.append(Spacer(1, SPACER_SMALL))
        return elements
    except Exception as e:
        logger.error(f"Error building stats table: {e}")
        return []


# ===== VULNERABILITY FINDINGS =====
def build_findings(report_data, styles):
    """Build the vulnerability findings section."""
    try:
        elements = []
        elements += section_divider('3. Vulnerability Findings', styles)

        vulns = report_data.get('vulnerabilities', [])
        if not vulns:
            elements.append(
                Paragraph('No vulnerabilities identified.', styles['body']))
            return elements

        for i, v in enumerate(vulns, 1):
            sev = v.get('severity', 'UNKNOWN')
            sev_col = SEV_COLORS.get(sev, BLACK)
            sev_bg = SEV_BG.get(sev, WHITE)
            
            cves = ', '.join(v.get('cve', [])) if v.get('cve') else 'N/A'
            cvss = v.get('cvss', 'N/A')
            description = v.get('description', 'No description')

            # Finding block as a table
            block_data = [
                [
                    Paragraph(f'Finding #{i}', styles['label']),
                    Paragraph(sev, ParagraphStyle('sev', fontName=FONT_TITLE,
                                                  fontSize=SIZE_BODY, textColor=sev_col, alignment=TA_RIGHT))
                ],
                [
                    Paragraph(description, styles['finding_title']),
                    ''
                ],
                [
                    Paragraph(f'CVE: {cves}    CVSS: {cvss}', styles['mono']),
                    ''
                ],
            ]

            block = Table(block_data, colWidths=[COL_FINDING_DESC, COL_FINDING_SEV])
            block.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (-1, -1), sev_bg),
                ('BACKGROUND',    (0, 0), (-1, 0),  ACCENT_GRAY),
                ('LEFTPADDING',   (0, 0), (-1, -1), 8),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
                ('TOPPADDING',    (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('SPAN',          (0, 1), (1, 1)),
                ('SPAN',          (0, 2), (1, 2)),
                ('BOX',           (0, 0), (-1, -1), 1, sev_col),
                ('LINEBELOW',     (0, 0), (-1, 0),  0.5, BORDER_GRAY),
            ]))

            elements.append(KeepTogether([block, Spacer(1, SPACER_TINY)]))

        return elements
    except Exception as e:
        logger.error(f"Error building findings section: {e}")
        return []


# ===== GENERIC LIST BUILDER (reduces duplication) =====
def build_list_section(section_title, data_list, styles, use_mono=False):
    """Build any bulleted list section."""
    try:
        elements = []
        if not data_list:
            return elements

        elements += section_divider(section_title, styles)
        style_to_use = styles['mono'] if use_mono else styles['body']
        
        for item in data_list:
            detail = item.get('detail', '') if isinstance(item, dict) else str(item)
            elements.append(Paragraph(f'• {detail}', style_to_use))
        
        elements.append(Spacer(1, SPACER_SMALL))
        return elements
    except Exception as e:
        logger.error(f"Error building list section '{section_title}': {e}")
        return []


# ===== SCAN RESULTS =====
def build_scan_results(report_data, styles):
    """Build the scan tool output section."""
    scans = report_data.get('scan_results', [])
    return build_list_section('4. Scan Tool Output', scans, styles, use_mono=True)


# ===== PENTEST NOTES =====
def build_notes(report_data, styles):
    """Build the penetration test notes section."""
    notes = report_data.get('notes', [])
    return build_list_section('5. Penetration Test Notes', notes, styles, use_mono=False)


# ===== PROOF / EVIDENCE =====
def build_proofs(report_data, styles):
    """Build the evidence and proof of concept section."""
    proofs = report_data.get('proofs', [])
    return build_list_section('6. Evidence & Proof of Concept', proofs, styles, use_mono=False)


# ===== RECOMMENDATIONS =====
def build_recommendations(report_data, styles):
    """Build the remediation recommendations section."""
    try:
        elements = []
        recs = report_data.get('recommendations', [])
        if not recs:
            return elements

        elements += section_divider('7. Remediation Recommendations', styles)

        for i, r in enumerate(recs, 1):
            sev = r.get('severity', 'UNKNOWN')
            sev_col = SEV_COLORS.get(sev, BLACK)
            
            finding = r.get('finding', 'No finding')
            recommendation = r.get('recommendation', 'No recommendation')

            finding_text = Paragraph(
                f'<b>{i}. [{sev}]</b> {finding}',
                ParagraphStyle('rt', fontName=FONT_BODY, fontSize=SIZE_BODY,
                               textColor=colors.HexColor('#1a1a1a'), leading=13)
            )
            rec_text = Paragraph(
                f'→ {recommendation}',
                ParagraphStyle('rec', fontName=FONT_BODY, fontSize=SIZE_BODY,
                               textColor=ACCENT_BLUE, leading=13,
                               leftIndent=10)
            )

            elements.append(KeepTogether(
                [finding_text, rec_text, Spacer(1, SPACER_TINY)]))

        return elements
    except Exception as e:
        logger.error(f"Error building recommendations section: {e}")
        return []


# ===== MAIN GENERATE FUNCTION =====
def generate_pdf(report_data, output_path):
    """
    Main entry point — called by app.py
    Builds and saves the complete PDF report.
    
    Args:
        report_data (dict): Complete report data structure
        output_path (str): Full path where PDF should be saved
        
    Returns:
        str: Path to generated PDF
        
    Raises:
        ValueError: If report_data is invalid
        IOError: If PDF cannot be written
    """
    try:
        # Validate inputs
        if not report_data:
            raise ValueError("report_data cannot be empty")
        if not output_path:
            raise ValueError("output_path must be specified")
            
        logger.info(f"Starting PDF generation for: {output_path}")

        # Validate required fields
        required_fields = ['title', 'date', 'targets', 'overall_risk', 'total_findings']
        for field in required_fields:
            if field not in report_data:
                logger.warning(f"Missing recommended field: {field}")

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=MARGIN_H,
            rightMargin=MARGIN_H,
            topMargin=MARGIN_V_TOP,
            bottomMargin=MARGIN_V_BOT,
            title=report_data.get('title', 'Vulnerability Report'),
            author='CyberReport Generator',
            subject='Vulnerability Assessment Report',
        )

        styles = build_styles()
        elements = []

        # --- Cover Page ---
        elements += build_cover(report_data, styles)

        # --- Report Sections ---
        elements += build_executive_summary(report_data, styles)
        elements += build_stats_table(report_data, styles)
        elements += build_findings(report_data, styles)
        elements += build_scan_results(report_data, styles)
        elements += build_notes(report_data, styles)
        elements += build_proofs(report_data, styles)
        elements += build_recommendations(report_data, styles)

        # --- Build PDF ---
        doc.build(elements, onFirstPage=make_page_template,
                  onLaterPages=make_page_template)

        logger.info(f"PDF successfully generated: {output_path}")
        return output_path
        
    except FileNotFoundError as e:
        logger.error(f"Output directory not found: {e}")
        raise
    except Exception as e:
        logger.error(f"Error generating PDF: {e}", exc_info=True)
        raise
