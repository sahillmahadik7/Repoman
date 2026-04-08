# pdf_generator.py — Generates a clean, professional PDF using reportlab
# No system dependencies — works on Windows out of the box
#
# To install: pip install reportlab

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

# ===== COLORS =====
BLACK = colors.HexColor('#000000')
WHITE = colors.HexColor('#ffffff')
DARK_GRAY = colors.HexColor('#1a1a2e')
MID_GRAY = colors.HexColor('#4a4a6a')
LIGHT_GRAY = colors.HexColor('#f5f5f5')
BORDER_GRAY = colors.HexColor('#cccccc')

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


# ===== PAGE TEMPLATE (Header & Footer on every page) =====
def make_page_template(canvas, doc):
    canvas.saveState()
    width, height = A4

    # --- Top border line ---
    canvas.setStrokeColor(DARK_GRAY)
    canvas.setLineWidth(2)
    canvas.line(15*mm, height - 12*mm, width - 15*mm, height - 12*mm)

    # --- Header: left = report title, right = page number ---
    canvas.setFont('Helvetica-Bold', 8)
    canvas.setFillColor(DARK_GRAY)
    canvas.drawString(15*mm, height - 9*mm,
                      'CYBERSECURITY VULNERABILITY ASSESSMENT REPORT')

    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(MID_GRAY)
    canvas.drawRightString(width - 15*mm, height - 9*mm, f'Page {doc.page}')

    # --- Bottom border line ---
    canvas.setStrokeColor(BORDER_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(15*mm, 10*mm, width - 15*mm, 10*mm)

    # --- Footer: left = confidential, right = date ---
    canvas.setFont('Helvetica', 7)
    canvas.setFillColor(MID_GRAY)
    canvas.drawString(
        15*mm, 6*mm, 'CONFIDENTIAL — For authorized personnel only')
    canvas.drawRightString(
        width - 15*mm, 6*mm,
        f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}'
    )

    canvas.restoreState()


# ===== STYLES =====
def build_styles():
    base = getSampleStyleSheet()

    styles = {
        'cover_title': ParagraphStyle(
            'cover_title',
            fontName='Helvetica-Bold',
            fontSize=26,
            textColor=WHITE,
            leading=32,
            alignment=TA_LEFT,
        ),
        'cover_sub': ParagraphStyle(
            'cover_sub',
            fontName='Helvetica',
            fontSize=11,
            textColor=colors.HexColor('#cccccc'),
            leading=16,
            alignment=TA_LEFT,
        ),
        'cover_meta': ParagraphStyle(
            'cover_meta',
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.HexColor('#aaaaaa'),
            leading=14,
            alignment=TA_LEFT,
        ),
        'section_heading': ParagraphStyle(
            'section_heading',
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=DARK_GRAY,
            leading=18,
            spaceBefore=6,
            spaceAfter=4,
        ),
        'body': ParagraphStyle(
            'body',
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.HexColor('#2c2c2c'),
            leading=14,
            spaceAfter=4,
        ),
        'body_bold': ParagraphStyle(
            'body_bold',
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=colors.HexColor('#1a1a1a'),
            leading=14,
        ),
        'label': ParagraphStyle(
            'label',
            fontName='Helvetica-Bold',
            fontSize=8,
            textColor=MID_GRAY,
            leading=12,
            spaceAfter=2,
        ),
        'mono': ParagraphStyle(
            'mono',
            fontName='Courier',
            fontSize=8,
            textColor=colors.HexColor('#333333'),
            leading=12,
            spaceAfter=2,
        ),
        'finding_title': ParagraphStyle(
            'finding_title',
            fontName='Helvetica-Bold',
            fontSize=10,
            textColor=colors.HexColor('#1a1a1a'),
            leading=14,
        ),
    }
    return styles


# ===== COVER PAGE =====
def build_cover(report_data, styles):
    elements = []
    width, height = A4

    # Dark background block — simulated with a Table
    target_str = ', '.join(report_data['targets'])
    date_str = report_data['date']
    title_str = report_data['title']
    overall = report_data['overall_risk']
    total = report_data['total_findings']

    cover_content = [
        [Paragraph('', styles['body'])],  # spacer row
        [Paragraph('CYBERSECURITY', ParagraphStyle('ct', fontName='Helvetica', fontSize=11,
                                                   textColor=colors.HexColor('#aaaaaa'), leading=14))],
        [Paragraph('Vulnerability Assessment Report', ParagraphStyle('ct2', fontName='Helvetica-Bold',
                                                                     fontSize=24, textColor=WHITE, leading=30))],
        [Paragraph('&nbsp;', styles['body'])],
        [Paragraph(title_str, ParagraphStyle('ct3', fontName='Helvetica-Bold',
                                             fontSize=14, textColor=colors.HexColor('#00cc88'), leading=18))],
        [Paragraph('&nbsp;', styles['body'])],
        [Paragraph(f'Target(s): {target_str}', ParagraphStyle('cm', fontName='Helvetica',
                                                              fontSize=10, textColor=colors.HexColor('#cccccc'), leading=14))],
        [Paragraph(f'Assessment Date: {date_str}', ParagraphStyle('cm2', fontName='Helvetica',
                                                                  fontSize=10, textColor=colors.HexColor('#cccccc'), leading=14))],
        [Paragraph(f'Total Findings: {total}  |  Overall Risk: {overall}',
                   ParagraphStyle('cm3', fontName='Helvetica-Bold',
                                  fontSize=10, textColor=colors.HexColor('#ffffff'), leading=14))],
        [Paragraph('&nbsp;', styles['body'])],
        [Paragraph('CONFIDENTIAL', ParagraphStyle('conf', fontName='Helvetica-Bold',
                                                  fontSize=9, textColor=colors.HexColor('#ff4444'), leading=12))],
    ]

    cover_table = Table(cover_content, colWidths=[170*mm])
    cover_table.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, -1), DARK_GRAY),
        ('TOPPADDING',  (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [DARK_GRAY]),
    ]))

    elements.append(Spacer(1, 20*mm))
    elements.append(cover_table)
    elements.append(PageBreak())
    return elements


# ===== SECTION DIVIDER =====
def section_divider(title, styles):
    return [
        Spacer(1, 6*mm),
        Paragraph(title.upper(), styles['section_heading']),
        HRFlowable(width='100%', thickness=1.5, color=DARK_GRAY, spaceAfter=4),
    ]


# ===== SEVERITY BADGE (text-based) =====
def severity_badge(severity):
    return f'[{severity}]'


# ===== EXECUTIVE SUMMARY =====
def build_executive_summary(report_data, styles):
    elements = []
    elements += section_divider('1. Executive Summary', styles)
    elements.append(
        Paragraph(report_data['executive_summary'], styles['body']))
    elements.append(Spacer(1, 4*mm))
    return elements


# ===== SEVERITY STATS TABLE =====
def build_stats_table(report_data, styles):
    elements = []
    elements += section_divider('2. Findings Summary', styles)

    stats = report_data['severity_stats']
    overall = report_data['overall_risk']

    # Stats table
    data = [['Severity', 'Count', 'Risk Level']]
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']

    for sev in severity_order:
        count = stats.get(sev, 0)
        data.append(
            [sev, str(count), '●' * min(count, 5) if count > 0 else '—'])

    data.append(
        ['TOTAL', str(report_data['total_findings']), f'Overall: {overall}'])

    t = Table(data, colWidths=[55*mm, 30*mm, 85*mm])
    t.setStyle(TableStyle([
        # Header row
        ('BACKGROUND',   (0, 0), (-1, 0), DARK_GRAY),
        ('TEXTCOLOR',    (0, 0), (-1, 0), WHITE),
        ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',     (0, 0), (-1, 0), 9),
        ('ALIGN',        (0, 0), (-1, 0), 'CENTER'),

        # Data rows
        ('FONTNAME',     (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',     (0, 1), (-1, -1), 9),
        ('ALIGN',        (1, 1), (1, -1), 'CENTER'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -2), [WHITE, LIGHT_GRAY]),

        # Total row
        ('BACKGROUND',   (0, -1), (-1, -1), colors.HexColor('#e8e8e8')),
        ('FONTNAME',     (0, -1), (-1, -1), 'Helvetica-Bold'),

        # Grid
        ('GRID',         (0, 0), (-1, -1), 0.5, BORDER_GRAY),
        ('TOPPADDING',   (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',  (0, 0), (-1, -1), 8),
    ]))

    elements.append(t)
    elements.append(Spacer(1, 4*mm))
    return elements


# ===== VULNERABILITY FINDINGS =====
def build_findings(report_data, styles):
    elements = []
    elements += section_divider('4. Vulnerability Findings', styles)

    vulns = report_data['vulnerabilities']
    if not vulns:
        elements.append(
            Paragraph('No vulnerabilities identified.', styles['body']))
        return elements

    for i, v in enumerate(vulns, 1):
        sev = v['severity']
        sev_col = SEV_COLORS.get(sev, BLACK)
        sev_bg = SEV_BG.get(sev, WHITE)
        cves = ', '.join(v['cve']) if v['cve'] else 'N/A'
        cvss = v['cvss'] if v['cvss'] else 'N/A'

        # Finding block as a table
        block_data = [
            [
                Paragraph(f'Finding #{i}', styles['label']),
                Paragraph(sev, ParagraphStyle('sev', fontName='Helvetica-Bold',
                                              fontSize=9, textColor=sev_col, alignment=TA_RIGHT))
            ],
            [
                Paragraph(v['description'], styles['finding_title']),
                ''
            ],
            [
                Paragraph(f'CVE: {cves}    CVSS: {cvss}', styles['mono']),
                ''
            ],
        ]

        block = Table(block_data, colWidths=[130*mm, 40*mm])
        block.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), sev_bg),
            ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor('#eeeeee')),
            ('LEFTPADDING',   (0, 0), (-1, -1), 8),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
            ('TOPPADDING',    (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('SPAN',          (0, 1), (1, 1)),
            ('SPAN',          (0, 2), (1, 2)),
            ('BOX',           (0, 0), (-1, -1), 1, sev_col),
            ('LINEBELOW',     (0, 0), (-1, 0),  0.5, BORDER_GRAY),
        ]))

        elements.append(KeepTogether([block, Spacer(1, 3*mm)]))

    return elements


# ===== OPEN PORTS TABLE (JSON mode) =====
def build_ports_table(report_data, styles):
    elements = []
    ports = report_data.get('ports_table', [])
    if not ports:
        return elements

    elements += section_divider('3. Network Enumeration — Open Ports', styles)

    # Scan metadata summary
    scan_lines = report_data.get('scan_summary_lines', [])
    if scan_lines:
        for line in scan_lines:
            elements.append(Paragraph(line, styles['mono']))
        elements.append(Spacer(1, 3*mm))

    # Ports table
    data = [['Port', 'Protocol', 'Service', 'Product', 'Version', 'Risk']]
    for p in ports:
        sev_col = SEV_COLORS.get(p['risk'], colors.HexColor('#7f8c8d'))
        data.append([
            str(p['port']),
            p['protocol'],
            p['service'],
            p['product'],
            p['version'],
            Paragraph(p['risk'], ParagraphStyle('risk', fontName='Helvetica-Bold',
                                                fontSize=8, textColor=sev_col, alignment=TA_CENTER)),
        ])

    t = Table(data, colWidths=[18*mm, 22*mm, 30*mm, 35*mm, 30*mm, 25*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  DARK_GRAY),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  WHITE),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0),  9),
        ('ALIGN',         (0, 0), (-1, 0),  'CENTER'),
        ('FONTNAME',      (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',      (0, 1), (-1, -1), 9),
        ('ALIGN',         (0, 1), (1, -1),  'CENTER'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ('GRID',          (0, 0), (-1, -1), 0.5, BORDER_GRAY),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
    ]))

    elements.append(t)
    elements.append(Spacer(1, 4*mm))
    return elements


# ===== SCAN RESULTS =====
def build_scan_results(report_data, styles):
    elements = []
    scans = report_data['scan_results']
    if not scans:
        return elements

    elements += section_divider('5. Scan Tool Output', styles)
    for s in scans:
        elements.append(Paragraph(f'• {s["detail"]}', styles['mono']))
    elements.append(Spacer(1, 4*mm))
    return elements


# ===== PENTEST NOTES =====
def build_notes(report_data, styles):
    elements = []
    notes = report_data['notes']
    if not notes:
        return elements

    elements += section_divider('6. Penetration Test Notes', styles)
    for n in notes:
        elements.append(Paragraph(f'• {n["detail"]}', styles['body']))
    elements.append(Spacer(1, 4*mm))
    return elements


# ===== PROOF / EVIDENCE =====
def build_proofs(report_data, styles):
    elements = []
    proofs = report_data['proofs']
    if not proofs:
        return elements

    elements += section_divider('7. Evidence & Proof of Concept', styles)
    for p in proofs:
        elements.append(Paragraph(f'• {p["detail"]}', styles['body']))
    elements.append(Spacer(1, 4*mm))
    return elements


# ===== RECOMMENDATIONS =====
def build_recommendations(report_data, styles):
    elements = []
    recs = report_data['recommendations']
    if not recs:
        return elements

    elements += section_divider('8. Remediation Recommendations', styles)

    for i, r in enumerate(recs, 1):
        sev = r['severity']
        sev_col = SEV_COLORS.get(sev, BLACK)

        finding_text = Paragraph(
            f'<b>{i}. [{sev}]</b> {r["finding"]}',
            ParagraphStyle('rt', fontName='Helvetica', fontSize=9,
                           textColor=colors.HexColor('#1a1a1a'), leading=13)
        )
        rec_text = Paragraph(
            f'→ {r["recommendation"]}',
            ParagraphStyle('rec', fontName='Helvetica', fontSize=9,
                           textColor=colors.HexColor('#2c5282'), leading=13,
                           leftIndent=10)
        )

        elements.append(KeepTogether(
            [finding_text, rec_text, Spacer(1, 3*mm)]))

    return elements


# ===== MAIN GENERATE FUNCTION =====
def generate_pdf(report_data, output_path):
    """
    Main entry point — called by app.py
    Builds and saves the complete PDF report.
    """

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=15*mm,
        rightMargin=15*mm,
        topMargin=18*mm,
        bottomMargin=15*mm,
        title=report_data['title'],
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
    elements += build_ports_table(report_data, styles)
    elements += build_findings(report_data, styles)
    elements += build_scan_results(report_data, styles)
    elements += build_notes(report_data, styles)
    elements += build_proofs(report_data, styles)
    elements += build_recommendations(report_data, styles)

    # --- Build PDF ---
    doc.build(elements, onFirstPage=make_page_template,
              onLaterPages=make_page_template)

    return output_path
