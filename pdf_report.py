from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import io

# Colors
COL_BG      = colors.HexColor('#0f1117')
COL_CARD    = colors.HexColor('#1a1d27')
COL_BORDER  = colors.HexColor('#2d3148')
COL_WHITE   = colors.HexColor('#e2e8f0')
COL_GREY    = colors.HexColor('#64748b')
COL_MID     = colors.HexColor('#94a3b8')
COL_PURPLE  = colors.HexColor('#6366f1')
COL_RED     = colors.HexColor('#dc2626')
COL_ORANGE  = colors.HexColor('#ea580c')
COL_YELLOW  = colors.HexColor('#d97706')
COL_GREEN   = colors.HexColor('#16a34a')
COL_RED_BG  = colors.HexColor('#3b0f0f')
COL_ORG_BG  = colors.HexColor('#3b1a0a')
COL_YEL_BG  = colors.HexColor('#3b2a05')
COL_GRN_BG  = colors.HexColor('#0a2e1a')

def risk_color(risk):
    return {
        'CRITICAL': COL_RED,
        'HIGH':     COL_ORANGE,
        'MEDIUM':   COL_YELLOW,
        'LOW':      COL_GREEN,
        'SAFE':     COL_GREEN,
    }.get(risk.upper(), COL_GREY)

def risk_bg(risk):
    return {
        'CRITICAL': COL_RED_BG,
        'HIGH':     COL_ORG_BG,
        'MEDIUM':   COL_YEL_BG,
        'LOW':      COL_GRN_BG,
        'SAFE':     COL_GRN_BG,
    }.get(risk.upper(), COL_CARD)

def make_styles():
    return {
        'title': ParagraphStyle('title',
            fontName='Helvetica-Bold', fontSize=22,
            textColor=COL_WHITE, spaceAfter=4, leading=28),
        'subtitle': ParagraphStyle('subtitle',
            fontName='Helvetica', fontSize=10,
            textColor=COL_GREY, spaceAfter=16),
        'h2': ParagraphStyle('h2',
            fontName='Helvetica-Bold', fontSize=13,
            textColor=COL_WHITE, spaceBefore=16, spaceAfter=8),
        'h3': ParagraphStyle('h3',
            fontName='Helvetica-Bold', fontSize=10,
            textColor=COL_WHITE, spaceBefore=4, spaceAfter=3),
        'body': ParagraphStyle('body',
            fontName='Helvetica', fontSize=9,
            textColor=COL_MID, leading=14, spaceAfter=4),
        'small': ParagraphStyle('small',
            fontName='Helvetica', fontSize=8,
            textColor=COL_GREY, leading=12),
        'center': ParagraphStyle('center',
            fontName='Helvetica-Bold', fontSize=10,
            textColor=COL_WHITE, alignment=TA_CENTER),
        'grade': ParagraphStyle('grade',
            fontName='Helvetica-Bold', fontSize=28,
            textColor=COL_WHITE, alignment=TA_CENTER, leading=34),
        'score': ParagraphStyle('score',
            fontName='Helvetica-Bold', fontSize=42,
            textColor=COL_WHITE, alignment=TA_CENTER, leading=48),
    }

def generate_pdf(results):
    buffer = io.BytesIO()
    S = make_styles()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20*2.83, rightMargin=20*2.83,
        topMargin=20*2.83, bottomMargin=20*2.83,
        title=f"Anirod Security Report - {results['filename']}",
        author="Anirod Android Security Scanner"
    )

    story = []
    grade = results['grade']
    score = results['risk_score']
    g_color = risk_color(grade.split()[0])

    # ── HEADER ──────────────────────────────────────────
    story.append(Paragraph("ANIROD", ParagraphStyle('brand',
        fontName='Helvetica-Bold', fontSize=11,
        textColor=COL_PURPLE, spaceAfter=8)))

    story.append(Paragraph(
        "Android Security Scanner Report",
        S['title']))

    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}  |  "
        f"App: {results['filename']}",
        S['subtitle']))

    story.append(HRFlowable(
        width="100%", thickness=1,
        color=COL_BORDER, spaceAfter=16))

    # ── RISK SCORE BANNER ────────────────────────────────
    score_data = [[
        Paragraph(f"{score}", ParagraphStyle('sc',
            fontName='Helvetica-Bold', fontSize=44,
            textColor=g_color, alignment=TA_CENTER, leading=50)),
        Paragraph(
            f"<b>{grade}</b><br/><br/>"
            f"{results['summary']}",
            ParagraphStyle('gd', fontName='Helvetica',
                fontSize=10, textColor=COL_MID,
                leading=16)),
    ]]

    score_table = Table(score_data, colWidths=[80, 370])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), COL_CARD),
        ('ROUNDEDCORNERS', [8]),
        ('BOX', (0,0), (-1,-1), 1, COL_BORDER),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 16),
        ('RIGHTPADDING', (0,0), (-1,-1), 16),
        ('TOPPADDING', (0,0), (-1,-1), 16),
        ('BOTTOMPADDING', (0,0), (-1,-1), 16),
        ('LINEAFTER', (0,0), (0,-1), 1, COL_BORDER),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 12))

    # ── ISSUE COUNT SUMMARY ──────────────────────────────
    counts = results['counts']
    summary_data = [[
        Paragraph(f"<b>{counts['CRITICAL']}</b><br/>CRITICAL",
            ParagraphStyle('c', fontName='Helvetica-Bold', fontSize=9,
                textColor=COL_RED, alignment=TA_CENTER, leading=14)),
        Paragraph(f"<b>{counts['HIGH']}</b><br/>HIGH",
            ParagraphStyle('h', fontName='Helvetica-Bold', fontSize=9,
                textColor=COL_ORANGE, alignment=TA_CENTER, leading=14)),
        Paragraph(f"<b>{counts['MEDIUM']}</b><br/>MEDIUM",
            ParagraphStyle('m', fontName='Helvetica-Bold', fontSize=9,
                textColor=COL_YELLOW, alignment=TA_CENTER, leading=14)),
        Paragraph(f"<b>{counts['LOW']}</b><br/>LOW",
            ParagraphStyle('l', fontName='Helvetica-Bold', fontSize=9,
                textColor=COL_GREEN, alignment=TA_CENTER, leading=14)),
        Paragraph(f"<b>{results['total_issues']}</b><br/>TOTAL",
            ParagraphStyle('t', fontName='Helvetica-Bold', fontSize=9,
                textColor=COL_WHITE, alignment=TA_CENTER, leading=14)),
    ]]

    summary_table = Table(summary_data, colWidths=[90]*5)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), COL_CARD),
        ('BOX', (0,0), (-1,-1), 1, COL_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, COL_BORDER),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # ── HELPER: finding rows ─────────────────────────────
    def add_findings_section(icon, title, items, name_key, desc_key, extra_key=None):
        if not items:
            return
        story.append(Paragraph(f"{icon}  {title}", S['h2']))

        for item in items:
            risk = item.get('risk', 'LOW')
            rc = risk_color(risk)
            rb = risk_bg(risk)

            name = item.get(name_key, '')
            desc = item.get(desc_key, '')
            extra = item.get(extra_key, '') if extra_key else ''

            row = [[
                Table([[
                    [Paragraph(f"<b>{name}</b>", S['h3'])],
                    [Paragraph(desc, S['body'])],
                    [Paragraph(extra, S['small'])] if extra else [''],
                ]], colWidths=[340]),
                Paragraph(f"<b>{risk}</b>", ParagraphStyle('r',
                    fontName='Helvetica-Bold', fontSize=8,
                    textColor=rc, alignment=TA_CENTER)),
            ]]

            t = Table(row, colWidths=[370, 80])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), rb),
                ('BOX', (0,0), (-1,-1), 1, rc),
                ('LEFTBORDER', (0,0), (0,-1), 3, rc),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('RIGHTPADDING', (0,0), (-1,-1), 10),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(t)
            story.append(Spacer(1, 5))

    # ── DANGEROUS COMBOS ─────────────────────────────────
    combos = results['findings'].get('dangerous_combos', [])
    if combos:
        story.append(Paragraph("Dangerous Permission Combinations", S['h2']))
        for combo in combos:
            risk = combo.get('risk', 'CRITICAL')
            rc = risk_color(risk)
            rb = risk_bg(risk)
            perms = ', '.join(combo.get('permissions', []))

            row = [[
                Table([[
                    [Paragraph(f"<b>{combo['name']}</b>", S['h3'])],
                    [Paragraph(combo.get('description',''), S['body'])],
                    [Paragraph(f"Permissions: {perms}", S['small'])],
                ]], colWidths=[340]),
                Paragraph(f"<b>{risk}</b>", ParagraphStyle('r',
                    fontName='Helvetica-Bold', fontSize=8,
                    textColor=rc, alignment=TA_CENTER)),
            ]]

            t = Table(row, colWidths=[370, 80])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), rb),
                ('BOX', (0,0), (-1,-1), 1, rc),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('RIGHTPADDING', (0,0), (-1,-1), 10),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(t)
            story.append(Spacer(1, 5))

    # ── PERMISSIONS ──────────────────────────────────────
    add_findings_section(
        "Dangerous Permissions",
        "Dangerous Permissions",
        results['findings'].get('permissions', []),
        name_key='short_name',
        desc_key='description',
        extra_key='category'
    )

    # ── SECRETS ──────────────────────────────────────────
    add_findings_section(
        "Hardcoded Secrets",
        "Hardcoded Secrets Found",
        results['findings'].get('secrets', []),
        name_key='name',
        desc_key='description',
        extra_key='file'
    )

    # ── CODE ISSUES ──────────────────────────────────────
    add_findings_section(
        "Insecure Code Patterns",
        "Insecure Code Patterns",
        results['findings'].get('code_issues', []),
        name_key='name',
        desc_key='description',
        extra_key='file'
    )

    # ── ALL PERMISSIONS LIST ─────────────────────────────
    all_perms = results.get('all_permissions', [])
    if all_perms:
        story.append(Spacer(1, 8))
        story.append(Paragraph("All Requested Permissions", S['h2']))
        short = [p.split('.')[-1] for p in all_perms]
        rows = [short[i:i+3] for i in range(0, len(short), 3)]
        perm_rows = []
        for row in rows:
            while len(row) < 3:
                row.append('')
            perm_rows.append([
                Paragraph(row[0], S['small']),
                Paragraph(row[1], S['small']),
                Paragraph(row[2], S['small']),
            ])
        pt = Table(perm_rows, colWidths=[150]*3)
        pt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), COL_CARD),
            ('BOX', (0,0), (-1,-1), 1, COL_BORDER),
            ('INNERGRID', (0,0), (-1,-1), 0.5, COL_BORDER),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(pt)

    # ── FOOTER ───────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(
        width="100%", thickness=1,
        color=COL_BORDER, spaceAfter=8))
    story.append(Paragraph(
        f"Generated by Anirod Android Security Scanner  |  "
        f"Scan Date: {results['scan_date']}  |  "
        f"For educational and security research purposes only.",
        ParagraphStyle('footer', fontName='Helvetica',
            fontSize=7, textColor=COL_GREY,
            alignment=TA_CENTER)))

    doc.build(story)
    buffer.seek(0)
    return buffer
