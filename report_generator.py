from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime


SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#d32f2f"),
    "HIGH":     colors.HexColor("#f57c00"),
    "MEDIUM":   colors.HexColor("#fbc02d"),
    "LOW":      colors.HexColor("#388e3c"),
}

VERDICT_COLORS = {
    "PHISHING":     colors.HexColor("#d32f2f"),
    "SUSPICIOUS":   colors.HexColor("#f57c00"),
    "LOW RISK":     colors.HexColor("#fbc02d"),
    "LIKELY SAFE":  colors.HexColor("#388e3c"),
}


def generate_pdf(data, output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )

    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle("Title", fontSize=20, fontName="Helvetica-Bold",
                                  textColor=colors.HexColor("#1a1a2e"), alignment=TA_CENTER, spaceAfter=6)
    subtitle_style = ParagraphStyle("Sub", fontSize=10, fontName="Helvetica",
                                     textColor=colors.HexColor("#666666"), alignment=TA_CENTER, spaceAfter=20)
    section_style = ParagraphStyle("Section", fontSize=13, fontName="Helvetica-Bold",
                                    textColor=colors.HexColor("#1a1a2e"), spaceBefore=14, spaceAfter=6)
    body_style = ParagraphStyle("Body", fontSize=9, fontName="Helvetica",
                                 textColor=colors.HexColor("#333333"), spaceAfter=4)
    label_style = ParagraphStyle("Label", fontSize=9, fontName="Helvetica-Bold",
                                  textColor=colors.HexColor("#1a1a2e"))

    parsed = data["parsed"]
    analysis = data["analysis"]
    vt_results = data.get("vt_results", [])

    # Header
    elements.append(Paragraph("PHISHING EMAIL ANALYZER", title_style))
    elements.append(Paragraph(f"Analysis Report — Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")))
    elements.append(Spacer(1, 12))

    # Verdict banner
    verdict = analysis["verdict"]
    vcolor = VERDICT_COLORS.get(verdict, colors.grey)
    verdict_table = Table([[Paragraph(f"VERDICT: {verdict}  |  RISK SCORE: {analysis['risk_score']}/100",
                                       ParagraphStyle("V", fontSize=14, fontName="Helvetica-Bold",
                                                       textColor=colors.white, alignment=TA_CENTER))]],
                           colWidths=[6.5*inch])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), vcolor),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [vcolor]),
        ("TOPPADDING", (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("ROUNDEDCORNERS", [4]),
    ]))
    elements.append(verdict_table)
    elements.append(Spacer(1, 14))

    # Summary stats
    stats_data = [
        [Paragraph("CRITICAL", ParagraphStyle("s", fontSize=10, fontName="Helvetica-Bold", textColor=SEVERITY_COLORS["CRITICAL"], alignment=TA_CENTER)),
         Paragraph("HIGH", ParagraphStyle("s", fontSize=10, fontName="Helvetica-Bold", textColor=SEVERITY_COLORS["HIGH"], alignment=TA_CENTER)),
         Paragraph("MEDIUM", ParagraphStyle("s", fontSize=10, fontName="Helvetica-Bold", textColor=SEVERITY_COLORS["MEDIUM"], alignment=TA_CENTER)),
         Paragraph("LOW", ParagraphStyle("s", fontSize=10, fontName="Helvetica-Bold", textColor=SEVERITY_COLORS["LOW"], alignment=TA_CENTER))],
        [Paragraph(str(analysis["critical"]), ParagraphStyle("n", fontSize=18, fontName="Helvetica-Bold", alignment=TA_CENTER)),
         Paragraph(str(analysis["high"]), ParagraphStyle("n", fontSize=18, fontName="Helvetica-Bold", alignment=TA_CENTER)),
         Paragraph(str(analysis["medium"]), ParagraphStyle("n", fontSize=18, fontName="Helvetica-Bold", alignment=TA_CENTER)),
         Paragraph(str(analysis["low"]), ParagraphStyle("n", fontSize=18, fontName="Helvetica-Bold", alignment=TA_CENTER))]
    ]
    stats_table = Table(stats_data, colWidths=[1.625*inch]*4)
    stats_table.setStyle(TableStyle([
        ("BOX", (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
        ("INNERGRID", (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#f5f5f5")),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 14))

    # Email details
    elements.append(Paragraph("EMAIL DETAILS", section_style))
    details = [
        ["Subject",    parsed["subject"] or "(none)"],
        ["From",       parsed["from"] or "(none)"],
        ["To",         parsed["to"] or "(none)"],
        ["Reply-To",   parsed["reply_to"] or "(none)"],
        ["Date",       parsed["date"] or "(none)"],
        ["Links Found", str(len(parsed["links"]))],
        ["Attachments", str(len(parsed["attachments"]))],
    ]
    detail_table = Table(
        [[Paragraph(r[0], label_style), Paragraph(str(r[1])[:100], body_style)] for r in details],
        colWidths=[1.5*inch, 5*inch]
    )
    detail_table.setStyle(TableStyle([
        ("BOX", (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
        ("INNERGRID", (0,0), (-1,-1), 0.5, colors.HexColor("#eeeeee")),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white]),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
    ]))
    elements.append(detail_table)
    elements.append(Spacer(1, 14))

    # Flags
    elements.append(Paragraph("THREAT INDICATORS", section_style))
    if analysis["flags"]:
        flag_data = [["Severity", "Type", "Detail"]]
        for flag in analysis["flags"]:
            sev = flag["severity"]
            flag_data.append([
                Paragraph(sev, ParagraphStyle("sev", fontSize=8, fontName="Helvetica-Bold",
                                               textColor=colors.white, alignment=TA_CENTER)),
                Paragraph(flag["type"].replace("_", " "), ParagraphStyle("t", fontSize=8, fontName="Helvetica-Bold")),
                Paragraph(flag["detail"][:120], ParagraphStyle("d", fontSize=8, fontName="Helvetica"))
            ])
        flag_table = Table(flag_data, colWidths=[0.9*inch, 1.8*inch, 3.8*inch])
        style_cmds = [
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,0), 9),
            ("BOX", (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
            ("INNERGRID", (0,0), (-1,-1), 0.5, colors.HexColor("#eeeeee")),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
        ]
        for i, flag in enumerate(analysis["flags"], 1):
            sev = flag["severity"]
            bg = SEVERITY_COLORS.get(sev, colors.grey)
            style_cmds.append(("BACKGROUND", (0, i), (0, i), bg))
        flag_table.setStyle(TableStyle(style_cmds))
        elements.append(flag_table)
    else:
        elements.append(Paragraph("No threat indicators detected.", body_style))

    # VT results
    if vt_results:
        elements.append(Spacer(1, 14))
        elements.append(Paragraph("VIRUSTOTAL URL SCAN RESULTS", section_style))
        vt_data = [["URL", "Malicious", "Suspicious", "Verdict"]]
        for r in vt_results:
            if r.get("error"):
                continue
            vt_data.append([
                Paragraph(r["url"][:60], ParagraphStyle("u", fontSize=7, fontName="Helvetica")),
                str(r.get("malicious", "-")),
                str(r.get("suspicious", "-")),
                r.get("verdict", "-")
            ])
        if len(vt_data) > 1:
            vt_table = Table(vt_data, colWidths=[3.5*inch, 1*inch, 1*inch, 1*inch])
            vt_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 8),
                ("BOX", (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
                ("INNERGRID", (0,0), (-1,-1), 0.5, colors.HexColor("#eeeeee")),
                ("ROWBACKGROUNDS", (1,1), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white]),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING", (0,0), (-1,-1), 6),
                ("ALIGN", (1,0), (-1,-1), "CENTER"),
            ]))
            elements.append(vt_table)

    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    elements.append(Paragraph("Generated by Phishing Email Analyzer | For authorized security analysis only.",
                               ParagraphStyle("footer", fontSize=7, fontName="Helvetica",
                                               textColor=colors.grey, alignment=TA_CENTER, spaceBefore=6)))

    doc.build(elements)
    return output_path