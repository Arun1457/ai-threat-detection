# generate_report.py
# AI-Driven Unified Threat Detection Platform
# Generates a professional PDF threat report using reportlab
#
# Usage (standalone):   python generate_report.py
# Usage (from dashboard): from generate_report import generate_pdf_report

import os
import datetime
import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────
BASE_DIR   = r"C:\study material\AI_driven threat detection system and response platform"
PRED_FILE  = os.path.join(BASE_DIR, "data",    "predicted_logs.csv")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

# ─────────────────────────────────────────────
# COLOURS
# ─────────────────────────────────────────────
C_RED      = colors.HexColor("#E24B4A")
C_ORANGE   = colors.HexColor("#EF9F27")
C_GREEN    = colors.HexColor("#1D9E75")
C_BLUE     = colors.HexColor("#185FA5")
C_DARK     = colors.HexColor("#1a1a2e")
C_LIGHT    = colors.HexColor("#f5f5f5")
C_WHITE    = colors.white
C_GRAY     = colors.HexColor("#888780")


# ─────────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────────
def generate_pdf_report(data: pd.DataFrame = None, out_path: str = None) -> str:
    """
    Generate a PDF threat report.

    Args:
        data:     predicted_logs DataFrame. If None, loads from PRED_FILE.
        out_path: output PDF path. If None, saves to reports/ with timestamp.

    Returns:
        Path to the generated PDF.
    """
    # Load data if not passed in
    if data is None:
        data = pd.read_csv(PRED_FILE, low_memory=False)

    if out_path is None:
        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(REPORT_DIR, f"threat_report_{ts}.pdf")

    now_str = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    # ── Compute stats ──────────────────────────
    total       = len(data)
    n_anomaly   = int(data["predicted_anomaly"].sum()) if "predicted_anomaly" in data.columns else 0
    n_normal    = total - n_anomaly
    pct_attack  = round(n_anomaly / total * 100, 1) if total else 0
    avg_risk    = round(data["ai_risk_score"].mean(), 1) if "ai_risk_score" in data.columns else 0
    max_risk    = round(data["ai_risk_score"].max(), 1) if "ai_risk_score" in data.columns else 0

    sev_counts  = data["severity"].value_counts().to_dict()         if "severity"        in data.columns else {}
    cat_counts  = data["attack_category"].value_counts().to_dict()  if "attack_category" in data.columns else {}
    port_counts = (data[data["predicted_anomaly"]==1]["Destination Port"]
                   .value_counts().head(10).to_dict()
                   if "Destination Port" in data.columns else {})

    # ── Document setup ─────────────────────────
    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
    )
    W = A4[0] - 4*cm   # usable width

    styles = getSampleStyleSheet()

    # Custom styles
    style_title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22, textColor=C_WHITE,
        spaceAfter=4, spaceBefore=0,
        fontName="Helvetica-Bold",
    )
    style_sub = ParagraphStyle(
        "SubTitle",
        parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#cccccc"),
        spaceAfter=2,
    )
    style_h2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=13, textColor=C_BLUE,
        spaceBefore=14, spaceAfter=4,
        fontName="Helvetica-Bold",
        borderPad=0,
    )
    style_body = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=10, leading=15,
        textColor=colors.HexColor("#333333"),
    )
    style_small = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontSize=8, textColor=C_GRAY,
    )

    story = []

    # ── HEADER BANNER ──────────────────────────
    header_data = [[
        Paragraph("<font color='white'><b>AI-Driven Unified Threat Detection &amp; Response Platform</b></font>", style_title),
    ]]
    header_table = Table(header_data, colWidths=[W])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), C_DARK),
        ("TOPPADDING",  (0,0), (-1,-1), 18),
        ("BOTTOMPADDING",(0,0),(-1,-1), 18),
        ("LEFTPADDING", (0,0), (-1,-1), 16),
        ("RIGHTPADDING",(0,0), (-1,-1), 16),
        ("ROUNDEDCORNERS", [8]),
    ]))
    story.append(header_table)

    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Threat Intelligence Report  |  Generated: {now_str}", style_small))
    story.append(Paragraph("Konkan Gyanpeeth College of Engineering, Karjat  |  Dept. of Computer Science &amp; Engineering  |  2024-25", style_small))
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width=W, thickness=0.5, color=C_GRAY))
    story.append(Spacer(1, 10))

    # ── SECTION 1: EXECUTIVE SUMMARY ───────────
    story.append(Paragraph("1. Executive Summary", style_h2))
    story.append(Paragraph(
        f"This report summarises the AI-driven threat analysis performed on <b>{total:,}</b> network flow records "
        f"sourced from the CICIDS 2017 dataset. The RandomForest classification model identified "
        f"<b>{n_anomaly:,} anomalous flows ({pct_attack}%)</b> and <b>{n_normal:,} benign flows</b>. "
        f"The average AI risk score across all events is <b>{avg_risk}/100</b>, with the highest recorded "
        f"score being <b>{max_risk}/100</b>.",
        style_body
    ))
    story.append(Spacer(1, 10))

    # ── SECTION 2: KPI TABLE ───────────────────
    story.append(Paragraph("2. Key Performance Indicators", style_h2))

    kpi_data = [
        ["Metric", "Value"],
        ["Total Events Analysed",   f"{total:,}"],
        ["Anomalies Detected",       f"{n_anomaly:,}  ({pct_attack}%)"],
        ["Normal / Benign Flows",    f"{n_normal:,}"],
        ["Average AI Risk Score",    f"{avg_risk} / 100"],
        ["Maximum AI Risk Score",    f"{max_risk} / 100"],
        ["Model",                    "RandomForest (100 estimators, max_depth=20)"],
        ["Model Accuracy",           "99.89%"],
        ["ROC-AUC Score",            "0.9999"],
        ["Dataset",                  "CICIDS 2017 (8 files, 2.83M rows)"],
    ]
    kpi_table = Table(kpi_data, colWidths=[W*0.55, W*0.45])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0),  C_DARK),
        ("TEXTCOLOR",    (0,0), (-1,0),  C_WHITE),
        ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_LIGHT, C_WHITE]),
        ("GRID",         (0,0), (-1,-1), 0.3, C_GRAY),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 14))

    # ── SECTION 3: SEVERITY BREAKDOWN ──────────
    story.append(Paragraph("3. Severity Breakdown", style_h2))

    SEV_ORDER  = ["Critical", "High", "Medium", "Low", "Normal"]
    SEV_COLORS = {
        "Critical": C_RED,
        "High":     C_ORANGE,
        "Medium":   colors.HexColor("#FAC775"),
        "Low":      C_GREEN,
        "Normal":   C_GREEN,
    }

    sev_rows = [["Severity", "Count", "% of Total", "Risk Level"]]
    for s in SEV_ORDER:
        cnt = sev_counts.get(s, 0)
        pct = round(cnt / total * 100, 1) if total else 0
        risk = {"Critical":"Immediate action required","High":"Investigate promptly",
                "Medium":"Monitor closely","Low":"Log and review","Normal":"No action"}.get(s,"")
        sev_rows.append([s, f"{cnt:,}", f"{pct}%", risk])

    sev_table = Table(sev_rows, colWidths=[W*0.18, W*0.18, W*0.18, W*0.46])
    sev_style = [
        ("BACKGROUND",   (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",    (0,0), (-1,0), C_WHITE),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("GRID",         (0,0), (-1,-1), 0.3, C_GRAY),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
    ]
    for i, s in enumerate(SEV_ORDER, start=1):
        col = SEV_COLORS.get(s, C_GRAY)
        sev_style.append(("TEXTCOLOR", (0,i), (0,i), col))
        sev_style.append(("FONTNAME",  (0,i), (0,i), "Helvetica-Bold"))

    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)
    story.append(Spacer(1, 14))

    # ── SECTION 4: ATTACK CATEGORIES ───────────
    story.append(Paragraph("4. Attack Category Distribution", style_h2))

    cat_rows = [["Attack Category", "Count", "% of Anomalies"]]
    for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
        if cat == "Normal":
            continue
        pct = round(cnt / n_anomaly * 100, 1) if n_anomaly else 0
        cat_rows.append([cat, f"{cnt:,}", f"{pct}%"])

    cat_table = Table(cat_rows, colWidths=[W*0.5, W*0.25, W*0.25])
    cat_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_DARK),
        ("TEXTCOLOR",     (0,0), (-1,0),  C_WHITE),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_LIGHT, C_WHITE]),
        ("GRID",          (0,0), (-1,-1), 0.3, C_GRAY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ]))
    story.append(cat_table)
    story.append(Spacer(1, 14))

    # ── SECTION 5: TOP TARGETED PORTS ──────────
    if port_counts:
        story.append(Paragraph("5. Top Targeted Destination Ports", style_h2))
        port_rows = [["Destination Port", "Attack Count"]]
        for port, cnt in list(port_counts.items())[:10]:
            port_rows.append([str(int(port)), f"{cnt:,}"])

        port_table = Table(port_rows, colWidths=[W*0.5, W*0.5])
        port_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  C_DARK),
            ("TEXTCOLOR",     (0,0), (-1,0),  C_WHITE),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_LIGHT, C_WHITE]),
            ("GRID",          (0,0), (-1,-1), 0.3, C_GRAY),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ]))
        story.append(port_table)
        story.append(Spacer(1, 14))

    # ── SECTION 6: SOAR RESPONSE SUMMARY ───────
    story.append(Paragraph("6. SOAR Automated Response Summary", style_h2))

    attacks     = data[data["predicted_anomaly"] == 1] if "predicted_anomaly" in data.columns else pd.DataFrame()
    auto_block  = len(attacks[attacks["ai_risk_score"] >= 80])  if "ai_risk_score" in attacks.columns else 0
    investigate = len(attacks[(attacks["ai_risk_score"] >= 50) & (attacks["ai_risk_score"] < 80)]) if "ai_risk_score" in attacks.columns else 0
    monitor     = len(attacks[attacks["ai_risk_score"] < 50])   if "ai_risk_score" in attacks.columns else 0

    soar_data = [
        ["Response Action", "Threshold", "Events", "Description"],
        ["Auto-Block",    "Risk >= 80", f"{auto_block:,}",  "Immediately isolate / block source"],
        ["Investigate",   "Risk 50-79", f"{investigate:,}", "Alert SOC team for manual review"],
        ["Monitor",       "Risk < 50",  f"{monitor:,}",     "Log and watch for escalation"],
    ]
    soar_colors = [C_RED, C_ORANGE, C_GREEN]
    soar_table = Table(soar_data, colWidths=[W*0.2, W*0.2, W*0.15, W*0.45])
    soar_style = [
        ("BACKGROUND",   (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",    (0,0), (-1,0), C_WHITE),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("GRID",         (0,0), (-1,-1), 0.3, C_GRAY),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
    ]
    for i, col in enumerate(soar_colors, start=1):
        soar_style.append(("TEXTCOLOR", (0,i), (0,i), col))
        soar_style.append(("FONTNAME",  (0,i), (0,i), "Helvetica-Bold"))
        soar_style.append(("BACKGROUND",(0,i), (-1,i),
                           colors.HexColor("#fff5f5") if i==1 else
                           colors.HexColor("#fffaf0") if i==2 else C_LIGHT))
    soar_table.setStyle(TableStyle(soar_style))
    story.append(soar_table)
    story.append(Spacer(1, 14))

    # ── SECTION 7: RECOMMENDATIONS ─────────────
    story.append(Paragraph("7. Recommendations", style_h2))
    recs = [
        "<b>Immediate:</b> Investigate all Critical-severity flows — particularly DoS Hulk and DDoS on port 80.",
        "<b>Short-term:</b> Enable automated blocking rules for flows with AI Risk Score above 80.",
        "<b>Medium-term:</b> Integrate VirusTotal and Shodan API keys for live IP reputation enrichment.",
        "<b>Long-term:</b> Retrain the model periodically with new attack signatures to maintain detection accuracy.",
        "<b>Compliance:</b> Archive predicted_logs.csv and this report for audit and regulatory requirements.",
    ]
    for rec in recs:
        story.append(Paragraph(f"&bull;  {rec}", style_body))
        story.append(Spacer(1, 4))

    # ── FOOTER ─────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width=W, thickness=0.5, color=C_GRAY))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "AI-Driven Unified Threat Detection &amp; Response Platform  |  "
        "Konkan Gyanpeeth College of Engineering, Karjat  |  "
        "Department of Computer Science &amp; Engineering  |  Academic Year 2024-25",
        style_small
    ))
    story.append(Paragraph(
        f"Report generated automatically by the platform AI engine  |  {now_str}",
        style_small
    ))

    # ── BUILD PDF ──────────────────────────────
    doc.build(story)
    print(f"✅ PDF report saved → {out_path}")
    return out_path


# ─────────────────────────────────────────────
# Run standalone
# ─────────────────────────────────────────────
if __name__ == "__main__":
    path = generate_pdf_report()
    print(f"Open it at: {path}")
