from fastapi import APIRouter
from fastapi.responses import Response
from pydantic import BaseModel
from datetime import datetime
import io

router = APIRouter()

class ReportPayload(BaseModel):
    org_name: str = "Organizzazione"
    sector: str = ""
    aes: float = 0
    aes_level: str = ""
    drs: float = 0
    drs_level: str = ""
    gci: float = 0
    gci_level: str = ""
    quadrant: str = ""
    quadrant_description: str = ""
    composite_score: float = 0
    strategic_gap: float = 0
    ZDR: float = 0; PV: float = 0; AS: float = 0; SC: float = 0; LD: float = 0
    SM: float = 0;  IR: float = 0; TI: float = 0; ZT: float = 0; RC: float = 0
    FA: float = 0;  AP: float = 0; CO: float = 0; VR: float = 0; BE: float = 0

@router.post("/report/executive")
def executive_report(payload: ReportPayload):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
            leftMargin=2.2*cm, rightMargin=2.2*cm, topMargin=2*cm, bottomMargin=2*cm)

        INK   = colors.HexColor("#0D0D0D")
        GRAY  = colors.HexColor("#3D3D3D")
        LGRAY = colors.HexColor("#888888")
        RULE  = colors.HexColor("#D8D4CC")
        BLUE  = colors.HexColor("#1A4A8A")
        RED   = colors.HexColor("#C0392B")
        GREEN = colors.HexColor("#1A7A4A")
        BG    = colors.HexColor("#F7F6F2")
        WHITE = colors.white

        def ps(name, size, color=INK, bold=False, align=TA_LEFT, space_after=6, leading=None):
            return ParagraphStyle(name, fontSize=size, textColor=color,
                fontName="Helvetica-Bold" if bold else "Helvetica",
                alignment=align, spaceAfter=space_after,
                leading=leading or size*1.4)

        story = []

        # Header
        story.append(Paragraph("AEGIS-AI", ps("h1",28,INK,True,space_after=2)))
        story.append(Paragraph("Advanced Exploitability &amp; Governance Intelligence System", ps("s",9,LGRAY,space_after=2)))
        story.append(Paragraph("AI Security Intelligence Report", ps("s2",10,GRAY,space_after=1)))
        story.append(Paragraph(f"{payload.org_name} · {payload.sector}", ps("s3",9,LGRAY,space_after=1)))
        story.append(Paragraph(f"Generato: {datetime.utcnow().strftime('%d %B %Y — %H:%M UTC')}", ps("s4",8,LGRAY,space_after=12,align=TA_LEFT)))
        story.append(HRFlowable(width="100%", thickness=1, color=INK, spaceAfter=16))

        # Scores table
        story.append(Paragraph("AEGIS INTELLIGENCE SCORES", ps("st",8,LGRAY,space_after=8)))

        def score_color(s, inverse=False):
            if inverse:  # higher = better (DRS, GCI)
                return GREEN if s >= 75 else colors.HexColor("#D68910") if s >= 50 else RED
            else:        # higher = worse (AES)
                return GREEN if s <= 25 else colors.HexColor("#D68910") if s <= 55 else RED

        score_data = [
            ["MODULO", "SCORE", "LIVELLO", "DESCRIZIONE"],
            ["AES — AI Exposure Score", f"{payload.aes}/100", payload.aes_level,
             "Esposizione alle vulnerabilità AI-discovered"],
            ["DRS — Defense Readiness Score", f"{payload.drs}/100", payload.drs_level,
             "Maturità dell'apparato difensivo"],
            ["GCI — Governance & Compliance Index", f"{payload.gci}/100", payload.gci_level,
             "Allineamento NIS2, DORA, NIST CSF"],
        ]
        t = Table(score_data, colWidths=[5.5*cm, 2.2*cm, 2.8*cm, 6.5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), INK),
            ("TEXTCOLOR",     (0,0),(-1,0), WHITE),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("BACKGROUND",    (0,1),(-1,1), colors.HexColor("#F7F6F2")),
            ("BACKGROUND",    (0,2),(-1,2), WHITE),
            ("BACKGROUND",    (0,3),(-1,3), colors.HexColor("#F7F6F2")),
            ("TEXTCOLOR",     (0,1),(-1,-1), INK),
            ("GRID",          (0,0),(-1,-1), 0.5, RULE),
            ("ALIGN",         (1,0),(2,-1), "CENTER"),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0),(-1,-1), 8),
            ("BOTTOMPADDING", (0,0),(-1,-1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.5*cm))

        # Quadrant
        story.append(Paragraph("QUADRANTE STRATEGICO", ps("qt",8,LGRAY,space_after=6)))
        q_data = [
            [f"{payload.quadrant}", f"Composite Score: {payload.composite_score}/100"],
            [payload.quadrant_description, f"Strategic Gap: {payload.strategic_gap:+.1f}"],
        ]
        qt = Table(q_data, colWidths=[12*cm, 5*cm])
        qt.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,0), INK),
            ("TEXTCOLOR",  (0,0),(-1,0), WHITE),
            ("FONTNAME",   (0,0),(0,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0),(-1,-1), 8),
            ("TEXTCOLOR",  (0,1),(-1,1), GRAY),
            ("GRID",       (0,0),(-1,-1), 0.5, RULE),
            ("TOPPADDING", (0,0),(-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1),8),
            ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
        ]))
        story.append(qt)
        story.append(Spacer(1, 0.5*cm))

        # Dimensions
        story.append(HRFlowable(width="100%", thickness=0.5, color=RULE, spaceAfter=10))
        story.append(Paragraph("ANALISI DIMENSIONALE", ps("dt",8,LGRAY,space_after=8)))

        dims_data = [["DIMENSIONE", "CODICE", "SCORE"]]
        dims = [
            ("Zero-Day Risk","ZDR",payload.ZDR,"AES"),
            ("Patch Velocity","PV",payload.PV,"AES"),
            ("Attack Surface","AS",payload.AS,"AES"),
            ("Supply Chain Risk","SC",payload.SC,"AES"),
            ("Legacy Debt","LD",payload.LD,"AES"),
            ("SOC Maturity","SM",payload.SM,"DRS"),
            ("Incident Response","IR",payload.IR,"DRS"),
            ("Threat Intelligence","TI",payload.TI,"DRS"),
            ("Zero Trust","ZT",payload.ZT,"DRS"),
            ("Recovery Capability","RC",payload.RC,"DRS"),
            ("Framework Adoption","FA",payload.FA,"GCI"),
            ("AI Policy","AP",payload.AP,"GCI"),
            ("Compliance NIS2/DORA","CO",payload.CO,"GCI"),
            ("Vendor Risk","VR",payload.VR,"GCI"),
            ("Board Engagement","BE",payload.BE,"GCI"),
        ]
        for name, code, score, module in dims:
            dims_data.append([name, code, f"{score:.1f}"])

        dt = Table(dims_data, colWidths=[8*cm, 2.5*cm, 6.5*cm])
        dt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), INK),
            ("TEXTCOLOR",     (0,0),(-1,0), WHITE),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.HexColor("#F7F6F2"), WHITE]),
            ("TEXTCOLOR",     (0,1),(-1,-1), GRAY),
            ("GRID",          (0,0),(-1,-1), 0.5, RULE),
            ("ALIGN",         (1,0),(2,-1), "CENTER"),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
        ]))
        story.append(dt)

        # Footer
        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=RULE, spaceAfter=8))
        story.append(Paragraph("AEGIS-AI — Advanced Exploitability &amp; Governance Intelligence System", ps("f1",7,LGRAY)))
        story.append(Paragraph(f"Confidenziale — {datetime.utcnow().year} — QuantumHorizon.it", ps("f2",7,LGRAY)))
        story.append(Paragraph("NIS2 · DORA · NIST CSF · ISO 27001", ps("f3",7,LGRAY)))

        doc.build(story)
        buf.seek(0)
        return Response(
            content=buf.read(),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="AEGIS-AI_Report_{datetime.utcnow().strftime("%Y%m%d")}.pdf"'}
        )
    except ImportError:
        return Response(content="reportlab non installato", status_code=500)
    except Exception as e:
        return Response(content=str(e), status_code=500)
