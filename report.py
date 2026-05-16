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

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
            leftMargin=2.2*cm, rightMargin=2.2*cm, topMargin=2*cm, bottomMargin=2*cm)

        INK   = colors.HexColor("#0D0D0D")
        GRAY  = colors.HexColor("#3D3D3D")
        LGRAY = colors.HexColor("#888888")
        RULE  = colors.HexColor("#D8D4CC")
        WHITE = colors.white

        def ps(name, size, color=INK, bold=False, space_after=6):
            return ParagraphStyle(name, fontSize=size, textColor=color,
                fontName="Helvetica-Bold" if bold else "Helvetica",
                spaceAfter=space_after, leading=size*1.4)

        story = []
        story.append(Paragraph("AEGIS-AI", ps("h1",28,INK,True,2)))
        story.append(Paragraph("AI Security Intelligence Report", ps("s",10,GRAY,space_after=2)))
        story.append(Paragraph(f"{payload.org_name} — {payload.sector}", ps("s2",9,LGRAY,space_after=2)))
        story.append(Paragraph(f"Generato: {datetime.utcnow().strftime('%d %B %Y %H:%M UTC')}", ps("s3",8,LGRAY,space_after=12)))
        story.append(HRFlowable(width="100%", thickness=1, color=INK, spaceAfter=16))

        story.append(Paragraph("SCORES", ps("st",8,LGRAY,space_after=8)))
        score_data = [
            ["MODULO", "SCORE", "LIVELLO"],
            ["AES — AI Exposure Score", f"{payload.aes}/100", payload.aes_level],
            ["DRS — Defense Readiness Score", f"{payload.drs}/100", payload.drs_level],
            ["GCI — Governance & Compliance Index", f"{payload.gci}/100", payload.gci_level],
        ]
        t = Table(score_data, colWidths=[8*cm, 3*cm, 6*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,0), INK),
            ("TEXTCOLOR",  (0,0),(-1,0), WHITE),
            ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0),(-1,-1), 8),
            ("GRID",       (0,0),(-1,-1), 0.5, RULE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#F7F6F2"),WHITE]),
            ("ALIGN",      (1,0),(2,-1), "CENTER"),
            ("TOPPADDING", (0,0),(-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.5*cm))

        story.append(Paragraph(f"Quadrante: {payload.quadrant}", ps("q",10,INK,True,space_after=4)))
        story.append(Paragraph(payload.quadrant_description, ps("qd",8,GRAY,space_after=12)))

        story.append(Spacer(1,1*cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=RULE, spaceAfter=8))
        story.append(Paragraph("AEGIS-AI — QuantumHorizon.it", ps("f",7,LGRAY)))
        story.append(Paragraph("NIS2 · DORA · NIST CSF · ISO 27001", ps("f2",7,LGRAY)))

        doc.build(story)
        buf.seek(0)
        return Response(
            content=buf.read(),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="AEGIS-AI_Report_{datetime.utcnow().strftime("%Y%m%d")}.pdf"'}
        )
    except Exception as e:
        return Response(content=str(e), status_code=500)
