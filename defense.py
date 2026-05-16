from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import anthropic, os, json

router = APIRouter()

class DefenseQuery(BaseModel):
    query: str
    context: str = ""

SYSTEM = """Sei AEGIS-AI, analista senior di AI Security intelligence (maggio 2026).
Contesto: Project Glasswing di Anthropic ha dimostrato che modelli AI scoprono zero-day a $50/sessione.
CVE documentate: CVE-2026-4747 (FreeBSD RCE root), FFmpeg 16 anni, OpenBSD CVE-2026-3891, hypervisor escape.
Rispondi in italiano, diretto, operativo, max 200 parole. Nessun markdown."""

@router.post("/defense/analyze")
async def defense_analyze(payload: DefenseQuery):
    async def stream():
        key = os.getenv("ANTHROPIC_API_KEY","")
        if not key:
            yield f"data: {json.dumps({'type':'content_block_delta','delta':{'text':'ANTHROPIC_API_KEY non configurata.'}})}\n\n"
            return
        client = anthropic.Anthropic(api_key=key)
        msg = payload.query
        if payload.context:
            msg = f"Contesto: {payload.context}\n\nAnalisi: {payload.query}"
        with client.messages.stream(
            model="claude-sonnet-4-20250514", max_tokens=800,
            system=SYSTEM,
            messages=[{"role":"user","content":msg}]
        ) as s:
            for text in s.text_stream:
                yield f"data: {json.dumps({'type':'content_block_delta','delta':{'text':text}})}\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream")
