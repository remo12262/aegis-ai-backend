from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import anthropic, os, json

router = APIRouter()

class GovQuery(BaseModel):
    query: str
    scores: dict = {}

SYSTEM = """Sei AEGIS-AI, esperto di governance e compliance cybersecurity (NIS2, DORA, NIST CSF, ISO 27001).
Rispondi in italiano, operativo, max 200 parole. Focus su implicazioni pratiche per CISO e DPO italiani."""

@router.post("/governance/analyze")
async def governance_analyze(payload: GovQuery):
    async def stream():
        key = os.getenv("ANTHROPIC_API_KEY","")
        if not key:
            yield f"data: {json.dumps({'type':'content_block_delta','delta':{'text':'ANTHROPIC_API_KEY non configurata.'}})}\n\n"
            return
        client = anthropic.Anthropic(api_key=key)
        ctx = f"Score GCI: {payload.scores}" if payload.scores else ""
        msg = f"{ctx}\n\n{payload.query}".strip()
        with client.messages.stream(
            model="claude-sonnet-4-20250514", max_tokens=800,
            system=SYSTEM,
            messages=[{"role":"user","content":msg}]
        ) as s:
            for text in s.text_stream:
                yield f"data: {json.dumps({'type':'content_block_delta','delta':{'text':text}})}\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream")
