from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from routers import assessment, report, defense, governance
import json, sqlite3, os
from scanner import run_full_scan, init_db, DB_PATH

app = FastAPI(title="AEGIS-AI Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

app.include_router(assessment.router)
app.include_router(report.router)
app.include_router(defense.router)
app.include_router(governance.router)

@app.get("/")
def root():
    return {"message": "AEGIS-AI online", "version": "1.0.0"}

@app.get("/scan")
def manual_scan():
    bulletin = run_full_scan()
    return JSONResponse(content={
        "status": "completed",
        "bulletin_id": bulletin.get("id"),
        "overall_level": bulletin.get("overall_level"),
        "total_items": bulletin.get("total_items"),
        "week_label": bulletin.get("week_label"),
    })

@app.get("/bulletin/latest")
def latest_bulletin():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM bulletins ORDER BY created_at DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    if not row:
        return JSONResponse(status_code=404, content={"error": "Nessun bollettino. Esegui /scan"})
    items = json.loads(row[4])
    return {
        "id": row[0], "week_label": row[1], "overall_level": row[2],
        "executive_summary": row[3], "total_items": len(items),
        "items": items, "created_at": row[5],
    }

@app.get("/bulletin/history")
def bulletin_history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id,week_label,overall_level,summary,created_at FROM bulletins ORDER BY created_at DESC LIMIT 20")
    rows = c.fetchall()
    conn.close()
    return [{"id":r[0],"week":r[1],"level":r[2],"summary":r[3][:120]+"...","date":r[4]} for r in rows]

@app.get("/stats")
def stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM raw_items"); total_raw = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyzed_items"); total_analyzed = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM bulletins"); total_bulletins = c.fetchone()[0]
    conn.close()
    return {"raw_items_collected": total_raw, "items_analyzed": total_analyzed, "bulletins_generated": total_bulletins}

import anthropic as _anthropic

@app.post("/api/analyze")
async def analyze(request: dict):
    prompt = request.get("prompt", "")
    if not prompt:
        return JSONResponse(status_code=400, content={"error": "Prompt mancante"})
    client = _anthropic.Anthropic()
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    return {"result": message.content[0].text}
