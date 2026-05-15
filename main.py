from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from Router import assessment, report, defense, governance
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
