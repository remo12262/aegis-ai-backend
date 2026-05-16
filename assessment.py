from fastapi import APIRouter
from pydantic import BaseModel
from scoring import (
    calculate_dimension_score, calculate_aes,
    calculate_drs, calculate_gci, calculate_quadrant
)
import sqlite3, json, hashlib, os
from datetime import datetime, timezone

router = APIRouter()
DB_PATH = os.getenv("DB_PATH", "aegis.db")

class AssessmentPayload(BaseModel):
    sector: str = "unknown"
    org_name: str = ""
    ZDR: list[int]
    PV:  list[int]
    AS_: list[int]
    SC:  list[int]
    LD:  list[int]
    SM:  list[int]
    IR:  list[int]
    TI:  list[int]
    ZT:  list[int]
    RC:  list[int]
    FA:  list[int]
    AP:  list[int]
    CO:  list[int]
    VR:  list[int]
    BE:  list[int]

@router.post("/assessment/calculate")
def calculate(payload: AssessmentPayload):
    ZDR = calculate_dimension_score(payload.ZDR)
    PV  = calculate_dimension_score(payload.PV)
    AS  = calculate_dimension_score(payload.AS_)
    SC  = calculate_dimension_score(payload.SC)
    LD  = calculate_dimension_score(payload.LD)
    aes, aes_level = calculate_aes(ZDR, PV, AS, SC, LD)

    SM  = calculate_dimension_score(payload.SM)
    IR  = calculate_dimension_score(payload.IR)
    TI  = calculate_dimension_score(payload.TI)
    ZT  = calculate_dimension_score(payload.ZT)
    RC  = calculate_dimension_score(payload.RC)
    drs, drs_level = calculate_drs(SM, IR, TI, ZT, RC)

    FA  = calculate_dimension_score(payload.FA)
    AP  = calculate_dimension_score(payload.AP)
    CO  = calculate_dimension_score(payload.CO)
    VR  = calculate_dimension_score(payload.VR)
    BE  = calculate_dimension_score(payload.BE)
    gci, gci_level = calculate_gci(FA, AP, CO, VR, BE)

    profile = calculate_quadrant(aes, drs, gci)

    result = {
        "sector": payload.sector,
        "org_name": payload.org_name,
        "aes": aes, "aes_level": aes_level,
        "drs": drs, "drs_level": drs_level,
        "gci": gci, "gci_level": gci_level,
        "ZDR": round(ZDR,1), "PV": round(PV,1), "AS": round(AS,1),
        "SC": round(SC,1), "LD": round(LD,1),
        "SM": round(SM,1), "IR": round(IR,1), "TI": round(TI,1),
        "ZT": round(ZT,1), "RC": round(RC,1),
        "FA": round(FA,1), "AP": round(AP,1), "CO": round(CO,1),
        "VR": round(VR,1), "BE": round(BE,1),
        **profile,
    }

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        assessment_id = hashlib.md5(f"{payload.org_name}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        c.execute("""INSERT INTO assessments
            (id,sector,org_name,aes,drs,gci,aes_level,drs_level,gci_level,quadrant,composite,answers_json,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (assessment_id, payload.sector, payload.org_name,
             aes, drs, gci, aes_level, drs_level, gci_level,
             profile["quadrant"], profile["composite_score"],
             json.dumps(payload.dict()),
             datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
        result["assessment_id"] = assessment_id
    except Exception as e:
        result["db_error"] = str(e)

    return result
