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

@router.post("/assessment/calculate"
