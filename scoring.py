"""
AEGIS-AI — Scoring Engine
AES: AI Exposure Score
DRS: Defense Readiness Score
GCI: Governance & Compliance Index
"""

def normalize(answer: int) -> float:
    """Normalizza risposta 1..5 → 0..100"""
    return ((answer - 1) / 4) * 100

def calculate_dimension_score(answers: list[int]) -> float:
    return sum(normalize(a) for a in answers) / len(answers)

# ── AES — AI Exposure Score ───────────────────────────────────────────────────

def calculate_aes(ZDR: float, PV: float, AS: float, SC: float, LD: float) -> tuple[float, str]:
    """
    Pesi:
      ZDR — Zero-Day Risk          0.25
      PV  — Patch Velocity         0.25
      AS  — Attack Surface         0.20
      SC  — Supply Chain Risk      0.20
      LD  — Legacy Debt            0.10
    Score alto = più esposto
    """
    AES = (ZDR*0.25) + (PV*0.25) + (AS*0.20) + (SC*0.20) + (LD*0.10)

    # Malus: combinazioni critiche
    if ZDR > 70 and PV > 70:
        AES += 7  # Alta esposizione zero-day + patch lente
    if SC > 75 and LD > 75:
        AES += 5  # Supply chain rischiosa + legacy massivo

    AES = min(AES, 100)

    if AES <= 25:   level = "Sicuro"
    elif AES <= 50: level = "Moderato"
    elif AES <= 75: level = "Elevato"
    else:           level = "Critico"

    return round(AES, 1), level

# ── DRS — Defense Readiness Score ────────────────────────────────────────────

def calculate_drs(SM: float, IR: float, TI: float, ZT: float, RC: float) -> tuple[float, str]:
    """
    Pesi:
      SM — SOC Maturity            0.25
      IR — Incident Response       0.25
      TI — Threat Intelligence     0.20
      ZT — Zero Trust              0.20
      RC — Recovery Capability     0.10
    Score alto = difese più mature
    """
    DRS = (SM*0.25) + (IR*0.25) + (TI*0.20) + (ZT*0.20) + (RC*0.10)

    # Bonus combinazioni eccellenti
    if SM > 80 and IR > 80:
        DRS += 5
    if TI > 75 and ZT > 75:
        DRS += 3

    DRS = min(DRS, 100)

    if DRS >= 75:   level = "Avanzato"
    elif DRS >= 50: level = "Adeguato"
    elif DRS >= 25: level = "Parziale"
    else:           level = "Insufficiente"

    return round(DRS, 1), level

# ── GCI — Governance & Compliance Index ──────────────────────────────────────

def calculate_gci(FA: float, AP: float, CO: float, VR: float, BE: float) -> tuple[float, str]:
    """
    Pesi:
      FA — Framework Adoption      0.25
      AP — AI Policy               0.25
      CO — Compliance (NIS2/DORA)  0.20
      VR — Vendor Risk             0.20
      BE — Board Engagement        0.10
    Score alto = governance matura
    """
    GCI = (FA*0.25) + (AP*0.25) + (CO*0.20) + (VR*0.20) + (BE*0.10)

    if FA > 75 and CO > 75:
        GCI += 4
    if AP > 80:
        GCI += 3

    GCI = min(GCI, 100)

    if GCI >= 75:   level = "Avanzato"
    elif GCI >= 50: level = "Adeguato"
    elif GCI >= 25: level = "Parziale"
    else:           level = "Insufficiente"

    return round(GCI, 1), level

# ── Quadrant ──────────────────────────────────────────────────────────────────

def calculate_quadrant(aes: float, drs: float, gci: float) -> dict:
    """
    Quadranti strategici AEGIS-AI:
      Bassa esposizione + Difese solide   → FORTEZZA DIGITALE
      Bassa esposizione + Difese deboli   → GUARDIANO ESPOSTO
      Alta esposizione  + Difese solide   → FORTEZZA SOTTO PRESSIONE
      Alta esposizione  + Difese deboli   → ZONA CRITICA
    """
    high_exp = aes > 55
    weak_def = drs < 50

    if not high_exp and not weak_def:
        quadrant = "FORTEZZA DIGITALE"
        desc = "Bassa esposizione AI e difese solide. Posizione strategica ottimale per guidare la sicurezza nell'era AI."
    elif not high_exp and weak_def:
        quadrant = "GUARDIANO ESPOSTO"
        desc = "Superficie d'attacco contenuta ma difese da rafforzare. Finestra disponibile per agire in modo ordinato."
    elif high_exp and not weak_def:
        quadrant = "FORTEZZA SOTTO PRESSIONE"
        desc = "Alta esposizione ma difese mature. L'organizzazione ha le capacità per reagire — deve farlo ora."
    else:
        quadrant = "ZONA CRITICA"
        desc = "CRITICO: alta esposizione e difese insufficienti. Intervento immediato richiesto. Priorità assoluta."

    # Composite score (come Q-Shield: ponderato)
    composite = round((( 100 - aes) * 0.35) + (drs * 0.35) + (gci * 0.30), 1)

    return {
        "quadrant": quadrant,
        "quadrant_description": desc,
        "aes": aes,
        "drs": drs,
        "gci": gci,
        "composite_score": composite,
        "strategic_gap": round(aes - drs, 1),  # positivo = più esposto che difeso
    }
