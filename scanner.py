"""
AEGIS-AI — AI Security Threat Intelligence Scanner
v1.0

Architettura identica a Q-STRATEGIX:
  1. Scraper     → raccoglie RSS/feed da fonti sicurezza AI
  2. AI Filter   → Claude API analizza e classifica ogni item
  3. Storage     → SQLite
  4. Exporter    → JSON bollettino strutturato
  5. Scheduler   → automatico ogni lunedì 07:00
"""

import os, json, sqlite3, hashlib, logging, argparse
from datetime import datetime, timezone
from typing import Optional

import feedparser, requests
from bs4 import BeautifulSoup
import anthropic

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("aegis-scanner")

DB_PATH = os.getenv("DB_PATH", "aegis.db")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MAX_ITEMS_PER_SOURCE = 10
MAX_ITEMS_TO_ANALYZE = 20

THREAT_LEVELS = {
    "CRITICO": {"score": 4, "color": "#C62828", "emoji": "🔴"},
    "ALTO":    {"score": 3, "color": "#E65100", "emoji": "🟠"},
    "MEDIO":   {"score": 2, "color": "#1565C0", "emoji": "🔵"},
    "BASSO":   {"score": 1, "color": "#546E7A", "emoji": "⚪"},
    "NESSUNO": {"score": 0, "color": "#9E9E9E", "emoji": "—"},
}

# ── Fonti RSS — AI Security ───────────────────────────────────────────────────
SOURCES = [
    {
        "name": "NVD — National Vulnerability Database",
        "type": "rss",
        "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
        "category": "cve",
        "keywords": ["critical","remote code execution","zero-day","AI","machine learning","supply chain","exploit"],
    },
    {
        "name": "CISA Alerts",
        "type": "rss",
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "category": "normativa",
        "keywords": ["AI","vulnerability","exploit","critical infrastructure","zero-day","ransomware"],
    },
    {
        "name": "Krebs on Security",
        "type": "rss",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "cybersecurity",
        "keywords": ["AI","exploit","zero-day","vulnerability","ransomware","supply chain","breach"],
    },
    {
        "name": "Schneier on Security",
        "type": "rss",
        "url": "https://www.schneier.com/feed/atom/",
        "category": "cybersecurity",
        "keywords": ["AI","machine learning","vulnerability","exploit","security","attack"],
    },
    {
        "name": "The Hacker News",
        "type": "rss",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "news",
        "keywords": ["AI","zero-day","exploit","vulnerability","CVE","ransomware","supply chain","critical"],
    },
    {
        "name": "Dark Reading",
        "type": "rss",
        "url": "https://www.darkreading.com/rss.xml",
        "category": "news",
        "keywords": ["AI","zero-day","exploit","vulnerability","LLM","machine learning","supply chain"],
    },
    {
        "name": "arXiv — Cryptography & Security",
        "type": "rss",
        "url": "https://rss.arxiv.org/rss/cs.CR",
        "category": "ricerca",
        "keywords": ["AI","adversarial","vulnerability","attack","exploit","LLM","machine learning","neural"],
    },
    {
        "name": "ENISA News",
        "type": "rss",
        "url": "https://www.enisa.europa.eu/media/news-items/RSS",
        "category": "normativa",
        "keywords": ["AI","vulnerability","cyber","NIS2","supply chain","critical infrastructure"],
    },
]

# ── Database ──────────────────────────────────────────────────────────────────

def init_db(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS raw_items (
        id TEXT PRIMARY KEY, source_name TEXT NOT NULL, category TEXT NOT NULL,
        title TEXT NOT NULL, summary TEXT, url TEXT, published TEXT,
        fetched_at TEXT NOT NULL, analyzed INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS analyzed_items (
        id TEXT PRIMARY KEY, raw_id TEXT NOT NULL, threat_level TEXT NOT NULL,
        threat_score INTEGER NOT NULL, relevance TEXT NOT NULL,
        implications TEXT NOT NULL, recommendation TEXT NOT NULL,
        category_tag TEXT NOT NULL, cve_ids TEXT DEFAULT '',
        analyzed_at TEXT NOT NULL,
        FOREIGN KEY (raw_id) REFERENCES raw_items(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS bulletins (
        id TEXT PRIMARY KEY, week_label TEXT NOT NULL, overall_level TEXT NOT NULL,
        summary TEXT NOT NULL, items_json TEXT NOT NULL, created_at TEXT NOT NULL
    )""")
    # Assessment results
    c.execute("""CREATE TABLE IF NOT EXISTS assessments (
        id TEXT PRIMARY KEY, sector TEXT, org_name TEXT,
        aes REAL, drs REAL, gci REAL,
        aes_level TEXT, drs_level TEXT, gci_level TEXT,
        quadrant TEXT, composite REAL,
        answers_json TEXT, created_at TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()
    log.info(f"Database inizializzato: {db_path}")

def item_exists(item_id: str, db_path: str = DB_PATH) -> bool:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT 1 FROM raw_items WHERE id = ?", (item_id,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def save_raw_item(item: dict, db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""INSERT OR IGNORE INTO raw_items
        (id,source_name,category,title,summary,url,published,fetched_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (item["id"],item["source_name"],item["category"],item["title"],
         item.get("summary",""),item.get("url",""),item.get("published",""),
         datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()

def save_analyzed_item(raw_id: str, analysis: dict, db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("UPDATE raw_items SET analyzed = 1 WHERE id = ?", (raw_id,))
    analysis_id = hashlib.md5(f"{raw_id}_analysis".encode()).hexdigest()
    score = THREAT_LEVELS.get(analysis["threat_level"], {}).get("score", 0)
    c.execute("""INSERT OR REPLACE INTO analyzed_items
        (id,raw_id,threat_level,threat_score,relevance,implications,
         recommendation,category_tag,cve_ids,analyzed_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (analysis_id, raw_id, analysis["threat_level"], score,
         analysis["relevance"], analysis["implications"],
         analysis["recommendation"], analysis["category_tag"],
         ",".join(analysis.get("cve_ids", [])),
         datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()

def get_unanalyzed_items(limit: int = MAX_ITEMS_TO_ANALYZE, db_path: str = DB_PATH) -> list:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""SELECT id,source_name,category,title,summary,url,published
        FROM raw_items WHERE analyzed=0 ORDER BY fetched_at DESC LIMIT ?""", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{"id":r[0],"source_name":r[1],"category":r[2],"title":r[3],"summary":r[4],"url":r[5],"published":r[6]} for r in rows]

def get_latest_analyzed(limit: int = 30, db_path: str = DB_PATH) -> list:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""SELECT r.title,r.url,r.source_name,r.category,r.published,
        a.threat_level,a.threat_score,a.relevance,a.implications,
        a.recommendation,a.category_tag,a.cve_ids
        FROM analyzed_items a JOIN raw_items r ON a.raw_id=r.id
        WHERE a.threat_score>0
        ORDER BY a.threat_score DESC, a.analyzed_at DESC LIMIT ?""", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{"title":r[0],"url":r[1],"source":r[2],"category":r[3],"published":r[4],
             "threat_level":r[5],"threat_score":r[6],"relevance":r[7],"implications":r[8],
             "recommendation":r[9],"category_tag":r[10],"cve_ids":r[11]} for r in rows]

# ── Scraper ───────────────────────────────────────────────────────────────────

def make_item_id(source_name: str, title: str, url: str = "") -> str:
    return hashlib.md5(f"{source_name}|{title}|{url}".encode()).hexdigest()

def keyword_match(text: str, keywords: list) -> bool:
    text_lower = text.lower()
    return any(kw.lower() in text_lower for kw in keywords)

def scrape_rss(source: dict) -> list:
    items = []
    try:
        log.info(f"Scraping: {source['name']}")
        feed = feedparser.parse(source["url"])
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "").strip()
            summary = BeautifulSoup(
                entry.get("summary", entry.get("description", "")), "html.parser"
            ).get_text()[:500]
            url = entry.get("link", "")
            published = entry.get("published", entry.get("updated", ""))
            combined = f"{title} {summary}"
            if source.get("keywords") and not keyword_match(combined, source["keywords"]):
                continue
            item_id = make_item_id(source["name"], title, url)
            if item_exists(item_id):
                continue
            items.append({"id":item_id,"source_name":source["name"],"category":source["category"],
                          "title":title,"summary":summary,"url":url,"published":published})
        log.info(f"  → {len(items)} nuovi item da {source['name']}")
    except Exception as e:
        log.error(f"Errore scraping {source['name']}: {e}")
    return items

def run_scraper() -> int:
    total = 0
    for source in SOURCES:
        if source["type"] == "rss":
            items = scrape_rss(source)
            for item in items:
                save_raw_item(item)
            total += len(items)
    log.info(f"Scraping completato. Totale nuovi item: {total}")
    return total

# ── AI Analysis ───────────────────────────────────────────────────────────────

ANALYSIS_PROMPT = """Sei un analista senior di AI Security specializzato in vulnerabilità scoperte da modelli AI.
Analizza il seguente articolo e rispondi SOLO con JSON valido, nessun testo aggiuntivo.

Articolo:
Titolo: {title}
Fonte: {source}
Categoria: {category}
Testo: {summary}

Schema JSON esatto:
{{
  "threat_level": "CRITICO|ALTO|MEDIO|BASSO|NESSUNO",
  "relevance": "1-2 frasi su perché è rilevante per la sicurezza AI-powered",
  "implications": "1-2 frasi sulle implicazioni pratiche per PA e aziende italiane",
  "recommendation": "1 azione concreta che un CISO italiano dovrebbe intraprendere",
  "category_tag": "CVE|EXPLOIT|SUPPLY_CHAIN|AI_ATTACK|NORMATIVA|RICERCA|ALTRO",
  "cve_ids": ["CVE-XXXX-XXXXX"]
}}

Criteri threat_level:
- CRITICO: vulnerabilità AI-discovered con exploit funzionante, RCE, CVSS ≥ 9.0
- ALTO: nuova tecnica di attacco AI-assisted, CVSS 7-9, supply chain critica
- MEDIO: ricerca rilevante, vulnerabilità patchabile, CVSS 4-7
- BASSO: notizia di settore, impatto indiretto
- NESSUNO: non rilevante per AI security"""

def analyze_item_with_ai(item: dict) -> Optional[dict]:
    if not ANTHROPIC_API_KEY:
        log.warning("ANTHROPIC_API_KEY non impostata — skip AI")
        return None
    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        prompt = ANALYSIS_PROMPT.format(
            title=item["title"], source=item["source_name"],
            category=item["category"], summary=item.get("summary","")[:400]
        )
        message = client.messages.create(
            model="claude-sonnet-4-20250514", max_tokens=512,
            messages=[{"role":"user","content":prompt}]
        )
        raw = message.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"): raw = raw[4:]
        analysis = json.loads(raw)
        required = ["threat_level","relevance","implications","recommendation","category_tag"]
        for f in required:
            if f not in analysis: raise ValueError(f"Campo mancante: {f}")
        if analysis["threat_level"] not in THREAT_LEVELS:
            analysis["threat_level"] = "BASSO"
        if "cve_ids" not in analysis: analysis["cve_ids"] = []
        log.info(f"  [{analysis['threat_level']}] {item['title'][:60]}")
        return analysis
    except Exception as e:
        log.error(f"Errore AI per '{item['title'][:50]}': {e}")
        return None

def run_ai_analysis() -> int:
    items = get_unanalyzed_items()
    if not items:
        log.info("Nessun nuovo item da analizzare.")
        return 0
    log.info(f"Analisi AI di {len(items)} item...")
    analyzed = 0
    for item in items:
        analysis = analyze_item_with_ai(item)
        if analysis:
            save_analyzed_item(item["id"], analysis)
            analyzed += 1
    log.info(f"Analisi completata: {analyzed}/{len(items)}")
    return analyzed

# ── Bulletin Generator ────────────────────────────────────────────────────────

BULLETIN_PROMPT = """Sei un analista senior di AI Security.
Basandoti sui seguenti item della settimana, scrivi un executive summary per CISO e dirigenti.

Rispondi SOLO con JSON:
{{
  "overall_level": "CRITICO|ALTO|MEDIO|BASSO",
  "executive_summary": "3-4 frasi in italiano per CISO e dirigenti PA"
}}

Item:
{items_text}"""

def generate_bulletin() -> dict:
    items = get_latest_analyzed(limit=20)
    if not items:
        log.warning("Nessun item analizzato per il bollettino.")
        return {}

    overall_level = "MEDIO"
    executive_summary = "Settimana con vulnerabilità rilevanti nel panorama AI security."

    if ANTHROPIC_API_KEY:
        try:
            items_text = "\n".join([
                f"- [{i['threat_level']}] {i['title']} ({i['source']}): {i['relevance']}"
                for i in items[:15]
            ])
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            message = client.messages.create(
                model="claude-sonnet-4-20250514", max_tokens=512,
                messages=[{"role":"user","content":BULLETIN_PROMPT.format(items_text=items_text)}]
            )
            raw = message.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"): raw = raw[4:]
            result = json.loads(raw)
            overall_level = result.get("overall_level", "MEDIO")
            executive_summary = result.get("executive_summary", executive_summary)
        except Exception as e:
            log.error(f"Errore summary: {e}")

    grouped = {}
    for item in items:
        lvl = item["threat_level"]
        if lvl not in grouped: grouped[lvl] = []
        grouped[lvl].append(item)

    bulletin = {
        "id": hashlib.md5(datetime.now().isoformat().encode()).hexdigest()[:8],
        "week_label": f"Settimana del {datetime.now().strftime('%d %B %Y')}",
        "overall_level": overall_level,
        "overall_emoji": THREAT_LEVELS.get(overall_level, {}).get("emoji", ""),
        "executive_summary": executive_summary,
        "total_items": len(items),
        "items_by_level": grouped,
        "all_items": items,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""INSERT INTO bulletins (id,week_label,overall_level,summary,items_json,created_at)
        VALUES (?,?,?,?,?,?)""",
        (bulletin["id"],bulletin["week_label"],overall_level,
         executive_summary,json.dumps(items),bulletin["generated_at"]))
    conn.commit()
    conn.close()
    log.info(f"Bollettino #{bulletin['id']} — {overall_level} — {len(items)} item")
    return bulletin

def run_full_scan() -> dict:
    log.info("="*50)
    log.info("AVVIO SCAN — AEGIS-AI Scanner")
    log.info("="*50)
    new_items = run_scraper()
    analyzed = run_ai_analysis()
    bulletin = generate_bulletin()
    log.info(f"SCAN COMPLETATO — Nuovi: {new_items} | Analizzati: {analyzed}")
    return bulletin

if __name__ == "__main__":
    init_db()
    bulletin = run_full_scan()
    print(json.dumps(bulletin, indent=2, ensure_ascii=False))
