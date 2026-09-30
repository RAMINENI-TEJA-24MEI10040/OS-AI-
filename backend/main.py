"""
OpenTrace AI — FastAPI Server & Turso / libSQL Database Engine
--------------------------------------------------------------
Provides REST endpoints for cybersecurity investigations, backed by
Turso Cloud libSQL / SQLite persistence with indexed tables.

Security & Architectural Notes:
- Reviewed against relevant OWASP Top 10:2025 security categories.
- Employs parameterized SQL query parameter binding across all database operations.
- Isolates Turso authentication credentials server-side via environment variables.
- Uses Hrana v2 HTTP pipeline protocol (/v2/pipeline) for Turso Cloud operations.
- Intended deployment scope: Single-user / Local SOC Workstation environment.
"""

import os
import sys
import json
import time
import sqlite3
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple, Set
import requests
from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Load environment variables from .env
load_dotenv()

# Add current directory to path if needed
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from agent import OpenTraceAgentHarness, normalize_indicator, is_ssrf_safe_url, sanitize_input


# ============================================================================
# 1. DATABASE ACCESS LAYER (Turso Cloud libSQL + Local SQLite Fallback)
# ============================================================================

TURSO_URL = os.getenv("TURSO_DATABASE_URL", "").strip()
TURSO_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "").strip()


class DatabaseClient:
    """
    Unified Database Client for Turso libSQL Cloud & Local SQLite.
    Connects to Turso via Hrana v2 HTTP pipeline protocol (/v2/pipeline) when configured with token.
    Falls back to local SQLite file `opentrace.db` if Turso credentials are not present.
    """

    def __init__(self):
        self.is_turso = bool(TURSO_URL and TURSO_TOKEN and ("turso.io" in TURSO_URL or TURSO_URL.startswith("libsql://") or TURSO_URL.startswith("https://")))
        if self.is_turso:
            clean_url = TURSO_URL.replace("libsql://", "https://")
            if not clean_url.endswith("/v2/pipeline"):
                if clean_url.endswith("/"):
                    clean_url += "v2/pipeline"
                else:
                    clean_url += "/v2/pipeline"
            self.turso_endpoint = clean_url
            self.headers = {
                "Authorization": f"Bearer {TURSO_TOKEN}",
                "Content-Type": "application/json"
            }
        else:
            self.db_path = os.path.join(current_dir, "opentrace.db")

    def execute_statements(self, statements: List[Tuple[str, List[Any]]]) -> List[Any]:
        """Executes list of (sql, params) using parameterized query bindings."""
        if self.is_turso:
            return self._execute_turso(statements)
        else:
            return self._execute_sqlite(statements)

    def _execute_turso(self, statements: List[Tuple[str, List[Any]]]) -> List[Any]:
        reqs = []
        for sql, params in statements:
            converted_params = []
            for p in params:
                if p is None:
                    converted_params.append({"type": "null"})
                elif isinstance(p, bool):
                    converted_params.append({"type": "integer", "value": "1" if p else "0"})
                elif isinstance(p, int):
                    converted_params.append({"type": "integer", "value": str(p)})
                elif isinstance(p, float):
                    converted_params.append({"type": "float", "value": float(p)})
                else:
                    converted_params.append({"type": "text", "value": str(p)})

            reqs.append({
                "type": "execute",
                "stmt": {
                    "sql": sql,
                    "args": converted_params
                }
            })
        reqs.append({"type": "close"})

        payload = {"requests": reqs}
        try:
            resp = requests.post(self.turso_endpoint, json=payload, headers=self.headers, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for res in data.get("results", []):
                    if res.get("type") == "ok":
                        exec_res = res.get("response", {}).get("result", {})
                        cols = [c["name"] for c in exec_res.get("cols", [])]
                        rows = []
                        for raw_row in exec_res.get("rows", []):
                            row_dict = {}
                            for col_name, cell in zip(cols, raw_row):
                                row_dict[col_name] = cell.get("value") if isinstance(cell, dict) else cell
                            rows.append(row_dict)
                        results.append(rows)
                return results
            else:
                print(f"[Turso DB Warning] HTTP {resp.status_code}: {resp.text}")
                return []
        except Exception as e:
            print(f"[Turso Connection Warning] {str(e)}")
            return []

    def _execute_sqlite(self, statements: List[Tuple[str, List[Any]]]) -> List[Any]:
        results = []
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            for sql, params in statements:
                cursor.execute(sql, params)
                if sql.strip().upper().startswith("SELECT") or "RETURNING" in sql.upper():
                    rows = [dict(row) for row in cursor.fetchall()]
                    results.append(rows)
                else:
                    results.append([])
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[SQLite Local Warning] {str(e)}")
        return results

    def init_tables(self):
        """Initializes database schema and performance indexes."""
        schema_sql = [
            ("""CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                raw_input TEXT,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                threat_level TEXT,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                duration_ms REAL
            );""", []),
            ("""CREATE TABLE IF NOT EXISTS indicators (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                value TEXT NOT NULL,
                type TEXT NOT NULL,
                reputation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );""", []),
            ("""CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                source TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );""", []),
            ("""CREATE TABLE IF NOT EXISTS relationships (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                source_indicator TEXT NOT NULL,
                target_indicator TEXT NOT NULL,
                relation_type TEXT NOT NULL
            );""", []),
            ("""CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                title TEXT NOT NULL,
                hypothesis TEXT NOT NULL,
                verification_status TEXT NOT NULL,
                evidence_sources TEXT,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );""", []),
            # Performance Indexes
            ("CREATE INDEX IF NOT EXISTS idx_cases_indicator ON cases(indicator);", []),
            ("CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at);", []),
            ("CREATE INDEX IF NOT EXISTS idx_indicators_case ON indicators(case_id);", []),
            ("CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);", []),
            ("CREATE INDEX IF NOT EXISTS idx_relationships_case ON relationships(case_id);", []),
            ("CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);", [])
        ]
        self.execute_statements(schema_sql)


# Initialize DB engine
db_client = DatabaseClient()
db_client.init_tables()

# Initialize Agent Harness
agent_harness = OpenTraceAgentHarness()


# ============================================================================
# 2. FASTAPI APP INITIALIZATION & MIDDLEWARE
# ============================================================================

app = FastAPI(
    title="OpenTrace AI",
    description="Evidence-Grounded Open-Source AI Cyber Investigation Agent",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class InvestigateRequest(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=10000, description="IP, Domain, URL, Hash, Email, Wallet, or Log text (max 10KB)")


# ============================================================================
# 3. REST API ENDPOINTS
# ============================================================================

@app.get("/api/health")
def get_health():
    """Health check & database status endpoint."""
    return {
        "status": "HEALTHY",
        "database_mode": "Turso libSQL Cloud" if db_client.is_turso else "Local SQLite",
        "agent_version": "1.0.0",
        "deployment_scope": "Single-User / Local SOC Workstation",
        "timestamp": time.time()
    }


@app.post("/api/investigate")
def run_investigation(req: InvestigateRequest):
    """
    Triggers complete OpenTrace AI cybersecurity investigation.
    Executes 8-stage pipeline & persists case records to Turso / SQLite.
    """
    raw_indicator = sanitize_input(req.indicator)
    if not raw_indicator:
        raise HTTPException(status_code=400, detail="Indicator string cannot be empty")

    investigation_result = agent_harness.run_investigation(raw_indicator)

    if investigation_result.get("status") == "BLOCKED_SECURITY_SSRF":
        raise HTTPException(status_code=400, detail=investigation_result.get("error"))

    case_id = investigation_result["case_id"]
    original_raw = investigation_result.get("raw_input", raw_indicator)
    target = investigation_result["target_indicator"]
    ind_type = investigation_result["indicator_type"]
    threat_level = investigation_result["threat_level"]
    status = investigation_result["status"]
    duration_ms = investigation_result["timing_ms"]["total_investigation"]

    # Parameterized DB persistence
    db_stmts = [
        ("INSERT INTO cases (id, raw_input, indicator, indicator_type, threat_level, status, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
         [case_id, original_raw, target, ind_type, threat_level, status, duration_ms]),
        ("INSERT INTO indicators (id, case_id, value, type, reputation) VALUES (?, ?, ?, ?, ?)",
         [f"ind_{case_id}", case_id, target, ind_type, threat_level])
    ]

    for idx, obs in enumerate(investigation_result.get("observations", [])):
        ev_id = f"ev_{case_id}_{idx}"
        source = obs.get("tool", "unknown_tool")
        ev_type = "TOOL_OBSERVATION"
        content_str = json.dumps(obs)
        db_stmts.append((
            "INSERT INTO evidence (id, case_id, source, evidence_type, content) VALUES (?, ?, ?, ?, ?)",
            [ev_id, case_id, source, ev_type, content_str]
        ))

    for idx, rel in enumerate(investigation_result.get("relationships", [])):
        rel_id = f"rel_{case_id}_{idx}"
        src = rel.get("source", "")
        tgt = rel.get("target", "")
        rtype = rel.get("type", "RELATED_TO")
        db_stmts.append((
            "INSERT INTO relationships (id, case_id, source_indicator, target_indicator, relation_type) VALUES (?, ?, ?, ?, ?)",
            [rel_id, case_id, src, tgt, rtype]
        ))

    for idx, find in enumerate(investigation_result.get("findings", [])):
        f_id = f"find_{case_id}_{idx}"
        title = find.get("title", "")
        hyp = find.get("hypothesis", "")
        vstatus = find.get("verification_status", "UNVERIFIED")
        sources_str = json.dumps(find.get("evidence_sources", []))
        conf = find.get("confidence", 0.5)
        db_stmts.append((
            "INSERT INTO findings (id, case_id, title, hypothesis, verification_status, evidence_sources, confidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [f_id, case_id, title, hyp, vstatus, sources_str, conf]
        ))

    db_client.execute_statements(db_stmts)

    return investigation_result


@app.get("/api/cases")
def list_cases(limit: int = 20):
    """
    Retrieves recent investigation cases list from database.
    Excludes automated test runner cases (`id NOT LIKE 'test_%'`) for clean production history.
    """
    safe_limit = min(max(1, limit), 100)
    sql = "SELECT id, raw_input, indicator, indicator_type, threat_level, status, created_at, duration_ms FROM cases WHERE id NOT LIKE 'test_%' ORDER BY created_at DESC LIMIT ?"
    results = db_client.execute_statements([(sql, [safe_limit])])
    rows = results[0] if results else []
    return {"cases": rows}


@app.get("/api/case/{case_id}")
def get_case_details(case_id: str):
    """Retrieves complete investigation details for a case."""
    clean_id = sanitize_input(case_id)
    stmts = [
        ("SELECT * FROM cases WHERE id = ?", [clean_id]),
        ("SELECT * FROM evidence WHERE case_id = ? ORDER BY created_at ASC", [clean_id]),
        ("SELECT * FROM relationships WHERE case_id = ?", [clean_id]),
        ("SELECT * FROM findings WHERE case_id = ? ORDER BY created_at ASC", [clean_id])
    ]
    res = db_client.execute_statements(stmts)
    if not res or not res[0]:
        raise HTTPException(status_code=404, detail="Case ID not found")

    case_row = res[0][0]
    evidence_rows = res[1] if len(res) > 1 else []
    rel_rows = res[2] if len(res) > 2 else []
    finding_rows = res[3] if len(res) > 3 else []

    parsed_evidence = []
    for ev in evidence_rows:
        try:
            content_obj = json.loads(ev["content"])
        except Exception:
            content_obj = ev["content"]
        parsed_evidence.append({
            "id": ev["id"],
            "source": ev["source"],
            "evidence_type": ev["evidence_type"],
            "content": content_obj,
            "created_at": ev.get("created_at")
        })

    parsed_findings = []
    for fn in finding_rows:
        try:
            sources_obj = json.loads(fn["evidence_sources"])
        except Exception:
            sources_obj = []
        
        vstatus = fn["verification_status"]
        conf_val = fn.get("confidence", 0.5)
        if vstatus == "VERIFIED":
            conf_type = "OBSERVATION_CERTAINTY"
            conf_lbl = f"Observation Certainty: {int(conf_val*100)}% (Deterministic Tool Output)"
        else:
            conf_type = "ANALYTICAL_CONFIDENCE"
            conf_lbl = f"Analytical Confidence: {int(conf_val*100)}% ({'Multi-Source Tool Correlation' if vstatus == 'CORRELATED' else 'Model Hypothesis'})"

        parsed_findings.append({
            "id": fn["id"],
            "title": fn["title"],
            "hypothesis": fn["hypothesis"],
            "verification_status": vstatus,
            "evidence_sources": sources_obj,
            "confidence": conf_val,
            "confidence_type": conf_type,
            "confidence_label": conf_lbl
        })

    return {
        "case": case_row,
        "evidence": parsed_evidence,
        "relationships": rel_rows,
        "findings": parsed_findings
    }


@app.get("/api/export/{case_id}")
def export_case_report(case_id: str):
    """Exports comprehensive Markdown report for a case."""
    data = get_case_details(case_id)
    case_info = data["case"]

    raw_inp = case_info.get('raw_input') or case_info['indicator']
    target_ind = case_info['indicator']
    ind_type = case_info['indicator_type']
    threat_level = case_info['threat_level']
    duration_ms = case_info.get('duration_ms', 0)
    created_at = case_info.get('created_at', 'N/A')

    md = f"""# OpenTrace AI — Cybersecurity Investigation Report

**Case ID:** `{case_info['id']}`  
**Original User Input:** `{raw_inp}`  
**Normalized Target Indicator:** `{target_ind}` ({ind_type})  
**Threat Classification:** **{threat_level}** *(Heuristic Rule Engine)*  
**Investigation Timestamp:** `{created_at}`  
**Total Wall-Clock Latency:** `{duration_ms} ms`  

---

## 1. Verified Findings & AI Hypotheses

"""
    for fn in data["findings"]:
        status = fn['verification_status']
        badge = f"[{status}]"
        md += f"### {badge} {fn['title']}\n"
        md += f"- **Hypothesis / Analysis:** {fn['hypothesis']}\n"
        md += f"- **Semantics / Confidence:** `{fn.get('confidence_label', 'Confidence: ' + str(int(fn.get('confidence', 0.5)*100)) + '%')}`\n"
        md += f"- **Supporting Evidence Feeds:** `{', '.join(fn['evidence_sources']) if fn['evidence_sources'] else 'None (Model Hypothesis)'}`\n\n"

    md += "## 2. Collected Evidence Ledger (Deterministic Tool Feeds)\n\n"
    for ev in data["evidence"]:
        md += f"#### Tool Source: `{ev['source']}`\n"
        md += f"```json\n{json.dumps(ev['content'], indent=2)}\n```\n\n"

    md += "## 3. Discovered Entity Relationships\n\n"
    md += "| Source Entity | Relationship Type | Target Entity | Rationale |\n|---|---|---|---|\n"
    for rel in data["relationships"]:
        md += f"| `{rel['source_indicator']}` | `{rel['relation_type']}` | `{rel['target_indicator']}` | `Deterministic tool map` |\n"

    md += """
---

## 4. Scope & Security Disclaimers

> **Principle: "AI Proposes. Evidence Verifies."**
> - Deterministic tool findings carry strict observation certainty provenance.
> - AI hypotheses do not independently elevate threat scoring unless verified by tool evidence rules.
> - Report generated by OpenTrace AI v1.0.0 (Local SOC Workstation Deployment).
"""

    return Response(content=md, media_type="text/markdown")


# ============================================================================
# 4. FRONTEND STATIC FILE SERVING
# ============================================================================

frontend_dir = os.path.join(os.path.dirname(current_dir), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    def serve_frontend_index():
        index_path = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return f.read()
        return "<h1>OpenTrace AI Backend Online</h1>"


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"[*] Starting OpenTrace AI Server on {host}:{port}...")
    uvicorn.run("main:app", host=host, port=port, reload=True)
