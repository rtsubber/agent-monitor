"""
Agent Monitor — Uptime & Cost Tracking for AI Agents
Refactored / security-hardened build.

Key changes vs. the original (see review notes):
  * API keys are no longer stored in plaintext. Only a SHA-256 hash is
    persisted; the raw key is shown to the user exactly once at creation.
  * Keys are generated with `secrets`, not from email + time.time().
  * /v1/keys/{key_id}/status no longer trusts the path param (IDOR fixed).
  * Admin auth uses constant-time compare and refuses to run if unset.
  * The previously-missing `suite_keys` table is now created.
  * Timestamp comparisons use one consistent format (fixes dropped rows).
  * One connection per request via a dependency, always closed.
  * Rate-limit windows match their documented "per-minute" semantics, and
    the table is evicted so it can't grow without bound.
  * X-Forwarded-For is only trusted when running behind a known proxy.
  * datetime.now(timezone.utc) instead of the deprecated utcnow().
"""

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
import sqlite3
import json
import os
import hashlib
import hmac
import secrets
import time
import logging
from datetime import datetime, timedelta, timezone
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent-monitor")

app = FastAPI(
    title="Agent Monitor",
    description="Uptime & cost monitoring for AI agents",
    version="1.1.0",
)

ALLOWED_ORIGINS = [
    "https://brandbooststudio.co",
    "https://suite.brandbooststudio.co",
    "https://agentseek.co",
    "https://localeye.co",
    "http://localhost:8789",  # local dev
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # API auth is via custom headers, not cookies, so credentials aren't needed.
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["X-API-Key", "X-Admin-Key", "X-Suite-Key", "Content-Type"],
)

DB_PATH = os.environ.get("AGENT_MONITOR_DB", "./monitor.db")
ADMIN_KEY = os.environ.get("AGENT_MONITOR_ADMIN_KEY", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
# Only honor X-Forwarded-For when we know we're behind a trusted proxy.
TRUST_PROXY = os.environ.get("TRUST_PROXY", "false").lower() == "true"
# Optional path to the sheets webhook; disabled if unset.
SHEETS_WEBHOOK = os.environ.get("SHEETS_WEBHOOK_PATH", "")

# --- Key helpers ---

KEY_PREFIX = "am_"


def hash_key(raw_key: str) -> str:
    """Hash a raw API key for storage/lookup. Never store the raw key."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def new_api_key() -> tuple[str, str]:
    """Return (raw_key, key_hash). The raw key is shown to the user once."""
    raw = f"{KEY_PREFIX}{secrets.token_urlsafe(24)}"
    return raw, hash_key(raw)


# --- Database ---

def get_db():
    # check_same_thread=False is safe here: each request gets its own
    # connection (via db_dependency) and connections are never shared
    # across concurrent requests.
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def db_dependency():
    """FastAPI dependency: one connection per request, always closed."""
    conn = get_db()
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    conn = get_db()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key_hash TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                name TEXT,
                tier TEXT DEFAULT 'free',
                created_at TEXT DEFAULT (datetime('now')),
                last_used_at TEXT,
                is_active INTEGER DEFAULT 1,
                monthly_heartbeat_limit INTEGER DEFAULT 100,
                monthly_spend_limit INTEGER DEFAULT 1000
            );

            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                key_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                endpoint_url TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (key_hash) REFERENCES api_keys(key_hash)
            );

            CREATE TABLE IF NOT EXISTS heartbeats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                status TEXT DEFAULT 'alive',
                response_time_ms INTEGER,
                metadata TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            );

            CREATE TABLE IF NOT EXISTS spend_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                api_name TEXT,
                cost REAL DEFAULT 0,
                tokens_used INTEGER DEFAULT 0,
                requests INTEGER DEFAULT 1,
                metadata TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                incident_type TEXT NOT NULL,
                message TEXT,
                is_resolved INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                resolved_at TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            );

            CREATE TABLE IF NOT EXISTS suite_keys (
                suite_key_hash TEXT PRIMARY KEY,
                monitor_key_hash TEXT NOT NULL,
                localeye_key TEXT,
                agentseek_key TEXT,
                email TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_hb_agent_ts  ON heartbeats(agent_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_spend_agent_ts ON spend_events(agent_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_agents_key ON agents(key_hash);
        """)
        conn.commit()
    finally:
        conn.close()


init_db()

# --- Time helpers (one consistent format everywhere) ---

# SQLite's datetime('now') yields "YYYY-MM-DD HH:MM:SS". We match that exactly
# so string comparisons in WHERE clauses are correct.
SQLITE_FMT = "%Y-%m-%d %H:%M:%S"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def sqlite_ts(dt: datetime) -> str:
    return dt.strftime(SQLITE_FMT)


def month_start_ts() -> str:
    now = utc_now()
    return sqlite_ts(now.replace(day=1, hour=0, minute=0, second=0, microsecond=0))


def days_ago_ts(days: int) -> str:
    return sqlite_ts(utc_now() - timedelta(days=days))


# --- Rate Limiting (in-memory; see review note re: multi-worker) ---

_rate_limits: dict[str, dict] = {}
MAX_KEYS_PER_HOUR = 5
MAX_SUITE_SIGNUPS_PER_HOUR = 3
MAX_HEARTBEATS_PER_MINUTE = 60
MAX_SPEND_PER_MINUTE = 30


def _check_rate_limit(bucket: str, limit: int, window_seconds: int) -> bool:
    """Returns True if under limit, False if over. Evicts expired buckets."""
    now = time.time()
    # Opportunistic eviction so the dict can't grow without bound.
    if len(_rate_limits) > 10000:
        for k in [k for k, v in _rate_limits.items() if now > v["reset"]]:
            _rate_limits.pop(k, None)
    entry = _rate_limits.get(bucket)
    if entry is None or now > entry["reset"]:
        _rate_limits[bucket] = {"count": 1, "reset": now + window_seconds}
        return True
    entry["count"] += 1
    return entry["count"] <= limit


def _get_client_ip(request: Request) -> str:
    if TRUST_PROXY:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# --- Auth ---

def _lookup_key(conn, raw_key: str):
    """Resolve a raw key (or suite key) to its api_keys row, or None."""
    if raw_key.startswith("suite_"):
        srow = conn.execute(
            "SELECT monitor_key_hash FROM suite_keys WHERE suite_key_hash = ?",
            (hash_key(raw_key),),
        ).fetchone()
        if not srow:
            return None
        key_hash = srow["monitor_key_hash"]
    else:
        key_hash = hash_key(raw_key)
    return conn.execute(
        "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1", (key_hash,)
    ).fetchone()


def verify_api_key(x_api_key: str = Header(...), conn=Depends(db_dependency)):
    row = _lookup_key(conn, x_api_key)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    conn.execute(
        "UPDATE api_keys SET last_used_at = datetime('now') WHERE key_hash = ?",
        (row["key_hash"],),
    )
    conn.commit()
    return dict(row)


def verify_admin(x_admin_key: str = Header(...)):
    # Refuse to run if no admin key is configured (empty == empty would otherwise pass).
    if not ADMIN_KEY:
        raise HTTPException(status_code=503, detail="Admin access not configured")
    if not hmac.compare_digest(x_admin_key, ADMIN_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin key")
    return True


# --- Models ---

class ApiKeyCreate(BaseModel):
    email: EmailStr
    name: Optional[str] = Field(default=None, max_length=200)


class AgentRegister(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    endpoint_url: Optional[str] = Field(default=None, max_length=2000)


class Heartbeat(BaseModel):
    agent_id: str = Field(max_length=64)
    status: str = Field(default="alive", max_length=32)
    response_time_ms: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    metadata: Optional[dict] = None


class SpendEvent(BaseModel):
    agent_id: str = Field(max_length=64)
    api_name: str = Field(max_length=200)
    cost: float = Field(default=0.0, ge=0)
    tokens_used: int = Field(default=0, ge=0)
    requests: int = Field(default=1, ge=0)
    metadata: Optional[dict] = None


# --- Helper for capped metadata ---

def _dump_metadata(meta: Optional[dict]) -> str:
    s = json.dumps(meta or {})
    if len(s) > 10_000:
        raise HTTPException(status_code=413, detail="metadata too large")
    return s


# --- Endpoints ---

@app.post("/v1/keys")
async def create_api_key(request: Request, data: ApiKeyCreate, conn=Depends(db_dependency)):
    """Create a new API key — rate limited per IP. Raw key returned once."""
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(f"{client_ip}:keys", MAX_KEYS_PER_HOUR, 3600):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 5 API keys per hour per IP.")
    raw_key, key_hash = new_api_key()
    conn.execute(
        "INSERT INTO api_keys (key_hash, email, name) VALUES (?, ?, ?)",
        (key_hash, data.email, data.name or data.email.split("@")[0]),
    )
    conn.commit()
    return {"api_key": raw_key, "email": data.email, "tier": "free",
            "note": "Store this key now — it is not retrievable later."}


@app.get("/v1/keys/status")
async def key_status(auth=Depends(verify_api_key), conn=Depends(db_dependency)):
    """Status and usage for the *authenticated* key (no IDOR)."""
    month_start = month_start_ts()
    heartbeats = conn.execute(
        "SELECT COUNT(*) AS count FROM heartbeats h JOIN agents a ON h.agent_id = a.agent_id "
        "WHERE a.key_hash = ? AND h.timestamp >= ?",
        (auth["key_hash"], month_start),
    ).fetchone()
    spend = conn.execute(
        "SELECT COALESCE(SUM(cost),0) AS total, COALESCE(SUM(requests),0) AS reqs "
        "FROM spend_events s JOIN agents a ON s.agent_id = a.agent_id "
        "WHERE a.key_hash = ? AND s.timestamp >= ?",
        (auth["key_hash"], month_start),
    ).fetchone()
    return {
        "email": auth["email"],
        "tier": auth["tier"],
        "is_active": bool(auth["is_active"]),
        "usage": {
            "heartbeats_this_month": heartbeats["count"],
            "spend_this_month": round(spend["total"], 2),
            "requests_this_month": spend["reqs"],
            "heartbeat_limit": auth["monthly_heartbeat_limit"],
            "spend_limit": auth["monthly_spend_limit"],
        },
    }


def _push_to_sheets(event: str, payload: dict):
    """Fire-and-forget sheets push, only if configured. Errors are logged."""
    if not SHEETS_WEBHOOK:
        return
    try:
        import subprocess
        subprocess.Popen(
            ["python3", SHEETS_WEBHOOK, event, json.dumps(payload)],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        logger.warning("Sheets push failed: %s", e)


@app.post("/v1/register")
async def register_agent(data: AgentRegister, auth=Depends(verify_api_key), conn=Depends(db_dependency)):
    """Register a new agent."""
    agent_id = f"mon_{secrets.token_hex(10)}"
    conn.execute(
        "INSERT INTO agents (agent_id, key_hash, name, description, endpoint_url) "
        "VALUES (?, ?, ?, ?, ?)",
        (agent_id, auth["key_hash"], data.name, data.description, data.endpoint_url),
    )
    conn.commit()
    _push_to_sheets("monitor_signup", {
        "email": auth.get("email", ""), "tier": auth.get("tier", "free"),
        "agent_name": data.name,
    })
    return {"agent_id": agent_id, "name": data.name, "status": "registered"}


@app.post("/v1/heartbeat")
async def send_heartbeat(request: Request, data: Heartbeat,
                         auth=Depends(verify_api_key), conn=Depends(db_dependency)):
    """Report an agent heartbeat — rate limited to 60/min per key."""
    if not _check_rate_limit(f"{auth['key_hash']}:heartbeat", MAX_HEARTBEATS_PER_MINUTE, 60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 60 heartbeats per minute per key.")

    agent = conn.execute(
        "SELECT * FROM agents WHERE agent_id = ? AND key_hash = ?",
        (data.agent_id, auth["key_hash"]),
    ).fetchone()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found or not owned by this key")

    last_hb = conn.execute(
        "SELECT status FROM heartbeats WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
        (data.agent_id,),
    ).fetchone()
    was_down = bool(last_hb and last_hb["status"] != "alive")

    conn.execute(
        "INSERT INTO heartbeats (agent_id, status, response_time_ms, metadata) VALUES (?, ?, ?, ?)",
        (data.agent_id, data.status, data.response_time_ms, _dump_metadata(data.metadata)),
    )

    if data.status != "alive":
        conn.execute(
            "INSERT INTO incidents (agent_id, incident_type, message) VALUES (?, ?, ?)",
            (data.agent_id, "agent_down", f"Agent {agent['name']} reported status: {data.status}"),
        )
    elif was_down:
        conn.execute(
            "UPDATE incidents SET is_resolved = 1, resolved_at = datetime('now') "
            "WHERE agent_id = ? AND is_resolved = 0",
            (data.agent_id,),
        )
        await send_telegram_alert(f"Agent {agent['name']} is back online")

    conn.commit()
    return {"status": "recorded", "agent_id": data.agent_id}


@app.post("/v1/spend")
async def report_spend(request: Request, data: SpendEvent,
                       auth=Depends(verify_api_key), conn=Depends(db_dependency)):
    """Report an API spend event — rate limited to 30/min per key."""
    if not _check_rate_limit(f"{auth['key_hash']}:spend", MAX_SPEND_PER_MINUTE, 60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 30 spend events per minute per key.")

    agent = conn.execute(
        "SELECT * FROM agents WHERE agent_id = ? AND key_hash = ?",
        (data.agent_id, auth["key_hash"]),
    ).fetchone()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    conn.execute(
        "INSERT INTO spend_events (agent_id, api_name, cost, tokens_used, requests, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (data.agent_id, data.api_name, data.cost, data.tokens_used, data.requests,
         _dump_metadata(data.metadata)),
    )

    month_start = month_start_ts()
    row = conn.execute(
        "SELECT COALESCE(SUM(cost),0) AS total FROM spend_events s JOIN agents a "
        "ON s.agent_id = a.agent_id WHERE a.key_hash = ? AND s.timestamp >= ?",
        (auth["key_hash"], month_start),
    ).fetchone()
    total = row["total"]

    # Alert only on the crossing event, not on every subsequent request.
    limit = auth["monthly_spend_limit"]
    if total > limit and (total - data.cost) <= limit:
        await send_telegram_alert(
            f"Spend limit reached: ${total:.2f}/${limit} for {auth['email']}"
        )

    conn.commit()
    return {"status": "recorded", "cost": data.cost}


@app.get("/v1/agents")
async def list_agents(auth=Depends(verify_api_key), conn=Depends(db_dependency)):
    """List all agents for this API key."""
    month_start = month_start_ts()
    agents = conn.execute(
        "SELECT * FROM agents WHERE key_hash = ? AND is_active = 1", (auth["key_hash"],)
    ).fetchall()
    result = []
    for a in agents:
        last_hb = conn.execute(
            "SELECT * FROM heartbeats WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
            (a["agent_id"],),
        ).fetchone()
        spend = conn.execute(
            "SELECT COALESCE(SUM(cost),0) AS total, COALESCE(SUM(requests),0) AS reqs "
            "FROM spend_events WHERE agent_id = ? AND timestamp >= ?",
            (a["agent_id"], month_start),
        ).fetchone()
        incidents = conn.execute(
            "SELECT COUNT(*) AS count FROM incidents WHERE agent_id = ? AND is_resolved = 0",
            (a["agent_id"],),
        ).fetchone()
        result.append({
            "agent_id": a["agent_id"],
            "name": a["name"],
            "description": a["description"],
            "endpoint_url": a["endpoint_url"],
            "last_heartbeat": dict(last_hb) if last_hb else None,
            "is_alive": (last_hb["status"] == "alive") if last_hb else False,
            "monthly_spend": round(spend["total"], 2),
            "monthly_requests": spend["reqs"],
            "open_incidents": incidents["count"],
        })
    return {"agents": result}


@app.get("/v1/agents/{agent_id}")
async def get_agent(agent_id: str, auth=Depends(verify_api_key), conn=Depends(db_dependency)):
    """Get agent details + 30d uptime."""
    agent = conn.execute(
        "SELECT * FROM agents WHERE agent_id = ? AND key_hash = ?",
        (agent_id, auth["key_hash"]),
    ).fetchone()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    thirty_days_ago = days_ago_ts(30)
    total_checks = conn.execute(
        "SELECT COUNT(*) AS count FROM heartbeats WHERE agent_id = ? AND timestamp >= ?",
        (agent_id, thirty_days_ago),
    ).fetchone()["count"]
    alive_checks = conn.execute(
        "SELECT COUNT(*) AS count FROM heartbeats WHERE agent_id = ? AND status = 'alive' AND timestamp >= ?",
        (agent_id, thirty_days_ago),
    ).fetchone()["count"]
    uptime_pct = (alive_checks / total_checks * 100) if total_checks > 0 else None

    month_start = month_start_ts()
    spend = conn.execute(
        "SELECT COALESCE(SUM(cost),0) AS total, COALESCE(SUM(requests),0) AS reqs "
        "FROM spend_events WHERE agent_id = ? AND timestamp >= ?",
        (agent_id, month_start),
    ).fetchone()
    recent = conn.execute(
        "SELECT * FROM heartbeats WHERE agent_id = ? ORDER BY id DESC LIMIT 10", (agent_id,)
    ).fetchall()
    recent_spend = conn.execute(
        "SELECT * FROM spend_events WHERE agent_id = ? ORDER BY id DESC LIMIT 10", (agent_id,)
    ).fetchall()

    return {
        "agent_id": agent_id,
        "name": agent["name"],
        "description": agent["description"],
        "endpoint_url": agent["endpoint_url"],
        "uptime_30d": round(uptime_pct, 2) if uptime_pct is not None else None,
        "total_checks_30d": total_checks,
        "alive_checks_30d": alive_checks,
        "monthly_spend": round(spend["total"], 2),
        "monthly_requests": spend["reqs"],
        "recent_heartbeats": [dict(h) for h in recent],
        "recent_spend": [dict(s) for s in recent_spend],
    }


@app.get("/v1/dashboard")
async def dashboard(auth=Depends(verify_api_key), conn=Depends(db_dependency)):
    """Dashboard summary for this API key."""
    month_start = month_start_ts()
    agents = conn.execute(
        "SELECT * FROM agents WHERE key_hash = ? AND is_active = 1", (auth["key_hash"],)
    ).fetchall()
    total_spend = conn.execute(
        "SELECT COALESCE(SUM(cost),0) AS total FROM spend_events s JOIN agents a "
        "ON s.agent_id = a.agent_id WHERE a.key_hash = ? AND s.timestamp >= ?",
        (auth["key_hash"], month_start),
    ).fetchone()["total"]

    alive_count = 0
    for a in agents:
        last = conn.execute(
            "SELECT status FROM heartbeats WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
            (a["agent_id"],),
        ).fetchone()
        if last and last["status"] == "alive":
            alive_count += 1

    open_incidents = conn.execute(
        "SELECT COUNT(*) AS count FROM incidents i JOIN agents a ON i.agent_id = a.agent_id "
        "WHERE a.key_hash = ? AND i.is_resolved = 0",
        (auth["key_hash"],),
    ).fetchone()["count"]

    return {
        "total_agents": len(agents),
        "agents_alive": alive_count,
        "agents_down": len(agents) - alive_count,
        "open_incidents": open_incidents,
        "monthly_spend": round(total_spend, 2),
        "spend_limit": auth["monthly_spend_limit"],
        "heartbeat_limit": auth["monthly_heartbeat_limit"],
    }


@app.get("/v1/admin/stats")
async def admin_stats(admin=Depends(verify_admin), conn=Depends(db_dependency)):
    """Admin dashboard - all stats."""
    total_keys = conn.execute("SELECT COUNT(*) AS count FROM api_keys").fetchone()["count"]
    total_agents = conn.execute("SELECT COUNT(*) AS count FROM agents").fetchone()["count"]
    total_heartbeats = conn.execute("SELECT COUNT(*) AS count FROM heartbeats").fetchone()["count"]
    total_spend = conn.execute("SELECT COALESCE(SUM(cost),0) AS total FROM spend_events").fetchone()["total"]
    total_incidents = conn.execute("SELECT COUNT(*) AS count FROM incidents WHERE is_resolved = 0").fetchone()["count"]
    return {
        "total_api_keys": total_keys,
        "total_agents": total_agents,
        "total_heartbeats": total_heartbeats,
        "total_spend": round(total_spend, 2),
        "open_incidents": total_incidents,
    }


# --- Telegram Alerts ---

async def send_telegram_alert(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    # Plain text (no parse_mode) so agent names can't inject markup.
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": f"Agent Monitor Alert\n\n{message}"}
    try:
        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload, timeout=10)
    except Exception as e:
        logger.warning("Telegram alert failed: %s", e)


# --- Suite Key Endpoints ---

@app.post("/v1/suite/signup")
async def suite_signup(request: Request, data: ApiKeyCreate, conn=Depends(db_dependency)):
    """Sign up for the Agent Business Suite — creates a key for each service."""
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(f"{client_ip}:suite", MAX_SUITE_SIGNUPS_PER_HOUR, 3600):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 3 suite signups per hour per IP.")
    email = data.email
    name = data.name or email.split("@")[0]

    raw_monitor_key, monitor_hash = new_api_key()
    conn.execute(
        "INSERT INTO api_keys (key_hash, email, name, tier) VALUES (?, ?, ?, 'free')",
        (monitor_hash, email, name),
    )
    conn.commit()

    localeye_key = ""
    try:
        async with httpx.AsyncClient() as client:
            le_resp = await client.post(
                os.getenv("LOCALEYE_API_URL", "https://localeye.co/v1/register"),
                params={"email": email}, timeout=10,
            )
            localeye_key = le_resp.json().get("key_id", "")
    except Exception as e:
        logger.warning("Local-Eye signup failed: %s", e)

    agentseek_key = ""
    try:
        async with httpx.AsyncClient() as client:
            ad_resp = await client.post(
                os.getenv("AGENTSEEK_API_URL", "https://agentseek.co/v1/register"),
                json={
                    "name": f"{name}'s Agent",
                    "description": "Agent registered via Agent Business Suite",
                    "capabilities": ["general"],
                    "endpoint_url": "https://example.com",
                    "owner_email": email,
                },
                timeout=10,
            )
            agentseek_key = ad_resp.json().get("api_key", "")
    except Exception as e:
        logger.warning("AgentSeek signup failed: %s", e)

    raw_suite_key = f"suite_{secrets.token_urlsafe(24)}"
    conn.execute(
        "INSERT INTO suite_keys (suite_key_hash, monitor_key_hash, localeye_key, agentseek_key, email) "
        "VALUES (?, ?, ?, ?, ?)",
        (hash_key(raw_suite_key), monitor_hash, localeye_key, agentseek_key, email),
    )
    conn.commit()

    _push_to_sheets("suite_signup", {"email": email})

    return {
        "suite_key": raw_suite_key,
        "monitor_key": raw_monitor_key,
        "localeye_key": localeye_key,
        "agentseek_key": agentseek_key,
        "email": email,
        "message": "Welcome to the Agent Business Suite! Store these keys now — they are not retrievable later.",
    }


@app.get("/v1/suite/keys")
async def suite_keys(x_suite_key: str = Header(None, alias="X-Suite-Key"),
                     conn=Depends(db_dependency)):
    """Look up the suite record for the presented suite key."""
    if not x_suite_key or not x_suite_key.startswith("suite_"):
        raise HTTPException(status_code=401, detail="Invalid suite key.")
    row = conn.execute(
        "SELECT * FROM suite_keys WHERE suite_key_hash = ?", (hash_key(x_suite_key),)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Suite key not found")
    # Note: monitor_key is stored only as a hash and cannot be shown again.
    return {
        "email": row["email"],
        "localeye_key": row["localeye_key"],
        "agentseek_key": row["agentseek_key"],
        "endpoints": {
            "agent_monitor": os.getenv("MONITOR_PUBLIC_URL", "https://brandbooststudio.co/monitor/v1/"),
            "local_eye": os.getenv("LOCALEYE_PUBLIC_URL", "https://localeye.co/v1/"),
            "agent_seek": "https://agentseek.co/v1/",
        },
    }


@app.get("/")
async def root():
    return {
        "name": "Agent Monitor",
        "version": "1.1.0",
        "description": "Uptime & cost monitoring for AI agents",
        "docs": "/docs",
        "endpoints": {
            "register": "/v1/register",
            "heartbeat": "/v1/heartbeat",
            "spend": "/v1/spend",
            "agents": "/v1/agents",
            "dashboard": "/v1/dashboard",
            "admin": "/v1/admin/stats",
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": utc_now().isoformat()}


@app.get("/dashboard")
async def dashboard_ui():
    from fastapi.responses import HTMLResponse
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    try:
        with open(dashboard_path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8789))
    uvicorn.run(app, host="0.0.0.0", port=port, root_path="/monitor")
