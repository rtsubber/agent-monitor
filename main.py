"""
Agent Monitor — Uptime & Cost Tracking for AI Agents
MVP: Heartbeat, spend tracking, status dashboard, Telegram alerts
"""

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import sqlite3
import json
import os
import hashlib
import time
from datetime import datetime, timedelta
import httpx

app = FastAPI(
    title="Agent Monitor",
    description="Uptime & cost monitoring for AI agents",
    version="1.0.0",
)

ALLOWED_ORIGINS = [
    "https://brandbooststudio.co",
    "https://suite.brandbooststudio.co",
    "https://agentseek.co",
    "https://localeye.co",
    # Tailscale Funnel URL added dynamically from env
    "http://localhost:8789",  # local dev
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["X-API-Key", "X-Admin-Key", "Content-Type", "Authorization"],
)

DB_PATH = os.environ.get("AGENT_MONITOR_DB", "/home/ron/.openclaw/workspace/agent-monitor/monitor.db")
ADMIN_KEY = os.environ.get("AGENT_MONITOR_ADMIN_KEY", "")  # Set via .env
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")  # Set via .env
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")  # Set via .env

# --- Database ---

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key_id TEXT PRIMARY KEY,
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
            key_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            endpoint_url TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (key_id) REFERENCES api_keys(key_id)
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
    """)
    conn.commit()
    conn.close()

init_db()

# --- Rate Limiting ---

# Simple in-memory rate limiter
_rate_limits = {}  # {ip: {"keys": count, "keys_reset": timestamp, ...}}
RATE_LIMIT_WINDOW = 3600  # 1 hour
MAX_KEYS_PER_IP = 5
MAX_HEARTBEATS_PER_KEY_PER_MINUTE = 60
MAX_SPEND_PER_KEY_PER_MINUTE = 30

def _check_rate_limit(ip: str, action: str, limit: int) -> bool:
    """Returns True if under limit, False if over."""
    now = time.time()
    key = f"{ip}:{action}"
    if key not in _rate_limits:
        _rate_limits[key] = {"count": 1, "reset": now + RATE_LIMIT_WINDOW}
        return True
    entry = _rate_limits[key]
    if now > entry["reset"]:
        _rate_limits[key] = {"count": 1, "reset": now + RATE_LIMIT_WINDOW}
        return True
    entry["count"] += 1
    return entry["count"] <= limit

def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, considering proxies."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# --- Auth ---

def resolve_api_key(api_key: str) -> str:
    """Resolve a suite key to the service-specific key, or return the key as-is."""
    if api_key.startswith("suite_"):
        conn = get_db()
        row = conn.execute("SELECT monitor_key FROM suite_keys WHERE suite_key = ?", (api_key,)).fetchone()
        conn.close()
        if row:
            return row[0]
        raise HTTPException(status_code=401, detail="Invalid suite key")
    return api_key

def verify_api_key(x_api_key: str = Header(...)):
    resolved_key = resolve_api_key(x_api_key)
    conn = get_db()
    row = conn.execute("SELECT * FROM api_keys WHERE key_id = ? AND is_active = 1", (resolved_key,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    # Update last used
    conn = get_db()
    conn.execute("UPDATE api_keys SET last_used_at = datetime('now') WHERE key_id = ?", (resolved_key,))
    conn.commit()
    conn.close()
    return dict(row)

def verify_admin(x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    return True

# --- Models ---

class ApiKeyCreate(BaseModel):
    email: str
    name: Optional[str] = None

class AgentRegister(BaseModel):
    name: str
    description: Optional[str] = None
    endpoint_url: Optional[str] = None

class Heartbeat(BaseModel):
    agent_id: str
    status: str = "alive"
    response_time_ms: Optional[int] = None
    metadata: Optional[dict] = None

class SpendEvent(BaseModel):
    agent_id: str
    api_name: str
    cost: float = 0.0
    tokens_used: int = 0
    requests: int = 1
    metadata: Optional[dict] = None

# --- Endpoints ---

@app.post("/v1/keys")
async def create_api_key(request: Request, data: ApiKeyCreate):
    """Create a new API key — rate limited to 5 per hour per IP"""
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip, "keys", MAX_KEYS_PER_IP):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 5 API keys per hour per IP.")
    key_id = f"am_{hashlib.sha256(f'{data.email}{time.time()}'.encode()).hexdigest()[:24]}"
    conn = get_db()
    conn.execute(
        "INSERT INTO api_keys (key_id, email, name) VALUES (?, ?, ?)",
        (key_id, data.email, data.name or data.email.split('@')[0])
    )
    conn.commit()
    conn.close()
    return {"api_key": key_id, "email": data.email, "tier": "free"}

@app.get("/v1/keys/{key_id}/status")
async def key_status(key_id: str, auth = Depends(verify_api_key)):
    """Check API key status and usage — requires authentication"""
    conn = get_db()
    row = conn.execute("SELECT * FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Key not found")
    
    # Get usage stats
    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    
    heartbeats = conn.execute(
        "SELECT COUNT(*) as count FROM heartbeats h JOIN agents a ON h.agent_id = a.agent_id WHERE a.key_id = ? AND h.timestamp >= ?",
        (key_id, month_start)
    ).fetchone()
    
    spend = conn.execute(
        "SELECT COALESCE(SUM(cost), 0) as total, COALESCE(SUM(requests), 0) as reqs FROM spend_events s JOIN agents a ON s.agent_id = a.agent_id WHERE a.key_id = ? AND s.timestamp >= ?",
        (key_id, month_start)
    ).fetchone()
    
    conn.close()
    return {
        "key_id": key_id,
        "email": row["email"],
        "tier": row["tier"],
        "is_active": bool(row["is_active"]),
        "usage": {
            "heartbeats_this_month": heartbeats["count"] if heartbeats else 0,
            "spend_this_month": round(spend["total"], 2) if spend else 0,
            "requests_this_month": spend["reqs"] if spend else 0,
            "heartbeat_limit": row["monthly_heartbeat_limit"],
            "spend_limit": row["monthly_spend_limit"]
        }
    }

@app.post("/v1/register")
async def register_agent(data: AgentRegister, auth = Depends(verify_api_key)):
    """Register a new agent"""
    agent_id = f"mon_{hashlib.sha256(f'{data.name}{time.time()}'.encode()).hexdigest()[:20]}"
    conn = get_db()
    conn.execute(
        "INSERT INTO agents (agent_id, key_id, name, description, endpoint_url) VALUES (?, ?, ?, ?, ?)",
        (agent_id, auth["key_id"], data.name, data.description, data.endpoint_url)
    )
    conn.commit()
    conn.close()
    return {
        "agent_id": agent_id,
        "name": data.name,
        "status": "registered"
    }

@app.post("/v1/heartbeat")
async def send_heartbeat(request: Request, data: Heartbeat, auth = Depends(verify_api_key)):
    """Report an agent heartbeat — rate limited to 60/min per key"""
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(f"{auth['key_id']}:heartbeat", "heartbeat", MAX_HEARTBEATS_PER_KEY_PER_MINUTE):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 60 heartbeats per minute per key.")
    conn = get_db()
    # Verify agent belongs to this key
    agent = conn.execute("SELECT * FROM agents WHERE agent_id = ? AND key_id = ?", (data.agent_id, auth["key_id"])).fetchone()
    if not agent:
        conn.close()
        raise HTTPException(status_code=404, detail="Agent not found or not owned by this key")
    
    # Check if agent was previously down (create incident resolution)
    last_hb = conn.execute(
        "SELECT status FROM heartbeats WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 1",
        (data.agent_id,)
    ).fetchone()
    
    was_down = last_hb and last_hb["status"] != "alive"
    
    conn.execute(
        "INSERT INTO heartbeats (agent_id, status, response_time_ms, metadata) VALUES (?, ?, ?, ?)",
        (data.agent_id, data.status, data.response_time_ms, json.dumps(data.metadata or {}))
    )
    
    # Create incident if down
    if data.status != "alive":
        conn.execute(
            "INSERT INTO incidents (agent_id, incident_type, message) VALUES (?, ?, ?)",
            (data.agent_id, "agent_down", f"Agent {agent['name']} reported status: {data.status}")
        )
    elif was_down:
        # Agent recovered — resolve incident and notify
        conn.execute(
            "UPDATE incidents SET is_resolved = 1, resolved_at = datetime('now') WHERE agent_id = ? AND is_resolved = 0",
            (data.agent_id,)
        )
        await send_telegram_alert(f"✅ Agent {agent['name']} is back online!")
    
    conn.commit()
    conn.close()
    return {"status": "recorded", "agent_id": data.agent_id}

@app.post("/v1/spend")
async def report_spend(request: Request, data: SpendEvent, auth = Depends(verify_api_key)):
    """Report an API spend event — rate limited to 30/min per key"""
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(f"{auth['key_id']}:spend", "spend", MAX_SPEND_PER_KEY_PER_MINUTE):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 30 spend events per minute per key.")
    """Report an API spend event"""
    conn = get_db()
    agent = conn.execute("SELECT * FROM agents WHERE agent_id = ? AND key_id = ?", (data.agent_id, auth["key_id"])).fetchone()
    if not agent:
        conn.close()
        raise HTTPException(status_code=404, detail="Agent not found")
    
    conn.execute(
        "INSERT INTO spend_events (agent_id, api_name, cost, tokens_used, requests, metadata) VALUES (?, ?, ?, ?, ?, ?)",
        (data.agent_id, data.api_name, data.cost, data.tokens_used, data.requests, json.dumps(data.metadata or {}))
    )
    
    # Check spend limits
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    total = conn.execute(
        "SELECT COALESCE(SUM(cost), 0) as total FROM spend_events s JOIN agents a ON s.agent_id = a.agent_id WHERE a.key_id = ? AND s.timestamp >= ?",
        (auth["key_id"], month_start)
    ).fetchone()
    
    if total and total["total"] > auth["monthly_spend_limit"]:
        await send_telegram_alert(f"⚠️ Spend limit reached: ${total['total']:.2f}/${auth['monthly_spend_limit']} for {auth['email']}")
    
    conn.commit()
    conn.close()
    return {"status": "recorded", "cost": data.cost}

@app.get("/v1/agents")
async def list_agents(auth = Depends(verify_api_key)):
    """List all agents for this API key"""
    conn = get_db()
    agents = conn.execute("SELECT * FROM agents WHERE key_id = ? AND is_active = 1", (auth["key_id"],)).fetchall()
    result = []
    for a in agents:
        # Get last heartbeat
        last_hb = conn.execute(
            "SELECT * FROM heartbeats WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 1",
            (a["agent_id"],)
        ).fetchone()
        
        # Get monthly spend
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        spend = conn.execute(
            "SELECT COALESCE(SUM(cost), 0) as total, COALESCE(SUM(requests), 0) as reqs FROM spend_events WHERE agent_id = ? AND timestamp >= ?",
            (a["agent_id"], month_start)
        ).fetchone()
        
        # Get open incidents
        incidents = conn.execute(
            "SELECT COUNT(*) as count FROM incidents WHERE agent_id = ? AND is_resolved = 0",
            (a["agent_id"],)
        ).fetchone()
        
        result.append({
            "agent_id": a["agent_id"],
            "name": a["name"],
            "description": a["description"],
            "endpoint_url": a["endpoint_url"],
            "last_heartbeat": dict(last_hb) if last_hb else None,
            "is_alive": last_hb["status"] == "alive" if last_hb else False,
            "monthly_spend": round(spend["total"], 2) if spend else 0,
            "monthly_requests": spend["reqs"] if spend else 0,
            "open_incidents": incidents["count"] if incidents else 0
        })
    
    conn.close()
    return {"agents": result}

@app.get("/v1/agents/{agent_id}")
async def get_agent(agent_id: str, auth = Depends(verify_api_key)):
    """Get agent details"""
    conn = get_db()
    agent = conn.execute("SELECT * FROM agents WHERE agent_id = ? AND key_id = ?", (agent_id, auth["key_id"])).fetchone()
    if not agent:
        conn.close()
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Uptime calculation (last 30 days)
    thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).isoformat()
    total_checks = conn.execute(
        "SELECT COUNT(*) as count FROM heartbeats WHERE agent_id = ? AND timestamp >= ?",
        (agent_id, thirty_days_ago)
    ).fetchone()["count"]
    
    alive_checks = conn.execute(
        "SELECT COUNT(*) as count FROM heartbeats WHERE agent_id = ? AND status = 'alive' AND timestamp >= ?",
        (agent_id, thirty_days_ago)
    ).fetchone()["count"]
    
    uptime_pct = (alive_checks / total_checks * 100) if total_checks > 0 else 100
    
    # Monthly spend
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    spend = conn.execute(
        "SELECT COALESCE(SUM(cost), 0) as total, COALESCE(SUM(requests), 0) as reqs FROM spend_events WHERE agent_id = ? AND timestamp >= ?",
        (agent_id, month_start)
    ).fetchone()
    
    # Recent heartbeats
    recent = conn.execute(
        "SELECT * FROM heartbeats WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 10",
        (agent_id,)
    ).fetchall()
    
    # Recent spend
    recent_spend = conn.execute(
        "SELECT * FROM spend_events WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 10",
        (agent_id,)
    ).fetchall()
    
    conn.close()
    
    return {
        "agent_id": agent_id,
        "name": agent["name"],
        "description": agent["description"],
        "endpoint_url": agent["endpoint_url"],
        "uptime_30d": round(uptime_pct, 2),
        "total_checks_30d": total_checks,
        "alive_checks_30d": alive_checks,
        "monthly_spend": round(spend["total"], 2) if spend else 0,
        "monthly_requests": spend["reqs"] if spend else 0,
        "recent_heartbeats": [dict(h) for h in recent],
        "recent_spend": [dict(s) for s in recent_spend]
    }

@app.get("/v1/dashboard")
async def dashboard(auth = Depends(verify_api_key)):
    """Dashboard summary for this API key"""
    conn = get_db()
    
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    
    agents = conn.execute("SELECT * FROM agents WHERE key_id = ? AND is_active = 1", (auth["key_id"],)).fetchall()
    
    total_spend = conn.execute(
        "SELECT COALESCE(SUM(cost), 0) as total FROM spend_events s JOIN agents a ON s.agent_id = a.agent_id WHERE a.key_id = ? AND s.timestamp >= ?",
        (auth["key_id"], month_start)
    ).fetchone()["total"]
    
    alive_count = 0
    for a in agents:
        last = conn.execute("SELECT status FROM heartbeats WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 1", (a["agent_id"],)).fetchone()
        if last and last["status"] == "alive":
            alive_count += 1
    
    open_incidents = conn.execute(
        "SELECT COUNT(*) as count FROM incidents i JOIN agents a ON i.agent_id = a.agent_id WHERE a.key_id = ? AND i.is_resolved = 0",
        (auth["key_id"],)
    ).fetchone()["count"]
    
    conn.close()
    
    return {
        "total_agents": len(agents),
        "agents_alive": alive_count,
        "agents_down": len(agents) - alive_count,
        "open_incidents": open_incidents,
        "monthly_spend": round(total_spend, 2),
        "spend_limit": auth["monthly_spend_limit"],
        "heartbeat_limit": auth["monthly_heartbeat_limit"]
    }

@app.get("/v1/admin/stats")
async def admin_stats(admin = Depends(verify_admin)):
    """Admin dashboard - all stats"""
    conn = get_db()
    
    total_keys = conn.execute("SELECT COUNT(*) as count FROM api_keys").fetchone()["count"]
    total_agents = conn.execute("SELECT COUNT(*) as count FROM agents").fetchone()["count"]
    total_heartbeats = conn.execute("SELECT COUNT(*) as count FROM heartbeats").fetchone()["count"]
    total_spend = conn.execute("SELECT COALESCE(SUM(cost), 0) as total FROM spend_events").fetchone()["total"]
    total_incidents = conn.execute("SELECT COUNT(*) as count FROM incidents WHERE is_resolved = 0").fetchone()["count"]
    
    conn.close()
    
    return {
        "total_api_keys": total_keys,
        "total_agents": total_agents,
        "total_heartbeats": total_heartbeats,
        "total_spend": round(total_spend, 2),
        "open_incidents": total_incidents
    }

# --- Telegram Alerts ---

async def send_telegram_alert(message: str):
    """Send a Telegram alert"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": f"🔴 Agent Monitor Alert\n\n{message}",
        "parse_mode": "HTML"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"Telegram alert failed: {e}")

# --- Health ---



# --- Suite Key Endpoints ---

@app.post("/v1/suite/signup")
async def suite_signup(request: Request, data: ApiKeyCreate):
    """Sign up for the Agent Business Suite - creates keys for all three services - rate limited"""
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip, "suite_signup", 3):  # 3 signups per hour per IP
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 3 suite signups per hour per IP.")
    email = data.email
    name = data.name or email.split('@')[0]
    
    # 1. Create Agent Monitor key
    monitor_key_id = f"am_{hashlib.sha256(f'{email}{time.time()}'.encode()).hexdigest()[:24]}"
    conn = get_db()
    conn.execute(
        "INSERT INTO api_keys (key_id, email, name, tier) VALUES (?, ?, ?, 'free')",
        (monitor_key_id, email, name)
    )
    conn.commit()
    
    # 2. Create Local-Eye key
    try:
        async with httpx.AsyncClient() as client:
            le_resp = await client.post(
                os.getenv("LOCALEYE_API_URL", "https://localeye.co/v1/register"),
                params={"email": email},
                timeout=10
            )
            le_data = le_resp.json()
            localeye_key = le_data.get("key_id", "")
    except Exception:
        localeye_key = ""
    
    # 3. Create AgentSeek key
    agentseek_key = ""
    try:
        async with httpx.AsyncClient() as client:
            ad_resp = await client.post(
                "https://agentseek.co/v1/register",
                json={
                    "name": f"{name}'s Agent",
                    "description": f"Agent registered via Agent Business Suite",
                    "capabilities": ["general"],
                    "endpoint_url": "https://example.com",
                    "owner_email": email
                },
                timeout=10
            )
            ad_data = ad_resp.json()
            agentseek_key = ad_data.get("api_key", "")
    except Exception:
        agentseek_key = ""
    
    # 4. Create suite key mapping
    suite_key = f"suite_{monitor_key_id[3:]}"
    conn.execute(
        "INSERT INTO suite_keys (suite_key, monitor_key, localeye_key, agentseek_key, email) VALUES (?, ?, ?, ?, ?)",
        (suite_key, monitor_key_id, localeye_key, agentseek_key, email)
    )
    conn.commit()
    conn.close()
    
    return {
        "suite_key": suite_key,
        "monitor_key": monitor_key_id,
        "localeye_key": localeye_key,
        "agentseek_key": agentseek_key,
        "email": email,
        "message": "Welcome to the Agent Business Suite! Your suite key works across all three APIs."
    }

@app.get("/v1/suite/keys")
async def suite_keys(x_suite_key: str = Header(None, alias="X-Suite-Key")):
    """Get all keys associated with a suite key"""
    if not x_suite_key or not x_suite_key.startswith("suite_"):
        raise HTTPException(status_code=401, detail="Invalid suite key. Use the suite_key returned from /v1/suite/signup")
    
    conn = get_db()
    row = conn.execute("SELECT * FROM suite_keys WHERE suite_key = ?", (x_suite_key,)).fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Suite key not found")
    
    return {
        "suite_key": row[0],
        "monitor_key": row[1],
        "localeye_key": row[2],
        "agentseek_key": row[3],
        "email": row[4],
        "endpoints": {
            "agent_monitor": os.getenv("MONITOR_PUBLIC_URL", "https://brandbooststudio.co/monitor/v1/"),
            "local_eye": os.getenv("LOCALEYE_PUBLIC_URL", "https://localeye.co/v1/"),
            "agent_seek": "https://agentseek.co/v1/"
        }
    }


@app.get("/")
async def root():
    return {
        "name": "Agent Monitor",
        "version": "1.0.0",
        "description": "Uptime & cost monitoring for AI agents",
        "docs": "/docs",
        "endpoints": {
            "register": "/v1/register",
            "heartbeat": "/v1/heartbeat",
            "spend": "/v1/spend",
            "agents": "/v1/agents",
            "dashboard": "/v1/dashboard",
            "admin": "/v1/admin/stats"
        }
    }

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8789))
    uvicorn.run(app, host="0.0.0.0", port=port, root_path="/monitor")
