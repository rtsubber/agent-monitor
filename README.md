# Agent Monitor 🔍

**Uptime & cost monitoring for AI agents**

Track your AI agents' health, response times, and API spend in one place. Get instant Telegram alerts when things break.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/keys` | POST | Create a new API key |
| `/v1/keys/{key_id}/status` | GET | Check key status & usage |
| `/v1/register` | POST | Register a new agent |
| `/v1/heartbeat` | POST | Report agent heartbeat |
| `/v1/spend` | POST | Report API spend event |
| `/v1/agents` | GET | List all agents |
| `/v1/agents/{agent_id}` | GET | Get agent details + uptime |
| `/v1/dashboard` | GET | Dashboard summary |
| `/v1/admin/stats` | GET | Admin stats (requires admin key) |

## Quick Start

### 1. Create an API key
```bash
curl -X POST https://brandbooststudio.co/agent-monitor/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "name": "Your Name"}'
```

### 2. Register an agent
```bash
curl -X POST https://brandbooststudio.co/agent-monitor/v1/register \
  -H "Content-Type: application/json" \
  -H "X-API-Key: am_your_key_here" \
  -d '{"name": "my-agent", "description": "My AI agent", "endpoint_url": "https://my-agent.example.com"}'
```

### 3. Send heartbeats (every 5 minutes)
```bash
curl -X POST https://brandbooststudio.co/agent-monitor/v1/heartbeat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: am_your_key_here" \
  -d '{"agent_id": "mon_xxx", "status": "alive", "response_time_ms": 120}'
```

### 4. Report spend
```bash
curl -X POST https://brandbooststudio.co/agent-monitor/v1/spend \
  -H "Content-Type: application/json" \
  -H "X-API-Key: am_your_key_here" \
  -d '{"agent_id": "mon_xxx", "api_name": "openai-gpt4", "cost": 0.03, "tokens_used": 1500, "requests": 1}'
```

## Features

- ✅ **Heartbeat monitoring** — Track agent uptime with response time
- ✅ **Spend tracking** — Log API costs per agent, per service
- ✅ **Incident detection** — Auto-create incidents when agents go down
- ✅ **Telegram alerts** — Instant notifications on downtime & spend limits
- ✅ **Dashboard API** — One endpoint for all your agent stats
- ✅ **Free tier** — 100 heartbeats/month, 1000 spend events/month

## Architecture

```
AI Agents → POST /v1/heartbeat → SQLite DB → Dashboard API
AI Agents → POST /v1/spend     → SQLite DB → Telegram Alerts
```

Part of the **Agent Business Suite**:
- 🔍 **AgentSeek** — Discover and register AI agents
- 👁️ **Local-Eye** — Verify the real world
- 💸 **Agent Monitor** — Track uptime & costs

## Pricing

| Tier | Price | Heartbeats/mo | Spend Events/mo |
|------|-------|---------------|-----------------|
| Free | $0 | 100 | 1,000 |
| Pro | $29/mo | 10,000 | 100,000 |
| Suite Bundle | $79/mo | Unlimited | Unlimited |

## Deployment

- **Port:** 8789
- **Database:** SQLite (`monitor.db`)
- **Service:** `systemctl --user start agent-monitor`
- **Public URL:** `https://brandbooststudio.co/agent-monitor/`
- **Tailscale path:** `/monitor`

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (default: 8789) |
| `AGENT_MONITOR_DB` | SQLite database path |
| `AGENT_MONITOR_ADMIN_KEY` | Admin API key |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token for alerts |
| `TELEGRAM_CHAT_ID` | Telegram chat ID for alerts |