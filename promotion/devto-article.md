---
title: "I Built a Monitor for AI Agents Because They Kept Dying Silently"
published: false
description: "Agent Monitor tracks uptime, response times, and API costs for AI agents — with instant Telegram alerts when things break. Because agents can't page you at 3am."
tags: ai, monitoring, devtools, agents
cover_image: https://brandbooststudio.co/agent-business-suite.html
---

# I Built a Monitor for AI Agents Because They Kept Dying Silently

Your API goes down at 2am. Your users get errors. Your revenue drips away. With a regular web service, you'd get a PagerDuty alert, fix it, and go back to sleep.

**AI agents don't work that way.**

When an agent's LLM call fails, it doesn't throw a 500. It hallucinates. When it gets rate-limited, it doesn't crash. It just returns garbage. When it overspends on API calls, you don't find out until the Stripe bill arrives. Agents fail *silently* — and by the time you notice, the damage is done.

**Agent Monitor** fixes that.

## What is Agent Monitor?

Agent Monitor is an uptime and cost tracking API built specifically for AI agents. Three things it does that general-purpose monitors don't:

### 1. Heartbeat Monitoring with Response Time

Your agent pings the monitor every 5 minutes. If it misses a beat, an incident is auto-created and you get a Telegram alert instantly. But it's not just "up or down" — it tracks response time too, because an agent that takes 30 seconds to respond is functionally broken even if it's technically alive.

```bash
curl -X POST https://monitor.brandbooststudio.co/v1/heartbeat \
  -H "X-API-Key: am_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "mon_my_agent_001",
    "status": "alive",
    "response_time_ms": 120
  }'
```

Miss 3 heartbeats? You get a Telegram message: "⚠️ Agent mon_my_agent_001 is DOWN — last heartbeat 15 minutes ago."

### 2. API Spend Tracking

Every API call your agent makes costs money. GPT-4 is $0.03/1K tokens. Claude is $0.015/1K tokens. Ollama is free but burns GPU time. When you're running multiple agents 24/7, those costs add up fast.

Agent Monitor lets you log every spend event:

```bash
curl -X POST https://monitor.brandbooststudio.co/v1/spend \
  -H "X-API-Key: am_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "mon_my_agent_001",
    "api_name": "openai-gpt4",
    "cost": 0.03,
    "tokens_used": 1500,
    "requests": 1
  }'
```

You get a dashboard that shows:
- Total spend per agent
- Spend per API service (OpenAI, Anthropic, Ollama, etc.)
- Spend trends over time
- Alerts when spend exceeds your monthly limit

### 3. Incident Detection & Instant Alerts

When an agent goes down, Agent Monitor auto-creates an incident record:

```json
{
  "incident_id": "inc_abc123",
  "agent_id": "mon_my_agent_001",
  "incident_type": "heartbeat_missed",
  "status": "open",
  "started_at": "2026-05-17T02:15:00Z",
  "resolved_at": null
}
```

And you get a Telegram alert immediately. No PagerDuty integration needed. No Slack webhook setup. Just a Telegram message to your phone, because that's where you are at 3am.

## The Dashboard API

One endpoint gives you everything:

```bash
curl https://monitor.brandbooststudio.co/v1/dashboard \
  -H "X-API-Key: am_your_key_here"
```

```json
{
  "total_agents": 3,
  "agents_up": 2,
  "agents_down": 1,
  "total_spend": 12.45,
  "spend_by_api": {
    "openai-gpt4": 8.20,
    "anthropic-claude": 3.15,
    "ollama-local": 1.10
  },
  "active_incidents": 1,
  "recent_heartbeats": [...],
  "recent_spend": [...]
}
```

This is the endpoint your own dashboard UI calls. Or your cron job checks. Or your status page pulls from.

## Why Not Just Use Datadog/UptimeRobot/Pingdom?

Good question. I tried them. Here's why they don't work for agents:

**Datadog** — Built for infrastructure, not agents. You'd need custom instrumentation for every agent. Costs scale with every metric. Overkill for "is my agent alive and how much is it spending?"

**UptimeRobot/Pingdom** — HTTP pings only. They can check if your agent's endpoint returns 200. They can't tell you if the agent is hallucinating, if response time tripled, or if it just spent $50 on GPT-4 calls.

**Custom Prometheus/Grafana** — Powerful but heavy. Requires running a metrics server, configuring exporters, building dashboards. For a solo dev running 3-5 agents, this is infrastructure for infrastructure's sake.

Agent Monitor is the simple version: heartbeat + spend + alerts. It does one thing well. You integrate it in 5 minutes with two curl calls.

## The Tech Stack

- **FastAPI** — Async Python, automatic OpenAPI docs
- **SQLite (WAL mode)** — Zero-ops database, one file, easy backup
- **Telegram Bot API** — Instant alerts to your phone
- **Tailscale Funnel** — Secure public exposure, auto HTTPS
- **Stripe** — Payment integration for Pro tier

All secrets from environment variables. No hardcoded defaults. The API is open source.

## Part of the Agent Business Suite

Agent Monitor is the third piece of the Agent Business Suite:

1. **[AgentSeek](https://agentseek.co)** — Discover AI agents
2. **[Local-Eye](https://localeye.co)** — Verify real-world data
3. **Agent Monitor** — Track uptime and cost

All three are available as a bundle at **$79/month** with a single suite API key. One key, three APIs, full agent infrastructure.

The suite key system means you authenticate once and access all three services. Register your agent on AgentSeek, verify businesses with Local-Eye, and monitor everything with Agent Monitor — all with the same `suite_*` key.

## Free Tier

Agent Monitor is free for up to 100 heartbeats and 1,000 spend events per month. That's enough to monitor 3-5 agents at 5-minute heartbeat intervals.

No credit card required. No time limit. Free means free.

## Try It Now

1. Get a free API key: `POST /v1/keys`
2. Register your agent: `POST /v1/register`
3. Send heartbeats: `POST /v1/heartbeat`
4. Track spend: `POST /v1/spend`
5. Check dashboard: `GET /v1/dashboard`

Five minutes. Two curl calls. Your agents are monitored.

---

*Agent Monitor is built by [BrandBoost Studio](https://brandbooststudio.co). We make tools for the AI agent economy.*