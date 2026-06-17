<h1 align="center">AuroraRecon</h1>

<p align="center">
  <strong>LLM-Powered Autonomous Penetration Testing Agent</strong><br>
  From Reconnaissance to Report — A Closed-Loop Kill-Chain Orchestrator
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue" alt="Python">
  <img src="https://img.shields.io/badge/vue-3.4+-green" alt="Vue">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="License">
  <img src="https://img.shields.io/badge/docker-required-blue" alt="Docker">
</p>

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Development](#development)
- [Compliance](#compliance)

---

## Architecture Overview

AuroraRecon is built around a **World Model (Attack Graph)** as its central decision hub. Five work streams orbit this hub, covering safety, world modeling, attack path reasoning, domain depth, and cross-engagement learning.

### Agent Orchestration (LangGraph)

### Prerequisites

- Python `>= 3.11`
- Node.js `>= 18`
- Docker & Docker Compose
- LLM API Key (DeepSeek / OpenAI-compatible)

### Step 1 — Build Toolbox Image

```bash
cd docker/toolbox
docker build -t pentest-toolbox:latest .
cd ../..
```

### Step 2 — Configure Environment

```bash
cp .env.example docker/.env
```

Edit `docker/.env` and set at minimum:

| Variable | Description |
|----------|-------------|
| `LLM_API_KEY` | Your LLM provider API key |
| `LHOST` | Reverse shell callback IP |
| `POSTGRES_PASSWORD` | Database password |
| `MSF_PASSWORD` | Metasploit RPC password |

### Step 3 — Start Backend Services

```bash
cd docker
docker compose up -d
```

Starts: `api` (FastAPI), `postgres` (PostgreSQL 16), `redis` (Redis 7), `minio` (object storage), `msf` (Metasploit RPC).

### Step 4 — Start Frontend

```bash
cd frontend
npm install
npm run dev
```

### Access Points

| Service | URL |
|---------|-----|
| Frontend | `http://localhost:3000` |
| API Docs (Swagger) | `http://localhost:8000/docs` |
| Health Check | `http://localhost:8000/health` |
| MinIO Console | `http://localhost:9001` |

---

### Agent Orchestration (LangGraph)

The orchestrator supports **3 execution modes**:

| Mode | Description |
|------|-------------|
| **Linear DAG** | Fixed phase order: recon → vuln_scan → exploit → post → report |
| **Feedback** | With back-edges for retry loops (failed exploits → alternative paths) |
| **Supervisor** | Star topology with 31 deterministic routing rules + LLM fallback |

Each phase is a LangGraph node. The supervisor routes between phases based on state, with human-in-the-loop approval gates before high-impact actions.

### World Model (Attack Graph)

The attack graph is a typed, queryable graph:

**Node Types** (color-coded in frontend):

| Type | Description | Examples |
|------|-------------|----------|
| `host` | Target host | IP/domain |
| `service` | Network service | HTTP:80, SSH:22 |
| `web_endpoint` | Web path/endpoint | /admin, /api |
| `finding` | Vulnerability | CVE-2022-xxx |
| `credential` | Discovered credential | user:pass@host |
| `session` | Active shell/session | Meterpreter, SSH |
| `loot` | Exfiltrated data | Hashes, DB dumps |
| `objective` | Mission objective | Flag found |

**Edge Relations**: `runs_on`, `exposes`, `vulnerable_to`, `yields`, `enables`, `leads_to`, `pivots_to`, `has_session_on`, `requires`, AD relations (member_of, admin_of, kerberoastable), cloud relations (assumes, can_read, can_write).

**Query API**: `exploitable_frontier()`, `chains()`, `paths_to_objective()`, `rank_frontier()`.

---

## Work Streams

AuroraRecon is organized around 5 engineering work streams:

### WS0 — Autonomous Safety Foundation

- **Scope Enforcement**: Per-command runtime validation against `authorized_scope` (CIDR/host whitelist)
- **Safety Gate (3-tier)**: Blocklist (cloud metadata IPs, critical keywords) → Warnlist (large CIDRs) → Allowlist
- **Irreversible Action Detection**: Persistence installation, user creation, scope expansion flagged for approval
- **Kill Switch**: Immediate task termination + container cleanup via `POST /tasks/{id}/abort`
- **Rate Limiting**: Token-based limiters on LLM calls, tool executions, MSF sessions

### WS1 — World Model (Central Hub)

- Structured attack graph with typed nodes and edges
- Query/write API (`WorldModelQuery`, `WorldModelWriter`)
- Real-time delta updates via WebSocket, rendered in ECharts force-directed graph
- Kill-chain path highlighting with flow animation
- Node pinning prevents layout jitter on updates

### WS2 — Attack Path Reasoning

- **Target Selection**: `rank_frontier()` scores exploitable nodes by severity, CVE presence, and path value
- **Chain Composition**: Links vulnerabilities → credentials → lateral movement targets
- **Failure Reflection**: Analyzes why exploits failed (WAF, version mismatch, environment) and adapts strategy
- **Hypothesis-Driven**: Activates targeted hypothesis testing for uncertain findings

### WS3 — Domain Depth

- **Active Directory**: SMB/LDAP/Kerberos enumeration, BloodHound ingestion, Kerberoasting, DCSync
- **Internal Network**: Service discovery, lateral movement (PsExec, WinRM, WMI, SSH hopping)
- **Cloud**: IAM role enumeration, S3 bucket discovery, assume-role chaining
- **Scene Classification**: Auto-detects environment type (Web/Intranet/AD/Cloud) for adaptive strategy

### WS4 — Memory & Learning

- **Cross-Engagement Memory**: Historical findings injected as `source=prior` hints (credential presence without plaintext)
- **Skill Priority Learning**: Per-scene, per-skill success rate tracking with automatic weight adjustment
- **Draft Skill Synthesis**: Successful exploit sequences auto-synthesized into `.drafts/` for human review

---

## Features

### Core Capabilities

- **Full Kill-Chain Execution**: Recon → Vuln Scan → Exploit → Post-Exploit → Report
- **Real Post-Exploitation**: Lateral movement (SMB/WinRM/PSExec/SSH), privilege escalation (kernel exploits, SUID, sudo), persistence (cron, SSH keys, web shells, systemd), objective collection (flag search, credential harvesting, database dumps)
- **Human-in-the-Loop**: Approval gates at exploitation and post-exploitation phases, checkpoint/resume, operator chat intervention mid-task, 3 autonomy levels (Manual / Supervised / Autonomous)

### Skill Engine

Deterministic exploit paths with LLM fallback:

| Phase | Mechanism |
|-------|-----------|
| **Match** | Scoring by CVE (+100), keyword (+60), fingerprint (+20), JSON probe (+40), evidence (+10) |
| **Probe** | Pre-exploitation environment checks (OS, version, architecture) |
| **Execute** | Deterministic shell command steps — no LLM overhead |
| **Fallback** | LLM ReAct loop with full context (skill principle + references + failed commands) |

**50+ skills** across 12 categories: Java Deserialization, Web RCE, SQL Injection, Network Exploitation, Privilege Escalation, Credential Attacks, Persistence, Server Misconfig, SSTI, LFI/RFI, XSS, SSRF.

### Real-Time Dashboard

- **Live Attack Graph**: ECharts force-directed graph with kill-chain flow animation, node pinning, >120 node degradation
- **Decision Timeline**: Per-action renderers (thought, target_selected, chain_selected, reflection, hypothesis_test), LLM typewriter streaming
- **Log Terminal**: @xterm/xterm with virtual scrolling, frame-buffered rendering

### Report Generation

- Two-round LLM generation: narrative first (discovery + verification + exploitation), then fix checklist
- Jinja2 markdown template with full structured data
- Cover page with task metadata and executive summary
- Online editing, PDF export, Markdown download

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Agent Framework** | LangGraph 0.2, LangChain 0.3 |
| **API** | FastAPI 0.115, Uvicorn 0.30, WebSocket (Redis Stream v2) |
| **Database** | PostgreSQL 16 (SQLAlchemy 2.0 async + asyncpg), Redis 7 |
| **Storage** | MinIO (reports, artifacts) |
| **LLM** | OpenAI-compatible API (DeepSeek, OpenAI, Anthropic) with failover |
| **Frontend** | Vue 3.4, Vite 5, Pinia 2.1, Element Plus 2.7, TypeScript 6.0 |
| **Charts** | ECharts 6.0, vue-echarts 8.0 |
| **Terminal** | @xterm/xterm 6.0 |
| **Testing** | pytest 8.3, pytest-asyncio 0.24 (54 backend test files), Vitest 4.1 (frontend) |
| **DevOps** | Docker Compose, Nginx reverse proxy |
| **Security** | Per-command scope guard, JWT auth, CORS middleware, RBAC (user/admin) |

---

## API Reference

### Tasks

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/tasks` | Create new pentest task |
| `GET` | `/tasks` | List all tasks |
| `GET` | `/tasks/{id}` | Task detail with findings, ports, credentials |
| `POST` | `/tasks/{id}/cancel` | Cancel running task |
| `POST` | `/tasks/{id}/abort` | Immediate kill + container cleanup |
| `POST` | `/tasks/{id}/approve` | Approve pending action |
| `POST` | `/tasks/{id}/checkpoint/respond` | Respond to checkpoint (approve/modify/reject) |
| `POST` | `/tasks/{id}/chat` | Inject operator message mid-task |
| `POST` | `/tasks/{id}/resume` | Resume paused task |
| `GET` | `/tasks/{id}/logs` | Paginated/streaming log access |
| `GET` | `/tasks/{id}/branches` | Branch tree |

### Real-Time

| Method | Endpoint | Description |
|--------|----------|-------------|
| `WS` | `/ws/{task_id}` | Redis Stream v2: logs, decision events, phase updates, approvals, branch events, done signal |

### Skills

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/skills` | List all skills with metadata |
| `GET` | `/skills/{id}/raw` | Get skill YAML content |
| `PUT` | `/skills/{id}/raw` | Save skill YAML |
| `GET` | `/skills/{id}/tree` | Directory tree (skill.yaml, SKILL.md, references/) |
| `GET` | `/skills/{id}/file?path=` | Read any file in skill directory |
| `PUT` | `/skills/{id}/file?path=` | Write any file in skill directory |
| `POST` | `/skills/reload` | Reload skill registry from disk |
| `GET` | `/skills/drafts` | List draft skills |
| `POST` | `/skills/drafts/{name}/promote` | Promote draft to skill |

### Knowledge Base

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/knowledge/entries` | List all KB entries |
| `GET` | `/knowledge/{id}/raw` | Get entry JSON |
| `PUT` | `/knowledge/{id}/raw` | Save entry JSON |
| `POST` | `/knowledge/build` | Build KB (full or single entry) |
| `POST` | `/knowledge/reload` | Reload KB from disk |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/metrics/overview` | System, tool, invocation, guard stats |

---

## Configuration

Key environment variables (see `.env.example` for full list):

| Variable | Purpose | Default |
|----------|---------|---------|
| `LLM_PROVIDER` | LLM provider | `deepseek` |
| `LLM_API_KEY` | API key | *(required)* |
| `LLM_MODEL` | Model name | `deepseek-v4-flash` |
| `LLM_BASE_URL` | API base URL | `https://api.deepseek.com` |
| `JWT_SECRET` | JWT signing key | auto-generated |
| `DATABASE_URL` | PostgreSQL connection | `postgresql+asyncpg://...` |
| `REDIS_URL` | Redis connection | `redis://localhost:6379/0` |
| `MSF_PASSWORD` | Metasploit RPC | `pentest123` |
| `LHOST` | Reverse shell IP | `127.0.0.1` |
| `TOOLBOX_IMAGE` | Docker toolbox image | `pentest-toolbox:latest` |
| `MAX_TOOL_TIMEOUT` | Max tool execution (s) | `360` |
| `MAX_STAGE_RUNTIME` | Max phase runtime (s) | `900` |

Safety config YAML files in `backend/config/`:
- `safety_rules.yaml` — Blocklist/allowlist/warnlist rules
- `detection_filter.yaml` — Service fingerprint filtering
- `path_reasoning.yaml` — Frontier scoring weights

---

## Project Structure

```
AuroraRecon/
├── backend/
│   ├── agents/           # Orchestrator, supervisor, specialized agents (28 files)
│   ├── api/              # FastAPI app, 11 routers, WebSocket, event stream
│   ├── tools/            # Docker executor, tool registry (6 YAML definitions, 16 parsers)
│   ├── skills/           # Skill engine, registry (50+ skills in 12 categories)
│   ├── knowledge/        # Exploit KB (22 entries + embeddings), hybrid retrieval
│   ├── llm/              # LLM router (failover chain), prompt templates
│   ├── report/           # Jinja2 report generator, markdown template
│   ├── db/               # PostgreSQL (SQLAlchemy async), Redis cache
│   ├── config/           # Safety rules, detection filters, path weights
│   ├── metrics/          # LLM call & tool execution metrics
│   ├── storage/          # MinIO client
│   └── tests/            # 54 pytest files
├── frontend/
│   └── src/
│       ├── views/        # 16 user pages + 10 admin pages
│       ├── components/   # 30 Vue 3 components
│       ├── stores/       # Pinia stores (taskLive, taskList, auth, uiPrefs)
│       ├── composables/  # 9 composables (chartTheme, attackGraphOption, etc.)
│       ├── api/          # Axios HTTP + WebSocket
│       ├── services/     # wsManager, eventStore (IndexedDB)
│       ├── types/        # Full TypeScript type definitions (729 lines)
│       └── router/       # Vue Router with role-based guards
├── docker/
│   ├── docker-compose.yml    # Full stack (api, postgres, redis, minio, msf)
│   ├── api/Dockerfile        # Python API container
│   ├── toolbox/Dockerfile    # Kali-based pentest toolbox (30+ tools)
│   └── frontend/             # Multi-stage Node build → Nginx serve
├── docs/                 # Architecture docs, project plan, speech script
├── .env.example         # Environment template (56 lines)
└── requirements.txt     # Python dependencies
```

---

## Development

### Backend (local)

```bash
pip install -r requirements.txt
uvicorn backend.api.main:app --reload --port 8000
```

### Frontend (local)

```bash
cd frontend
npm install
npm run dev        # Dev server on :3000, proxies /api + /ws to :8000
npm run build      # Production build
npm run test       # Vitest
npm run lint       # ESLint
```

### Running Tests

```bash
# Backend
cd backend
pytest tests/ -v

# Frontend
cd frontend
npm run test
```

---

## Compliance

This project is intended exclusively for **authorized security testing** — CTF competitions, internal red team exercises, and penetration tests with explicit written authorization.

**Do not use on targets without proper authorization.** The system includes multiple safety mechanisms (scope enforcement, irreversible action detection, kill switch), but ultimate responsibility lies with the operator.

---

## License

MIT
