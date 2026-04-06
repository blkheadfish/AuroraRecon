# AuroraRecon (PentestAI v2)

面向 **CTF/授权靶场/授权红蓝对抗** 的 AI 渗透测试工作台。  
项目核心是基于 LangGraph 的攻链编排，配合 Docker 工具沙箱、Skill 引擎、知识库检索与人工审批，实现从侦察到报告的闭环。

## 1) 架构总览

```text
Vue 3 Frontend
  ├─ 任务中心 / 决策视图 / 报告中心 / 工具管理 / Skill管理 / 知识库管理
  └─ WebSocket 实时事件流（日志、命令执行、审批状态）
             │
             ▼
FastAPI API Gateway
  ├─ 任务与审批 API
  ├─ Metrics API
  ├─ Skill/Knowledge/Profile/Settings API
  └─ Chat API（用户与任务代理对话）
             │
             ▼
LangGraph Orchestrator
  recon → vuln_scan → surface_enum → exploit_decision
      → awaiting_approval → foothold_attempt → secondary_attack
      → post_foothold_enum → privesc_attempt → objective_collect → report
             │
             ▼
Tool Executor + Registry
  ├─ container-exec（任务持久容器）
  ├─ container-run（临时容器）
  └─ remote（阶段二预留）
             │
             ▼
Toolbox / MSF / LLM / Storage
  ├─ pentest-toolbox (Kali tools)
  ├─ Metasploit RPC
  ├─ DeepSeek/OpenAI/Anthropic
  └─ PostgreSQL + Redis + MinIO
```

## 2) 核心特性

- **攻链优先编排**：流程不止“扫洞”，而是围绕立足点、提权与目标收集推进完整攻链。
- **人工审批断点续跑**：在利用前强制进入 `awaiting_approval`，批准后无缝 `resume`。
- **任务级容器隔离**：每个任务可复用独立 toolbox 容器，兼顾状态保留与并发隔离。
- **结构化执行可观测**：命令、耗时、退出码、stdout/stderr 全链路入库并在前端可视化。
- **Skill 引擎 + ReAct 兜底**：先走确定性利用路径，失败后进入 LLM 自由推理补偿。
- **知识库混合检索**：关键词 + 语义向量（可降级），为利用决策提供上下文知识。
- **报告中心在线编辑**：任务报告支持 Markdown 编辑与预览，便于二次修订输出。

## 3) 功能模块

### 后端能力

- 任务生命周期：创建、执行、取消、删除、恢复、统计。
- 实时推送：`/ws/{task_id}` 推送日志、决策事件、审批状态、完成态。
- 指标总览：`/metrics/overview` 输出系统状态、工具分布、调用成功率等。
- 配置管理：LLM、执行器、流程策略可通过 API 动态配置。
- Skill/Knowledge 管理：支持在线读取、编辑、重载 YAML/JSON。
- 持久化策略：优先 PostgreSQL/Redis/MinIO，不可用时自动降级到内存/本地。

### 前端能力

- `StartPage`：启动页 + 系统简报（调用 metrics 聚合看板）。
- `Dashboard`：系统、工具、调用分布与成功率可视化。
- `TaskList`：筛选/批量操作/任务创建（含策略提示）。
- `TaskDetail`：Mermaid 进度、审批卡片、决策时间线、实时日志、原始数据。
- `DecisionView`：专注决策流 + 用户消息干预代理行为。
- `ReportCenter`：报告在线编辑与预览。
- `ToolsManage` / `SkillsManage` / `KnowledgeManage`：运营与知识维护界面。
- `Settings` / `Profile`：系统配置、LLM 测试、用户资料管理。

## 4) 支持工具（当前注册）

> 工具由 `backend/tools/definitions/*.yaml` 注册，可按 YAML 扩展。

### Recon
`nmap`, `masscan`, `gobuster`, `ffuf`, `subfinder`, `whatweb`, `httpx`, `wafw00f`, `dirb`, `sslscan`

### Vuln Scan
`nuclei`, `nikto`, `sqlmap`, `wpscan`

### Exploit
`jndi_fastjson`, `bcel_fastjson`, `hydra`, `medusa`, `john`, `hashcat`

### General / Post Exploit
`curl`, `wget`, `python3`, `java`, `socat`, `nc`, `enum4linux`, `smbclient`, `tcpdump`, `hping3`

此外，toolbox 镜像内还预装了 `metasploit-framework`、`tshark`、`dnsrecon`、`arjun`、`paramspider` 等，可按需接入注册表。

## 5) 技术栈

- **Backend**: FastAPI, LangGraph, LangChain, SQLAlchemy Async, Redis, MinIO
- **Frontend**: Vue 3, Vite, Pinia, Element Plus, Axios
- **Runtime**: Docker, Docker Compose
- **LLM Router**: DeepSeek / OpenAI / Anthropic（OpenAI-compatible 接口）

## 6) 快速启动

### 环境要求

- Python `>= 3.11`
- Node.js `>= 18`
- Docker / Docker Compose
- 可用的 LLM API Key

### Step 1. 构建工具箱镜像

```bash
cd docker/toolbox
docker build -t pentest-toolbox:latest .
cd ../..
```

### Step 2. 配置环境变量

Linux/macOS:

```bash
cp .env.example docker/.env
```

Windows (PowerShell):

```powershell
Copy-Item .env.example docker/.env
```

至少修改 `docker/.env` 中的以下值：

- `LLM_API_KEY`
- `LHOST`（反弹连接地址）
- `POSTGRES_PASSWORD` / `MSF_PASSWORD`（建议改默认）

### Step 3. 启动后端服务栈

```bash
cd docker
docker compose up -d
```

默认会启动：`api`、`postgres`、`redis`、`minio`、`msf`。  
前端服务在 compose 中默认注释，建议开发时本地运行。

### Step 4. 启动前端

```bash
cd frontend
npm install
npm run dev
```

默认访问：

- Frontend: [http://localhost:3000](http://localhost:3000)
- API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health: [http://localhost:8000/health](http://localhost:8000/health)
- MinIO Console: [http://localhost:9001](http://localhost:9001)

## 7) 本地开发（不走 API 容器）

后端：

```bash
pip install -r requirements.txt
uvicorn backend.api.main:app --reload --port 8000
```

前端：

```bash
cd frontend
npm install
npm run dev
```

`vite` 已将 `/api` 与 `/ws` 代理到 `http://localhost:8000`。

## 8) 关键 API（节选）

### 任务与执行

- `POST /tasks`
- `GET /tasks`
- `GET /tasks/{task_id}`
- `POST /tasks/{task_id}/cancel`
- `POST /tasks/{task_id}/approve`
- `WS /ws/{task_id}`

### 指标与系统

- `GET /health`
- `GET /metrics/overview`

### Skill / Knowledge

- `GET /skills`
- `PUT /skills/{skill_id}/raw`
- `GET /knowledge/entries`
- `PUT /knowledge/{vuln_id}/raw`

## 9) 项目结构（精简）

```text
backend/
  agents/         # 编排器与各阶段 Agent
  api/            # FastAPI 入口与全部路由
  tools/          # 执行器、注册表、工具定义 YAML
  skills/         # Skill 模型、加载、匹配、执行引擎
  knowledge/      # 知识库与检索器
  report/         # Markdown 报告生成
  db/             # PostgreSQL / Redis 持久化
  storage/        # MinIO 客户端

frontend/src/
  views/          # 页面（任务、决策、报告、工具、技能、知识等）
  components/     # 可视化与编辑组件
  stores/         # Pinia 状态管理
  api/            # Axios API 封装

docker/
  docker-compose.yml
  api/
  toolbox/
```

## 10) 合规声明

本项目仅用于 **合法授权** 的安全测试场景（CTF、内网演练、授权渗透测试）。  
禁止在未获授权的目标上使用本系统，使用者需自行承担合规责任。

## License

MIT
