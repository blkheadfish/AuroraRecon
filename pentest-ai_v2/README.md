# PentestAI v2.0 —— AI 驱动的自动化渗透测试平台

基于 LangGraph 编排的多 Agent 渗透测试系统，集成 30+ 安全工具，支持从侦察到报告的全自动化流程。

## 系统架构

```
┌──────────────────────────────────────────────────────────┐
│            Web 前端（Vue 3 + TypeScript）                 │
│         任务配置 · 实时日志流 · 报告预览                    │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│              API 网关（FastAPI）                           │
│         WebSocket 推送 · REST · 任务队列                   │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│           主编排 Agent（LangGraph）                        │
│      任务规划 · 阶段调度 · 上下文管理 · 异常处理             │
└────┬─────────┬──────────┬──────────┬─────────────────────┘
     │         │          │          │
 ┌───▼──┐  ┌──▼───┐  ┌──▼───┐  ┌──▼────┐
 │ 侦察  │  │ 漏洞  │  │ 利用  │  │ 后渗透 │
 │Agent │  │Agent │  │Agent │  │ Agent │
 └───┬──┘  └──┬───┘  └──┬───┘  └──┬────┘
     └─────────┴─────────┴─────────┘
                    │  工具调用
     ┌──────────────▼──────────────────────────────────────┐
     │        工具执行沙箱（Docker 隔离）                     │
     │  Nmap · Masscan · SQLMap · Hydra · Nikto · Nuclei   │
     │  Gobuster · Metasploit · John · Hashcat · ...       │
     └──────────┬─────────────────────┬────────────────────┘
                │                     │
     ┌──────────▼──────┐   ┌─────────▼─────────┐
     │    大模型层      │   │   数据持久层        │
     │ DeepSeek/GPT/   │   │ PostgreSQL · Redis │
     │ Claude          │   │ · MinIO            │
     └────────┬────────┘   └───────────────────┘
              │
     ┌────────▼────────┐
     │   报告生成引擎    │
     │ Markdown · PDF   │
     └─────────────────┘
```

## 核心特性

- **多 Agent 协同**：侦察、漏洞扫描、利用、后渗透 4 个专业 Agent，由 LangGraph 编排
- **LLM 智能决策**：大模型分析漏洞优先级、制定利用策略、解读工具输出
- **Docker 沙箱**：所有工具在隔离容器中执行，安全可控
- **实时监控**：WebSocket 推送日志和状态，前端实时展示
- **数据持久化**：PostgreSQL 存储任务、Redis 缓存状态、MinIO 归档报告
- **自动报告**：自动生成包含修复建议的 Markdown 渗透测试报告

## 快速部署

### 1. 克隆项目

```bash
git clone <repo-url> pentestai
cd pentestai
```

### 2. 配置环境变量

```bash
cp .env.example docker/.env
vim docker/.env   # 修改 LLM_API_KEY、LHOST 等必要配置
```

### 3. 构建工具箱镜像

```bash
cd docker/toolbox
docker build -t pentest-toolbox:latest .
cd ../..
```

### 4. 启动全部服务

```bash
cd docker
docker compose up -d
```

### 5. 访问

- **前端**: http://localhost:3000
- **API**: http://localhost:8000
- **API 文档**: http://localhost:8000/docs
- **MinIO 控制台**: http://localhost:9001

## 开发模式

### 后端（API）

```bash
pip install -r requirements.txt
uvicorn backend.api.main:app --reload --port 8000
```

### 前端

```bash
npm install
npm run dev    # http://localhost:5173
```

前端开发服务器自动将 `/api` 代理到 `localhost:8000`。

## 服务组件

| 服务 | 端口 | 说明 |
|------|------|------|
| Frontend | 3000 | Vue 3 SPA（Nginx） |
| API | 8000 | FastAPI + WebSocket |
| PostgreSQL | 5432（内网） | 任务持久化存储 |
| Redis | 6379（内网） | 状态缓存 / 任务队列 |
| MinIO | 9000/9001 | 报告对象存储 |
| MSF RPC | 55553（内网） | Metasploit 服务 |
| Toolbox | 临时容器 | 安全工具沙箱 |

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /health | 健康检查（含数据库/Redis 状态） |
| POST | /tasks | 创建渗透测试任务 |
| GET | /tasks | 列出所有任务 |
| GET | /tasks/stats | 全局统计信息 |
| GET | /tasks/{id} | 任务详情（含完整扫描数据） |
| GET | /tasks/{id}/logs | 任务日志 |
| GET | /tasks/{id}/report | 下载报告 |
| POST | /tasks/{id}/cancel | 取消运行中任务 |
| DELETE | /tasks/{id} | 删除任务记录 |
| WS | /ws/{id} | 实时日志推送 |

## 支持的 LLM

通过环境变量 `LLM_PROVIDER` 切换：

| Provider | 模型 | BASE_URL |
|----------|------|----------|
| deepseek | deepseek-chat | https://api.deepseek.com |
| openai | gpt-4o | https://api.openai.com/v1 |
| anthropic | claude-sonnet-4-6 | https://api.anthropic.com/v1 |

## 项目结构

```
├── backend/
│   ├── agents/
│   │   ├── models.py          # 共享数据模型（PentestState 等）
│   │   ├── orchestrator.py    # LangGraph 主编排
│   │   ├── recon_agent.py     # 侦察 Agent
│   │   ├── vuln_agent.py      # 漏洞扫描 Agent
│   │   ├── exploit_agent.py   # 利用 Agent
│   │   └── post_agent.py      # 后渗透 Agent
│   ├── api/
│   │   └── main.py            # FastAPI 应用入口
│   ├── db/
│   │   ├── database.py        # PostgreSQL 持久层
│   │   └── redis_cache.py     # Redis 缓存层
│   ├── storage/
│   │   └── minio_client.py    # MinIO 对象存储
│   ├── llm/
│   │   ├── router.py          # LLM 统一路由
│   │   └── prompts/
│   │       └── templates.py   # Prompt 模板
│   ├── report/
│   │   └── generator.py       # 报告生成器
│   └── tools/
│       ├── executor.py        # Docker 工具执行器
│       ├── msf_client.py      # Metasploit RPC 客户端
│       └── parsers/           # 工具输出解析器
├── src/                       # Vue 3 前端
│   ├── views/
│   │   ├── Dashboard.vue      # 仪表盘
│   │   ├── TaskList.vue       # 任务列表
│   │   ├── TaskDetail.vue     # 任务详情
│   │   └── Settings.vue       # 系统设置
│   ├── components/            # UI 组件
│   ├── stores/                # Pinia 状态管理
│   └── api/                   # API 客户端
├── docker/
│   ├── docker-compose.yml     # 完整服务编排
│   ├── api/Dockerfile         # API 服务镜像
│   ├── frontend/              # 前端镜像 + Nginx
│   └── toolbox/Dockerfile     # 安全工具箱镜像
└── requirements.txt           # Python 依赖
```

## 安全声明

本工具仅供合法授权的安全测试使用（CTF 靶场、授权渗透测试）。使用者须遵守相关法律法规，未经授权对他人系统进行渗透测试属违法行为。

## License

MIT
