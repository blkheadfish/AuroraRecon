<p align="center">
  <img src="assets/logo.png" alt="Aurora Recon" width="100%">
</p>

<p align="center">
  <strong>基于大模型的自主渗透测试智能体</strong><br>
  从侦察到报告 — 闭环 Kill-Chain 编排系统
</p>

<p align="center">
  <a href="README.md">English</a> | <strong>中文</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue" alt="Python">
  <img src="https://img.shields.io/badge/vue-3.4+-green" alt="Vue">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="License">
  <img src="https://img.shields.io/badge/docker-required-blue" alt="Docker">
</p>

---

## 目录

- [架构概览](#架构概览)
- [快速启动](#快速启动)
- [工作流 (WS0-WS4)](#工作流)
- [核心功能](#核心功能)
- [技术栈](#技术栈)
- [API 参考](#api-参考)
- [配置说明](#配置说明)
- [项目结构](#项目结构)
- [开发指南](#开发指南)
- [合规声明](#合规声明)

---

## 架构概览

AuroraRecon 以 **世界模型（攻击图）** 为核心决策中枢，五条工作流围绕其展开，分别覆盖安全地基、世界建模、攻击路径推理、领域纵深和跨任务学习。

### 智能体编排 (LangGraph)

编排器支持 **3 种执行模式**：

| 模式 | 说明 |
|------|------|
| **线性 DAG** | 固定阶段顺序：侦察 → 漏洞扫描 → 利用 → 后渗透 → 报告 |
| **反馈环** | 支持回边重试（利用失败 → 切换到替代路径） |
| **监督路由** | 星形拓扑，31 条确定性路由规则 + LLM 兜底决策 |

每个阶段是一个 LangGraph 节点，监督器根据状态在节点间路由。高风险操作前会触发人工审批门。

### 世界模型（攻击图）

攻击图是一个有类型的、可查询的图：

**节点类型**（前端颜色编码）：

| 类型 | 说明 | 示例 |
|------|------|------|
| `host` | 目标主机 | IP/域名 |
| `service` | 网络服务 | HTTP:80, SSH:22 |
| `web_endpoint` | Web 路径 | /admin, /api |
| `finding` | 漏洞发现 | CVE-2022-xxx |
| `credential` | 凭据 | user:pass@host |
| `session` | 活动会话 | Meterpreter, SSH |
| `loot` | 战利品 | 哈希、数据库导出 |
| `objective` | 任务目标 | Flag 获取 |

**边关系**：`runs_on`（运行在）、`exposes`（暴露）、`vulnerable_to`（易受）、`yields`（产出）、`enables`（使能）、`leads_to`（导致）、`pivots_to`（跳转至）、`has_session_on`（会话）、`requires`（需要），以及 AD 关系（member_of、admin_of、kerberoastable）和云关系（assumes、can_read、can_write）。

**查询 API**：`exploitable_frontier()`、`chains()`、`paths_to_objective()`、`rank_frontier()`。

---

## 快速启动

### 环境要求

- Python `>= 3.11`
- Node.js `>= 18`
- Docker & Docker Compose
- LLM API Key（DeepSeek 或 OpenAI 兼容接口）

### 第一步 — 构建工具箱镜像

```bash
cd docker/toolbox
docker build -t pentest-toolbox:latest .
cd ../..
```

### 第二步 — 配置环境变量

```bash
cp .env.example docker/.env
```

编辑 `docker/.env`，至少设置：

| 变量 | 说明 |
|------|------|
| `LLM_API_KEY` | LLM API 密钥 |
| `LHOST` | 反弹 Shell 回调 IP |
| `POSTGRES_PASSWORD` | 数据库密码 |
| `MSF_PASSWORD` | Metasploit RPC 密码 |

### 第三步 — 启动后端服务

```bash
cd docker
docker compose up -d
```

启动的服务：`api`（FastAPI）、`postgres`（PostgreSQL 16）、`redis`（Redis 7）、`minio`（对象存储）、`msf`（Metasploit RPC）。

### 第四步 — 启动前端

```bash
cd frontend
npm install
npm run dev
```

### 访问地址

| 服务 | URL |
|------|-----|
| 前端 | `http://localhost:3000` |
| API 文档 (Swagger) | `http://localhost:8000/docs` |
| 健康检查 | `http://localhost:8000/health` |
| MinIO 控制台 | `http://localhost:9001` |

---

## 工作流

AuroraRecon 围绕 5 条工程工作流组织：

### WS0 — 自治安全地基

- **作用域强制**：每条命令执行前 runtime 验证目标是否在 `authorized_scope` 内
- **三级安全门**：黑名单（云元数据 IP、敏感关键词）→ 警告（大 CIDR）→ 白名单
- **不可逆操作检测**：持久化安装、用户创建、作用域扩展等操作标记为需审批
- **急停开关**：`POST /tasks/{id}/abort` 立即终止任务 + 清理容器
- **速率限制**：基于令牌桶的 LLM 调用、工具执行、MSF 会话限制

### WS1 — 世界模型（核心中枢）

- 有类型的攻击图（节点 + 边）
- 查询/写入 API（`WorldModelQuery`、`WorldModelWriter`）
- WebSocket 实时增量更新，前端 ECharts 力导向图渲染
- Kill-Chain 路径高亮 + 流动动画
- 节点钉位，避免新增节点时全图重新弹跳

### WS2 — 攻击路径推理

- **目标选择**：`rank_frontier()` 按严重度、CVE、路径价值评分排序可利用节点
- **链条编织**：漏洞 → 凭据 → 横向移动目标串联
- **失败归因**：分析利用失败原因（WAF 拦截、版本不符、环境差异）并自适应调整策略
- **假设驱动**：对不确定的发现启动针对性验证

### WS3 — 领域纵深

- **内网/AD**：SMB/LDAP/Kerberos 枚举、BloodHound 摄入、Kerberoasting、DCSync
- **横向移动**：PsExec、WinRM、WMI、SSH 跳板
- **云环境**：IAM 角色枚举、S3 Bucket 发现、Assume-Role 链式调用
- **场景识别**：自动检测环境类型（Web/内网/AD/云）以自适应调整策略

### WS4 — 记忆与学习

- **跨任务记忆**：历史发现以 `source=prior` 注入新任务（凭据仅标记存在，不含明文）
- **Skill 优先级学习**：按场景、按 Skill 追踪成功率并自动调整权重
- **草案自动合成**：成功的利用序列自动合成 Skill 草案存入 `.drafts/`，等待人工审核

---

## 核心功能

### Kill-Chain 全流程

侦察 → 漏洞扫描 → 漏洞利用 → 后渗透（横向移动、提权、持久化）→ 目标收集 → AI 生成报告

### 真正的后渗透能力

- **横向移动**：SMB / WinRM / PSExec / SSH 跳板
- **权限提升**：内核漏洞利用、SUID/Sudo 提权
- **持久化**：Cron 计划任务、SSH 密钥、Web Shell、Systemd 服务
- **目标收集**：Flag 搜索、凭据收割、数据库导出

### 人在回路

- 利用和后渗透阶段设审批门
- Checkpoint/Resume 断点续跑
- 任务中途可通过对话注入操作员指令
- 3 种自治级别：手动 / 监督 / 全自动

### Skill 引擎

确定性与 LLM 兜底结合的利用引擎：

| 阶段 | 机制 |
|------|------|
| **匹配** | CVE (+100)、关键词 (+60)、指纹 (+20)、JSON 探针 (+40)、证据 (+10) 加权评分 |
| **探测** | 利用前环境检查（OS、版本、架构） |
| **执行** | 确定性 Shell 命令步骤 — 无需 LLM 开销 |
| **兜底** | LLM ReAct 循环（Skill 原理 + References + 失败命令日志完整注入） |

**50+ Skill**，跨越 12 个分类：Java 反序列化、Web RCE、SQL 注入、网络利用、权限提升、凭据攻击、持久化、服务器配置错误、SSTI、LFI/RFI、XSS、SSRF。

### 实时仪表盘

- **实时攻击图**：ECharts 力导向图 + Kill-Chain 流动动画 + 节点钉位 + 120+ 节点自动降级
- **决策时间线**：按 Action 分类的专属渲染卡片（推理、目标选择、攻击链、失败归因、假设验证），LLM 逐字打字机效果
- **实时日志终端**：@xterm/xterm + 虚拟滚动 + 帧缓冲渲染

### 报告生成

- 两轮 LLM 生成：第一轮生成发现/验证/攻击链叙事，第二轮专注修复 Checklist
- Jinja2 Markdown 模板渲染，包含完整结构化数据
- 封面页（目标/报告 ID/日期）+ 执行摘要指标卡
- 在线编辑、PDF 导出、Markdown 下载

---

## 技术栈

| 层级 | 技术选型 |
|------|---------|
| **智能体框架** | LangGraph 0.2, LangChain 0.3 |
| **API** | FastAPI 0.115, Uvicorn 0.30, WebSocket (Redis Stream v2) |
| **数据库** | PostgreSQL 16 (SQLAlchemy 2.0 async + asyncpg), Redis 7 |
| **存储** | MinIO（报告、工具产物） |
| **LLM** | OpenAI 兼容接口（DeepSeek、OpenAI、Anthropic），支持故障转移 |
| **前端** | Vue 3.4, Vite 5, Pinia 2.1, Element Plus 2.7, TypeScript 6.0 |
| **图表** | ECharts 6.0, vue-echarts 8.0 |
| **终端** | @xterm/xterm 6.0 |
| **测试** | pytest 8.3, pytest-asyncio 0.24（54 个后端测试文件）, Vitest 4.1（前端） |
| **运维** | Docker Compose, Nginx 反向代理 |
| **安全** | 逐命令作用域守卫, JWT 鉴权, CORS 中间件, RBAC（用户/管理员） |

---

## API 参考

### 任务

| 方法 | 端点 | 说明 |
|------|------|------|
| `POST` | `/tasks` | 创建渗透测试任务 |
| `GET` | `/tasks` | 任务列表 |
| `GET` | `/tasks/{id}` | 任务详情（含发现、端口、凭据） |
| `POST` | `/tasks/{id}/cancel` | 取消运行中任务 |
| `POST` | `/tasks/{id}/abort` | 立即终止 + 容器清理 |
| `POST` | `/tasks/{id}/approve` | 审批通过 |
| `POST` | `/tasks/{id}/checkpoint/respond` | 响应确认点（同意/修改/拒绝） |
| `POST` | `/tasks/{id}/chat` | 任务中途注入操作员消息 |
| `POST` | `/tasks/{id}/resume` | 恢复暂停的任务 |
| `GET` | `/tasks/{id}/logs` | 分页/流式日志 |
| `GET` | `/tasks/{id}/branches` | 分支树 |

### 实时推送

| 方法 | 端点 | 说明 |
|------|------|------|
| `WS` | `/ws/{task_id}` | Redis Stream v2：日志、决策事件、阶段更新、审批、分支事件、完成信号 |

### 技能管理

| 方法 | 端点 | 说明 |
|------|------|------|
| `GET` | `/skills` | 列出全部技能 |
| `GET` | `/skills/{id}/raw` | 获取 Skill YAML 原文 |
| `PUT` | `/skills/{id}/raw` | 保存 Skill YAML |
| `GET` | `/skills/{id}/tree` | 目录树（skill.yaml、SKILL.md、references/） |
| `GET` | `/skills/{id}/file?path=` | 读取 Skill 目录下任意文件 |
| `PUT` | `/skills/{id}/file?path=` | 写入 Skill 目录下任意文件 |
| `POST` | `/skills/reload` | 从磁盘重载 Skill 注册表 |
| `GET` | `/skills/drafts` | 列出待审核草案 |
| `POST` | `/skills/drafts/{name}/promote` | 转正草案到正式 Skill |

### 知识库

| 方法 | 端点 | 说明 |
|------|------|------|
| `GET` | `/knowledge/entries` | 列出全部知识条目 |
| `GET` | `/knowledge/{id}/raw` | 获取条目 JSON |
| `PUT` | `/knowledge/{id}/raw` | 保存条目 JSON |
| `POST` | `/knowledge/build` | 构建知识库（全量或单条） |
| `POST` | `/knowledge/reload` | 从磁盘重载知识库 |

### 系统

| 方法 | 端点 | 说明 |
|------|------|------|
| `GET` | `/health` | 健康检查 |
| `GET` | `/metrics/overview` | 系统、工具、调用、安全门统计 |

---

## 配置说明

关键环境变量（完整列表见 `.env.example`）：

| 变量 | 用途 | 默认值 |
|------|------|--------|
| `LLM_PROVIDER` | LLM 提供商 | `deepseek` |
| `LLM_API_KEY` | API 密钥 | *（必填）* |
| `LLM_MODEL` | 模型名称 | `deepseek-v4-flash` |
| `LLM_BASE_URL` | API 地址 | `https://api.deepseek.com` |
| `JWT_SECRET` | JWT 签名密钥 | 自动生成 |
| `DATABASE_URL` | PostgreSQL 连接串 | `postgresql+asyncpg://...` |
| `REDIS_URL` | Redis 连接串 | `redis://localhost:6379/0` |
| `MSF_PASSWORD` | Metasploit RPC 密码 | `pentest123` |
| `LHOST` | 反弹 Shell IP | `127.0.0.1` |
| `TOOLBOX_IMAGE` | Docker 工具箱镜像 | `pentest-toolbox:latest` |
| `MAX_TOOL_TIMEOUT` | 工具最大执行秒数 | `360` |
| `MAX_STAGE_RUNTIME` | 阶段最大运行秒数 | `900` |

安全配置 YAML（`backend/config/` 目录下）：
- `safety_rules.yaml` — 黑名单/白名单/警告规则
- `detection_filter.yaml` — 服务指纹过滤
- `path_reasoning.yaml` — 攻击前沿评分权重

---

## 项目结构

```
AuroraRecon/
├── backend/
│   ├── agents/           # 编排器、监督器、专用 Agent（28 个文件）
│   ├── api/              # FastAPI 入口、11 个路由模块、WebSocket、事件流
│   ├── tools/            # Docker 执行器、工具注册表（6 个 YAML 定义、16 个解析器）
│   ├── skills/           # Skill 引擎、注册表（50+ Skill、12 个分类）
│   ├── knowledge/        # 漏洞知识库（22 个 JSON 条目 + 向量嵌入）、混合检索
│   ├── llm/              # LLM 路由（故障转移链）、Prompt 模板
│   ├── report/           # Jinja2 报告生成器、Markdown 模板
│   ├── db/               # PostgreSQL（SQLAlchemy async）、Redis 缓存
│   ├── config/           # 安全规则、检测过滤器、路径权重
│   ├── metrics/          # LLM 调用 & 工具执行指标
│   ├── storage/          # MinIO 客户端
│   └── tests/            # 54 个 pytest 文件
├── frontend/
│   └── src/
│       ├── views/        # 16 个用户页面 + 10 个管理页面
│       ├── components/   # 30 个 Vue 3 组件
│       ├── stores/       # Pinia 状态管理
│       ├── composables/  # 9 个组合式函数
│       ├── api/          # Axios HTTP + WebSocket 封装
│       ├── services/     # wsManager, eventStore (IndexedDB)
│       ├── types/        # TypeScript 类型定义（729 行）
│       └── router/       # Vue Router + 角色守卫
├── docker/
│   ├── docker-compose.yml    # 全栈编排
│   ├── api/Dockerfile        # Python API 容器
│   ├── toolbox/Dockerfile    # Kali 工具箱（30+ 工具预装）
│   └── frontend/             # Node 构建 → Nginx 服务
├── docs/                 # 架构文档、项目方案、演讲稿
├── .env.example          # 环境变量模板（56 行）
└── requirements.txt      # Python 依赖
```

---

## 开发指南

### 后端（本地开发）

```bash
pip install -r requirements.txt
uvicorn backend.api.main:app --reload --port 8000
```

### 前端（本地开发）

```bash
cd frontend
npm install
npm run dev        # 开发服务器 :3000, 代理 /api + /ws → :8000
npm run build      # 生产构建
npm run test       # Vitest 测试
npm run lint       # ESLint 代码检查
```

### 运行测试

```bash
# 后端
cd backend
pytest tests/ -v

# 前端
cd frontend
npm run test
```

---

## 合规声明

本项目仅用于 **合法授权** 的安全测试场景——CTF 竞赛、内部红蓝对抗演练，以及获得明确书面授权的渗透测试。

**禁止在未授权目标上使用本系统。** 系统内置了多层安全机制（作用域强制、不可逆操作检测、急停开关），但最终责任由操作者承担。

---

## License

MIT
