"""
api/main.py —— FastAPI 应用入口（完整版）

端点：
  POST   /tasks                  创建任务并异步执行
  GET    /tasks                  列出所有任务
  GET    /tasks/stats            任务统计信息
  GET    /tasks/{task_id}        查询任务详情（含完整状态）
  GET    /tasks/{task_id}/report 下载报告
  GET    /tasks/{task_id}/logs   查询任务日志
  POST   /tasks/{task_id}/cancel 取消运行中任务
  DELETE /tasks/{task_id}        删除任务记录
  WS     /ws/{task_id}           WebSocket 实时日志推送
  GET    /health                 健康检查
"""
from __future__ import annotations

import os
import asyncio
import logging
import re
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from backend.agents.models import PentestState, TaskStatus, parse_target
from backend.agents.orchestrator import Orchestrator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── 内存态 ────────────────────────────────────────────────
_tasks: dict[str, PentestState] = {}
_ws_connections: dict[str, list[WebSocket]] = {}
_running_tasks: set[str] = set()
_approval_inflight: dict[str, float] = {}
_APPROVAL_INFLIGHT_TIMEOUT = 600  # 10 minutes
_tool_registry_cache = None

# ── 基础设施可用性 ────────────────────────────────────────
_db_available = False
_redis_available = False
_msf_available = False

# ── 全局单例 Orchestrator（MemorySaver 必须共享同一实例）──
_orchestrator: Orchestrator | None = None
_TOOL_START_RE = re.compile(r"执行\s+([^\s]+)\s+\[([^\]]+)\]")
_TOOL_DONE_RE = re.compile(r"(?:✅|❌)\s+([^\s]+)\s+完成:\s+exit=([-]?\d+),.*?耗时=([\d.]+)s")

def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator


def _get_tool_registry():
    """
    进程内复用 ToolRegistry，避免 metrics 轮询时反复加载 definitions 并刷日志。
    """
    global _tool_registry_cache
    if _tool_registry_cache is None:
        from backend.tools.tool_registry import ToolRegistry

        _tool_registry_cache = ToolRegistry()
    return _tool_registry_cache


# ── 生命周期 ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db_available, _redis_available

    # 初始化 PostgreSQL
    try:
        from backend.db.database import init_db
        await init_db()
        _db_available = True
        logger.info("[启动] PostgreSQL 连接成功")
    except Exception as e:
        logger.warning(f"[启动] PostgreSQL 不可用，使用内存模式: {e}")

    # 初始化 Redis
    try:
        from backend.db.redis_cache import get_redis
        r = await get_redis()
        await r.ping()
        _redis_available = True
        logger.info("[启动] Redis 连接成功")
    except Exception as e:
        logger.warning(f"[启动] Redis 不可用，使用内存模式: {e}")

    # 初始化 MinIO
    try:
        from backend.storage.minio_client import get_storage
        get_storage()
        logger.info("[启动] MinIO 初始化完成")
    except Exception as e:
        logger.warning(f"[启动] MinIO 不可用，使用本地文件: {e}")

    # 检测 Metasploit RPC 可用性
    global _msf_available
    try:
        from backend.tools.msf_client import MsfClient
        _msf_client_probe = MsfClient()
        await asyncio.wait_for(
            _msf_client_probe.connect(),
            timeout=5.0,
        )
        _msf_available = True
        logger.info(f"[启动] MSF RPC 连接成功 ({os.getenv('MSF_HOST', 'msf')}:{os.getenv('MSF_PORT', '55553')})")
    except asyncio.TimeoutError:
        logger.warning("[启动] MSF RPC 连接超时，MSF 功能不可用（exploit/post 阶段将跳过 MSF）")
    except Exception as e:
        logger.warning(f"[启动] MSF RPC 不可用: {e}（exploit/post 阶段将跳过 MSF）")

    # 从数据库恢复任务
    if _db_available:
        try:
            from backend.db.database import list_tasks_from_db, load_task
            db_tasks = await list_tasks_from_db()
            for t in db_tasks:
                state = await load_task(t["task_id"])
                if state:
                    _tasks[state.task_id] = state
            logger.info(f"[启动] 从数据库恢复 {len(db_tasks)} 个任务")
        except Exception as e:
            logger.warning(f"[启动] 恢复任务失败: {e}")

    import ipaddress as _ipaddress
    _lhost = os.getenv("LHOST", "")
    if not _lhost or _lhost in ("127.0.0.1", "0.0.0.0", "localhost"):
        logger.warning("[启动] LHOST 未设置或为本地地址，反弹类利用将不可用")
    else:
        try:
            _addr = _ipaddress.ip_address(_lhost)
            if _addr.is_private:
                logger.warning(f"[启动] LHOST={_lhost} 是内网地址，公网靶场的反弹类利用将不可用")
        except ValueError:
            pass

    yield

    if _redis_available:
        try:
            from backend.db.redis_cache import close_redis
            await close_redis()
        except Exception:
            pass
    logger.info("[关闭] 服务已停止")


app = FastAPI(title="PentestAI", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── JWT 认证 ──────────────────────────────────────────────

import secrets as _secrets
import jwt as _jwt
import bcrypt as _bcrypt_lib

_JWT_SECRET = os.getenv("JWT_SECRET", _secrets.token_urlsafe(32))
_JWT_ALGORITHM = "HS256"
_JWT_EXPIRE_DAYS = 7

_AUTH_WHITELIST_PREFIXES = (
    "/health",
    "/auth/login",
    "/auth/register",
    "/docs",
    "/openapi.json",
    "/redoc",
)


def _create_jwt(user_id: str, username: str) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "exp": datetime.utcnow() + timedelta(days=_JWT_EXPIRE_DAYS),
        "iat": datetime.utcnow(),
    }
    return _jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def _decode_jwt(token: str) -> dict | None:
    try:
        return _jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
    except _jwt.ExpiredSignatureError:
        return None
    except _jwt.InvalidTokenError:
        return None


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS":
        return await call_next(request)
    if any(path.startswith(p) for p in _AUTH_WHITELIST_PREFIXES):
        return await call_next(request)
    if path.startswith("/ws/"):
        return await call_next(request)

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "未登录"})
    token = auth_header[7:]
    claims = _decode_jwt(token)
    if not claims:
        return JSONResponse(status_code=401, content={"detail": "登录已过期，请重新登录"})
    request.state.user_id = claims.get("sub", "")
    request.state.username = claims.get("username", "")
    return await call_next(request)


# ── 请求/响应模型 ─────────────────────────────────────────

class CreateTaskRequest(BaseModel):
    target: str
    scope_note: str = "CTF/授权靶场测试"
    extra_hint: str = ""
    user_prompt: str = ""
    workflow_mode: str = "standard"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """
        服务端目标地址校验（与前端 isValidTarget 对齐）。

        接受格式:
          192.168.1.1
          192.168.1.1:8080
          example.com
          example.com:443
          http(s)://host:port/path

        拒绝: 空字符串、含空格/分号/管道等注入字符、非法端口
        """
        raw = v.strip()
        if not raw:
            raise ValueError("目标地址不能为空")

        # 拒绝明显的命令注入字符
        if re.search(r'[;\|`$&<>(){}\[\]!]', raw):
            raise ValueError("目标地址包含非法字符")

        parsed = parse_target(raw)

        if not parsed.host:
            raise ValueError("无法解析目标主机地址")

        # 端口范围检查
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            raise ValueError(f"端口号超出范围: {parsed.port}")

        # 协议检查（如果带协议，只允许 http/https）
        if parsed.scheme and parsed.scheme not in ("http", "https"):
            raise ValueError(f"不支持的协议: {parsed.scheme}")

        # 主机名基本格式检查（IP 或域名）
        host = parsed.host
        # IPv4
        ipv4_match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', host)
        if ipv4_match:
            octets = [int(g) for g in ipv4_match.groups()]
            if not all(0 <= o <= 255 for o in octets):
                raise ValueError(f"无效的 IPv4 地址: {host}")
        elif host != "localhost":
            # 域名格式检查
            if not re.match(
                r'^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?'
                r'(\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$',
                host,
            ):
                raise ValueError(f"无效的主机名: {host}")

        return raw


class TaskSummary(BaseModel):
    task_id: str
    target: str
    status: str
    current_phase: str
    findings_count: int
    got_shell: bool
    report_path: str
    privilege_level: str = ""
    created_at: str = ""
    updated_at: str = ""


class TaskDetail(TaskSummary):
    """完整任务详情（含侦察数据 / findings 列表等）"""
    target_os: str = "unknown"
    scope_note: str = ""
    error_msg: str = ""
    open_ports: list = []
    os_info: dict = {}
    web_paths: list = []
    subdomains: list = []
    findings: list = []
    exploit_results: list = []
    post_findings: dict = {}
    report_md: str = ""
    phase_log: list = []


class TaskStats(BaseModel):
    total: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    pending: int = 0
    shells_obtained: int = 0
    root_reached: int = 0
    total_findings: int = 0


# ── API 路由 ──────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "version": "2.0.0",
        "metrics_overview": True,
        "metrics_paths": ["/metrics/overview", "/api/metrics/overview"],
        "database": "connected" if _db_available else "unavailable",
        "redis": "connected" if _redis_available else "unavailable",
        "msf": "connected" if _msf_available else "unavailable",
        "active_tasks": len(_running_tasks),
        "timestamp": datetime.utcnow().isoformat(),
    }


def _safe_rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100.0, 2)


def _parse_iso_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _build_system_overview(tasks: list[PentestState]) -> dict:
    def _is_root_priv(s: PentestState) -> bool:
        return (s.privilege_level or "").lower() == "root" or bool(
            (s.objective_status or {}).get("root_reached")
        )

    return {
        "api_status": "ok",
        "database": "connected" if _db_available else "unavailable",
        "redis": "connected" if _redis_available else "unavailable",
        "msf": "connected" if _msf_available else "unavailable",
        "version": app.version,
        "total_tasks": len(tasks),
        "running_tasks": sum(1 for t in tasks if t.status == TaskStatus.RUNNING),
        "completed_tasks": sum(1 for t in tasks if t.status == TaskStatus.COMPLETED),
        "failed_tasks": sum(1 for t in tasks if t.status == TaskStatus.FAILED),
        "active_task_ids": len(_running_tasks),
        "shells_obtained_tasks": sum(1 for t in tasks if t.got_shell),
        "root_reached_tasks": sum(1 for t in tasks if _is_root_priv(t)),
        "mean_privesc_rounds": round(
            sum(t.privesc_attempt_count for t in tasks) / len(tasks), 2
        ) if tasks else 0.0,
    }


def _build_tool_overview() -> dict:
    try:
        registry = _get_tool_registry()
        by_executor: dict[str, int] = defaultdict(int)
        tools = []
        for td in registry.list_all():
            by_executor[td.executor] += 1
            tools.append({
                "name": td.name,
                "category": td.category,
                "executor": td.executor,
                "timeout": td.timeout,
            })

        tools.sort(key=lambda item: (item["category"], item["name"]))
        return {
            "total_tools": registry.size,
            "by_category": registry.summary(),
            "by_executor": dict(by_executor),
            "tools": tools,
        }
    except Exception as e:
        logger.warning(f"[Metrics] 工具概览构建失败: {e}")
        return {
            "total_tools": 0,
            "by_category": {},
            "by_executor": {},
            "tools": [],
            "error": str(e),
        }


def _build_tool_invocation_overview(tasks: list[PentestState]) -> dict:
    calls_by_tool: dict[str, int] = defaultdict(int)
    backend_calls: dict[str, int] = defaultdict(int)
    done_by_tool: dict[str, int] = defaultdict(int)
    success_by_tool: dict[str, int] = defaultdict(int)
    elapsed_sum_by_tool: dict[str, float] = defaultdict(float)
    backend_by_tool: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    total_calls = 0
    success_calls = 0
    failed_calls = 0
    total_elapsed = 0.0
    done_count = 0

    for state in tasks:
        for entry in state.phase_log:
            start_match = _TOOL_START_RE.search(entry)
            if start_match:
                tool_name = start_match.group(1).strip()
                backend = start_match.group(2).strip()
                calls_by_tool[tool_name] += 1
                backend_calls[backend] += 1
                backend_by_tool[tool_name][backend] += 1
                total_calls += 1

            done_match = _TOOL_DONE_RE.search(entry)
            if done_match:
                tool_name = done_match.group(1).strip()
                exit_code = int(done_match.group(2))
                elapsed = float(done_match.group(3))
                done_by_tool[tool_name] += 1
                elapsed_sum_by_tool[tool_name] += elapsed
                total_elapsed += elapsed
                done_count += 1
                if exit_code == 0:
                    success_by_tool[tool_name] += 1
                    success_calls += 1
                else:
                    failed_calls += 1

    top_tools = []
    for tool_name, calls in sorted(calls_by_tool.items(), key=lambda item: item[1], reverse=True):
        completed = done_by_tool.get(tool_name, 0)
        succeeded = success_by_tool.get(tool_name, 0)
        avg_elapsed_ms = 0.0
        if completed > 0:
            avg_elapsed_ms = round((elapsed_sum_by_tool[tool_name] / completed) * 1000.0, 2)
        top_tools.append({
            "tool": tool_name,
            "calls": calls,
            "completed_calls": completed,
            "success_rate": _safe_rate(succeeded, completed),
            "avg_elapsed_ms": avg_elapsed_ms,
            "backends": dict(backend_by_tool.get(tool_name, {})),
        })

    return {
        "total_calls": total_calls,
        "completed_calls": done_count,
        "success_calls": success_calls,
        "failed_calls": failed_calls,
        "success_rate": _safe_rate(success_calls, done_count),
        "avg_elapsed_ms": round((total_elapsed / done_count) * 1000.0, 2) if done_count > 0 else 0.0,
        "by_backend": dict(sorted(backend_calls.items(), key=lambda item: item[1], reverse=True)),
        "top_tools": top_tools[:10],
    }


@app.get("/metrics/overview")
@app.get("/api/metrics/overview")
async def get_metrics_overview(window_hours: int = 24):
    bounded_window = max(1, min(window_hours, 168))
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=bounded_window)

    all_tasks = list(_tasks.values())
    scoped_tasks = []
    for state in all_tasks:
        task_ts = _parse_iso_ts(state.created_at)
        if task_ts is None or task_ts >= cutoff:
            scoped_tasks.append(state)

    return {
        "generated_at": now.isoformat(),
        "window_hours": bounded_window,
        "system_overview": _build_system_overview(all_tasks),
        "tool_overview": _build_tool_overview(),
        "tool_invocation_overview": _build_tool_invocation_overview(scoped_tasks),
    }


@app.post("/tasks", response_model=TaskSummary)
async def create_task(req: CreateTaskRequest, background_tasks: BackgroundTasks):
    task_id = str(uuid.uuid4())
    state = PentestState(
        task_id=task_id,
        target=req.target,
        scope_note=req.scope_note,
        extra_hint=req.extra_hint,
        user_prompt=req.user_prompt,
        workflow_mode=req.workflow_mode or "standard",
    )
    _tasks[task_id] = state

    if _db_available:
        try:
            from backend.db.database import save_task
            await save_task(state)
        except Exception as e:
            logger.warning(f"[DB] 保存失败: {e}")

    background_tasks.add_task(
        _run_task,
        task_id,
        req.target,
        req.scope_note,
        req.extra_hint,
        req.user_prompt,
        req.workflow_mode or "standard",
    )
    return _to_summary(state)


@app.get("/tasks/stats", response_model=TaskStats)
async def get_stats():
    """注意: 此路由必须在 /tasks/{task_id} 之前定义"""
    if _db_available:
        try:
            from backend.db.database import get_task_stats
            return TaskStats(**(await get_task_stats()))
        except Exception as e:
            logger.warning(f"[DB] 统计查询失败: {e}")

    tasks_list = list(_tasks.values())
    return TaskStats(
        total=len(tasks_list),
        running=sum(1 for t in tasks_list if t.status == TaskStatus.RUNNING),
        completed=sum(1 for t in tasks_list if t.status == TaskStatus.COMPLETED),
        failed=sum(1 for t in tasks_list if t.status == TaskStatus.FAILED),
        pending=sum(1 for t in tasks_list if t.status == TaskStatus.PENDING),
        shells_obtained=sum(1 for t in tasks_list if t.got_shell),
        root_reached=sum(
            1 for t in tasks_list
            if (t.privilege_level or "").lower() == "root"
            or (t.objective_status or {}).get("root_reached")
        ),
        total_findings=sum(len(t.findings) for t in tasks_list),
    )


@app.get("/tasks", response_model=list[TaskSummary])
async def list_tasks():
    if _db_available:
        try:
            from backend.db.database import list_tasks_from_db
            db_list = await list_tasks_from_db()
            result = []
            seen = set()
            for t in db_list:
                tid = t["task_id"]
                seen.add(tid)
                if tid in _tasks:
                    result.append(_to_summary(_tasks[tid]))
                else:
                    result.append(TaskSummary(**t))
            for tid, state in _tasks.items():
                if tid not in seen:
                    result.append(_to_summary(state))
            return result
        except Exception as e:
            logger.warning(f"[DB] 查询失败: {e}")

    return [_to_summary(s) for s in _tasks.values()]


@app.get("/tasks/{task_id}")
async def get_task(task_id: str):
    """返回完整任务详情，包含 findings / ports 等数据"""
    state = await _resolve_state(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    return _to_detail(state)


@app.get("/tasks/{task_id}/report")
async def get_report(task_id: str):
    state = await _resolve_state(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not state.report_md:
        raise HTTPException(status_code=404, detail="报告尚未生成")
    return {"markdown": state.report_md, "path": state.report_path}


@app.get("/tasks/{task_id}/logs")
async def get_logs(task_id: str):
    if _redis_available:
        try:
            from backend.db.redis_cache import get_task_logs
            logs = await get_task_logs(task_id)
            if logs:
                return {"logs": logs}
        except Exception:
            pass
    state = _tasks.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"logs": state.phase_log}


@app.post("/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    state = _tasks.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    if state.status not in (TaskStatus.RUNNING, TaskStatus.PENDING):
        raise HTTPException(status_code=400, detail="任务不在运行状态")

    state.status = TaskStatus.FAILED
    state.error_msg = "用户手动取消"
    state.log("任务被用户取消")

    if _redis_available:
        try:
            from backend.db.redis_cache import set_cancel_flag
            await set_cancel_flag(task_id)
        except Exception:
            pass
    if _db_available:
        try:
            from backend.db.database import save_task
            await save_task(state)
        except Exception:
            pass

    _running_tasks.discard(task_id)
    await _broadcast(task_id, {"type": "done", "status": "failed", "message": "任务已取消"})
    return {"status": "cancelled", "task_id": task_id}


@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    state = _tasks.get(task_id)
    if state and state.status in (TaskStatus.RUNNING, TaskStatus.PENDING):
        raise HTTPException(status_code=400, detail="运行中的任务不能删除，请先取消")

    _tasks.pop(task_id, None)

    if _db_available:
        try:
            from backend.db.database import delete_task_from_db
            await delete_task_from_db(task_id)
        except Exception as e:
            logger.warning(f"[DB] 删除失败: {e}")
    if _redis_available:
        try:
            from backend.db.redis_cache import delete_cached_task
            await delete_cached_task(task_id)
        except Exception:
            pass
    try:
        from backend.storage.minio_client import get_storage
        get_storage().delete_task_files(task_id)
    except Exception:
        pass

    return {"status": "deleted", "task_id": task_id}


# ── WebSocket ─────────────────────────────────────────────

@app.websocket("/ws/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    await websocket.accept()
    _ws_connections.setdefault(task_id, []).append(websocket)

    async def _send(payload: dict) -> bool:
        """Best-effort send; return False when connection is gone."""
        try:
            await websocket.send_json(payload)
            return True
        except Exception:
            return False

    async def _push_loop():
        """Cursor-based incremental push — fast poll, no full rebuild each tick."""
        state = _tasks.get(task_id)
        sent_decision_ids: set[str] = set()

        if state:
            for log_entry in state.phase_log:
                if not await _send({"type": "log", "data": log_entry}):
                    return
            existing_events = _build_decision_events(state)
            snapshot = existing_events[-120:] if len(existing_events) > 120 else existing_events
            for event in snapshot:
                if not await _send({"type": "decision_event", "data": event}):
                    return
                sent_decision_ids.add(str(event.get("id") or ""))

        last_log_cursor = len(state.phase_log) if state else 0
        last_rec_cursor = len(state.tool_records) if state else 0
        last_exploit_sig = ""
        sent_approval = False
        heartbeat_counter = 0

        while True:
            await asyncio.sleep(0.15)
            state = _tasks.get(task_id)
            if not state:
                break

            dirty = False

            # incremental logs
            log_len = len(state.phase_log)
            if log_len > last_log_cursor:
                for entry in state.phase_log[last_log_cursor:]:
                    if not await _send({"type": "log", "data": entry}):
                        return
                last_log_cursor = log_len
                dirty = True

            # incremental tool_records
            rec_len = len(state.tool_records)
            if rec_len > last_rec_cursor:
                for record in state.tool_records[last_rec_cursor:]:
                    payload = record.model_dump() if hasattr(record, "model_dump") else dict(record or {})
                    cmd = str(payload.get("command") or "")
                    runtime_cmd = str(payload.get("runtime_command") or "")
                    stdout = str(payload.get("stdout") or "")
                    stderr = str(payload.get("stderr") or "")
                    timestamp = str(payload.get("timestamp") or "")
                    phase = str(payload.get("phase") or "unknown")
                    tool = str(payload.get("tool") or "shell")
                    backend = str(payload.get("backend") or "")
                    exit_code = payload.get("exit_code")
                    elapsed = payload.get("elapsed")
                    purpose = str(payload.get("purpose") or "")
                    round_no = payload.get("round")
                    truncated = bool(payload.get("truncated") or False)
                    total_len = payload.get("total_len")
                    if total_len is None:
                        total_len = len(stdout) + len(stderr)
                    try:
                        total_len_val = int(total_len)
                    except Exception:
                        total_len_val = len(stdout) + len(stderr)
                    rec_id = str(payload.get("id") or f"tool-rec-{last_rec_cursor}")
                    event_id = f"exec-{rec_id}"
                    if event_id not in sent_decision_ids:
                        sent_decision_ids.add(event_id)
                        event = {
                            "id": event_id,
                            "timestamp": timestamp,
                            "phase": phase,
                            "action": "command_exec",
                            "tool": tool,
                            "backend": backend,
                            "poc_or_vuln": "",
                            "command": cmd,
                            "runtime_command": runtime_cmd,
                            "stdout": stdout,
                            "stderr": stderr,
                            "exit_code": exit_code,
                            "elapsed_ms": int(float(elapsed) * 1000.0) if elapsed is not None else None,
                            "purpose": purpose,
                            "round": round_no,
                            "truncated": truncated,
                            "total_len": total_len_val,
                            "message": f"命令执行: {tool} {cmd[:120]}".strip(),
                            "raw": "",
                            "tone": "success" if exit_code == 0 else "danger",
                        }
                        if not await _send({"type": "decision_event", "data": event}):
                            return
                    last_rec_cursor += 1
                dirty = True

            # incremental exploit_results (detect change via length signature)
            exploit_sig = str(len(state.exploit_results or []))
            if exploit_sig != last_exploit_sig:
                last_exploit_sig = exploit_sig
                for ridx, result in enumerate(state.exploit_results or []):
                    result_payload = result.model_dump() if hasattr(result, "model_dump") else result
                    vuln_id = result_payload.get("vuln_id", "")
                    records = result_payload.get("command_records") or result_payload.get("command_results") or []
                    for cidx, record in enumerate(records):
                        eid = f"cmd-{ridx}-{cidx}"
                        if eid in sent_decision_ids:
                            continue
                        sent_decision_ids.add(eid)
                        cmd = str(record.get("command") or "")
                        runtime_cmd = str(record.get("runtime_command") or "")
                        stdout = str(record.get("stdout") or "")
                        stderr = str(record.get("stderr") or "")
                        exit_code = record.get("exit_code")
                        elapsed = record.get("elapsed")
                        timestamp = str(record.get("timestamp") or "")
                        purpose = str(record.get("purpose") or "")
                        round_no = record.get("round")
                        truncated = bool(record.get("truncated") or False)
                        total_len = record.get("total_len")
                        if total_len is None:
                            total_len = len(stdout) + len(stderr)
                        try:
                            total_len_val = int(total_len)
                        except Exception:
                            total_len_val = len(stdout) + len(stderr)
                        if not await _send({"type": "decision_event", "data": {
                            "id": eid,
                            "timestamp": timestamp,
                            "phase": str(record.get("phase") or "exploit"),
                            "action": "command_exec",
                            "tool": str(record.get("tool") or "shell"),
                            "backend": str(record.get("backend") or ""),
                            "poc_or_vuln": vuln_id,
                            "command": cmd,
                            "runtime_command": runtime_cmd,
                            "stdout": stdout,
                            "stderr": stderr,
                            "exit_code": exit_code,
                            "elapsed_ms": int(float(elapsed) * 1000.0) if elapsed is not None else None,
                            "purpose": purpose,
                            "round": round_no,
                            "truncated": truncated,
                            "total_len": total_len_val,
                            "message": f"命令执行: {cmd[:120]}",
                            "raw": "",
                            "tone": "success" if exit_code == 0 else "danger",
                        }}):
                            return
                dirty = True

            # incremental phase_log-derived events (thoughts, approvals, tool_start/result)
            # re-scan only new log lines for structured events
            for idx in range(last_log_cursor - (log_len - (last_log_cursor - (len(state.phase_log) - log_len)) if False else 0), log_len):
                pass  # already handled above via log push

            # approval signal
            if state.current_phase == "awaiting_approval":
                if not sent_approval:
                    if not await _send({
                        "type":           "approval_required",
                        "phase":          "awaiting_approval",
                        "status":         "running",
                        "findings_count": len(state.findings),
                        "exploitable_count": sum(1 for f in state.findings if f.exploitable),
                        "got_shell":      state.got_shell,
                    }):
                        return
                    sent_approval = True
            else:
                sent_approval = False

            # done
            if state.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                if not await _send({
                    "type": "done",
                    "status": state.status.value,
                    "findings_count": len(state.findings),
                    "got_shell": state.got_shell,
                }):
                    return
                break

            # heartbeat every ~3s (20 ticks * 150ms)
            heartbeat_counter += 1
            if heartbeat_counter >= 20:
                heartbeat_counter = 0
                if not await _send({"type": "heartbeat"}):
                    return

    async def _recv_loop():
        """Consume client frames (pings) to keep the connection alive through NAT."""
        while True:
            try:
                data = await websocket.receive_text()
                if data == "ping":
                    if not await _send({"type": "pong"}):
                        break
            except Exception:
                break

    push_task = asyncio.create_task(_push_loop())
    recv_task = asyncio.create_task(_recv_loop())
    try:
        done, _pending = await asyncio.wait(
            [push_task, recv_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            try:
                task.result()
            except WebSocketDisconnect:
                pass
            except Exception:
                pass
    finally:
        for task in [push_task, recv_task]:
            if not task.done():
                task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        if task_id in _ws_connections:
            _ws_connections[task_id] = [
                ws for ws in _ws_connections[task_id] if ws != websocket
            ]

# ── 后台任务执行 ──────────────────────────────────────────

async def _run_task(
    task_id: str,
    target: str,
    scope_note: str,
    extra_hint: str = "",
    user_prompt: str = "",
    workflow_mode: str = "standard",
):
    _running_tasks.add(task_id)
    orchestrator = get_orchestrator()   # 使用全局单例，MemorySaver checkpoint 共享

    try:
        async for node_name, raw_state in orchestrator.run_stream(
            target=target,
            scope_note=scope_note,
            extra_hint=extra_hint,
            user_prompt=user_prompt,
            workflow_mode=workflow_mode,
            task_id=task_id,
        ):
            # 检查取消
            if _redis_available:
                try:
                    from backend.db.redis_cache import is_cancelled
                    if await is_cancelled(task_id):
                        logger.info(f"[API] 任务 {task_id} 已被取消")
                        break
                except Exception:
                    pass

            if isinstance(raw_state, dict):
                try:
                    state = PentestState(**raw_state)
                except Exception as e:
                    logger.warning(f"[API] State 反序列化失败: {e}")
                    continue
            else:
                state = raw_state

            _tasks[task_id] = state

            # Redis 缓存
            if _redis_available:
                try:
                    from backend.db.redis_cache import cache_task_state, append_task_log
                    await cache_task_state(task_id, {
                        "status": state.status.value,
                        "current_phase": state.current_phase,
                        "findings_count": len(state.findings),
                        "got_shell": state.got_shell,
                    })
                    for log_entry in state.phase_log[-5:]:
                        await append_task_log(task_id, log_entry)
                except Exception:
                    pass

            # 数据库持久化
            if _db_available:
                try:
                    from backend.db.database import save_task
                    await save_task(state)
                except Exception as e:
                    logger.warning(f"[DB] 保存失败: {e}")

            await _broadcast(task_id, {
                "type": "phase_update",
                **_ws_phase_payload(state, log_tail=5),
            })

    except Exception as e:
        logger.error(f"[API] 任务 {task_id} 执行异常: {e}")
        state = _tasks.get(task_id)
        if state:
            state.status = TaskStatus.FAILED
            state.error_msg = str(e)
            if _db_available:
                try:
                    from backend.db.database import save_task
                    await save_task(state)
                except Exception:
                    pass
    finally:
        _running_tasks.discard(task_id)

    # ── 检测 LangGraph interrupt 暂停（等待人工审批）──────
    # interrupt_before 触发时 astream() 正常结束，但任务仍是 RUNNING
    # 此时不是"完成"，而是等待前端调用 /approve 后 resume
    state = _tasks.get(task_id)
    if state and state.status == TaskStatus.RUNNING:
        state.current_phase = "awaiting_approval"
        state.log("⏸ 等待人工审批，请在前端点击「授权并继续」")
        _tasks[task_id] = state
        await _broadcast(task_id, {
            "type":           "approval_required",
            "phase":          "awaiting_approval",
            "status":         "running",
            "logs":           state.phase_log[-3:],
            "findings_count": len(state.findings),
            "got_shell":      state.got_shell,
        })
        if _db_available:
            try:
                from backend.db.database import save_task
                await save_task(state)
            except Exception:
                pass
        logger.info(f"[API] 任务 {task_id} 等待人工审批")
        return  # 不打"任务完成"日志，任务还没结束

    # 最终持久化（正常完成 / 失败）
    if state and _db_available:
        try:
            from backend.db.database import save_task
            await save_task(state)
        except Exception:
            pass

    logger.info(f"[API] 任务 {task_id} 完成")


def is_msf_available() -> bool:
    """供 exploit_agent / post_agent 调用，判断是否可以使用 MSF。"""
    return _msf_available


# ── 辅助函数 ──────────────────────────────────────────────

async def _resolve_state(task_id: str) -> PentestState | None:
    """从内存或数据库获取状态"""
    state = _tasks.get(task_id)
    if state:
        return state
    if _db_available:
        try:
            from backend.db.database import load_task
            state = await load_task(task_id)
            if state:
                _tasks[task_id] = state
                return state
        except Exception:
            pass
    return None


async def _broadcast(task_id: str, data: dict):
    connections = _ws_connections.get(task_id, [])
    dead = []
    for ws in connections:
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        connections.remove(ws)


def _extract_phase_log(log_entry: str) -> tuple[str, str, str]:
    """
    Parse log line: [HH:MM:SS] [phase] message
    Return: (timestamp, phase, message)
    """
    match = re.match(r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<phase>[^\]]+)\]\s+(?P<msg>.*)$", log_entry or "")
    if not match:
        return "", "", log_entry or ""
    return match.group("ts"), match.group("phase"), match.group("msg")


def _build_decision_events(state: PentestState) -> list[dict]:
    events: list[dict] = []
    seen_exec_keys: set[tuple[str, str, str]] = set()

    # 1) phase_log 事件
    for idx, entry in enumerate(state.phase_log or []):
        ts, phase, msg = _extract_phase_log(entry)
        tone = "info"
        action = "log"
        tool = ""
        backend = ""
        exit_code = None
        elapsed_ms = None

        start_match = _TOOL_START_RE.search(msg)
        if start_match:
            tool = start_match.group(1).strip()
            backend = start_match.group(2).strip()
            action = "tool_start"
            tone = "primary"

        done_match = _TOOL_DONE_RE.search(msg)
        if done_match:
            tool = done_match.group(1).strip()
            exit_code = int(done_match.group(2))
            elapsed_ms = int(float(done_match.group(3)) * 1000.0)
            action = "tool_result"
            tone = "success" if exit_code == 0 else "danger"

        if "审批" in msg or "授权" in msg:
            action = "approval"
            tone = "warning"

        _THOUGHT_RE = re.compile(
            r"LLM|分析|决策|策略|推理|建议|主动发现|KB|知识库|扫描策略|优先级|"
            r"Skill 引擎|ReAct|模型",
            re.IGNORECASE,
        )
        if action == "log" and _THOUGHT_RE.search(msg):
            action = "thought"
            tone = "primary"

        events.append({
            "id": f"log-{idx}",
            "timestamp": ts,
            "phase": phase,
            "action": action,
            "tool": tool,
            "backend": backend,
            "poc_or_vuln": "",
            "command": "",
            "runtime_command": "",
            "stdout": "",
            "stderr": "",
            "exit_code": exit_code,
            "elapsed_ms": elapsed_ms,
            "purpose": "",
            "round": None,
            "truncated": False,
            "total_len": 0,
            "message": msg,
            "raw": entry,
            "tone": tone,
        })

    # 2) 全阶段结构化执行记录（recon/vuln/exploit）
    for ridx, record in enumerate(state.tool_records or []):
        payload = record.model_dump() if hasattr(record, "model_dump") else dict(record or {})
        cmd = str(payload.get("command") or "")
        runtime_cmd = str(payload.get("runtime_command") or "")
        stdout = str(payload.get("stdout") or "")
        stderr = str(payload.get("stderr") or "")
        timestamp = str(payload.get("timestamp") or "")
        phase = str(payload.get("phase") or "")
        tool = str(payload.get("tool") or "shell")
        backend = str(payload.get("backend") or "")
        exit_code = payload.get("exit_code")
        elapsed = payload.get("elapsed")
        purpose = str(payload.get("purpose") or "")
        round_no = payload.get("round")
        truncated = bool(payload.get("truncated") or False)
        total_len = payload.get("total_len")
        if total_len is None:
            total_len = len(stdout) + len(stderr)
        try:
            total_len_val = int(total_len)
        except Exception:
            total_len_val = len(stdout) + len(stderr)

        dedupe_key = (timestamp, phase, cmd)
        if dedupe_key in seen_exec_keys:
            continue
        seen_exec_keys.add(dedupe_key)

        rec_id = str(payload.get("id") or f"tool-rec-{ridx}")
        events.append({
            "id": f"exec-{rec_id}",
            "timestamp": timestamp,
            "phase": phase or "unknown",
            "action": "command_exec",
            "tool": tool,
            "backend": backend,
            "poc_or_vuln": "",
            "command": cmd,
            "runtime_command": runtime_cmd,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "elapsed_ms": int(float(elapsed) * 1000.0) if elapsed is not None else None,
            "purpose": purpose,
            "round": round_no,
            "truncated": truncated,
            "total_len": total_len_val,
            "message": f"命令执行: {tool} {cmd[:120]}".strip(),
            "raw": "",
            "tone": "success" if exit_code == 0 else "danger",
        })

    # 3) exploit_results 命令执行明细（兼容旧任务，无全阶段 tool_records 时仍可展示）
    for ridx, result in enumerate(state.exploit_results or []):
        result_payload = result.model_dump() if hasattr(result, "model_dump") else result
        vuln_id = result_payload.get("vuln_id", "")
        records = result_payload.get("command_records") or result_payload.get("command_results") or []
        for cidx, record in enumerate(records):
            cmd = str(record.get("command") or "")
            runtime_cmd = str(record.get("runtime_command") or "")
            stdout = str(record.get("stdout") or "")
            stderr = str(record.get("stderr") or "")
            exit_code = record.get("exit_code")
            elapsed = record.get("elapsed")
            timestamp = str(record.get("timestamp") or "")
            purpose = str(record.get("purpose") or "")
            round_no = record.get("round")
            truncated = bool(record.get("truncated") or False)
            total_len = record.get("total_len")
            if total_len is None:
                total_len = len(stdout) + len(stderr)
            try:
                total_len_val = int(total_len)
            except Exception:
                total_len_val = len(stdout) + len(stderr)
            dedupe_key = (timestamp, "exploit", cmd)
            if dedupe_key in seen_exec_keys:
                continue
            seen_exec_keys.add(dedupe_key)
            events.append({
                "id": f"cmd-{ridx}-{cidx}",
                "timestamp": timestamp,
                "phase": str(record.get("phase") or "exploit"),
                "action": "command_exec",
                "tool": str(record.get("tool") or "shell"),
                "backend": str(record.get("backend") or ""),
                "poc_or_vuln": vuln_id,
                "command": cmd,
                "runtime_command": runtime_cmd,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "elapsed_ms": int(float(elapsed) * 1000.0) if elapsed is not None else None,
                "purpose": purpose,
                "round": round_no,
                "truncated": truncated,
                "total_len": total_len_val,
                "message": f"命令执行: {cmd[:120]}",
                "raw": "",
                "tone": "success" if exit_code == 0 else "danger",
            })

    for event in events:
        event.setdefault("purpose", "")
        event.setdefault("round", None)
        event.setdefault("truncated", False)
        event.setdefault("total_len", 0)
        event.setdefault("runtime_command", "")

    return events


def _to_summary(state: PentestState) -> TaskSummary:
    return TaskSummary(
        task_id=state.task_id,
        target=state.target,
        status=state.status.value,
        current_phase=state.current_phase,
        findings_count=len(state.findings),
        got_shell=state.got_shell,
        report_path=state.report_path,
        privilege_level=state.privilege_level,
        created_at=state.created_at,
        updated_at=datetime.utcnow().isoformat(),
    )


def _to_detail(state: PentestState) -> dict:
    """返回完整详情（含 ports / findings 等子对象）"""
    base = _to_summary(state).model_dump()
    base.update({
        "target_os": state.target_os,
        "scope_note": state.scope_note,
        "extra_hint": state.extra_hint,
        "user_prompt": state.user_prompt,
        "workflow_mode": state.workflow_mode,
        "error_msg": state.error_msg,
        "open_ports": [p.model_dump() for p in state.open_ports],
        "os_info": state.os_info,
        "web_paths": state.web_paths,
        "subdomains": state.subdomains,
        "findings": [f.model_dump() for f in state.findings],
        "exploit_results": [r.model_dump() for r in state.exploit_results],
        "tool_records": [r.model_dump() for r in state.tool_records],
        "decision_events": _build_decision_events(state),
        "post_findings": state.post_findings,
        "report_md": state.report_md,
        "phase_log": state.phase_log,
        "fingerprints": state.fingerprints,
        "foothold_status": state.foothold_status,
        "credential_store": state.credential_store,
        "loot_store": state.loot_store,
        "privesc_hypotheses": state.privesc_hypotheses,
        "objective_status": state.objective_status,
        "attack_next_steps": state.attack_next_steps,
        "privesc_attempt_count": state.privesc_attempt_count,
        "max_privesc_rounds": state.max_privesc_rounds,
        "chain_summary": state.chain_summary,
        "chain_visited": state.chain_visited,
        "secondary_elided": state.secondary_elided,
    })
    return base


def _ws_phase_payload(state: PentestState, log_tail: int = 5) -> dict:
    """WebSocket phase_update 附加攻链字段，供决策页/详情实时展示。"""
    tail = max(1, min(log_tail, 50))
    return {
        "phase": state.current_phase,
        "status": state.status.value,
        "logs": state.phase_log[-tail:],
        "findings_count": len(state.findings),
        "got_shell": state.got_shell,
        "privilege_level": state.privilege_level,
        "foothold_status": state.foothold_status,
        "chain_visited": state.chain_visited,
        "secondary_elided": state.secondary_elided,
        "attack_next_steps": state.attack_next_steps,
        "privesc_attempt_count": state.privesc_attempt_count,
    }


# ── 认证端点 ──────────────────────────────────────────────

class AuthRegisterRequest(BaseModel):
    username: str
    password: str
    nickname: str = ""

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) < 2 or len(v) > 64:
            raise ValueError("用户名长度 2-64 字符")
        if not re.match(r"^[A-Za-z0-9_\-]+$", v):
            raise ValueError("用户名仅允许字母/数字/_/-")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("密码至少 6 位")
        return v


class AuthLoginRequest(BaseModel):
    username: str
    password: str


class AuthUpdateMeRequest(BaseModel):
    nickname: str = ""
    avatar_url: str = ""
    oss_url: str = ""
    old_password: str = ""
    new_password: str = ""


def _user_to_dict(user) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "nickname": user.nickname or user.username,
        "avatar_url": user.avatar_url or "",
        "oss_url": user.oss_url or "",
        "created_at": user.created_at.isoformat() if user.created_at else "",
    }


@app.post("/auth/register")
async def auth_register(req: AuthRegisterRequest):
    from backend.db.database import create_user, get_user_by_username
    existing = await get_user_by_username(req.username)
    if existing:
        raise HTTPException(409, "用户名已存在")
    hashed = _bcrypt_lib.hashpw(req.password.encode(), _bcrypt_lib.gensalt()).decode()
    user = await create_user(req.username, hashed, req.nickname or req.username)
    token = _create_jwt(user.id, user.username)
    return {"token": token, "user": _user_to_dict(user)}


@app.post("/auth/login")
async def auth_login(req: AuthLoginRequest):
    from backend.db.database import get_user_by_username
    user = await get_user_by_username(req.username.strip())
    if not user or not _bcrypt_lib.checkpw(req.password.encode(), user.password_hash.encode()):
        raise HTTPException(401, "用户名或密码错误")
    token = _create_jwt(user.id, user.username)
    return {"token": token, "user": _user_to_dict(user)}


@app.get("/auth/me")
async def auth_me(request: Request):
    from backend.db.database import get_user_by_id
    user_id = getattr(request.state, "user_id", "")
    if not user_id:
        raise HTTPException(401, "未登录")
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(404, "用户不存在")
    return _user_to_dict(user)


@app.put("/auth/me")
async def auth_update_me(request: Request, req: AuthUpdateMeRequest):
    from backend.db.database import get_user_by_id, update_user
    user_id = getattr(request.state, "user_id", "")
    if not user_id:
        raise HTTPException(401, "未登录")
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(404, "用户不存在")

    updates = {}
    if req.nickname.strip():
        updates["nickname"] = req.nickname.strip()[:64]
    if req.avatar_url is not None:
        updates["avatar_url"] = req.avatar_url.strip()[:1024]
    if req.oss_url is not None:
        updates["oss_url"] = req.oss_url.strip()[:1024]

    if req.old_password and req.new_password:
        if not _bcrypt_lib.checkpw(req.old_password.encode(), user.password_hash.encode()):
            raise HTTPException(400, "旧密码错误")
        if len(req.new_password) < 6:
            raise HTTPException(400, "新密码至少 6 位")
        updates["password_hash"] = _bcrypt_lib.hashpw(req.new_password.encode(), _bcrypt_lib.gensalt()).decode()

    if updates:
        user = await update_user(user_id, **updates)
    return {"status": "ok", "user": _user_to_dict(user)}


# ── 设置持久化 ────────────────────────────────────────────

import json
from pathlib import Path
import yaml

SETTINGS_FILE = Path(os.getenv("REPORTS_DIR", "/tmp/pentest_reports")) / "settings.json"
PROFILE_FILE = Path(os.getenv("REPORTS_DIR", "/tmp/pentest_reports")) / "profile.json"
KB_SOURCES_FILE = Path(os.getenv("REPORTS_DIR", "/tmp/pentest_reports")) / "kb_sources.json"

DEFAULT_SETTINGS = {
    "llm": {
        "provider":   "deepseek",
        "api_key":    "",
        "model":      "deepseek-chat",
        "base_url":   "https://api.deepseek.com",
        "max_tokens": 4096,
    },
    "embedding": {
        "enabled": os.getenv("EMBEDDING_ENABLED", "true").lower() == "true",
        "api_key": os.getenv("KB_EMBEDDING_API_KEY", os.getenv("LLM_API_KEY", "")),
        "base_url": os.getenv("KB_EMBEDDING_BASE_URL", os.getenv("LLM_BASE_URL", "https://api.deepseek.com")),
        "model": os.getenv("KB_EMBEDDING_MODEL", ""),
    },
    "executor": {
        "docker_network":       "pentest_net",
        "toolbox_image":        "pentest-toolbox:latest",
        "persistent_container": True,
        "lhost":                os.getenv("LHOST", ""),
    },
    "workflow": {
        "require_approval": True,
        "max_retries":      3,
        "default_scope":    "CTF/授权靶场测试",
        "report_lang":      "zh",
    },
}

DEFAULT_PROFILE = {
    "nickname": "安全研究员",
    "avatar": "",
    "updated_at": "",
}


def _deep_merge_dict(base: dict, override: dict) -> dict:
    merged = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = _deep_merge_dict(merged[k], v)
        else:
            merged[k] = v
    return merged


def _load_settings() -> dict:
    defaults = _deep_merge_dict({}, DEFAULT_SETTINGS)
    if SETTINGS_FILE.exists():
        try:
            loaded = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                return _deep_merge_dict(defaults, loaded)
        except Exception:
            pass
    return defaults


def _save_settings_to_file(data: dict) -> None:
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2))


def _load_profile() -> dict:
    if PROFILE_FILE.exists():
        try:
            raw = json.loads(PROFILE_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return {
                    "nickname": str(raw.get("nickname") or DEFAULT_PROFILE["nickname"]),
                    "avatar": str(raw.get("avatar") or ""),
                    "updated_at": str(raw.get("updated_at") or ""),
                }
        except Exception:
            pass
    return DEFAULT_PROFILE.copy()


def _save_profile(data: dict) -> None:
    PROFILE_FILE.parent.mkdir(parents=True, exist_ok=True)
    PROFILE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# ── 审批端点 ──────────────────────────────────────────────

class ApproveRequest(BaseModel):
    approved: bool = True


@app.post("/tasks/{task_id}/approve")
async def approve_task(task_id: str, req: ApproveRequest):
    import time as _time

    state = _tasks.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")

    if task_id in _approval_inflight:
        elapsed = _time.time() - _approval_inflight[task_id]
        if elapsed < _APPROVAL_INFLIGHT_TIMEOUT:
            return {"status": "ok", "approved": req.approved, "note": "审批已在执行中"}
        logger.warning(
            f"[审批] inflight 超时 ({elapsed:.0f}s)，清除锁并允许重新审批: {task_id}"
        )
        del _approval_inflight[task_id]

    if state.current_phase != "awaiting_approval":
        raise HTTPException(
            status_code=400,
            detail=f"任务当前阶段 '{state.current_phase}' 不需要审批",
        )

    state.current_phase = "foothold_attempt" if req.approved else "report"
    state.log(f"[审批] {'已授权，继续利用' if req.approved else '已拒绝，跳过利用'}")
    _tasks[task_id] = state

    _approval_inflight[task_id] = _time.time()

    asyncio.create_task(_resume_task(task_id, req.approved))

    await _broadcast(task_id, {
        "type": "phase_update",
        **_ws_phase_payload(state, log_tail=3),
        "status": "running",
    })
    return {"status": "ok", "approved": req.approved}


async def _resume_task(task_id: str, approved: bool):
    """
    审批后的流式恢复执行。

    与 _run_task 共享同一套状态更新 + 广播逻辑，
    确保 foothold → 枚举/提权/目标收集 → report 阶段的状态变化
    能实时推送到前端。
    """
    _running_tasks.add(task_id)
    orchestrator = get_orchestrator()

    try:
        async for node_name, raw_state in orchestrator.resume_stream(
            task_id=task_id, approved=approved,
        ):
            if isinstance(raw_state, dict):
                try:
                    state = PentestState(**raw_state)
                except Exception as e:
                    logger.warning(f"[API] Resume state 反序列化失败: {e}")
                    continue
            else:
                state = raw_state

            _tasks[task_id] = state

            # 数据库持久化
            if _db_available:
                try:
                    from backend.db.database import save_task
                    await save_task(state)
                except Exception as e:
                    logger.warning(f"[DB] Resume 保存失败: {e}")

            # Redis 缓存
            if _redis_available:
                try:
                    from backend.db.redis_cache import cache_task_state
                    await cache_task_state(task_id, {
                        "status": state.status.value,
                        "current_phase": state.current_phase,
                        "findings_count": len(state.findings),
                        "got_shell": state.got_shell,
                    })
                except Exception:
                    pass

            await _broadcast(task_id, {
                "type": "phase_update",
                **_ws_phase_payload(state, log_tail=5),
            })

    except Exception as e:
        logger.error(f"[API] Resume 任务 {task_id} 异常: {e}")
        state = _tasks.get(task_id)
        if state:
            state.status = TaskStatus.FAILED
            state.error_msg = f"Resume 异常: {e}"
            _tasks[task_id] = state
            if _db_available:
                try:
                    from backend.db.database import save_task
                    await save_task(state)
                except Exception:
                    pass
    finally:
        _running_tasks.discard(task_id)
        _approval_inflight.pop(task_id, None)

    # 最终状态持久化
    state = _tasks.get(task_id)
    if state and _db_available:
        try:
            from backend.db.database import save_task
            await save_task(state)
        except Exception:
            pass

    logger.info(f"[API] 任务 {task_id} resume 完成")


# ── 设置端点 ──────────────────────────────────────────────

@app.get("/settings")
async def get_settings():
    return _load_settings()


@app.post("/settings")
async def save_settings(data: dict):
    merged = _deep_merge_dict(_load_settings(), data or {})
    _save_settings_to_file(merged)
    # 动态更新环境变量，LLM 配置立即生效，无需重启
    llm = merged.get("llm", {})
    if llm.get("api_key"):    os.environ["LLM_API_KEY"]   = llm["api_key"]
    if llm.get("model"):      os.environ["LLM_MODEL"]      = llm["model"]
    if llm.get("base_url"):   os.environ["LLM_BASE_URL"]   = llm["base_url"]
    if llm.get("provider"):   os.environ["LLM_PROVIDER"]   = llm["provider"]
    if llm.get("max_tokens"): os.environ["LLM_MAX_TOKENS"] = str(llm["max_tokens"])
    embedding = merged.get("embedding", {})
    if embedding.get("enabled") is not None:
        os.environ["EMBEDDING_ENABLED"] = "true" if bool(embedding.get("enabled")) else "false"
    if embedding.get("api_key") is not None:
        os.environ["KB_EMBEDDING_API_KEY"] = str(embedding.get("api_key") or "")
    if embedding.get("base_url") is not None:
        os.environ["KB_EMBEDDING_BASE_URL"] = str(embedding.get("base_url") or "")
    if embedding.get("model") is not None:
        os.environ["KB_EMBEDDING_MODEL"] = str(embedding.get("model") or "")

    lhost = merged.get("executor", {}).get("lhost")
    if lhost:
        os.environ["LHOST"] = lhost
    return {"status": "ok"}


@app.post("/settings/test-llm")
async def test_llm_connection():
    try:
        from backend.llm.router import LLMRouter
        llm = LLMRouter()
        result = await llm.chat("请回复 pong", response_format="text")
        return {"status": "ok", "response": result[:100]}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


class ProfileUpdateRequest(BaseModel):
    nickname: str
    avatar: str = ""


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str


@app.get("/profile")
async def get_profile():
    return _load_profile()


@app.put("/profile")
async def update_profile(req: ProfileUpdateRequest):
    nickname = req.nickname.strip()
    if not nickname:
        raise HTTPException(status_code=400, detail="昵称不能为空")
    profile = {
        "nickname": nickname[:32],
        "avatar": req.avatar.strip()[:1024],
        "updated_at": datetime.utcnow().isoformat(),
    }
    _save_profile(profile)
    return {"status": "ok", "profile": profile}


@app.post("/profile/change-password")
async def change_password(req: PasswordChangeRequest):
    old_password = req.old_password.strip()
    new_password = req.new_password.strip()
    if not old_password or not new_password:
        raise HTTPException(status_code=400, detail="旧密码和新密码不能为空")
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="新密码至少 8 位")
    if old_password == new_password:
        raise HTTPException(status_code=400, detail="新旧密码不能相同")
    # 最小化实现：当前版本不接入真实鉴权，仅返回成功占位响应。
    return {"status": "ok", "updated_at": datetime.utcnow().isoformat()}


# ── Skill 系统接口 ────────────────────────────────────────

class SkillRawUpdateRequest(BaseModel):
    yaml: str

@app.get("/skills")
async def list_skills():
    """列出所有已加载的 Exploit Skill"""
    try:
        from backend.skills.registry import SkillRegistry
        registry = SkillRegistry()
        return {"skills": registry.list_all(), "total": registry.size}
    except Exception as e:
        return {"skills": [], "total": 0, "error": str(e)}


@app.post("/skills/reload")
async def reload_skills():
    """重新加载 Skill YAML（开发调试用）"""
    try:
        from backend.skills.registry import SkillRegistry
        registry = SkillRegistry()
        registry.reload()
        return {"status": "ok", "total": registry.size}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/skills/{skill_id}/raw")
async def get_skill_raw(skill_id: str):
    """读取指定 Skill 的 YAML 原文"""
    try:
        from backend.skills.registry import SkillRegistry
        registry = SkillRegistry()
        skill = registry.get_by_id(skill_id)
        if not skill:
            raise HTTPException(status_code=404, detail=f"Skill 不存在: {skill_id}")
        source_path = Path(skill.source_file)
        if not source_path.exists():
            raise HTTPException(status_code=404, detail=f"Skill 文件不存在: {skill.source_file}")
        return {
            "skill_id": skill.skill_id,
            "source": str(source_path),
            "yaml": source_path.read_text(encoding="utf-8"),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/skills/{skill_id}/raw")
async def update_skill_raw(skill_id: str, req: SkillRawUpdateRequest):
    """更新指定 Skill 的 YAML 并立即重载"""
    try:
        from backend.skills.registry import SkillRegistry

        registry = SkillRegistry()
        skill = registry.get_by_id(skill_id)
        if not skill:
            raise HTTPException(status_code=404, detail=f"Skill 不存在: {skill_id}")

        source_path = Path(skill.source_file).resolve()
        skills_root = (Path(__file__).resolve().parents[1] / "skills").resolve()
        try:
            source_path.relative_to(skills_root)
        except Exception:
            raise HTTPException(status_code=403, detail="Skill 文件路径非法，拒绝写入")

        # 基础 YAML 校验，避免写入不可解析内容
        try:
            parsed = yaml.safe_load(req.yaml)
        except yaml.YAMLError as ye:
            raise HTTPException(status_code=400, detail=f"YAML 语法错误: {ye}")

        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="YAML 顶层必须是对象")
        file_skill_id = parsed.get("skill_id")
        if not file_skill_id:
            raise HTTPException(status_code=400, detail="YAML 缺少 skill_id 字段")
        if str(file_skill_id) != skill_id:
            raise HTTPException(
                status_code=400,
                detail=f"skill_id 不一致: path={skill_id}, yaml={file_skill_id}",
            )

        source_path.write_text(req.yaml, encoding="utf-8")
        registry.reload()
        return {"status": "ok", "skill_id": skill_id, "source": str(source_path)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Knowledge Base 管理 ────────────────────────────────────
@app.get("/knowledge/entries")
@app.get("/api/knowledge/entries")
async def list_knowledge_entries():
    """列出所有知识库条目（按 category 分组）"""
    from backend.knowledge.exploit_kb import ExploitKB
    kb = ExploitKB()
    entries = []
    for entry in kb.list_all():
        entries.append({
            "vuln_id": entry.vuln_id,
            "description": entry.description[:120] if entry.description else "",
            "category": entry.category,
            "cves": entry.match_cves,
            "tags": entry.tags,
            "default_port": entry.default_port,
        })
    entries.sort(key=lambda e: (e["category"], e["vuln_id"]))
    return {"entries": entries, "total": len(entries)}


def _load_custom_kb_sources() -> list[dict]:
    if not KB_SOURCES_FILE.exists():
        return []
    try:
        raw = json.loads(KB_SOURCES_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
    except Exception:
        pass
    return []


def _save_custom_kb_sources(items: list[dict]) -> None:
    KB_SOURCES_FILE.parent.mkdir(parents=True, exist_ok=True)
    KB_SOURCES_FILE.write_text(
        json.dumps(items, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _collect_kb_sources():
    from backend.knowledge.builder import VulnSource, VULN_SOURCES

    merged: dict[str, VulnSource] = {src.vuln_id: src for src in VULN_SOURCES}
    custom_rows = _load_custom_kb_sources()
    for row in custom_rows:
        vuln_id = str(row.get("vuln_id") or "").strip()
        if not vuln_id:
            continue
        urls = row.get("urls") or []
        if not isinstance(urls, list):
            urls = []
        merged[vuln_id] = VulnSource(
            vuln_id=vuln_id,
            name=str(row.get("name") or vuln_id),
            urls=[str(u).strip() for u in urls if str(u).strip()],
            extra_context=str(row.get("extra_context") or ""),
            fallback_content=str(row.get("fallback_content") or ""),
        )
    return list(merged.values()), custom_rows


class KnowledgeSourceCreateRequest(BaseModel):
    vuln_id: str
    name: str
    urls: list[str]
    extra_context: str = ""
    fallback_content: str = ""

    @field_validator("vuln_id")
    @classmethod
    def validate_vuln_id(cls, v: str) -> str:
        vv = v.strip().lower()
        if not re.match(r"^[a-z0-9][a-z0-9_\-]{1,63}$", vv):
            raise ValueError("vuln_id 仅允许小写字母/数字/_/-，长度 2-64")
        return vv

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        vv = v.strip()
        if not vv:
            raise ValueError("name 不能为空")
        return vv[:120]


class KnowledgeBuildRequest(BaseModel):
    vuln_id: str | None = None


@app.get("/knowledge/sources")
@app.get("/api/knowledge/sources")
async def list_knowledge_sources():
    """列出知识库构建数据源（内置 + 自定义）"""
    from pathlib import Path

    kb_dir = Path(__file__).parent.parent / "knowledge" / "kb_data"
    sources, custom_rows = _collect_kb_sources()
    custom_ids = {
        str(item.get("vuln_id") or "").strip()
        for item in custom_rows
        if str(item.get("vuln_id") or "").strip()
    }
    rows = []
    for source in sorted(sources, key=lambda s: s.vuln_id):
        target = kb_dir / f"{source.vuln_id}.json"
        rows.append({
            "vuln_id": source.vuln_id,
            "name": source.name,
            "urls": source.urls,
            "url_count": len(source.urls),
            "extra_context": source.extra_context,
            "has_fallback": bool(source.fallback_content),
            "is_custom": source.vuln_id in custom_ids,
            "built": target.exists(),
        })
    return {"sources": rows, "total": len(rows)}


@app.post("/knowledge/sources")
@app.post("/api/knowledge/sources")
async def add_knowledge_source(req: KnowledgeSourceCreateRequest):
    """新增或更新自定义知识源（持久化）"""
    urls = [str(u).strip() for u in (req.urls or []) if str(u).strip()]
    if not urls and not req.extra_context.strip() and not req.fallback_content.strip():
        raise HTTPException(400, "至少提供一个 URL，或填写额外上下文/兜底内容")
    for u in urls:
        if not re.match(r"^https?://", u, flags=re.IGNORECASE):
            raise HTTPException(400, f"URL 非法: {u}")

    custom_rows = _load_custom_kb_sources()
    upsert = {
        "vuln_id": req.vuln_id,
        "name": req.name,
        "urls": urls,
        "extra_context": req.extra_context.strip(),
        "fallback_content": req.fallback_content.strip(),
    }
    replaced = False
    for idx, row in enumerate(custom_rows):
        if str(row.get("vuln_id") or "").strip() == req.vuln_id:
            custom_rows[idx] = upsert
            replaced = True
            break
    if not replaced:
        custom_rows.append(upsert)
    _save_custom_kb_sources(custom_rows)
    return {"status": "saved", "source": upsert}


# ── 单条知识来源 CRUD ─────────────────────────────────────

def _get_source_for_vuln(vuln_id: str) -> dict:
    """获取某个 vuln_id 的来源信息（合并内置+自定义覆盖层）"""
    from backend.knowledge.builder import VulnSource, VULN_SOURCES

    kb_dir = Path(__file__).parent.parent / "knowledge" / "kb_data"
    builtin_map: dict[str, VulnSource] = {s.vuln_id: s for s in VULN_SOURCES}
    custom_rows = _load_custom_kb_sources()
    custom_map: dict[str, dict] = {}
    for row in custom_rows:
        vid = str(row.get("vuln_id") or "").strip()
        if vid:
            custom_map[vid] = row

    custom = custom_map.get(vuln_id)
    builtin = builtin_map.get(vuln_id)

    if custom:
        urls = custom.get("urls") or []
        return {
            "vuln_id": vuln_id,
            "name": custom.get("name") or vuln_id,
            "urls": urls if isinstance(urls, list) else [],
            "extra_context": str(custom.get("extra_context") or ""),
            "fallback_content": str(custom.get("fallback_content") or ""),
            "is_custom": True,
            "built": (kb_dir / f"{vuln_id}.json").exists(),
        }
    elif builtin:
        return {
            "vuln_id": vuln_id,
            "name": builtin.name,
            "urls": builtin.urls,
            "extra_context": builtin.extra_context,
            "fallback_content": builtin.fallback_content,
            "is_custom": False,
            "built": (kb_dir / f"{vuln_id}.json").exists(),
        }
    else:
        return {
            "vuln_id": vuln_id,
            "name": vuln_id,
            "urls": [],
            "extra_context": "",
            "fallback_content": "",
            "is_custom": False,
            "built": (kb_dir / f"{vuln_id}.json").exists(),
        }


def _upsert_custom_source(vuln_id: str, data: dict) -> None:
    """写入/更新自定义覆盖层中某个 vuln_id 的来源"""
    custom_rows = _load_custom_kb_sources()
    replaced = False
    for idx, row in enumerate(custom_rows):
        if str(row.get("vuln_id") or "").strip() == vuln_id:
            custom_rows[idx] = data
            replaced = True
            break
    if not replaced:
        custom_rows.append(data)
    _save_custom_kb_sources(custom_rows)


@app.get("/knowledge/{vuln_id}/sources")
@app.get("/api/knowledge/{vuln_id}/sources")
async def get_knowledge_entry_source(vuln_id: str):
    """获取单条知识的来源信息"""
    return _get_source_for_vuln(vuln_id)


class KnowledgeSourceSaveRequest(BaseModel):
    name: str = ""
    urls: list[str] = []
    extra_context: str = ""
    fallback_content: str = ""


@app.put("/knowledge/{vuln_id}/sources")
@app.put("/api/knowledge/{vuln_id}/sources")
async def save_knowledge_entry_source(vuln_id: str, req: KnowledgeSourceSaveRequest):
    """保存单条知识的来源（完整覆盖写入自定义层）"""
    urls = [str(u).strip() for u in (req.urls or []) if str(u).strip()]
    for u in urls:
        if not re.match(r"^https?://", u, flags=re.IGNORECASE):
            raise HTTPException(400, f"URL 非法: {u}")

    current = _get_source_for_vuln(vuln_id)
    data = {
        "vuln_id": vuln_id,
        "name": req.name.strip() or current.get("name") or vuln_id,
        "urls": urls,
        "extra_context": req.extra_context.strip(),
        "fallback_content": req.fallback_content.strip(),
    }
    _upsert_custom_source(vuln_id, data)
    return {"status": "saved", "source": data}


class KnowledgeSourceUrlRequest(BaseModel):
    url: str


@app.post("/knowledge/{vuln_id}/sources/url")
@app.post("/api/knowledge/{vuln_id}/sources/url")
async def add_knowledge_source_url(vuln_id: str, req: KnowledgeSourceUrlRequest):
    """追加一个 URL 到某条知识的来源"""
    url = req.url.strip()
    if not url or not re.match(r"^https?://", url, flags=re.IGNORECASE):
        raise HTTPException(400, "URL 必须以 http:// 或 https:// 开头")

    current = _get_source_for_vuln(vuln_id)
    urls = list(current.get("urls") or [])
    if url not in urls:
        urls.append(url)

    data = {
        "vuln_id": vuln_id,
        "name": current.get("name") or vuln_id,
        "urls": urls,
        "extra_context": current.get("extra_context") or "",
        "fallback_content": current.get("fallback_content") or "",
    }
    _upsert_custom_source(vuln_id, data)
    return {"status": "added", "url": url, "urls": urls}


@app.delete("/knowledge/{vuln_id}/sources/url")
@app.delete("/api/knowledge/{vuln_id}/sources/url")
async def remove_knowledge_source_url(vuln_id: str, req: KnowledgeSourceUrlRequest):
    """从某条知识的来源中删除一个 URL"""
    url = req.url.strip()
    current = _get_source_for_vuln(vuln_id)
    urls = [u for u in (current.get("urls") or []) if u != url]

    data = {
        "vuln_id": vuln_id,
        "name": current.get("name") or vuln_id,
        "urls": urls,
        "extra_context": current.get("extra_context") or "",
        "fallback_content": current.get("fallback_content") or "",
    }
    _upsert_custom_source(vuln_id, data)
    return {"status": "removed", "url": url, "urls": urls}


@app.post("/knowledge/sources/new")
@app.post("/api/knowledge/sources/new")
async def create_knowledge_source(req: KnowledgeSourceCreateRequest):
    """创建一个全新的 vuln_id 来源条目"""
    from backend.knowledge.builder import VULN_SOURCES

    builtin_ids = {s.vuln_id for s in VULN_SOURCES}
    custom_rows = _load_custom_kb_sources()
    custom_ids = {str(r.get("vuln_id") or "").strip() for r in custom_rows}

    if req.vuln_id in builtin_ids or req.vuln_id in custom_ids:
        raise HTTPException(409, f"vuln_id '{req.vuln_id}' 已存在")

    urls = [str(u).strip() for u in (req.urls or []) if str(u).strip()]
    for u in urls:
        if not re.match(r"^https?://", u, flags=re.IGNORECASE):
            raise HTTPException(400, f"URL 非法: {u}")

    data = {
        "vuln_id": req.vuln_id,
        "name": req.name,
        "urls": urls,
        "extra_context": req.extra_context.strip(),
        "fallback_content": req.fallback_content.strip(),
    }
    custom_rows.append(data)
    _save_custom_kb_sources(custom_rows)
    return {"status": "created", "source": data}


@app.post("/knowledge/build")
@app.post("/api/knowledge/build")
async def build_knowledge(req: KnowledgeBuildRequest | None = None):
    """构建知识库（可全量或指定 vuln_id）"""
    if not os.getenv("LLM_API_KEY", "").strip():
        raise HTTPException(400, "未配置 LLM_API_KEY，请先在系统设置中填写并保存")

    from backend.knowledge.builder import build_all, build_one

    sources, _ = _collect_kb_sources()
    source_map = {src.vuln_id: src for src in sources}

    target_vuln = (req.vuln_id or "").strip() if req else ""
    if target_vuln:
        source = source_map.get(target_vuln)
        if not source:
            raise HTTPException(404, f"未找到知识源: {target_vuln}")
        ok = await build_one(source)
        return {
            "status": "ok" if ok else "failed",
            "mode": "single",
            "vuln_id": target_vuln,
            "success": int(ok),
            "failed": int(not ok),
        }

    results = await build_all(sources=sources)
    success = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    return {
        "status": "ok",
        "mode": "all",
        "total": len(results),
        "success": success,
        "failed": failed,
        "results": results,
    }


@app.post("/knowledge/{vuln_id}/build")
@app.post("/api/knowledge/{vuln_id}/build")
async def build_one_knowledge(vuln_id: str):
    """构建单个知识条目"""
    return await build_knowledge(KnowledgeBuildRequest(vuln_id=vuln_id))


@app.get("/knowledge/{vuln_id}/raw")
@app.get("/api/knowledge/{vuln_id}/raw")
async def get_knowledge_raw(vuln_id: str):
    """获取知识条目原始 JSON"""
    import json as _json
    from pathlib import Path
    kb_dir = Path(__file__).parent.parent / "knowledge" / "kb_data"
    target = kb_dir / f"{vuln_id}.json"
    if not target.exists() or not str(target.resolve()).startswith(str(kb_dir.resolve())):
        raise HTTPException(404, f"知识条目 {vuln_id} 不存在")
    raw = target.read_text(encoding="utf-8")
    return {"vuln_id": vuln_id, "source": str(target.name), "json": raw}


class KnowledgeRawRequest(BaseModel):
    json_content: str

@app.put("/knowledge/{vuln_id}/raw")
@app.put("/api/knowledge/{vuln_id}/raw")
async def save_knowledge_raw(vuln_id: str, req: KnowledgeRawRequest):
    """保存知识条目 JSON"""
    import json as _json
    from pathlib import Path
    kb_dir = Path(__file__).parent.parent / "knowledge" / "kb_data"
    target = kb_dir / f"{vuln_id}.json"
    if not str(target.resolve()).startswith(str(kb_dir.resolve())):
        raise HTTPException(400, "非法路径")
    try:
        parsed = _json.loads(req.json_content)
    except _json.JSONDecodeError as e:
        raise HTTPException(400, f"JSON 解析失败: {e}")
    if parsed.get("vuln_id") != vuln_id:
        raise HTTPException(400, f"vuln_id 不匹配: 期望 {vuln_id}")
    target.write_text(_json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"status": "saved", "vuln_id": vuln_id}


@app.post("/knowledge/reload")
@app.post("/api/knowledge/reload")
async def reload_knowledge():
    """重载知识库"""
    from backend.knowledge.exploit_kb import ExploitKB
    kb = ExploitKB()
    return {"status": "reloaded", "total": kb.size}


# ── 用户-代理对话接口 ──────────────────────────────────────

class ChatMessageRequest(BaseModel):
    text: str


@app.post("/tasks/{task_id}/chat")
@app.post("/api/tasks/{task_id}/chat")
async def send_chat_message(task_id: str, req: ChatMessageRequest):
    """用户向任务代理发送消息"""
    state = _tasks.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    msg = {
        "role": "user",
        "text": req.text.strip(),
        "timestamp": datetime.utcnow().isoformat(),
    }
    state.user_messages.append(msg)
    _tasks[task_id] = state
    await _broadcast(task_id, {
        "type": "decision_event",
        "data": {
            "id": f"chat-user-{len(state.user_messages)}",
            "timestamp": msg["timestamp"],
            "phase": state.current_phase,
            "action": "user_chat",
            "message": msg["text"],
            "tone": "primary",
        },
    })
    return {"status": "sent", "message": msg}


@app.get("/tasks/{task_id}/chat")
@app.get("/api/tasks/{task_id}/chat")
async def get_chat_history(task_id: str):
    """获取任务的用户-代理对话历史"""
    state = _tasks.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    timeline = []
    for m in state.user_messages:
        timeline.append({**m, "role": "user"})
    for m in state.agent_replies:
        timeline.append({**m, "role": "agent"})
    timeline.sort(key=lambda x: x.get("timestamp", ""))
    return {"messages": timeline}


# ── 团队协作预留接口（阶段二实现）────────────────────────

@app.get("/team/members")
async def list_members():
    # 最小化实现：仅返回当前可渲染的团队占位数据，避免前端依赖 501。
    return [
        {"user_id": "local-owner", "email": "owner@aurorarecon.local", "role": "owner"},
    ]


@app.post("/team/members")
async def invite_member(data: dict):
    raise HTTPException(status_code=501, detail="团队功能阶段二实现")


@app.delete("/team/members/{user_id}")
async def remove_member(user_id: str):
    raise HTTPException(status_code=501, detail="团队功能阶段二实现")


@app.post("/tasks/{task_id}/assign")
async def assign_task(task_id: str, data: dict):
    raise HTTPException(status_code=501, detail="团队功能阶段二实现")


@app.get("/tasks/{task_id}/comments")
async def get_comments(task_id: str):
    raise HTTPException(status_code=501, detail="团队功能阶段二实现")


@app.post("/tasks/{task_id}/comments")
async def add_comment(task_id: str, data: dict):
    raise HTTPException(status_code=501, detail="团队功能阶段二实现")