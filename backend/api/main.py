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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.agents.models import PentestState, TaskStatus
from backend.agents.orchestrator import Orchestrator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── 内存态 ────────────────────────────────────────────────
_tasks: dict[str, PentestState] = {}
_ws_connections: dict[str, list[WebSocket]] = {}
_running_tasks: set[str] = set()
_approval_inflight: set[str] = set()

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


# ── 请求/响应模型 ─────────────────────────────────────────

class CreateTaskRequest(BaseModel):
    target: str
    scope_note: str = "CTF/授权靶场测试"
    extra_hint: str = ""
    user_prompt: str = ""
    workflow_mode: str = "standard"


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
    }


def _build_tool_overview() -> dict:
    try:
        from backend.tools.tool_registry import ToolRegistry

        registry = ToolRegistry()
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
    try:
        # 发送已有日志
        state = _tasks.get(task_id)
        if state:
            for log_entry in state.phase_log:
                await websocket.send_json({"type": "log", "data": log_entry})

        # 主动推送循环
        last_log_count = len(state.phase_log) if state else 0
        approval_sent = False  # 防止每 2 秒重复发送 approval_required
        while True:
            await asyncio.sleep(1.5)
            state = _tasks.get(task_id)
            if not state:
                break

            # 推送新日志
            current_count = len(state.phase_log)
            if current_count > last_log_count:
                for entry in state.phase_log[last_log_count:]:
                    await websocket.send_json({"type": "log", "data": entry})
                last_log_count = current_count

            # awaiting_approval：只推送一次
            if state.current_phase == "awaiting_approval" and not approval_sent:
                await websocket.send_json({
                    "type":           "approval_required",
                    "phase":          "awaiting_approval",
                    "status":         "running",
                    "findings_count": len(state.findings),
                    "exploitable_count": sum(1 for f in state.findings if f.exploitable),
                    "got_shell":      state.got_shell,
                })
                approval_sent = True
            elif state.current_phase != "awaiting_approval":
                approval_sent = False  # 阶段变了，重置

            # 任务完成/失败则通知并退出
            if state.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                await websocket.send_json({
                    "type": "done",
                    "status": state.status.value,
                    "findings_count": len(state.findings),
                    "got_shell": state.got_shell,
                })
                break

            # 心跳保活
            await websocket.send_json({"type": "heartbeat"})

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
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
                "phase": state.current_phase,
                "status": state.status.value,
                "logs": state.phase_log[-5:],
                "findings_count": len(state.findings),
                "got_shell": state.got_shell,
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

        events.append({
            "id": f"log-{idx}",
            "timestamp": ts,
            "phase": phase,
            "action": action,
            "tool": tool,
            "backend": backend,
            "exit_code": exit_code,
            "elapsed_ms": elapsed_ms,
            "message": msg,
            "raw": entry,
            "tone": tone,
        })

    # 2) exploit_results 命令执行明细
    for ridx, result in enumerate(state.exploit_results or []):
        result_payload = result.model_dump() if hasattr(result, "model_dump") else result
        vuln_id = result_payload.get("vuln_id", "")
        records = result_payload.get("command_records") or result_payload.get("command_results") or []
        for cidx, record in enumerate(records):
            cmd = str(record.get("command") or "")
            stdout = str(record.get("stdout") or "")
            stderr = str(record.get("stderr") or "")
            exit_code = record.get("exit_code")
            elapsed = record.get("elapsed")
            events.append({
                "id": f"cmd-{ridx}-{cidx}",
                "timestamp": "",
                "phase": "exploit",
                "action": "command_exec",
                "tool": "shell",
                "backend": "",
                "poc_or_vuln": vuln_id,
                "command": cmd,
                "stdout": stdout[:3000],
                "stderr": stderr[:1200],
                "exit_code": exit_code,
                "elapsed_ms": int(float(elapsed) * 1000.0) if elapsed is not None else None,
                "message": f"命令执行: {cmd[:120]}",
                "tone": "success" if exit_code == 0 else "danger",
            })

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
        "decision_events": _build_decision_events(state),
        "post_findings": state.post_findings,
        "report_md": state.report_md,
        "phase_log": state.phase_log,
        "fingerprints": state.fingerprints,
    })
    return base


# ── 设置持久化 ────────────────────────────────────────────

import json
from pathlib import Path
import yaml

SETTINGS_FILE = Path(os.getenv("REPORTS_DIR", "/tmp/pentest_reports")) / "settings.json"
PROFILE_FILE = Path(os.getenv("REPORTS_DIR", "/tmp/pentest_reports")) / "profile.json"

DEFAULT_SETTINGS = {
    "llm": {
        "provider":   "deepseek",
        "api_key":    "",
        "model":      "deepseek-chat",
        "base_url":   "https://api.deepseek.com",
        "max_tokens": 4096,
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


def _load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            return json.loads(SETTINGS_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()


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
    state = _tasks.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task_id in _approval_inflight:
        raise HTTPException(status_code=409, detail="审批已提交，任务正在继续执行")
    if state.current_phase != "awaiting_approval":
        raise HTTPException(
            status_code=400,
            detail=f"任务当前阶段 '{state.current_phase}' 不需要审批",
        )

    # 立即切换阶段，防止重复提交（乐观锁）
    state.current_phase = "exploit" if req.approved else "report"
    state.log(f"[审批] {'已授权，继续利用' if req.approved else '已拒绝，跳过利用'}")
    _tasks[task_id] = state

    # 标记审批已提交，防止重复触发 resume。
    _approval_inflight.add(task_id)

    # 用 _resume_task 代替 fire-and-forget，确保后续阶段的状态更新能推送到前端
    asyncio.create_task(_resume_task(task_id, req.approved))

    await _broadcast(task_id, {
        "type":           "phase_update",
        "phase":          state.current_phase,
        "status":         "running",
        "logs":           state.phase_log[-3:],
        "findings_count": len(state.findings),
        "got_shell":      state.got_shell,
    })
    return {"status": "ok", "approved": req.approved}


async def _resume_task(task_id: str, approved: bool):
    """
    审批后的流式恢复执行。

    与 _run_task 共享同一套状态更新 + 广播逻辑，
    确保 exploit → post_exploit → report 阶段的状态变化
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
                "phase": state.current_phase,
                "status": state.status.value,
                "logs": state.phase_log[-5:],
                "findings_count": len(state.findings),
                "got_shell": state.got_shell,
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
        _approval_inflight.discard(task_id)

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
    _save_settings_to_file(data)
    # 动态更新环境变量，LLM 配置立即生效，无需重启
    llm = data.get("llm", {})
    if llm.get("api_key"):    os.environ["LLM_API_KEY"]   = llm["api_key"]
    if llm.get("model"):      os.environ["LLM_MODEL"]      = llm["model"]
    if llm.get("base_url"):   os.environ["LLM_BASE_URL"]   = llm["base_url"]
    if llm.get("provider"):   os.environ["LLM_PROVIDER"]   = llm["provider"]
    if llm.get("max_tokens"): os.environ["LLM_MAX_TOKENS"] = str(llm["max_tokens"])
    lhost = data.get("executor", {}).get("lhost")
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