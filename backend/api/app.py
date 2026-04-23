"""
app.py —— FastAPI 应用入口

职责：
  1. 创建 FastAPI 实例 + lifespan
  2. 注册 CORS + 认证 middleware
  3. include_router 挂载所有路由模块
"""
from __future__ import annotations

import os
import asyncio
import uuid
import ipaddress as _ipaddress
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.deps import decode_jwt
from backend.api.state import get_state_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Auth 白名单 ───────────────────────────────────────────
_AUTH_WHITELIST_PREFIXES = (
    "/health",
    "/auth/login",
    "/auth/register",
    "/docs",
    "/openapi.json",
    "/redoc",
)


# ── 生命周期 ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    sm = get_state_manager()

    # PostgreSQL
    try:
        from backend.db.database import init_db
        await init_db()
        sm.db_available = True
        logger.info("[启动] PostgreSQL 连接成功")
    except Exception as e:
        logger.warning(f"[启动] PostgreSQL 不可用，使用内存模式: {e}")

    # Redis
    try:
        from backend.db.redis_cache import get_redis
        r = await get_redis()
        await r.ping()
        sm.redis_available = True
        logger.info("[启动] Redis 连接成功")
    except Exception as e:
        logger.warning(f"[启动] Redis 不可用，使用内存模式: {e}")

    # MinIO
    try:
        from backend.storage.minio_client import get_storage
        get_storage()
        logger.info("[启动] MinIO 初始化完成")
    except Exception as e:
        logger.warning(f"[启动] MinIO 不可用，使用本地文件: {e}")

    # Metasploit RPC
    try:
        from backend.tools.msf_client import MsfClient
        _msf_client_probe = MsfClient()
        await asyncio.wait_for(_msf_client_probe.connect(), timeout=5.0)
        sm.msf_available = True
        logger.info(f"[启动] MSF RPC 连接成功 ({os.getenv('MSF_HOST', 'msf')}:{os.getenv('MSF_PORT', '55553')})")
    except asyncio.TimeoutError:
        logger.warning("[启动] MSF RPC 连接超时，MSF 功能不可用")
    except Exception as e:
        logger.warning(f"[启动] MSF RPC 不可用: {e}")

    # 从数据库恢复任务
    if sm.db_available:
        try:
            from backend.db.database import list_tasks_from_db, load_task
            db_tasks = await list_tasks_from_db()
            for t in db_tasks:
                state = await load_task(t["task_id"])
                if state:
                    sm.set(state.task_id, state)
            logger.info(f"[启动] 从数据库恢复 {len(db_tasks)} 个任务")
        except Exception as e:
            logger.warning(f"[启动] 恢复任务失败: {e}")

    # Orphan container cleanup
    try:
        from backend.tools.executor import TaskContainerManager
        cleaned = await TaskContainerManager.cleanup_orphans()
        if cleaned:
            logger.info(f"[启动] 清理 {cleaned} 个孤儿容器")
    except Exception as e:
        logger.warning(f"[启动] 孤儿容器清理失败: {e}")

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

    # KB 向量索引
    try:
        from backend.knowledge.exploit_kb import ExploitKB
        _kb = ExploitKB()
        asyncio.create_task(_kb.build_index())
        logger.info("[启动] 知识库向量索引构建任务已提交")
    except Exception as e:
        logger.warning(f"[启动] 知识库向量索引构建失败: {e}")

    yield

    if sm.redis_available:
        try:
            from backend.db.redis_cache import close_redis
            await close_redis()
        except Exception:
            pass
    logger.info("[关闭] 服务已停止")


# ── 创建 App ──────────────────────────────────────────────
app = FastAPI(title="PentestAI", version="2.0.0", lifespan=lifespan)

# ── 全局异常处理 ──────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """将 Pydantic 校验错误转为统一的前端友好格式。"""
    messages = []
    for err in exc.errors():
        field = ".".join(str(loc) for loc in err.get("loc", []) if loc != "body")
        msg = err.get("msg", "").replace("Value error, ", "")
        messages.append(f"{field}: {msg}" if field else msg)
    detail = "；".join(messages) if messages else "请求参数校验失败"
    return JSONResponse(status_code=422, content={"detail": detail})


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """兜底：未捕获异常不暴露堆栈。"""
    logger.error(f"[未处理异常] {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "服务器内部错误，请稍后重试"})


# CORS（环境变量控制）
ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# ── 认证中间件 ────────────────────────────────────────────
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    request.state.trace_id = request.headers.get("x-trace-id", "") or uuid.uuid4().hex[:16]
    path = request.url.path
    if request.method == "OPTIONS":
        response = await call_next(request)
        response.headers["x-trace-id"] = request.state.trace_id
        return response
    if any(path.startswith(p) for p in _AUTH_WHITELIST_PREFIXES):
        return await call_next(request)
    if path.startswith("/ws/") or path == "/admin/terminal":
        response = await call_next(request)
        response.headers["x-trace-id"] = request.state.trace_id
        return response

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "未登录"})
    token = auth_header[7:]
    claims = decode_jwt(token)
    if not claims:
        return JSONResponse(status_code=401, content={"detail": "登录已过期，请重新登录"})
    request.state.user_id = claims.get("sub", "")
    request.state.username = claims.get("username", "")
    request.state.tenant_id = claims.get("tenant_id", "default")
    response = await call_next(request)
    response.headers["x-trace-id"] = request.state.trace_id
    return response


# ── 挂载路由 ──────────────────────────────────────────────
from backend.api.routers import (
    health, tasks, ws, auth, settings, skills, knowledge, team, prompts, admin,
    admin_terminal,
)

app.include_router(health.router)
app.include_router(tasks.router)
app.include_router(ws.router)
app.include_router(auth.router)
app.include_router(settings.router)
app.include_router(skills.router)
app.include_router(knowledge.router)
app.include_router(prompts.router)
app.include_router(team.router)
app.include_router(admin.router)
app.include_router(admin_terminal.router)
