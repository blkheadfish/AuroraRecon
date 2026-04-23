"""
routers/admin.py —— 管理员专用端点

仅 role == "admin" 的用户可访问（通过 require_admin 依赖）。
暂时提供：
  - GET    /admin/users                     列出全部用户
  - PATCH  /admin/users/{user_id}/role      修改用户角色
  - POST   /admin/users/{user_id}/reset-password  管理员重置某用户密码
  - DELETE /admin/users/{user_id}           删除用户
  - GET    /admin/llm-runtime               查看当前 LLM/Embedding 运行时配置（只读，便于
                                             管理员确认服务端是否已分配 API Key）
"""
from __future__ import annotations

import asyncio
import logging
import os
import time

import bcrypt as _bcrypt_lib
from fastapi import APIRouter, Depends, HTTPException, Request

from backend.api.deps import require_admin
from backend.api.schemas import AdminResetPasswordRequest, AdminUpdateRoleRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
async def list_users(_admin=Depends(require_admin)):
    from backend.db.database import list_all_users
    users = await list_all_users()
    return {"users": users, "total": len(users)}


@router.patch("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    req: AdminUpdateRoleRequest,
    admin=Depends(require_admin),
):
    from backend.db.database import (
        append_audit_log,
        count_admins,
        get_user_by_id,
        update_user,
    )
    target = await get_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "用户不存在")

    # 降级保护：不能把最后一个 admin 改成 user
    if (getattr(target, "role", "user") == "admin") and req.role != "admin":
        if await count_admins() <= 1:
            raise HTTPException(400, "至少需要保留一名管理员")

    updated = await update_user(user_id, role=req.role)
    if not updated:
        raise HTTPException(500, "更新失败")

    try:
        await append_audit_log(
            owner_id=admin.get("user_id", ""),
            tenant_id="default",
            action="admin_update_role",
            resource_type="user",
            resource_key=user_id,
            detail={"new_role": req.role},
        )
    except Exception:
        pass

    return {
        "status": "ok",
        "user": {
            "id": updated.id,
            "username": updated.username,
            "role": updated.role,
        },
    }


@router.post("/users/{user_id}/reset-password")
async def reset_password(
    user_id: str,
    req: AdminResetPasswordRequest,
    admin=Depends(require_admin),
):
    from backend.db.database import append_audit_log, get_user_by_id, update_user
    target = await get_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "用户不存在")
    new_hash = await asyncio.to_thread(
        _bcrypt_lib.hashpw, req.new_password.encode(), _bcrypt_lib.gensalt()
    )
    await update_user(user_id, password_hash=new_hash.decode())
    try:
        await append_audit_log(
            owner_id=admin.get("user_id", ""),
            tenant_id="default",
            action="admin_reset_password",
            resource_type="user",
            resource_key=user_id,
            detail={},
        )
    except Exception:
        pass
    return {"status": "ok"}


@router.delete("/users/{user_id}")
async def delete_user_route(user_id: str, admin=Depends(require_admin)):
    from backend.db.database import (
        append_audit_log,
        count_admins,
        delete_user,
        get_user_by_id,
    )
    if user_id == admin.get("user_id"):
        raise HTTPException(400, "不能删除当前登录的管理员")

    target = await get_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "用户不存在")

    if getattr(target, "role", "user") == "admin":
        if await count_admins() <= 1:
            raise HTTPException(400, "至少需要保留一名管理员")

    ok = await delete_user(user_id)
    if not ok:
        raise HTTPException(500, "删除失败")
    try:
        await append_audit_log(
            owner_id=admin.get("user_id", ""),
            tenant_id="default",
            action="admin_delete_user",
            resource_type="user",
            resource_key=user_id,
            detail={},
        )
    except Exception:
        pass
    return {"status": "ok"}


@router.get("/audit-logs")
async def list_audit_logs_route(
    page: int = 1,
    page_size: int = 50,
    action: str | None = None,
    owner_id: str | None = None,
    _admin=Depends(require_admin),
):
    from backend.db.database import list_audit_logs
    items, total = await list_audit_logs(
        page=page, page_size=page_size, action=action, owner_id=owner_id
    )
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.patch("/skills/{skill_id}/enabled")
async def set_skill_enabled(
    skill_id: str,
    request: Request,
    admin=Depends(require_admin),
):
    from backend.db.database import append_audit_log, set_override
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    record = await set_override("skill", skill_id, enabled)
    try:
        await append_audit_log(
            owner_id=admin.get("user_id", ""),
            tenant_id="default",
            action="admin_set_skill_enabled",
            resource_type="skill",
            resource_key=skill_id,
            detail={"enabled": enabled},
        )
    except Exception:
        pass
    return {"status": "ok", "resource_type": "skill", "resource_key": skill_id, "enabled": record.enabled}


@router.patch("/tools/{tool_name}/enabled")
async def set_tool_enabled(
    tool_name: str,
    request: Request,
    admin=Depends(require_admin),
):
    from backend.db.database import append_audit_log, set_override
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    record = await set_override("tool", tool_name, enabled)
    try:
        await append_audit_log(
            owner_id=admin.get("user_id", ""),
            tenant_id="default",
            action="admin_set_tool_enabled",
            resource_type="tool",
            resource_key=tool_name,
            detail={"enabled": enabled},
        )
    except Exception:
        pass
    return {"status": "ok", "resource_type": "tool", "resource_key": tool_name, "enabled": record.enabled}


@router.get("/overrides")
async def list_overrides_route(
    resource_type: str | None = None,
    _admin=Depends(require_admin),
):
    from backend.db.database import list_overrides
    items = await list_overrides(resource_type)
    return {"items": items, "total": len(items)}


@router.patch("/tools/{tool_name}/timeout")
async def set_tool_timeout(
    tool_name: str,
    request: Request,
    admin=Depends(require_admin),
):
    from backend.db.database import append_audit_log, set_override, get_override
    body = await request.json()
    timeout = int(body.get("timeout", 120))
    if timeout < 1 or timeout > 7200:
        raise HTTPException(400, "超时时间须在 1~7200 秒之间")
    record = await get_override("tool", tool_name)
    if record:
        from backend.db.database import async_session
        from datetime import datetime
        async with async_session() as session:
            rec = await session.get(
                type(record), record.id
            )
            if rec:
                import json as _json
                existing = {}
                try:
                    existing = _json.loads(getattr(rec, 'detail_json', '{}') or '{}')
                except Exception:
                    pass
                existing["timeout"] = timeout
                rec.detail_json = _json.dumps(existing, ensure_ascii=False)
                rec.updated_at = datetime.utcnow()
                await session.commit()
    else:
        await set_override("tool", tool_name, True)
        record = await get_override("tool", tool_name)
        if record:
            from backend.db.database import async_session
            from datetime import datetime
            import json as _json
            async with async_session() as session:
                rec = await session.get(type(record), record.id)
                if rec:
                    rec.detail_json = _json.dumps({"timeout": timeout}, ensure_ascii=False)
                    rec.updated_at = datetime.utcnow()
                    await session.commit()
    try:
        await append_audit_log(
            owner_id=admin.get("user_id", ""),
            tenant_id="default",
            action="admin_set_tool_timeout",
            resource_type="tool",
            resource_key=tool_name,
            detail={"timeout": timeout},
        )
    except Exception:
        pass
    return {"status": "ok", "tool": tool_name, "timeout": timeout}


@router.get("/system-metrics")
async def get_system_metrics(_admin=Depends(require_admin)):
    host_info = {}
    try:
        import psutil
        mem = psutil.virtual_memory()
        host_info = {
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "cpu_count": psutil.cpu_count(),
            "memory": {
                "total_gb": round(mem.total / (1024**3), 2),
                "used_gb": round(mem.used / (1024**3), 2),
                "percent": mem.percent,
            },
            "disk": [],
            "uptime_seconds": int(time.time() - psutil.boot_time()),
        }
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                host_info["disk"].append({
                    "mountpoint": part.mountpoint,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_gb": round(usage.used / (1024**3), 2),
                    "percent": usage.percent,
                })
            except Exception:
                pass
    except ImportError:
        host_info = {"error": "psutil not installed"}

    docker_info = {"containers": [], "total_running": 0, "total_stopped": 0}
    try:
        import docker as _docker
        client = _docker.from_env()
        for c in client.containers.list(all=True):
            info = {
                "name": c.name,
                "status": c.status,
                "image": str(c.image.tags[0]) if c.image.tags else str(c.image.short_id),
            }
            if c.status == "running":
                docker_info["total_running"] += 1
                try:
                    stats = c.stats(stream=False)
                    cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
                    sys_delta = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
                    cpu_count = stats["cpu_stats"].get("online_cpus", 1)
                    info["cpu_percent"] = round((cpu_delta / sys_delta) * cpu_count * 100.0, 2) if sys_delta > 0 else 0.0
                    mem_usage = stats["memory_stats"].get("usage", 0)
                    mem_limit = stats["memory_stats"].get("limit", 0)
                    info["memory_mb"] = round(mem_usage / (1024**2), 1)
                    info["memory_limit_mb"] = round(mem_limit / (1024**2), 1)
                except Exception:
                    info["cpu_percent"] = 0.0
                    info["memory_mb"] = 0
                    info["memory_limit_mb"] = 0
            else:
                docker_info["total_stopped"] += 1
                info["cpu_percent"] = 0.0
                info["memory_mb"] = 0
                info["memory_limit_mb"] = 0
            docker_info["containers"].append(info)
    except Exception:
        docker_info["error"] = "docker not available"

    return {"host": host_info, "docker": docker_info}


@router.post("/docker/{container_name}/{action}")
async def docker_container_action(
    container_name: str,
    action: str,
    admin=Depends(require_admin),
):
    if action not in ("restart", "stop", "start"):
        raise HTTPException(400, "action 必须是 restart / stop / start")
    try:
        import docker as _docker
        client = _docker.from_env()
        container = client.containers.get(container_name)
        getattr(container, action)()
    except Exception as e:
        raise HTTPException(500, f"操作失败: {e}")
    try:
        from backend.db.database import append_audit_log
        await append_audit_log(
            owner_id=admin.get("user_id", ""),
            tenant_id="default",
            action=f"admin_docker_{action}",
            resource_type="container",
            resource_key=container_name,
            detail={},
        )
    except Exception:
        pass
    return {"status": "ok", "container": container_name, "action": action}


@router.put("/knowledge/{vuln_id}/raw")
async def admin_save_knowledge_raw_global(
    vuln_id: str,
    request: Request,
    admin=Depends(require_admin),
):
    """Admin 写入全局知识条目（不走 tenant scope，所有用户可见）。"""
    import json as _json
    from pathlib import Path
    body = await request.json()
    json_content = body.get("json_content", "")
    try:
        parsed = _json.loads(json_content)
    except _json.JSONDecodeError as e:
        raise HTTPException(400, f"JSON 解析失败: {e}")
    if parsed.get("vuln_id") != vuln_id:
        raise HTTPException(400, f"vuln_id 不匹配: 期望 {vuln_id}")
    kb_dir = Path(__file__).resolve().parents[2] / "knowledge" / "kb_data"
    kb_dir.mkdir(parents=True, exist_ok=True)
    target = kb_dir / f"{vuln_id}.json"
    target.write_text(
        _json.dumps(parsed, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    try:
        from backend.db.database import append_audit_log
        await append_audit_log(
            owner_id=admin.get("user_id", ""),
            tenant_id="default",
            action="admin_save_knowledge_global",
            resource_type="knowledge",
            resource_key=vuln_id,
            detail={},
        )
    except Exception:
        pass
    return {"status": "saved", "vuln_id": vuln_id, "source": str(target.name), "scope": "global"}


@router.get("/llm-runtime")
async def get_llm_runtime(_admin=Depends(require_admin)):
    """管理员查看当前服务端实际在用的 LLM/Embedding 配置（只读）。

    目前 API Key 从环境变量统一读取；此端点仅用于告诉管理员「服务端是否已经
    配置过 key」，而不回显真实 key。后续可以扩展为「管理员可在此写入并热更新
    环境变量」，但当前阶段刻意保持只读。
    """
    return {
        "llm": {
            "provider": os.getenv("LLM_PROVIDER", ""),
            "model": os.getenv("LLM_MODEL", ""),
            "base_url": os.getenv("LLM_BASE_URL", ""),
            "has_key": bool(os.getenv("LLM_API_KEY", "")),
        },
        "embedding": {
            "enabled": os.getenv("EMBEDDING_ENABLED", "true").lower() == "true",
            "model": os.getenv("KB_EMBEDDING_MODEL", ""),
            "base_url": os.getenv("KB_EMBEDDING_BASE_URL", ""),
            "has_key": bool(
                os.getenv("KB_EMBEDDING_API_KEY", "") or os.getenv("LLM_API_KEY", "")
            ),
        },
        "note": "API Key 由服务端统一通过环境变量 LLM_API_KEY / KB_EMBEDDING_API_KEY 配置",
    }
