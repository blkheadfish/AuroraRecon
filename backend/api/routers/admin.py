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


CORE_CONTAINERS = {
    "pentest_api",
    "pentest_frontend",
    "pentest_redis",
    "pentest_postgres",
    "pentest_reverse_proxy",
    "pentest_nginx",
    "pentest_toolbox",
}


def _is_core_container(name: str) -> bool:
    if not name:
        return False
    return name.lstrip("/").lower() in CORE_CONTAINERS


def _docker_client():
    """Create a short-timeout docker client so a stuck daemon can't hang the API."""
    import docker as _docker
    if not hasattr(_docker, "from_env"):
        src = getattr(_docker, "__file__", None) or getattr(_docker, "__path__", "unknown")
        raise RuntimeError(
            f"docker-py 未正确安装：当前 import 命中 {src}，"
            "可能是镜像过旧或项目根 docker/ 目录未被 .dockerignore 排除。"
            "请执行: docker compose build api --no-cache && docker compose up -d api"
        )
    return _docker.from_env(timeout=5)


def _collect_host_metrics() -> dict:
    """Blocking: collect host CPU/memory/disk via psutil.  Runs in a thread."""
    host_info: dict = {"source": "container", "error": ""}
    try:
        import psutil

        host_proc = os.environ.get("HOST_PROC")
        host_sys = os.environ.get("HOST_SYS")
        if host_proc:
            psutil.PROCFS_PATH = host_proc
            host_info["source"] = "host"
        if host_sys:
            try:
                psutil.SYSFS_PATH = host_sys
            except Exception:
                pass

        mem = psutil.virtual_memory()
        host_info.update({
            "cpu_percent": psutil.cpu_percent(interval=0.3),
            "cpu_count": psutil.cpu_count(),
            "memory": {
                "total_gb": round(mem.total / (1024**3), 2),
                "used_gb": round(mem.used / (1024**3), 2),
                "percent": mem.percent,
            },
            "disk": [],
            "uptime_seconds": int(time.time() - psutil.boot_time()),
        })

        host_rootfs = os.environ.get("HOST_ROOTFS")
        disk_mounts: list[str] = []
        if host_rootfs and os.path.isdir(host_rootfs):
            disk_mounts.append(host_rootfs)
        try:
            for part in psutil.disk_partitions(all=False):
                if part.fstype in ("nfs", "nfs4", "cifs", "smbfs", "fuse.sshfs"):
                    continue
                if part.mountpoint not in disk_mounts:
                    disk_mounts.append(part.mountpoint)
        except Exception:
            pass

        for mount in disk_mounts:
            try:
                usage = psutil.disk_usage(mount)
                host_info["disk"].append({
                    "mountpoint": "/" if mount == host_rootfs else mount,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_gb": round(usage.used / (1024**3), 2),
                    "percent": usage.percent,
                })
            except Exception:
                pass
    except ImportError:
        host_info["error"] = "psutil not installed"
    except Exception as exc:
        host_info["error"] = f"psutil error: {exc}"
    return host_info


def _collect_docker_metrics() -> dict:
    """Blocking: list containers + parallel stats.  Runs in a thread."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    docker_info: dict = {
        "containers": [],
        "total_running": 0,
        "total_stopped": 0,
        "error": "",
    }
    try:
        client = _docker_client()
        containers = client.containers.list(all=True)

        def _stat_one(c):
            info = {
                "name": c.name,
                "status": c.status,
                "image": str(c.image.tags[0]) if c.image.tags else str(c.image.short_id),
                "is_core": _is_core_container(c.name),
                "cpu_percent": 0.0,
                "memory_mb": 0,
                "memory_limit_mb": 0,
            }
            if c.status == "running":
                try:
                    stats = c.stats(stream=False)
                    cpu_delta = (
                        stats["cpu_stats"]["cpu_usage"]["total_usage"]
                        - stats["precpu_stats"]["cpu_usage"]["total_usage"]
                    )
                    sys_delta = (
                        stats["cpu_stats"]["system_cpu_usage"]
                        - stats["precpu_stats"]["system_cpu_usage"]
                    )
                    cpu_count = stats["cpu_stats"].get("online_cpus", 1)
                    info["cpu_percent"] = round((cpu_delta / sys_delta) * cpu_count * 100.0, 2) if sys_delta > 0 else 0.0
                    info["memory_mb"] = round(stats["memory_stats"].get("usage", 0) / (1024**2), 1)
                    info["memory_limit_mb"] = round(stats["memory_stats"].get("limit", 0) / (1024**2), 1)
                except Exception:
                    pass
            return info

        pool = ThreadPoolExecutor(max_workers=6)
        try:
            futures = {pool.submit(_stat_one, c): c for c in containers}
            done_iter = as_completed(futures, timeout=8)
            for fut in done_iter:
                try:
                    info = fut.result(timeout=0.1)
                    docker_info["containers"].append(info)
                    if info["status"] == "running":
                        docker_info["total_running"] += 1
                    else:
                        docker_info["total_stopped"] += 1
                except Exception:
                    c = futures[fut]
                    docker_info["containers"].append({
                        "name": getattr(c, "name", "?"),
                        "status": getattr(c, "status", "unknown"),
                        "image": "?",
                        "is_core": False,
                        "cpu_percent": 0.0,
                        "memory_mb": 0,
                        "memory_limit_mb": 0,
                    })
        except Exception as inner_exc:
            docker_info["warning"] = f"部分容器 stats 采集超时（{type(inner_exc).__name__}），已跳过"
            for fut in futures:
                if not fut.done():
                    c = futures[fut]
                    docker_info["containers"].append({
                        "name": getattr(c, "name", "?"),
                        "status": getattr(c, "status", "unknown"),
                        "image": "?",
                        "is_core": _is_core_container(getattr(c, "name", "")),
                        "cpu_percent": 0.0,
                        "memory_mb": 0,
                        "memory_limit_mb": 0,
                    })
                    if getattr(c, "status", "") == "running":
                        docker_info["total_running"] += 1
                    else:
                        docker_info["total_stopped"] += 1
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    except ImportError:
        docker_info["error"] = "docker SDK 未安装"
    except Exception as exc:
        docker_info["error"] = f"{type(exc).__name__}: {exc}"
    return docker_info


@router.get("/system-metrics")
async def get_system_metrics(_admin=Depends(require_admin)):
    host_coro = asyncio.to_thread(_collect_host_metrics)
    docker_coro = asyncio.to_thread(_collect_docker_metrics)

    host_task = asyncio.ensure_future(host_coro)
    docker_task = asyncio.ensure_future(docker_coro)

    await asyncio.sleep(0)

    done, pending = await asyncio.wait(
        [host_task, docker_task], timeout=10, return_when=asyncio.ALL_COMPLETED,
    )

    if host_task in done:
        try:
            host_info = host_task.result()
        except Exception as exc:
            host_info = {"source": "container", "error": f"{type(exc).__name__}: {exc}", "cpu_percent": 0, "cpu_count": 0, "memory": {}, "disk": []}
    else:
        host_task.cancel()
        host_info = {"source": "container", "error": "宿主机指标采集超时（>10s），可能存在无响应的网络挂载", "cpu_percent": 0, "cpu_count": 0, "memory": {}, "disk": []}

    if docker_task in done:
        try:
            docker_info = docker_task.result()
        except Exception as exc:
            docker_info = {"containers": [], "total_running": 0, "total_stopped": 0, "error": f"{type(exc).__name__}: {exc}"}
    else:
        docker_task.cancel()
        docker_info = {"containers": [], "total_running": 0, "total_stopped": 0, "error": "Docker 采集超时（>10s），daemon 响应缓慢或容器过多"}

    return {"host": host_info, "docker": docker_info}


@router.post("/docker/{container_name}/{action}")
async def docker_container_action(
    container_name: str,
    action: str,
    admin=Depends(require_admin),
):
    if action not in ("restart", "stop", "start"):
        raise HTTPException(400, "action 必须是 restart / stop / start")
    if _is_core_container(container_name) and action in ("stop", "restart"):
        raise HTTPException(
            status_code=403,
            detail=f"{container_name} 是核心容器，禁止通过管理台执行 {action}（避免自锁）。",
        )
    try:
        client = _docker_client()
        container = client.containers.get(container_name)
        getattr(container, action)()
    except HTTPException:
        raise
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
