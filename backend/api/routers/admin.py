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
