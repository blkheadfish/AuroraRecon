"""
routers/auth.py —— 认证端点
"""
from __future__ import annotations

import asyncio
import logging
import os
import time as _time

import bcrypt as _bcrypt_lib
from fastapi import APIRouter, HTTPException, Request

from backend.api.deps import create_jwt, get_current_user
from backend.api.schemas import AuthRegisterRequest, AuthLoginRequest, AuthUpdateMeRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_login_attempts: dict[str, list[float]] = {}
_LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "10"))
_LOGIN_WINDOW_SECONDS = 300


def _check_login_rate(ip: str) -> bool:
    now = _time.time()
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < _LOGIN_WINDOW_SECONDS]
    if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
        _login_attempts[ip] = attempts
        return False
    attempts.append(now)
    _login_attempts[ip] = attempts
    return True


def _user_to_dict(user) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "nickname": user.nickname or user.username,
        "avatar_url": user.avatar_url or "",
        "oss_url": user.oss_url or "",
        "role": getattr(user, "role", None) or "user",
        "created_at": user.created_at.isoformat() if user.created_at else "",
    }


@router.post("/register")
async def auth_register(req: AuthRegisterRequest):
    from backend.db.database import count_users, create_user, get_user_by_username
    existing = await get_user_by_username(req.username)
    if existing:
        raise HTTPException(409, "用户名已存在")
    hashed = await asyncio.to_thread(
        _bcrypt_lib.hashpw, req.password.encode(), _bcrypt_lib.gensalt()
    )
    try:
        is_first = (await count_users()) == 0
    except Exception:
        is_first = False
    role = "admin" if is_first else "user"
    user = await create_user(req.username, hashed.decode(), req.nickname or req.username, role=role)
    if is_first:
        logger.info(f"[Auth] 首位用户 {user.username} 已自动提升为 admin")
    token = create_jwt(user.id, user.username)
    return {"token": token, "user": _user_to_dict(user)}


@router.post("/login")
async def auth_login(request: Request, req: AuthLoginRequest):
    client_ip = request.client.host if request.client else "unknown"
    if not _check_login_rate(client_ip):
        raise HTTPException(429, "登录尝试过于频繁，请 5 分钟后再试")
    from backend.db.database import get_user_by_username
    user = await get_user_by_username(req.username.strip())
    if not user:
        raise HTTPException(401, "用户名或密码错误")
    valid = await asyncio.to_thread(
        _bcrypt_lib.checkpw, req.password.encode(), user.password_hash.encode()
    )
    if not valid:
        raise HTTPException(401, "用户名或密码错误")
    token = create_jwt(user.id, user.username)
    return {"token": token, "user": _user_to_dict(user)}


@router.get("/me")
async def auth_me(request: Request):
    user_info = await get_current_user(request)
    from backend.db.database import get_user_by_id
    user = await get_user_by_id(user_info["user_id"])
    if not user:
        raise HTTPException(404, "用户不存在")
    return _user_to_dict(user)


@router.put("/me")
async def auth_update_me(request: Request, req: AuthUpdateMeRequest):
    user_info = await get_current_user(request)
    from backend.db.database import get_user_by_id, update_user
    user = await get_user_by_id(user_info["user_id"])
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
        valid = await asyncio.to_thread(
            _bcrypt_lib.checkpw, req.old_password.encode(), user.password_hash.encode()
        )
        if not valid:
            raise HTTPException(400, "旧密码错误")
        if len(req.new_password) < 6:
            raise HTTPException(400, "新密码至少 6 位")
        new_hash = await asyncio.to_thread(
            _bcrypt_lib.hashpw, req.new_password.encode(), _bcrypt_lib.gensalt()
        )
        updates["password_hash"] = new_hash.decode()

    if updates:
        user = await update_user(user_info["user_id"], **updates)
    return {"status": "ok", "user": _user_to_dict(user)}
