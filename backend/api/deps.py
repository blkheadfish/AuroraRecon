"""
deps.py —— FastAPI 依赖注入

所有 Router 通过 Depends() 获取共享资源，
避免 import 全局变量或函数内 lazy import。
"""
from __future__ import annotations

import os
import logging
import secrets

from fastapi import Request, HTTPException

logger = logging.getLogger(__name__)

# ── JWT 配置 ──────────────────────────────────────────────

_MIN_SECRET_LEN = 32

_JWT_SECRET = os.getenv("JWT_SECRET", "")
if not _JWT_SECRET:
    logger.critical(
        "[安全] JWT_SECRET 未设置！使用随机值，重启后所有 token 失效。"
        "生产环境请在 .env 中设置 JWT_SECRET（至少 %d 字符）。", _MIN_SECRET_LEN,
    )
    _JWT_SECRET = secrets.token_urlsafe(32)
elif len(_JWT_SECRET) < _MIN_SECRET_LEN:
    logger.critical(
        "[安全] JWT_SECRET 仅 %d 字符，低于最低要求 %d 字符！"
        "已自动替换为随机值，重启后所有 token 失效。"
        "请在 .env 中设置更长的 JWT_SECRET。",
        len(_JWT_SECRET), _MIN_SECRET_LEN,
    )
    _JWT_SECRET = secrets.token_urlsafe(32)

JWT_SECRET = _JWT_SECRET
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 7


def get_jwt_secret() -> str:
    return JWT_SECRET


# ── JWT 编解码 ────────────────────────────────────────────

from datetime import datetime, timedelta
import jwt as _jwt


def create_jwt(user_id: str, username: str) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS),
        "iat": datetime.utcnow(),
    }
    return _jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict | None:
    try:
        return _jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except _jwt.ExpiredSignatureError:
        return None
    except _jwt.InvalidTokenError:
        return None


# ── 依赖注入函数 ──────────────────────────────────────────

async def get_current_user(request: Request) -> dict:
    """从 middleware 注入的 request.state 中提取认证信息。"""
    user_id = getattr(request.state, "user_id", "")
    if not user_id:
        raise HTTPException(status_code=401, detail="未登录")
    return {
        "user_id": user_id,
        "username": getattr(request.state, "username", ""),
    }
