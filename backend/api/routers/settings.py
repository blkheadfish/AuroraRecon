"""
routers/settings.py —— 系统设置 + 用户资料
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path

import bcrypt as _bcrypt_lib
from fastapi import APIRouter, HTTPException, Request

from backend.api.deps import get_current_user
from backend.api.schemas import ProfileUpdateRequest, PasswordChangeRequest
from backend.api.tenant_store import resolve_scope

logger = logging.getLogger(__name__)

router = APIRouter(tags=["settings"])

SETTINGS_FILE = Path(os.getenv("REPORTS_DIR", "/tmp/pentest_reports")) / "settings.json"
PROFILE_FILE = Path(os.getenv("REPORTS_DIR", "/tmp/pentest_reports")) / "profile.json"

DEFAULT_SETTINGS = {
    "llm": {
        "provider":   "deepseek",
        "api_key":    "",
        "model":      "deepseek-v4-flash",
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
    # workflow 块里保留全局"默认值"(给前端新建任务对话框预填),
    # 但这些字段都是 per-task 的,不会再写回 os.environ。
    # 真正的策略源是 models._MODE_DEFAULTS,此处仅用于 UI 显示。
    "workflow": {
        "default_mode":       "pentest_engineer",   # pentest_engineer | ctf_expert
        "max_retries":        3,
        "default_scope":      "CTF/授权靶场测试",
        "report_lang":        "zh",
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


async def _load_user_settings(owner_id: str) -> dict:
    from backend.api.state import get_state_manager
    sm = get_state_manager()
    if sm.db_available and owner_id:
        try:
            from backend.db.database import load_user_scoped_json
            payload = await load_user_scoped_json(owner_id, "settings")
            if isinstance(payload, dict):
                return _deep_merge_dict(_load_settings(), payload)
        except Exception as exc:
            logger.warning(f"[Settings] load_user_scoped_json failed: {exc}")
    return _load_settings()


async def _save_user_settings(owner_id: str, payload: dict) -> None:
    from backend.api.state import get_state_manager
    sm = get_state_manager()
    if sm.db_available and owner_id:
        from backend.db.database import append_audit_log, save_user_scoped_json
        await save_user_scoped_json(owner_id, "settings", payload)
        await append_audit_log(
            owner_id=owner_id,
            tenant_id="default",
            action="settings_update",
            resource_type="settings",
            resource_key=owner_id,
            detail={"keys": sorted(list((payload or {}).keys()))[:12]},
        )
    else:
        _save_settings_to_file(payload)


async def _load_user_profile(owner_id: str) -> dict:
    from backend.api.state import get_state_manager
    sm = get_state_manager()
    if sm.db_available and owner_id:
        try:
            from backend.db.database import load_user_scoped_json
            payload = await load_user_scoped_json(owner_id, "profile")
            if isinstance(payload, dict):
                return {
                    "nickname": str(payload.get("nickname") or DEFAULT_PROFILE["nickname"]),
                    "avatar": str(payload.get("avatar") or ""),
                    "updated_at": str(payload.get("updated_at") or ""),
                }
        except Exception as exc:
            logger.warning(f"[Settings] load user profile failed: {exc}")
    return _load_profile()


async def _save_user_profile(owner_id: str, profile: dict) -> None:
    from backend.api.state import get_state_manager
    sm = get_state_manager()
    if sm.db_available and owner_id:
        from backend.db.database import append_audit_log, save_user_scoped_json
        await save_user_scoped_json(owner_id, "profile", profile)
        await append_audit_log(
            owner_id=owner_id,
            tenant_id="default",
            action="profile_update",
            resource_type="profile",
            resource_key=owner_id,
            detail={"nickname": profile.get("nickname", "")},
        )
    else:
        _save_profile(profile)


# ── 敏感字段处理 ─────────────────────────────────────────
#
# 设计：LLM / Embedding 的 API Key 改为"后端统一分配"（当前阶段仍从
#   环境变量读取），前端不再直接编辑 api_key：
#   - GET /settings：不返回真实 api_key，只返回 `has_key` 布尔值
#   - POST /settings：忽略前端提交的 api_key（不会覆盖服务端已配置的 key）
# 这样可以避免把 Key 暴露到前端/日志/备份里。

_REDACTED_SECTIONS = ("llm", "embedding")


def _redact_api_keys(data: dict) -> dict:
    """返回前端的版本：去掉真实 api_key，用 has_key 代替。"""
    if not isinstance(data, dict):
        return data
    out = dict(data)
    for section in _REDACTED_SECTIONS:
        block = out.get(section)
        if isinstance(block, dict):
            block = dict(block)
            key = str(block.get("api_key") or "")
            # 兼容历史：如果落盘时存过真实 key，这里也不回传
            block["api_key"] = ""
            block["has_key"] = bool(key)
            out[section] = block
    # 追加一份服务端当前生效的 key 状态（从环境变量读取），管理员可见
    out["_llm_runtime"] = {
        "has_key": bool(os.getenv("LLM_API_KEY", "")),
        "provider": os.getenv("LLM_PROVIDER", ""),
        "model": os.getenv("LLM_MODEL", ""),
        "base_url": os.getenv("LLM_BASE_URL", ""),
    }
    out["_embedding_runtime"] = {
        "has_key": bool(os.getenv("KB_EMBEDDING_API_KEY", "") or os.getenv("LLM_API_KEY", "")),
        "base_url": os.getenv("KB_EMBEDDING_BASE_URL", ""),
        "model": os.getenv("KB_EMBEDDING_MODEL", ""),
    }
    return out


def _strip_client_api_keys(incoming: dict) -> dict:
    """POST 入参清洗：剥掉前端传来的 api_key 字段，避免被持久化/写入环境变量。"""
    if not isinstance(incoming, dict):
        return incoming
    cleaned = dict(incoming)
    for section in _REDACTED_SECTIONS:
        block = cleaned.get(section)
        if isinstance(block, dict):
            block = dict(block)
            block.pop("api_key", None)
            block.pop("has_key", None)
            cleaned[section] = block
    return cleaned


# ── 设置端点 ──────────────────────────────────────────────

@router.get("/settings")
async def get_settings(request: Request):
    owner_id, _tenant_id = resolve_scope(request)
    raw = await _load_user_settings(owner_id)
    return _redact_api_keys(raw)


@router.post("/settings")
async def save_settings(data: dict, request: Request):
    owner_id, _tenant_id = resolve_scope(request)
    incoming = _strip_client_api_keys(dict(data or {}))
    # allowlist: 禁止普通用户覆盖高风险运行时安全参数
    if isinstance(incoming.get("executor"), dict):
        blocked = {"docker_network", "toolbox_image", "persistent_container"}
        for k in list(incoming["executor"].keys()):
            if k in blocked:
                incoming["executor"].pop(k, None)
    merged = _deep_merge_dict(await _load_user_settings(owner_id), incoming)
    # 持久化前再次剥掉 api_key（兼容历史数据），避免污染磁盘/DB
    await _save_user_settings(owner_id, _strip_client_api_keys(merged))
    llm = merged.get("llm", {})
    # api_key 不再由 /settings 写入环境变量，只接受非敏感字段
    if llm.get("model"):      os.environ["LLM_MODEL"]      = llm["model"]
    if llm.get("base_url"):   os.environ["LLM_BASE_URL"]   = llm["base_url"]
    if llm.get("provider"):   os.environ["LLM_PROVIDER"]   = llm["provider"]
    if llm.get("max_tokens"): os.environ["LLM_MAX_TOKENS"] = str(llm["max_tokens"])
    embedding = merged.get("embedding", {})
    if embedding.get("enabled") is not None:
        os.environ["EMBEDDING_ENABLED"] = "true" if bool(embedding.get("enabled")) else "false"
    if embedding.get("base_url") is not None:
        os.environ["KB_EMBEDDING_BASE_URL"] = str(embedding.get("base_url") or "")
    if embedding.get("model") is not None:
        os.environ["KB_EMBEDDING_MODEL"] = str(embedding.get("model") or "")

    lhost = merged.get("executor", {}).get("lhost")
    if lhost:
        os.environ["LHOST"] = lhost
    # workflow 设置全部改为 per-task,不再通过 os.environ 广播给引擎
    return {"status": "ok"}


@router.post("/settings/test-llm")
async def test_llm_connection():
    try:
        from backend.llm.router import LLMRouter
        llm = LLMRouter()
        result = await llm.chat("请回复 pong", response_format="text")
        return {"status": "ok", "response": result[:100]}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


# ── Profile 端点 ──────────────────────────────────────────

@router.get("/profile")
async def get_profile(request: Request):
    owner_id, _tenant_id = resolve_scope(request)
    return await _load_user_profile(owner_id)


@router.put("/profile")
async def update_profile(req: ProfileUpdateRequest, request: Request):
    nickname = req.nickname.strip()
    if not nickname:
        raise HTTPException(status_code=400, detail="昵称不能为空")
    profile = {
        "nickname": nickname[:32],
        "avatar": req.avatar.strip()[:1024],
        "updated_at": datetime.utcnow().isoformat(),
    }
    owner_id, _tenant_id = resolve_scope(request)
    await _save_user_profile(owner_id, profile)
    return {"status": "ok", "profile": profile}


@router.post("/profile/change-password")
async def change_password(request: Request, req: PasswordChangeRequest):
    user_info = await get_current_user(request)
    from backend.db.database import get_user_by_id, update_user
    user = await get_user_by_id(user_info["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    old_password = req.old_password.strip()
    new_password = req.new_password.strip()
    if not old_password or not new_password:
        raise HTTPException(status_code=400, detail="旧密码和新密码不能为空")
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="新密码至少 8 位")
    if old_password == new_password:
        raise HTTPException(status_code=400, detail="新旧密码不能相同")
    valid = await asyncio.to_thread(
        _bcrypt_lib.checkpw, old_password.encode(), user.password_hash.encode()
    )
    if not valid:
        raise HTTPException(status_code=400, detail="旧密码错误")
    new_hash = await asyncio.to_thread(
        _bcrypt_lib.hashpw, new_password.encode(), _bcrypt_lib.gensalt()
    )
    await update_user(user_info["user_id"], password_hash=new_hash.decode())
    return {"status": "ok", "updated_at": datetime.utcnow().isoformat()}
