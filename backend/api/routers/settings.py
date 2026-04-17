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

logger = logging.getLogger(__name__)

router = APIRouter(tags=["settings"])

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
        "operator_role":    os.getenv("OPERATOR_ROLE", "pentest_engineer"),
        "success_gate":     os.getenv("SUCCESS_GATE", "strict"),
        "max_react_rounds": int(os.getenv("MAX_REACT_ROUNDS", "25")),
        "max_explore_rounds": int(os.getenv("MAX_EXPLORE_ROUNDS", "15")),
        "risk_budget":      int(os.getenv("RISK_BUDGET", "3")),
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


# ── 设置端点 ──────────────────────────────────────────────

@router.get("/settings")
async def get_settings():
    return _load_settings()


@router.post("/settings")
async def save_settings(data: dict):
    merged = _deep_merge_dict(_load_settings(), data or {})
    _save_settings_to_file(merged)
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
    wf = merged.get("workflow", {})
    if wf.get("operator_role"):
        os.environ["OPERATOR_ROLE"] = str(wf["operator_role"])
    if wf.get("success_gate"):
        os.environ["SUCCESS_GATE"] = str(wf["success_gate"])
    if wf.get("max_react_rounds"):
        os.environ["MAX_REACT_ROUNDS"] = str(wf["max_react_rounds"])
    if wf.get("max_explore_rounds"):
        os.environ["MAX_EXPLORE_ROUNDS"] = str(wf["max_explore_rounds"])
    if wf.get("risk_budget"):
        os.environ["RISK_BUDGET"] = str(wf["risk_budget"])
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
async def get_profile():
    return _load_profile()


@router.put("/profile")
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
