"""
routers/skills.py —— Skill YAML 管理
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException, Request

from backend.api.schemas import SkillRawUpdateRequest
from backend.api.tenant_store import get_asset, resolve_scope, upsert_asset

logger = logging.getLogger(__name__)

router = APIRouter(tags=["skills"])


@router.get("/skills")
async def list_skills():
    try:
        from backend.skills.registry import get_registry
        registry = get_registry()
        return {"skills": registry.list_all(), "total": registry.size}
    except Exception as e:
        return {"skills": [], "total": 0, "error": str(e)}


@router.post("/skills/reload")
async def reload_skills():
    try:
        from backend.skills.registry import get_registry
        registry = get_registry()
        registry.reload()
        return {"status": "ok", "total": registry.size}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/skills/stats")
async def skills_stats():
    """Aggregated success-rate statistics from execution logs."""
    try:
        from backend.skills.execution_log import get_stats
        return get_stats()
    except Exception as e:
        return {"total": 0, "skills": {}, "error": str(e)}


@router.get("/skills/{skill_id}/raw")
async def get_skill_raw(skill_id: str, request: Request):
    try:
        owner_id, tenant_id = resolve_scope(request)
        scoped = await get_asset(
            asset_type="skill",
            asset_key=skill_id,
            owner_id=owner_id,
            tenant_id=tenant_id,
        )
        if isinstance(scoped, dict) and scoped.get("yaml"):
            return {
                "skill_id": skill_id,
                "source": f"tenant://{tenant_id}/{owner_id}/skill/{skill_id}",
                "yaml": str(scoped.get("yaml") or ""),
            }
        from backend.skills.registry import get_registry
        registry = get_registry()
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


@router.put("/skills/{skill_id}/raw")
async def update_skill_raw(skill_id: str, req: SkillRawUpdateRequest, request: Request):
    try:
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
        owner_id, tenant_id = resolve_scope(request)
        await upsert_asset(
            asset_type="skill",
            asset_key=skill_id,
            layer="user_override",
            owner_id=owner_id,
            tenant_id=tenant_id,
            payload={"skill_id": skill_id, "yaml": req.yaml},
        )
        return {
            "status": "ok",
            "skill_id": skill_id,
            "source": f"tenant://{tenant_id}/{owner_id}/skill/{skill_id}",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
