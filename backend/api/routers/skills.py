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
        skills = registry.list_all()
        try:
            from backend.db.database import list_overrides
            overrides = await list_overrides("skill")
            disabled_keys = {o["resource_key"] for o in overrides if not o["enabled"]}
            for s in skills:
                sid = s.get("skill_id") or s.get("id", "")
                s["enabled"] = sid not in disabled_keys
        except Exception:
            for s in skills:
                s["enabled"] = True
        return {"skills": skills, "total": registry.size}
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


# ── W4-T3: Skill 草案管理 ────────────────────────────────────

@router.get("/skills/drafts")
async def list_skill_drafts():
    """列出 .drafts/ 下所有待审核草案。"""
    try:
        from backend.skills.draft_synthesizer import list_drafts
        return {"drafts": list_drafts()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/skills/drafts/{name}")
async def get_skill_draft(name: str):
    """获取单个草案详情（含 YAML）。"""
    try:
        from backend.skills.draft_synthesizer import get_draft
        draft = get_draft(name)
        if not draft:
            raise HTTPException(status_code=404, detail=f"草案不存在: {name}")
        return draft
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/skills/drafts/{name}/promote")
async def promote_skill_draft(name: str):
    """将草案转正到正式 skill 目录，并删除 draft 文件。"""
    try:
        from backend.skills.draft_synthesizer import promote_draft
        dest = promote_draft(name)
        if not dest:
            raise HTTPException(status_code=404, detail=f"草案不存在或转正失败: {name}")
        from backend.skills.registry import get_registry
        get_registry().reload()
        return {"status": "ok", "skill_id": name, "destination": str(dest)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/skills/drafts/{name}")
async def delete_skill_draft(name: str):
    """丢弃一个草案文件。"""
    try:
        from backend.skills.draft_synthesizer import delete_draft
        if not delete_draft(name):
            raise HTTPException(status_code=404, detail=f"草案不存在: {name}")
        return {"status": "ok", "deleted": name}
    except HTTPException:
        raise
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


@router.get("/skills/{skill_id}/stats")
async def get_skill_stats(skill_id: str):
    """返回指定 skill 的执行学习统计（分场景成功率等）。"""
    try:
        from backend.skills.execution_learner import get_learner
        from backend.skills.registry import get_registry
        learner = get_learner()
        profile = learner.get_profile(skill_id)
        if not profile:
            registry = get_registry()
            skill = registry.get_by_id(skill_id)
            return {
                "skill_id": skill_id,
                "name": skill.name if skill else skill_id,
                "total_runs": 0,
                "success_rate": 0.0,
                "scene_breakdown": {},
                "fingerprint_breakdown": {},
                "path_stats": {},
                "message": "暂无执行记录",
            }
        return {
            "skill_id": profile.skill_id,
            "total_runs": profile.total_runs,
            "successful_runs": profile.successful_runs,
            "success_rate": profile.success_rate,
            "avg_elapsed": profile.avg_elapsed,
            "avg_commands": profile.avg_commands,
            "avg_probes": profile.avg_probes,
            "scene_breakdown": profile.scene_breakdown,
            "fingerprint_breakdown": profile.fingerprint_breakdown,
            "path_stats": profile.path_stats,
            "priority_adjustments": profile.priority_adjustments,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
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
