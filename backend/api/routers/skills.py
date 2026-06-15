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


# ── Skill 目录树与文件读写 ─────────────────────────────────

def _skill_source_dir(skill_id: str) -> Path | None:
    """根据 skill_id 反查 skill 所在的目录路径。"""
    from backend.skills.registry import get_registry
    registry = get_registry()
    skill = registry.get_by_id(skill_id)
    if not skill or not skill.source_file:
        return None
    source = Path(skill.source_file)
    if not source.exists():
        return None
    return source.parent if source.is_file() else source


def _build_file_tree(dir_path: Path, rel: str = "") -> list[dict]:
    """递归构建目录树，只包含文本类文件。"""
    entries: list[dict] = []
    try:
        items = sorted(dir_path.iterdir(), key=lambda p: (p.is_file(), p.name))
    except PermissionError:
        return entries
    for p in items:
        if p.name.startswith(".") or p.name == "__pycache__":
            continue
        rp = f"{rel}/{p.name}" if rel else p.name
        if p.is_dir():
            children = _build_file_tree(p, rp)
            if children or not any(True for _ in p.iterdir()):
                entries.append({
                    "name": p.name,
                    "type": "directory",
                    "path": rp,
                    "children": children,
                })
        elif p.is_file():
            ext = p.suffix.lower()
            if ext in (".yaml", ".yml", ".md", ".py", ".txt", ".json", ".xml",
                       ".sh", ".bat", ".ps1", ".cfg", ".ini", ".toml", ".conf",
                       ".html", ".css", ".js", ".ts", ""):
                try:
                    size = p.stat().st_size
                except OSError:
                    size = 0
                entries.append({
                    "name": p.name,
                    "type": "file",
                    "path": rp,
                    "ext": ext,
                    "size": size,
                })
    return entries


@router.get("/skills/{skill_id}/tree")
async def get_skill_tree(skill_id: str):
    """返回 skill 目录的文件树。"""
    dir_path = _skill_source_dir(skill_id)
    if not dir_path:
        raise HTTPException(status_code=404, detail=f"Skill 目录不存在: {skill_id}")
    return {
        "skill_id": skill_id,
        "root": dir_path.name,
        "tree": _build_file_tree(dir_path),
    }


@router.get("/skills/{skill_id}/file")
async def get_skill_file(skill_id: str, path: str = ""):
    """读取 skill 目录下指定文件的内容（相对路径）。"""
    dir_path = _skill_source_dir(skill_id)
    if not dir_path:
        raise HTTPException(status_code=404, detail=f"Skill 目录不存在: {skill_id}")
    file_path = (dir_path / path).resolve()
    if not str(file_path).startswith(str(dir_path.resolve())):
        raise HTTPException(status_code=403, detail="路径越界")
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail=f"文件不存在: {path}")
    return {
        "skill_id": skill_id,
        "path": path,
        "filename": file_path.name,
        "content": file_path.read_text(encoding="utf-8"),
    }


@router.put("/skills/{skill_id}/file")
async def update_skill_file(skill_id: str, path: str = "", req: SkillRawUpdateRequest = None):
    """写入 skill 目录下指定文件（相对路径）。仅允许文本文件。"""
    content = req.yaml if req else ""
    dir_path = _skill_source_dir(skill_id)
    if not dir_path:
        raise HTTPException(status_code=404, detail=f"Skill 目录不存在: {skill_id}")
    file_path = (dir_path / path).resolve()
    if not str(file_path).startswith(str(dir_path.resolve())):
        raise HTTPException(status_code=403, detail="路径越界")
    ext = file_path.suffix.lower()
    allowed = {".yaml", ".yml", ".md", ".py", ".txt", ".json", ".xml",
               ".sh", ".bat", ".ps1", ".cfg", ".ini", ".toml", ".conf",
               ".html", ".css", ".js", ".ts"}
    if ext not in allowed:
        raise HTTPException(status_code=400, detail=f"不支持的文件类型: {ext}")
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    return {"status": "ok", "skill_id": skill_id, "path": path}
