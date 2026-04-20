from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from backend.api.tenant_store import resolve_scope, upsert_asset, get_asset

router = APIRouter(tags=["prompts"])


_DEFAULT_PROMPTS = [
    {"id": "vuln", "name": "漏洞分析 Prompt", "version": "v1.4", "active": True, "content": "你是漏洞分析助手，请严格基于证据输出。"},
    {"id": "exploit", "name": "利用决策 Prompt", "version": "v1.7", "active": True, "content": "你是利用决策助手，优先输出可审计 payload。"},
    {"id": "report", "name": "报告生成 Prompt", "version": "v1.2", "active": True, "content": "你是安全报告助手，输出结构化修复建议。"},
]


@router.get("/prompts")
async def get_prompts(request: Request):
    owner_id, tenant_id = resolve_scope(request)
    payload = await get_asset(
        asset_type="prompt",
        asset_key="prompt.manage.v1",
        owner_id=owner_id,
        tenant_id=tenant_id,
    )
    if isinstance(payload, dict) and isinstance(payload.get("prompts"), list):
        return {"prompts": payload["prompts"], "source": "user_override"}
    return {"prompts": _DEFAULT_PROMPTS, "source": "global_template"}


@router.post("/prompts")
async def save_prompts(request: Request, data: dict):
    owner_id, tenant_id = resolve_scope(request)
    prompts = data.get("prompts")
    if not isinstance(prompts, list) or not prompts:
        raise HTTPException(status_code=400, detail="prompts 不能为空")
    for item in prompts:
        if not isinstance(item, dict) or not item.get("id"):
            raise HTTPException(status_code=400, detail="prompt 格式非法")
    await upsert_asset(
        asset_type="prompt",
        asset_key="prompt.manage.v1",
        layer="user_override",
        owner_id=owner_id,
        tenant_id=tenant_id,
        payload={"prompts": prompts},
    )
    return {"status": "ok", "count": len(prompts)}
