from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import Request

from backend.api.state import get_state_manager

logger = logging.getLogger(__name__)

TENANT_FALLBACK_DIR = Path(".tenant_store")


def resolve_scope(request: Request) -> tuple[str, str]:
    owner_id = getattr(request.state, "user_id", "") or ""
    tenant_id = getattr(request.state, "tenant_id", "") or "default"
    return owner_id, tenant_id


def _fallback_file(asset_type: str, asset_key: str, owner_id: str, tenant_id: str) -> Path:
    return TENANT_FALLBACK_DIR / tenant_id / owner_id / asset_type / f"{asset_key}.json"


async def upsert_asset(
    *,
    asset_type: str,
    asset_key: str,
    layer: str,
    owner_id: str,
    tenant_id: str,
    payload: dict[str, Any],
) -> None:
    sm = get_state_manager()
    content = json.dumps(payload, ensure_ascii=False)
    if sm.db_available:
        from backend.db.database import append_audit_log, upsert_tenant_asset
        await upsert_tenant_asset(
            asset_type=asset_type,
            asset_key=asset_key,
            layer=layer,
            owner_id=owner_id,
            tenant_id=tenant_id,
            content=content,
        )
        await append_audit_log(
            owner_id=owner_id,
            tenant_id=tenant_id,
            action="asset_upsert",
            resource_type=asset_type,
            resource_key=asset_key,
            detail={"layer": layer},
        )
        return

    path = _fallback_file(asset_type, asset_key, owner_id, tenant_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


async def get_asset(
    *,
    asset_type: str,
    asset_key: str,
    owner_id: str,
    tenant_id: str,
) -> dict[str, Any] | None:
    sm = get_state_manager()
    if sm.db_available:
        from backend.db.database import get_tenant_asset_resolved
        row = await get_tenant_asset_resolved(
            asset_type=asset_type,
            asset_key=asset_key,
            owner_id=owner_id,
            tenant_id=tenant_id,
        )
        if not row:
            return None
        try:
            return json.loads(row.content or "{}")
        except Exception:
            return {}

    path = _fallback_file(asset_type, asset_key, owner_id, tenant_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


async def list_assets(
    *,
    asset_type: str,
    owner_id: str,
    tenant_id: str,
) -> list[dict[str, Any]]:
    sm = get_state_manager()
    if sm.db_available:
        from backend.db.database import list_tenant_assets
        rows = await list_tenant_assets(asset_type=asset_type, owner_id=owner_id, tenant_id=tenant_id)
        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row.content or "{}")
            except Exception:
                payload = {}
            payload.setdefault("_asset_key", row.asset_key)
            payload.setdefault("_layer", row.layer)
            out.append(payload)
        return out

    root = TENANT_FALLBACK_DIR / tenant_id / owner_id / asset_type
    if not root.exists():
        return []
    out: list[dict[str, Any]] = []
    for p in root.glob("*.json"):
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        payload.setdefault("_asset_key", p.stem)
        payload.setdefault("_layer", "user_override")
        out.append(payload)
    return out
