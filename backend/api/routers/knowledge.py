"""
routers/knowledge.py —— 知识库管理
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException

from backend.api.schemas import (
    KnowledgeSourceCreateRequest,
    KnowledgeBuildRequest,
    KnowledgeSourceSaveRequest,
    KnowledgeSourceUrlRequest,
    KnowledgeRawRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["knowledge"])

KB_SOURCES_FILE = Path(os.getenv("REPORTS_DIR", "/tmp/pentest_reports")) / "kb_sources.json"


# ── 辅助函数 ──────────────────────────────────────────────

def _load_custom_kb_sources() -> list[dict]:
    if not KB_SOURCES_FILE.exists():
        return []
    try:
        raw = json.loads(KB_SOURCES_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
    except Exception:
        pass
    return []


def _save_custom_kb_sources(items: list[dict]) -> None:
    KB_SOURCES_FILE.parent.mkdir(parents=True, exist_ok=True)
    KB_SOURCES_FILE.write_text(
        json.dumps(items, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _collect_kb_sources():
    from backend.knowledge.builder import VulnSource, VULN_SOURCES

    merged: dict[str, VulnSource] = {src.vuln_id: src for src in VULN_SOURCES}
    custom_rows = _load_custom_kb_sources()
    for row in custom_rows:
        vuln_id = str(row.get("vuln_id") or "").strip()
        if not vuln_id:
            continue
        urls = row.get("urls") or []
        if not isinstance(urls, list):
            urls = []
        merged[vuln_id] = VulnSource(
            vuln_id=vuln_id,
            name=str(row.get("name") or vuln_id),
            urls=[str(u).strip() for u in urls if str(u).strip()],
            extra_context=str(row.get("extra_context") or ""),
            fallback_content=str(row.get("fallback_content") or ""),
        )
    return list(merged.values()), custom_rows


def _get_source_for_vuln(vuln_id: str) -> dict:
    from backend.knowledge.builder import VulnSource, VULN_SOURCES

    kb_dir = Path(__file__).resolve().parents[2] / "knowledge" / "kb_data"
    builtin_map: dict[str, VulnSource] = {s.vuln_id: s for s in VULN_SOURCES}
    custom_rows = _load_custom_kb_sources()
    custom_map: dict[str, dict] = {}
    for row in custom_rows:
        vid = str(row.get("vuln_id") or "").strip()
        if vid:
            custom_map[vid] = row

    custom = custom_map.get(vuln_id)
    builtin = builtin_map.get(vuln_id)

    if custom:
        urls = custom.get("urls") or []
        return {
            "vuln_id": vuln_id,
            "name": custom.get("name") or vuln_id,
            "urls": urls if isinstance(urls, list) else [],
            "extra_context": str(custom.get("extra_context") or ""),
            "fallback_content": str(custom.get("fallback_content") or ""),
            "is_custom": True,
            "built": (kb_dir / f"{vuln_id}.json").exists(),
        }
    elif builtin:
        return {
            "vuln_id": vuln_id,
            "name": builtin.name,
            "urls": builtin.urls,
            "extra_context": builtin.extra_context,
            "fallback_content": builtin.fallback_content,
            "is_custom": False,
            "built": (kb_dir / f"{vuln_id}.json").exists(),
        }
    else:
        return {
            "vuln_id": vuln_id,
            "name": vuln_id,
            "urls": [],
            "extra_context": "",
            "fallback_content": "",
            "is_custom": False,
            "built": (kb_dir / f"{vuln_id}.json").exists(),
        }


def _upsert_custom_source(vuln_id: str, data: dict) -> None:
    custom_rows = _load_custom_kb_sources()
    replaced = False
    for idx, row in enumerate(custom_rows):
        if str(row.get("vuln_id") or "").strip() == vuln_id:
            custom_rows[idx] = data
            replaced = True
            break
    if not replaced:
        custom_rows.append(data)
    _save_custom_kb_sources(custom_rows)


# ── 知识库条目列表 ────────────────────────────────────────

@router.get("/knowledge/entries")
@router.get("/api/knowledge/entries")
async def list_knowledge_entries():
    from backend.knowledge.exploit_kb import ExploitKB
    kb = ExploitKB()
    entries = []
    for entry in kb.list_all():
        entries.append({
            "vuln_id": entry.vuln_id,
            "description": entry.description[:120] if entry.description else "",
            "category": entry.category,
            "cves": entry.match_cves,
            "tags": entry.tags,
            "default_port": entry.default_port,
        })
    entries.sort(key=lambda e: (e["category"], e["vuln_id"]))
    return {"entries": entries, "total": len(entries)}


# ── 知识源 CRUD ───────────────────────────────────────────

@router.get("/knowledge/sources")
@router.get("/api/knowledge/sources")
async def list_knowledge_sources():
    kb_dir = Path(__file__).resolve().parents[2] / "knowledge" / "kb_data"
    sources, custom_rows = _collect_kb_sources()
    custom_ids = {
        str(item.get("vuln_id") or "").strip()
        for item in custom_rows
        if str(item.get("vuln_id") or "").strip()
    }
    rows = []
    for source in sorted(sources, key=lambda s: s.vuln_id):
        target = kb_dir / f"{source.vuln_id}.json"
        rows.append({
            "vuln_id": source.vuln_id,
            "name": source.name,
            "urls": source.urls,
            "url_count": len(source.urls),
            "extra_context": source.extra_context,
            "has_fallback": bool(source.fallback_content),
            "is_custom": source.vuln_id in custom_ids,
            "built": target.exists(),
        })
    return {"sources": rows, "total": len(rows)}


@router.post("/knowledge/sources")
@router.post("/api/knowledge/sources")
async def add_knowledge_source(req: KnowledgeSourceCreateRequest):
    urls = [str(u).strip() for u in (req.urls or []) if str(u).strip()]
    if not urls and not req.extra_context.strip() and not req.fallback_content.strip():
        raise HTTPException(400, "至少提供一个 URL，或填写额外上下文/兜底内容")
    for u in urls:
        if not re.match(r"^https?://", u, flags=re.IGNORECASE):
            raise HTTPException(400, f"URL 非法: {u}")

    custom_rows = _load_custom_kb_sources()
    upsert = {
        "vuln_id": req.vuln_id,
        "name": req.name,
        "urls": urls,
        "extra_context": req.extra_context.strip(),
        "fallback_content": req.fallback_content.strip(),
    }
    replaced = False
    for idx, row in enumerate(custom_rows):
        if str(row.get("vuln_id") or "").strip() == req.vuln_id:
            custom_rows[idx] = upsert
            replaced = True
            break
    if not replaced:
        custom_rows.append(upsert)
    _save_custom_kb_sources(custom_rows)
    return {"status": "saved", "source": upsert}


# ── 单条知识来源 CRUD ─────────────────────────────────────

@router.get("/knowledge/{vuln_id}/sources")
@router.get("/api/knowledge/{vuln_id}/sources")
async def get_knowledge_entry_source(vuln_id: str):
    return _get_source_for_vuln(vuln_id)


@router.put("/knowledge/{vuln_id}/sources")
@router.put("/api/knowledge/{vuln_id}/sources")
async def save_knowledge_entry_source(vuln_id: str, req: KnowledgeSourceSaveRequest):
    urls = [str(u).strip() for u in (req.urls or []) if str(u).strip()]
    for u in urls:
        if not re.match(r"^https?://", u, flags=re.IGNORECASE):
            raise HTTPException(400, f"URL 非法: {u}")

    current = _get_source_for_vuln(vuln_id)
    data = {
        "vuln_id": vuln_id,
        "name": req.name.strip() or current.get("name") or vuln_id,
        "urls": urls,
        "extra_context": req.extra_context.strip(),
        "fallback_content": req.fallback_content.strip(),
    }
    _upsert_custom_source(vuln_id, data)
    return {"status": "saved", "source": data}


@router.post("/knowledge/{vuln_id}/sources/url")
@router.post("/api/knowledge/{vuln_id}/sources/url")
async def add_knowledge_source_url(vuln_id: str, req: KnowledgeSourceUrlRequest):
    url = req.url.strip()
    if not url or not re.match(r"^https?://", url, flags=re.IGNORECASE):
        raise HTTPException(400, "URL 必须以 http:// 或 https:// 开头")

    current = _get_source_for_vuln(vuln_id)
    urls = list(current.get("urls") or [])
    if url not in urls:
        urls.append(url)

    data = {
        "vuln_id": vuln_id,
        "name": current.get("name") or vuln_id,
        "urls": urls,
        "extra_context": current.get("extra_context") or "",
        "fallback_content": current.get("fallback_content") or "",
    }
    _upsert_custom_source(vuln_id, data)
    return {"status": "added", "url": url, "urls": urls}


@router.delete("/knowledge/{vuln_id}/sources/url")
@router.delete("/api/knowledge/{vuln_id}/sources/url")
async def remove_knowledge_source_url(vuln_id: str, req: KnowledgeSourceUrlRequest):
    url = req.url.strip()
    current = _get_source_for_vuln(vuln_id)
    urls = [u for u in (current.get("urls") or []) if u != url]

    data = {
        "vuln_id": vuln_id,
        "name": current.get("name") or vuln_id,
        "urls": urls,
        "extra_context": current.get("extra_context") or "",
        "fallback_content": current.get("fallback_content") or "",
    }
    _upsert_custom_source(vuln_id, data)
    return {"status": "removed", "url": url, "urls": urls}


@router.post("/knowledge/sources/new")
@router.post("/api/knowledge/sources/new")
async def create_knowledge_source(req: KnowledgeSourceCreateRequest):
    from backend.knowledge.builder import VULN_SOURCES

    builtin_ids = {s.vuln_id for s in VULN_SOURCES}
    custom_rows = _load_custom_kb_sources()
    custom_ids = {str(r.get("vuln_id") or "").strip() for r in custom_rows}

    if req.vuln_id in builtin_ids or req.vuln_id in custom_ids:
        raise HTTPException(409, f"vuln_id '{req.vuln_id}' 已存在")

    urls = [str(u).strip() for u in (req.urls or []) if str(u).strip()]
    for u in urls:
        if not re.match(r"^https?://", u, flags=re.IGNORECASE):
            raise HTTPException(400, f"URL 非法: {u}")

    data = {
        "vuln_id": req.vuln_id,
        "name": req.name,
        "urls": urls,
        "extra_context": req.extra_context.strip(),
        "fallback_content": req.fallback_content.strip(),
    }
    custom_rows.append(data)
    _save_custom_kb_sources(custom_rows)
    return {"status": "created", "source": data}


# ── 构建 ──────────────────────────────────────────────────

@router.post("/knowledge/build")
@router.post("/api/knowledge/build")
async def build_knowledge(req: KnowledgeBuildRequest | None = None):
    if not os.getenv("LLM_API_KEY", "").strip():
        raise HTTPException(400, "未配置 LLM_API_KEY，请先在系统设置中填写并保存")

    from backend.knowledge.builder import build_all, build_one

    sources, _ = _collect_kb_sources()
    source_map = {src.vuln_id: src for src in sources}

    target_vuln = (req.vuln_id or "").strip() if req else ""
    if target_vuln:
        source = source_map.get(target_vuln)
        if not source:
            raise HTTPException(404, f"未找到知识源: {target_vuln}")
        ok = await build_one(source)
        return {
            "status": "ok" if ok else "failed",
            "mode": "single",
            "vuln_id": target_vuln,
            "success": int(ok),
            "failed": int(not ok),
        }

    results = await build_all(sources=sources)
    success = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    return {
        "status": "ok",
        "mode": "all",
        "total": len(results),
        "success": success,
        "failed": failed,
        "results": results,
    }


@router.post("/knowledge/{vuln_id}/build")
@router.post("/api/knowledge/{vuln_id}/build")
async def build_one_knowledge(vuln_id: str):
    return await build_knowledge(KnowledgeBuildRequest(vuln_id=vuln_id))


# ── 原始 JSON 读写 ────────────────────────────────────────

@router.get("/knowledge/{vuln_id}/raw")
@router.get("/api/knowledge/{vuln_id}/raw")
async def get_knowledge_raw(vuln_id: str):
    kb_dir = Path(__file__).resolve().parents[2] / "knowledge" / "kb_data"
    target = kb_dir / f"{vuln_id}.json"
    if not target.exists() or not str(target.resolve()).startswith(str(kb_dir.resolve())):
        raise HTTPException(404, f"知识条目 {vuln_id} 不存在")
    raw = target.read_text(encoding="utf-8")
    return {"vuln_id": vuln_id, "source": str(target.name), "json": raw}


@router.put("/knowledge/{vuln_id}/raw")
@router.put("/api/knowledge/{vuln_id}/raw")
async def save_knowledge_raw(vuln_id: str, req: KnowledgeRawRequest):
    kb_dir = Path(__file__).resolve().parents[2] / "knowledge" / "kb_data"
    target = kb_dir / f"{vuln_id}.json"
    if not str(target.resolve()).startswith(str(kb_dir.resolve())):
        raise HTTPException(400, "非法路径")
    try:
        parsed = json.loads(req.json_content)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"JSON 解析失败: {e}")
    if parsed.get("vuln_id") != vuln_id:
        raise HTTPException(400, f"vuln_id 不匹配: 期望 {vuln_id}")
    target.write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"status": "saved", "vuln_id": vuln_id}


@router.post("/knowledge/reload")
@router.post("/api/knowledge/reload")
async def reload_knowledge():
    from backend.knowledge.exploit_kb import ExploitKB
    kb = ExploitKB()
    return {"status": "reloaded", "total": kb.size}
