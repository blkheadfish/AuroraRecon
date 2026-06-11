"""abort_registry.py — 进程内统一急停注册表。

参照 interrupt_registry.py 的进程内 dict + threading.Lock + DB 持久化模式。
abort 优先级最高，先于 scope/dangerous — 无人值守下必须有即时叫停能力。
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)

_db_enabled: bool = False


def set_db_enabled(v: bool) -> None:
    global _db_enabled
    _db_enabled = v


async def _save_abort_to_db(task_id: str, reason: str, requested_at: str) -> None:
    try:
        from backend.db.database import save_abort
        await save_abort(
            task_id=task_id,
            reason=reason,
            requested_at=requested_at,
        )
    except Exception:
        logger.debug("[AbortRegistry] DB save skipped", exc_info=True)


async def _delete_abort_from_db(task_id: str) -> None:
    try:
        from backend.db.database import delete_abort
        await delete_abort(task_id)
    except Exception:
        logger.debug("[AbortRegistry] DB delete skipped", exc_info=True)


async def load_from_db() -> dict[str, dict[str, Any]]:
    try:
        from backend.db.database import load_all_aborts
        rows = await load_all_aborts()
    except Exception as e:
        logger.warning(f"[AbortRegistry] 从DB加载abort信号失败: {e}")
        return {}
    restored: dict[str, dict[str, Any]] = {}
    for row in rows:
        tid = row["task_id"]
        restored[tid] = {
            "task_id": tid,
            "reason": row.get("reason", ""),
            "requested_at": row.get("requested_at", ""),
        }
    if restored:
        with _lock:
            for tid, entry in restored.items():
                _aborts[tid] = entry
        logger.info(f"[AbortRegistry] 从DB恢复 {len(restored)} 个 abort 信号")
    return restored


_lock = threading.Lock()
_aborts: dict[str, dict[str, Any]] = {}


def request_abort(task_id: str, reason: str = "") -> dict[str, Any]:
    if not task_id:
        raise ValueError("task_id is required")
    now = datetime.utcnow().isoformat()
    with _lock:
        entry = {
            "task_id": task_id,
            "reason": reason or "manual_abort",
            "requested_at": now,
        }
        _aborts[task_id] = entry
    logger.info("[AbortRegistry] request_abort task=%s reason=%s", task_id, entry["reason"])
    if _db_enabled:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_save_abort_to_db(
                    task_id=task_id, reason=entry["reason"],
                    requested_at=entry["requested_at"],
                ))
        except RuntimeError:
            pass
    return dict(entry)


def check_abort(task_id: str) -> bool:
    if not task_id:
        return False
    with _lock:
        return task_id in _aborts


def clear_abort(task_id: str) -> bool:
    if not task_id:
        return False
    with _lock:
        existed = task_id in _aborts
        _aborts.pop(task_id, None)
    if existed:
        if _db_enabled:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(_delete_abort_from_db(task_id))
            except RuntimeError:
                pass
    return existed


def snapshot() -> dict[str, dict[str, Any]]:
    with _lock:
        return {k: dict(v) for k, v in _aborts.items()}


def reset_all() -> None:
    with _lock:
        _aborts.clear()
