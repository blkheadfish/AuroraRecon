"""interrupt_registry.py — 进程内的协作式中断注册表。

设计目的:
    HTTP 协程(``send_chat_message`` / branch fork / activate)需要把"操作员
    意图"广播给后台正在运行的 LangGraph 节点 / ReAct 循环, 但 PentestState
    的内存对象在不同协程间不共享(LangGraph 节点拿到的是 checkpoint
    回放出来的 state 副本)。所以这里用一个进程级的轻量 dict 作为信号
    通道:
      - HTTP handler 调 ``request_interrupt(task_id, reason, payload)``;
      - 每个 LangGraph 节点入口、ReAct 每轮开头调 ``check_interrupt(task_id)``;
        命中则写一条 decision_event 并提前返回, 控制权回到 supervisor;
      - supervisor 路由完成后调 ``consume_interrupt(task_id)`` 一次, 防止
        信号被重复消费成死循环。

重要: 这是进程内 registry。多实例部署时换成 Redis pub/sub 即可,接口
不变。当前 StateManager 也是进程内持有 state, 与之同构。
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


async def _save_interrupt_to_db(
    task_id: str, reason: str, payload: dict, requested_at: str, count: int,
) -> None:
    try:
        from backend.db.database import save_interrupt
        await save_interrupt(
            task_id=task_id,
            reason=reason,
            payload_json=json.dumps(payload, ensure_ascii=False),
            requested_at=requested_at,
            count=count,
        )
    except Exception:
        logger.debug("[InterruptRegistry] DB save skipped", exc_info=True)


async def _delete_interrupt_from_db(task_id: str) -> None:
    try:
        from backend.db.database import delete_interrupt_from_db
        await delete_interrupt_from_db(task_id)
    except Exception:
        logger.debug("[InterruptRegistry] DB delete skipped", exc_info=True)


async def load_from_db() -> dict[str, dict[str, Any]]:
    """启动时从 PostgreSQL 恢复所有中断信号到内存。"""
    try:
        from backend.db.database import load_all_interrupts
        rows = await load_all_interrupts()
    except Exception as e:
        logger.warning(f"[InterruptRegistry] 从DB加载中断失败: {e}")
        return {}
    restored: dict[str, dict[str, Any]] = {}
    for row in rows:
        tid = row["task_id"]
        payload = {}
        try:
            payload = json.loads(row.get("payload_json", "{}"))
        except Exception:
            pass
        restored[tid] = {
            "task_id": tid,
            "reason": row.get("reason", ""),
            "payload": payload,
            "requested_at": row.get("requested_at", ""),
            "count": int(row.get("count", 1)),
        }
    if restored:
        with _lock:
            for tid, entry in restored.items():
                existing = _interrupts.get(tid)
                if existing and int(existing.get("count", 0)) >= entry["count"]:
                    continue
                _interrupts[tid] = entry
        logger.info(f"[InterruptRegistry] 从DB恢复 {len(restored)} 个中断信号")
    return restored


class OperatorInterrupt(Exception):
    """Raised inside deeply-nested call stacks (e.g. LLM streaming callbacks)
    to unwind back to a place that can write a decision event and return the
    state cleanly. Most callers should *not* raise this directly — prefer the
    cooperative ``check_interrupt`` polling pattern instead."""

    def __init__(self, task_id: str, reason: str, payload: Optional[dict] = None):
        super().__init__(f"OperatorInterrupt(task={task_id}, reason={reason})")
        self.task_id = task_id
        self.reason = reason
        self.payload = payload or {}


_lock = threading.Lock()
_interrupts: dict[str, dict[str, Any]] = {}


def request_interrupt(
    task_id: str,
    reason: str,
    payload: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Register a pending interrupt for ``task_id``.

    Multiple calls before the next ``consume_interrupt`` are coalesced — only
    the latest reason/payload is kept, but the per-task counter is bumped so
    that observers can detect repeated taps. This is the typical fire-and-
    forget HTTP path::

        request_interrupt(task_id, reason="operator_chat", payload={"text": "..."})

    Returns the stored entry (after coalescing).
    """
    if not task_id:
        raise ValueError("task_id is required")
    now = datetime.utcnow().isoformat()
    with _lock:
        existing = _interrupts.get(task_id) or {}
        entry = {
            "task_id": task_id,
            "reason": reason or "unknown",
            "payload": dict(payload or {}),
            "requested_at": now,
            "count": int(existing.get("count", 0)) + 1,
        }
        _interrupts[task_id] = entry
    logger.info(
        "[InterruptRegistry] request_interrupt task=%s reason=%s count=%d",
        task_id, entry["reason"], entry["count"],
    )
    # Fire-and-forget persist to PostgreSQL
    if _db_enabled:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_save_interrupt_to_db(
                    task_id=task_id, reason=entry["reason"],
                    payload=entry["payload"],
                    requested_at=entry["requested_at"],
                    count=entry["count"],
                ))
        except RuntimeError:
            pass
    return dict(entry)


def check_interrupt(task_id: str) -> Optional[dict[str, Any]]:
    """Read the pending interrupt for ``task_id`` *without* consuming it.

    Cheap polling primitive used inside ReAct loops and at LangGraph node
    entry points. Returns ``None`` when no interrupt is pending.
    """
    if not task_id:
        return None
    with _lock:
        entry = _interrupts.get(task_id)
        return dict(entry) if entry else None


def consume_interrupt(task_id: str) -> Optional[dict[str, Any]]:
    """Atomically read and clear the interrupt for ``task_id``.

    Called by the supervisor (or branch_manager) after it has acknowledged
    the operator intent and emitted a routing decision, so subsequent rounds
    don't keep re-routing on the stale signal.
    """
    if not task_id:
        return None
    with _lock:
        entry = _interrupts.pop(task_id, None)
    if entry:
        logger.info(
            "[InterruptRegistry] consume_interrupt task=%s reason=%s",
            task_id, entry.get("reason", ""),
        )
        # Fire-and-forget delete from PostgreSQL
        if _db_enabled:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(_delete_interrupt_from_db(task_id))
            except RuntimeError:
                pass
        return dict(entry)
    return None


def clear_interrupt(task_id: str) -> bool:
    """Force-clear without returning the entry. Returns whether something was cleared."""
    if not task_id:
        return False
    with _lock:
        return _interrupts.pop(task_id, None) is not None


def snapshot() -> dict[str, dict[str, Any]]:
    """Return a deep-ish copy of all current interrupts (debug / tests)."""
    with _lock:
        return {k: dict(v) for k, v in _interrupts.items()}


def reset_all() -> None:
    """Clear the entire registry. Mainly for tests."""
    with _lock:
        _interrupts.clear()
