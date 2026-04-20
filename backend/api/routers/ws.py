"""
routers/ws.py —— WebSocket 实时推送

改造要点：
  1. 用 EventBus queue.get() 替代 150ms 轮询，延迟接近 0
  2. 添加 token 认证（从查询参数获取）
  3. 历史事件批量回放（一次 send_json 而非逐条）
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from backend.api.deps import decode_jwt
from backend.api.state import get_state_manager, TaskStateManager, TOOL_START_RE, TOOL_DONE_RE
from backend.api.event_bus import get_event_bus, TaskEventBus
from backend.agents.models import TaskStatus

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    # ── 认证：从查询参数获取 token ────────────────────────
    token = websocket.query_params.get("token", "")
    claims = decode_jwt(token) if token else None
    if not claims:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid token")
        logger.warning(f"[WS] rejected unauthenticated connection: task_id={task_id}")
        return

    sm = get_state_manager()
    bus = get_event_bus()
    owner_id = claims.get("sub", "")
    state = sm.get(task_id)
    if state is None and sm.db_available:
        try:
            from backend.db.database import load_task
            state = await load_task(task_id)
            if state:
                sm.set(task_id, state)
        except Exception:
            state = None
    if state is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="task not found")
        return
    if (state.owner_id or "") and (state.owner_id or "") != owner_id:
        logger.warning(
            f"[WS] blocked cross-owner subscribe: task={task_id}, owner={state.owner_id}, actor={owner_id}"
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="forbidden")
        return

    await websocket.accept()

    async def _send(payload: dict) -> bool:
        try:
            await websocket.send_json(payload)
            return True
        except Exception:
            return False

    async def _push_loop():
        # ── 批量回放历史 ──────────────────────────────────
        state = sm.get(task_id)
        if state:
            history_logs = list(state.phase_log)
            if history_logs:
                if not await _send({"type": "history_logs", "data": history_logs}):
                    return

            existing_events = sm.build_decision_events(state)
            for de in state.live_decision_events:
                existing_events.append(de)
            snapshot = existing_events[-120:] if len(existing_events) > 120 else existing_events
            if snapshot:
                if not await _send({"type": "history_events", "data": snapshot}):
                    return

        # 如果任务已结束，发送 done 后返回
        if state and state.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
            await _send({
                "type": "done",
                "status": state.status.value,
                "findings_count": len(state.findings),
                "got_shell": state.got_shell,
            })
            return

        # 如果任务等待审批，发送审批信号
        if state and state.current_phase == "awaiting_approval":
            await _send({
                "type": "approval_required",
                "phase": "awaiting_approval",
                "status": "running",
                "findings_count": len(state.findings),
                "exploitable_count": sum(1 for f in state.findings if f.exploitable),
                "got_shell": state.got_shell,
            })

        # ── 事件驱动推送 ──────────────────────────────────
        queue = bus.subscribe(task_id)
        heartbeat_counter = 0
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=3.0)
                    if not await _send(event):
                        return
                    heartbeat_counter = 0

                    # 检查是否是终结事件
                    etype = event.get("type", "")
                    if etype == "done":
                        return
                except asyncio.TimeoutError:
                    heartbeat_counter += 1
                    if heartbeat_counter >= 1:
                        if not await _send({"type": "heartbeat"}):
                            return
                        heartbeat_counter = 0
        finally:
            bus.unsubscribe(task_id, queue)

    async def _recv_loop():
        while True:
            try:
                data = await websocket.receive_text()
                if data == "ping":
                    if not await _send({"type": "pong"}):
                        break
            except Exception:
                break

    push_task = asyncio.create_task(_push_loop())
    recv_task = asyncio.create_task(_recv_loop())
    try:
        done, _pending = await asyncio.wait(
            [push_task, recv_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            try:
                task.result()
            except WebSocketDisconnect:
                pass
            except Exception:
                pass
    finally:
        for task in [push_task, recv_task]:
            if not task.done():
                task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
