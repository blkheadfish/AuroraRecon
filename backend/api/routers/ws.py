"""
routers/ws.py —— WebSocket 实时推送

改造要点：
  1. 用 EventBus queue.get() 替代 150ms 轮询，延迟接近 0
  2. 添加 token 认证（从查询参数获取）
  3. 历史事件批量回放（一次 send_json 而非逐条）
  4. 历史回放有界:phase_log 默认最多回放最近 N 条,客户端通过
     ``?after_log_seq=K`` 仅请求缺失的增量,避免长任务每次重连都重传
     上 MB 历史日志把页面打卡。
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

# 建连首包默认回放的最近日志条数。任务超过该量级的历史日志走
# /tasks/{id}/logs 的分页接口按需拉取,避免单帧回放数 MB 文本。
WS_DEFAULT_HISTORY_LOG_TAIL = 200
WS_MAX_HISTORY_LOG_TAIL = 5000
WS_HISTORY_DECISION_TAIL = 120


@router.websocket("/ws/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    # ── 认证：从查询参数获取 token ────────────────────────
    token = websocket.query_params.get("token", "")
    claims = decode_jwt(token) if token else None
    if not claims:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid token")
        logger.warning(f"[WS] rejected unauthenticated connection: task_id={task_id}")
        return

    # ── 客户端可选参数 ─────────────────────────────────
    # after_log_seq=K → 只回放 index > K 的 phase_log(增量重连)
    # log_tail=N      → 不传 after_log_seq 时,首包回放最近 N 条
    try:
        after_log_seq = int(websocket.query_params.get("after_log_seq", "-1"))
    except (TypeError, ValueError):
        after_log_seq = -1
    try:
        log_tail_param = int(websocket.query_params.get("log_tail", str(WS_DEFAULT_HISTORY_LOG_TAIL)))
    except (TypeError, ValueError):
        log_tail_param = WS_DEFAULT_HISTORY_LOG_TAIL
    log_tail_param = max(0, min(log_tail_param, WS_MAX_HISTORY_LOG_TAIL))

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
        # ── 批量回放历史(有界) ─────────────────────────
        state = sm.get(task_id)
        if state:
            log_total = len(state.phase_log or [])
            if after_log_seq >= 0:
                # 增量回放:只补客户端缺失的部分
                start_idx = max(0, after_log_seq)
            else:
                # 首次连接:仅回放最近 log_tail_param 条
                start_idx = max(0, log_total - log_tail_param)

            history_logs = state.phase_log[start_idx:log_total] if log_total > start_idx else []

            # 先发 history_meta,前端可据此决定是否再走分页接口拉更早历史
            if not await _send({
                "type": "history_meta",
                "phase_log_total": log_total,
                "phase_log_start": start_idx,
                "phase_log_replayed": len(history_logs),
            }):
                return

            if history_logs:
                if not await _send({
                    "type": "history_logs",
                    "data": history_logs,
                    "start_seq": start_idx,
                    "next_seq": start_idx + len(history_logs),
                    "total": log_total,
                }):
                    return

            existing_events = sm.build_decision_events(state)
            for de in state.live_decision_events:
                existing_events.append(de)
            snapshot = (
                existing_events[-WS_HISTORY_DECISION_TAIL:]
                if len(existing_events) > WS_HISTORY_DECISION_TAIL
                else existing_events
            )
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
        if state and state.current_phase in ("awaiting_approval", "post_foothold_approval"):
            await _send({
                "type": "approval_required",
                "phase": state.current_phase,
                "status": "running",
                "findings_count": len(state.findings),
                "exploitable_count": sum(1 for f in state.findings if f.exploitable),
                "got_shell": state.got_shell,
            })

        # 如果存在 pending checkpoint(Plan 风格确认),把它作为 decision_event 重放,
        # 让前端确认卡片在重连后立刻可见,而不必等待新的事件流。
        if state and state.pending_checkpoint:
            cp = dict(state.pending_checkpoint)
            await _send({
                "type": "decision_event",
                "data": {
                    "id": f"checkpoint-replay-{cp.get('checkpoint_id', '')}",
                    "timestamp": cp.get("created_at", ""),
                    "phase": cp.get("phase", state.current_phase),
                    "action": "checkpoint_request",
                    "checkpoint_id": cp.get("checkpoint_id", ""),
                    "checkpoint_type": cp.get("checkpoint_type", "generic"),
                    "thinking": cp.get("thinking", ""),
                    "summary": cp.get("summary", ""),
                    "recommendation": cp.get("recommendation", ""),
                    "risk": cp.get("risk", ""),
                    "options": cp.get("options", []),
                    "requires_input": cp.get("requires_input", True),
                    "default_action": cp.get("default_action", "approve"),
                    "context": cp.get("context", {}),
                    "message": cp.get("summary") or cp.get("recommendation") or "等待人工确认",
                    "tone": "warning",
                    "replay": True,
                },
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
