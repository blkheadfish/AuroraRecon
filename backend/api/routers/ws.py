"""routers/ws.py —— WebSocket 实时推送 (协议 v2, 基于 Redis Stream)

握手流程:
    1. 立即 ``accept()`` -- 不在 accept 之前做任何阻塞操作 (DB load 等放后面)
    2. 鉴权: 失败发 ``{type:"error",code:"auth"}`` 后 close 1008
    3. 任务校验: 找不到 / 跨 owner 发 ``{type:"error"}`` 后 close 1008
    4. 历史回放: ``event_stream.replay(after_id, count=1000)``
    5. 订阅: ``event_stream.subscribe(last_id)`` 直到客户端断开

客户端参数:
    * ``token``     : JWT, 必填
    * ``after_id``  : 上次断线时已经收到的最后 event id (Redis Stream ID), 协议 v2
    * ``log_tail``  : (legacy / 兼容) 首次连接想要回放最近多少条事件
                       (上限 1000)。

服务端推送的事件就是 Stream envelope, 不再做二次包装:

.. code-block:: json

    {
      "id": "1735689600123-0",
      "task_id": "task-xxx",
      "branch_id": "b-xxx",
      "ts": "2026-04-30T12:00:00.123456",
      "type": "log | decision_event | phase_update | ...",
      "v": 2,
      "payload": { ... }
    }

控制帧 (非业务事件) 仍然由后端在 WS 层注入:
    * ``{type:"hello", protocol_version:2, replay_count, has_more}``
      首包发送, 让前端知道协议版本与已回放条数。
    * ``{type:"heartbeat"}``
      服务端在 25s 内没有任何业务事件时主动推送, 让浏览器/中间盒维持连接。
    * ``{type:"pong"}``
      响应客户端 ``ping``。
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from backend.api import event_stream
from backend.api.deps import decode_jwt
from backend.api.state import get_state_manager
from backend.agents.models import TaskStatus

logger = logging.getLogger(__name__)

router = APIRouter()

WS_HISTORY_DEFAULT = 1000
WS_HISTORY_MAX = 5000
WS_HISTORY_CHUNK = 200


@router.websocket("/ws/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    await websocket.accept()

    async def _send(payload: dict) -> bool:
        try:
            await websocket.send_json(payload)
            return True
        except Exception:
            return False

    async def _send_error_and_close(code: str, message: str, ws_code: int) -> None:
        await _send({"type": "error", "code": code, "message": message})
        try:
            await websocket.close(code=ws_code, reason=message[:120])
        except Exception:
            pass

    token = websocket.query_params.get("token", "")
    claims = decode_jwt(token) if token else None
    if not claims:
        logger.warning(f"[WS] 未授权连接: task_id={task_id}")
        await _send_error_and_close(
            "auth",
            "token invalid or expired",
            status.WS_1008_POLICY_VIOLATION,
        )
        return

    owner_id = claims.get("sub", "") or ""

    raw_after_id = websocket.query_params.get("after_id", "")
    after_id = (raw_after_id or "").strip()
    try:
        log_tail_param = int(websocket.query_params.get("log_tail", str(WS_HISTORY_DEFAULT)))
    except (TypeError, ValueError):
        log_tail_param = WS_HISTORY_DEFAULT
    log_tail_param = max(1, min(log_tail_param, WS_HISTORY_MAX))

    sm = get_state_manager()
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
        await _send_error_and_close(
            "not_found",
            f"task {task_id} not found",
            status.WS_1008_POLICY_VIOLATION,
        )
        return
    if (state.owner_id or "") and (state.owner_id or "") != owner_id:
        logger.warning(
            f"[WS] 跨 owner 拒绝: task={task_id}, owner={state.owner_id}, actor={owner_id}"
        )
        await _send_error_and_close(
            "forbidden",
            "task owned by another user",
            status.WS_1008_POLICY_VIOLATION,
        )
        return

    history: list[dict] = []
    if after_id:
        try:
            history = await event_stream.replay(
                task_id, after_id=after_id, count=WS_HISTORY_MAX,
            )
        except Exception as exc:
            logger.warning(f"[WS] replay(after_id={after_id}) 失败: {exc}")
            history = []
    else:
        try:
            history = await event_stream.replay_tail(task_id, count=log_tail_param)
        except Exception as exc:
            logger.warning(f"[WS] replay_tail(initial) 失败: {exc}")
            history = []

    last_id = history[-1]["id"] if history else (after_id or "$")

    if not await _send({
        "type": "hello",
        "protocol_version": 2,
        "task_id": task_id,
        "replay_count": len(history),
        "after_id": after_id or "",
        "stream_redis_backed": event_stream.is_redis_backed(),
    }):
        return

    if history:
        overall_first = history[0]["id"]
        overall_last = history[-1]["id"]
        for i in range(0, len(history), WS_HISTORY_CHUNK):
            chunk = history[i:i + WS_HISTORY_CHUNK]
            if not await _send({
                "type": "history",
                "events": chunk,
                "first_id": overall_first,
                "last_id": overall_last,
            }):
                return


    if state and state.pending_checkpoint and not after_id:
        already_in_history = any(
            ev.get("type") == "decision_event"
            and (ev.get("payload") or {}).get("checkpoint_id")
                == state.pending_checkpoint.get("checkpoint_id")
            for ev in history
        )
        if not already_in_history:
            cp = dict(state.pending_checkpoint)
            await _send({
                "type": "decision_event",
                "id": f"replay-cp-{cp.get('checkpoint_id', '')}",
                "task_id": task_id,
                "branch_id": state.active_branch_id or "",
                "ts": cp.get("created_at", ""),
                "v": 2,
                "payload": {
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

    HEARTBEAT_GAP_S = 25.0

    async def _push_loop():
        """从 Stream 订阅事件并转发给客户端; 静默期主动发 heartbeat。"""
        nonlocal last_id
        sub = event_stream.subscribe(task_id, last_id=last_id)
        try:
            while True:
                try:
                    ev = await asyncio.wait_for(sub.__anext__(), timeout=HEARTBEAT_GAP_S)
                except asyncio.TimeoutError:
                    if not await _send({"type": "heartbeat"}):
                        return
                    continue
                except StopAsyncIteration:
                    return
                if not await _send(ev):
                    return
                if ev.get("type") == "done":
                    return
        finally:
            try:
                await sub.aclose()
            except Exception:
                pass

    async def _recv_loop():
        """处理客户端控制帧: ping/pong + ack (本期仅记录, 不阻塞推送)。"""
        while True:
            try:
                data = await websocket.receive_text()
            except WebSocketDisconnect:
                return
            except Exception:
                return
            if not data:
                continue
            if data == "ping":
                if not await _send({"type": "pong"}):
                    return
                continue
            if data.startswith("{"):
                logger.debug(f"[WS] client control frame task={task_id}: {data[:120]}")

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
            except (WebSocketDisconnect, asyncio.CancelledError):
                pass
            except Exception as exc:
                logger.debug(f"[WS] task ended with err: {exc}")
    finally:
        for task in [push_task, recv_task]:
            if not task.done():
                task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
