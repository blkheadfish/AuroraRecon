"""event_bus.py —— Sink 注册表 + 主 event loop 注册表

历史上这里维护一套 ``asyncio.Queue`` 的 fan-out 总线; v2 协议把"事件存储 +
分发"职责交给了 :mod:`backend.api.event_stream` (Redis Stream), 本模块只
保留两件事:

    1. **Task-level sinks**: 让 ``PentestState.log()`` / ``PentestState.push_decision()``
       这些 *业务节点内部* 的 fire-and-forget 调用能够把事件投递出去。WS 路由层
       不再消费 sink, 而是订阅 Stream; sink 只负责把事件写进 Stream。
    2. **Task-level main loop registry**: ``state.log() / push_decision()`` 在
       worker 线程命中时, ``asyncio.get_running_loop()`` 会抛 RuntimeError;
       这时退到主协程注册的 loop, 配合 ``run_coroutine_threadsafe`` 跨线程投递。

这套抽象保留, 是因为 LangGraph 节点 / 工具执行器 / dir_scan_orchestrator 等
都已经按 sink 在写代码; 替换协议时尽量不影响它们的调用面。
"""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

DecisionSink = Callable[[dict], Awaitable[None]]
_TASK_EVENT_SINK: dict[str, DecisionSink] = {}


def set_task_sink(task_id: str, sink: DecisionSink) -> None:
    _TASK_EVENT_SINK[task_id] = sink


def clear_task_sink(task_id: str) -> None:
    _TASK_EVENT_SINK.pop(task_id, None)


def get_task_sink(task_id: str) -> Optional[DecisionSink]:
    return _TASK_EVENT_SINK.get(task_id)


LogSink = Callable[[str, int], Awaitable[None]]
_TASK_LOG_SINK: dict[str, LogSink] = {}


def set_log_sink(task_id: str, sink: LogSink) -> None:
    _TASK_LOG_SINK[task_id] = sink


def clear_log_sink(task_id: str) -> None:
    _TASK_LOG_SINK.pop(task_id, None)


def get_log_sink(task_id: str) -> Optional[LogSink]:
    return _TASK_LOG_SINK.get(task_id)


_TASK_LOOP: dict[str, asyncio.AbstractEventLoop] = {}


def set_task_loop(task_id: str, loop: asyncio.AbstractEventLoop) -> None:
    _TASK_LOOP[task_id] = loop


def clear_task_loop(task_id: str) -> None:
    _TASK_LOOP.pop(task_id, None)


def get_task_loop(task_id: str) -> Optional[asyncio.AbstractEventLoop]:
    return _TASK_LOOP.get(task_id)


class _LegacyBusAdapter:
    """v1 -> v2 适配层。优先把帧拆成 ``(type, payload, branch_id)``。"""

    async def publish(self, task_id: str, frame: dict) -> None:
        if not isinstance(frame, dict):
            return
        from backend.api import event_stream
        ftype = str(frame.get("type") or "")
        if not ftype:
            return
        branch_id = str(frame.get("branch_id") or "")
        if "data" in frame and isinstance(frame["data"], dict):
            payload = dict(frame["data"])
        else:
            payload = {k: v for k, v in frame.items() if k not in ("type", "branch_id")}
        if not branch_id and isinstance(payload.get("branch_id"), str):
            branch_id = payload["branch_id"]
        try:
            await event_stream.publish(
                task_id, type=ftype, payload=payload, branch_id=branch_id,
            )
        except Exception as exc:
            logger.warning(
                "[event_bus] legacy adapter publish 失败 task=%s type=%s err=%s",
                task_id, ftype, exc,
            )

    def has_subscribers(self, task_id: str) -> bool:
        return True

    def subscriber_count(self, task_id: str) -> int:
        return 0


_legacy_bus = _LegacyBusAdapter()


def get_event_bus() -> _LegacyBusAdapter:
    return _legacy_bus


TaskEventBus = _LegacyBusAdapter


def get_dropped_count(task_id: str) -> int:
    return 0


def reset_dropped_count(task_id: str) -> None:
    return None
