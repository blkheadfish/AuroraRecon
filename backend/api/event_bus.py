"""
event_bus.py —— 事件总线

基于 asyncio.Queue 的发布/订阅，替代 WebSocket 150ms 轮询。
生产者（task_runner）push 事件，消费者（ws.py）await queue.get()，延迟接近 0。
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class TaskEventBus:
    """
    每个 task_id 可以有多个订阅者（多个 WS 连接）。
    publish 是 fire-and-forget，消费者太慢则丢弃。
    """

    def __init__(self):
        self._channels: dict[str, list[asyncio.Queue]] = {}

    def subscribe(self, task_id: str, maxsize: int = 1000) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._channels.setdefault(task_id, []).append(q)
        return q

    def unsubscribe(self, task_id: str, q: asyncio.Queue):
        if task_id in self._channels:
            self._channels[task_id] = [x for x in self._channels[task_id] if x is not q]
            if not self._channels[task_id]:
                del self._channels[task_id]

    async def publish(self, task_id: str, event: dict):
        for q in self._channels.get(task_id, []):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # 消费者太慢，丢弃最旧的事件腾出空间
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    def has_subscribers(self, task_id: str) -> bool:
        return bool(self._channels.get(task_id))

    def subscriber_count(self, task_id: str) -> int:
        return len(self._channels.get(task_id, []))


# ── 模块级单例 ────────────────────────────────────────────
_event_bus = TaskEventBus()


def get_event_bus() -> TaskEventBus:
    return _event_bus


# ── Task-level decision event sink ────────────────────────
# Allows push_decision() inside PentestState to fire-and-forget
# events into the EventBus without importing task_runner or bus.

from typing import Callable, Awaitable

_TASK_EVENT_SINK: dict[str, Callable[[dict], Awaitable[None]]] = {}


def set_task_sink(task_id: str, sink: Callable[[dict], Awaitable[None]]) -> None:
    _TASK_EVENT_SINK[task_id] = sink


def clear_task_sink(task_id: str) -> None:
    _TASK_EVENT_SINK.pop(task_id, None)


def get_task_sink(task_id: str) -> Callable[[dict], Awaitable[None]] | None:
    return _TASK_EVENT_SINK.get(task_id)
