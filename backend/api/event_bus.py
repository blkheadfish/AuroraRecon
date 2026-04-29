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
                # 消费者太慢, 丢弃最旧的事件腾出空间。同时累加
                # 丢弃计数 + 限频 warning, 便于运维和前端 history_meta
                # 感知"已经丢了 N 条历史事件"。
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass
                _DROPPED_TOTAL[task_id] = _DROPPED_TOTAL.get(task_id, 0) + 1
                import time as _t
                now = _t.monotonic()
                last = _DROPPED_LAST_WARN.get(task_id, 0.0)
                if now - last >= _DROPPED_WARN_INTERVAL:
                    _DROPPED_LAST_WARN[task_id] = now
                    logger.warning(
                        "[EventBus] task=%s 队列满, 已累计丢弃 %d 条事件 "
                        "(消费者过慢 / WS 客户端卡顿)",
                        task_id,
                        _DROPPED_TOTAL[task_id],
                    )

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


# ── Task-level phase_log sink ──────────────────────────────
# 让 PentestState.log() 也能 fire-and-forget 把每条 phase_log 实时推到 WS,
# 而不是等到节点 yield 后随 phase_update 批量下发。两套 sink 分开注册,
# 避免 decision_event 的包装格式被复用到普通日志上(前端需要 type='log').

LogSink = Callable[[str, int], Awaitable[None]]
_TASK_LOG_SINK: dict[str, LogSink] = {}


def set_log_sink(task_id: str, sink: LogSink) -> None:
    _TASK_LOG_SINK[task_id] = sink


def clear_log_sink(task_id: str) -> None:
    _TASK_LOG_SINK.pop(task_id, None)


def get_log_sink(task_id: str) -> LogSink | None:
    return _TASK_LOG_SINK.get(task_id)


# ── Task-level event loop registry ─────────────────────────
# 主协程(run_task / resume_task / _resume_branch_bg)在入口
# 把自己运行的 event loop 登记进来。``PentestState.log /
# push_decision`` 在 worker 线程(LLM 同步调用、阻塞 IO 线程池)
# 命中时, ``asyncio.get_running_loop()`` 会抛 RuntimeError, 这时
# 退回到注册表里的 loop, 配合 ``run_coroutine_threadsafe`` 把
# 事件投递回主 loop, 避免事件被 try/except 静默吞掉。
_TASK_LOOP: dict[str, asyncio.AbstractEventLoop] = {}


def set_task_loop(task_id: str, loop: asyncio.AbstractEventLoop) -> None:
    _TASK_LOOP[task_id] = loop


def clear_task_loop(task_id: str) -> None:
    _TASK_LOOP.pop(task_id, None)


def get_task_loop(task_id: str) -> asyncio.AbstractEventLoop | None:
    return _TASK_LOOP.get(task_id)


# ── 队列丢弃计数 ──────────────────────────────────────────
# subscriber 队列满时, ``publish`` 会丢掉最旧的事件腾位置。
# 频繁丢弃通常意味着前端消费者卡住或吞吐瓶颈, 需要限频
# warning 让运维感知; 同时把累计计数透出, 便于 ws 重连时
# 给前端发 ``history_meta`` 提示"刚刚丢了 N 条历史事件,
# 请刷新看完整记录"。
_DROPPED_TOTAL: dict[str, int] = {}
_DROPPED_LAST_WARN: dict[str, float] = {}
_DROPPED_WARN_INTERVAL = 5.0  # 秒


def get_dropped_count(task_id: str) -> int:
    return _DROPPED_TOTAL.get(task_id, 0)


def reset_dropped_count(task_id: str) -> None:
    _DROPPED_TOTAL.pop(task_id, None)
    _DROPPED_LAST_WARN.pop(task_id, None)
