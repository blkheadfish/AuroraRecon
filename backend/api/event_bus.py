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

# ── Task-level decision event sink ────────────────────────────
# Sink 签名: ``async def(event_dict) -> None``。``event_dict`` 是
# 业务层的 decision payload (含 action / message / tool / phase 等), 由
# 注册方决定要怎么把它转成 Stream envelope 并 publish。
DecisionSink = Callable[[dict], Awaitable[None]]
_TASK_EVENT_SINK: dict[str, DecisionSink] = {}


def set_task_sink(task_id: str, sink: DecisionSink) -> None:
    _TASK_EVENT_SINK[task_id] = sink


def clear_task_sink(task_id: str) -> None:
    _TASK_EVENT_SINK.pop(task_id, None)


def get_task_sink(task_id: str) -> Optional[DecisionSink]:
    return _TASK_EVENT_SINK.get(task_id)


# ── Task-level phase_log sink ─────────────────────────────────
# Sink 签名: ``async def(line, seq) -> None``。
LogSink = Callable[[str, int], Awaitable[None]]
_TASK_LOG_SINK: dict[str, LogSink] = {}


def set_log_sink(task_id: str, sink: LogSink) -> None:
    _TASK_LOG_SINK[task_id] = sink


def clear_log_sink(task_id: str) -> None:
    _TASK_LOG_SINK.pop(task_id, None)


def get_log_sink(task_id: str) -> Optional[LogSink]:
    return _TASK_LOG_SINK.get(task_id)


# ── Task-level event loop registry ────────────────────────────
# 主协程 (run_task / resume_task / _resume_branch_bg) 在入口把自己运行的 loop
# 登记进来, 让 worker 线程命中 sink 调用时能 ``run_coroutine_threadsafe`` 把
# 事件投递回主 loop。
_TASK_LOOP: dict[str, asyncio.AbstractEventLoop] = {}


def set_task_loop(task_id: str, loop: asyncio.AbstractEventLoop) -> None:
    _TASK_LOOP[task_id] = loop


def clear_task_loop(task_id: str) -> None:
    _TASK_LOOP.pop(task_id, None)


def get_task_loop(task_id: str) -> Optional[asyncio.AbstractEventLoop]:
    return _TASK_LOOP.get(task_id)


# ── 兼容: 老调用方仍然 ``from backend.api.event_bus import get_event_bus`` ──
# v1 协议里这里返回一个 ``TaskEventBus``; v2 协议下没有真正的 bus 单例了, 但
# ``get_event_bus().publish(task_id, frame)`` 这种调用面遍布在 task_runner /
# branch_manager / tasks router / dir_scan_orchestrator。为了让迁移期内老代码
# 不至于一次性全爆, 我们提供一个**适配层**: ``publish(task_id, frame)`` 解析
# v1 帧 (``{type:..., data:...}`` 或 flat ``{type:..., **kwargs}``) 把它写进
# v2 Stream。这条路径不应当作长期 API, 内部代码会逐步切到 ``event_stream``。
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
        # v1 帧: ``decision_event`` 用 ``data`` 装载; 其它类型直接平铺 (例如
        # ``{type:"phase_update", phase:..., logs:[...], ...}``)。我们统一把
        # 业务字段塞进 ``payload``, type 不变。
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

    # 老接口里有些调用还引用了这些 helper, 留空兜底。
    def has_subscribers(self, task_id: str) -> bool:  # pragma: no cover
        return True

    def subscriber_count(self, task_id: str) -> int:  # pragma: no cover
        return 0


_legacy_bus = _LegacyBusAdapter()


def get_event_bus() -> _LegacyBusAdapter:
    return _legacy_bus


# ``TaskEventBus`` 类型在老代码里用作 Type Hint, 保留一个 alias 让 import 不爆
TaskEventBus = _LegacyBusAdapter


# ── 队列丢弃计数 (v2 不需要, 但老代码可能 import) ────────────
def get_dropped_count(task_id: str) -> int:
    return 0


def reset_dropped_count(task_id: str) -> None:
    return None
