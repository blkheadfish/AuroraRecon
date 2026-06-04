"""event_stream.py —— 基于 Redis Stream 的统一事件总线 (协议 v2)

设计目标:
    1. 单一事件源: ``push_decision`` / ``state.log`` / ``task_runner`` 写入的所有
       实时事件都走这里, WS 客户端只从 Stream 读, 不再混合 ``phase_log``
       字符串派生 + ``live_decision_events`` 内存数组的拼图。
    2. 持久化 + 增量回放: ``XADD`` 追加, ``XRANGE`` 翻历史, ``XREAD BLOCK``
       低延迟订阅。客户端用 last_event_id 重连即可补差量, F5 刷新无损。
    3. 自动裁剪: ``MAXLEN ~ 50000`` (近似裁剪) 保证单任务最多 ~5MB Stream;
       任务结束 / 长期未更新由 ``EXPIRE`` 7d 兜底回收。
    4. 跨进程友好: 多 worker 部署时, 任意 worker 写入, 任意 worker 订阅 (虽然
       本期仍按单 worker 部署, 但协议已就位)。
    5. Redis 不可用时降级: 退到 in-process ``asyncio.Queue`` fan-out, 仍能让
       本进程 WS 客户端收到事件 (持久化 / 跨进程能力丧失, 但任务不会失败)。

Wire envelope (UTF-8 JSON in stream field ``data``):

.. code-block:: json

    {
      "id": "1735689600123-0",          // Redis Stream ID, frontend dedup key
      "task_id": "task-xxx",
      "branch_id": "b-xxx",
      "ts": "2026-04-30T12:00:00.123456",
      "type": "log | decision_event | phase_update | approval_required |"
              "branch_forked | branch_switched | branch_status_changed |"
              "done | error",
      "v": 2,
      "payload": { ... }
    }

``type`` 与 ``payload`` 的语义沿用 v1 协议字段, 但脱离了"WS 帧由后端拼装"
那一层 -- WS 直接转发 envelope。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import defaultdict, deque
from typing import AsyncIterator, Optional

logger = logging.getLogger(__name__)

STREAM_MAXLEN = int(os.getenv("EVENT_STREAM_MAXLEN", "50000"))
STREAM_TTL_SECONDS = int(os.getenv("EVENT_STREAM_TTL", str(7 * 24 * 3600)))
XREAD_BLOCK_MS = int(os.getenv("EVENT_STREAM_BLOCK_MS", "25000"))
PROTOCOL_VERSION = int(os.getenv("REALTIME_PROTOCOL_VERSION", "2"))

_EXPIRE_INTERVAL_S = 60.0
_last_expire: dict[str, float] = {}

_LOCAL_RING_CAP = 2000
_local_rings: dict[str, deque[dict]] = defaultdict(lambda: deque(maxlen=_LOCAL_RING_CAP))
_local_seq: dict[str, int] = defaultdict(int)
_local_subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)


def _stream_key(task_id: str) -> str:
    return f"task:{task_id}:events"


def _ts_now_iso() -> str:
    from datetime import datetime
    return datetime.utcnow().isoformat(timespec="microseconds")


_redis_probe_done = False
_redis_ok = False

_xread_probe_done = False
_xread_ok = False


async def _get_redis_or_none():
    """懒探测 Redis 连接; 失败后短期内不重试 (避免每次 publish 都打连接)。

    Tests 可以通过 ``reset_redis_probe()`` 强制重新探测。
    """
    global _redis_probe_done, _redis_ok
    try:
        from backend.db.redis_cache import get_redis
        r = await get_redis()
        if not _redis_probe_done:
            try:
                await r.ping()
                _redis_ok = True
                logger.info("[event_stream] 使用 Redis Stream 模式")
            except Exception as exc:
                _redis_ok = False
                logger.warning(
                    "[event_stream] Redis ping 失败, 走本地降级: %s", exc,
                )
            finally:
                _redis_probe_done = True
        return r if _redis_ok else None
    except Exception as exc:
        if not _redis_probe_done:
            logger.warning(
                "[event_stream] 加载 Redis 失败, 走本地降级: %s", exc,
            )
            _redis_probe_done = True
            _redis_ok = False
        return None


async def _get_redis_xread_or_none():
    """与 ``_get_redis_or_none`` 一样, 但使用 XREAD 专用连接池。

    XREAD BLOCK 长连接占用时间远高于短操作, 分离后 publish / cache
    不会被 WS 订阅者饿死。
    """
    global _xread_probe_done, _xread_ok
    try:
        from backend.db.redis_cache import get_redis_xread
        r = await get_redis_xread()
        if not _xread_probe_done:
            try:
                await r.ping()
                _xread_ok = True
                logger.info("[event_stream] XREAD 池 ping OK")
            except Exception as exc:
                _xread_ok = False
                logger.warning(
                    "[event_stream] XREAD 池 ping 失败, 走本地降级: %s", exc,
                )
            finally:
                _xread_probe_done = True
        return r if _xread_ok else None
    except Exception as exc:
        if not _xread_probe_done:
            logger.warning(
                "[event_stream] 加载 XREAD 池失败, 走本地降级: %s", exc,
            )
            _xread_probe_done = True
            _xread_ok = False
        return None


def reset_redis_probe() -> None:
    """供测试 / fixture 强制重新探测 Redis 状态。"""
    global _redis_probe_done, _redis_ok
    _redis_probe_done = False
    _redis_ok = False


async def publish(
    task_id: str,
    *,
    type: str,
    payload: dict | None = None,
    branch_id: str = "",
) -> str:
    """Publish 一条事件到 ``task:{task_id}:events`` Stream。

    返回 Redis Stream 分配的 ID (``ms-seq``); 降级模式下返回本地伪 ID
    ``"local-{counter}"``。失败 / 异常时返回空串, 业务侧不应中断。

    所有调用都保证不会抛异常 -- 实时推送层永远不应让任务节点崩。
    """
    if not task_id:
        return ""
    body = {
        "task_id": task_id,
        "branch_id": branch_id or "",
        "ts": _ts_now_iso(),
        "type": type,
        "v": PROTOCOL_VERSION,
        "payload": payload or {},
    }
    r = await _get_redis_or_none()
    if r is not None:
        try:
            data = json.dumps(body, ensure_ascii=False, default=str)
            key = _stream_key(task_id)
            stream_id = await r.xadd(
                key,
                {"data": data},
                maxlen=STREAM_MAXLEN,
                approximate=True,
            )
            import time as _time
            now = _time.monotonic()
            if now - _last_expire.get(key, 0) > _EXPIRE_INTERVAL_S:
                try:
                    await r.expire(key, STREAM_TTL_SECONDS)
                    _last_expire[key] = now
                except Exception:
                    pass
            sid = (
                stream_id.decode() if isinstance(stream_id, bytes) else str(stream_id)
            )
            body["id"] = sid
            return sid
        except Exception as exc:
            msg = str(exc)
            if "Too many connections" in msg:
                global _redis_ok
                _redis_ok = False
                logger.warning(
                    "[event_stream] Redis 连接池耗尽, 降级到本地 ring, "
                    "直到下一次 reset_redis_probe() 或服务重启才重试: %s", exc,
                )
            else:
                logger.warning(
                    "[event_stream] XADD 失败, 退到本地 ring task=%s err=%s",
                    task_id, exc,
                )

    return await _publish_local(task_id, body)


async def _publish_local(task_id: str, body: dict) -> str:
    _local_seq[task_id] += 1
    sid = f"local-{_local_seq[task_id]:09d}"
    body["id"] = sid
    _local_rings[task_id].append(body)
    queues = list(_local_subscribers.get(task_id, ()))
    for q in queues:
        try:
            q.put_nowait(body)
        except asyncio.QueueFull:
            try:
                q.get_nowait()
                q.put_nowait(body)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass
    return sid


async def replay(
    task_id: str,
    *,
    after_id: str = "0",
    count: int = 1000,
) -> list[dict]:
    """返回严格大于 ``after_id`` 的事件列表, 用于 WS 重连首批 / REST 翻页。

    ``after_id`` 取值:
        - ``"0"`` 或 ``""`` -> 从最早开始 (实际以 MAXLEN 裁剪后的最早为准)
        - 一个具体 stream id -> 严格大于该 ID 的事件 (XRANGE 的 ``(`` 排他语法)
    """
    if count <= 0:
        return []
    count = min(count, 5000)
    if not after_id or after_id == "0":
        start = "-"
        inclusive = True
    else:
        start = f"({after_id}"
        inclusive = False

    r = await _get_redis_or_none()
    if r is not None:
        try:
            entries = await r.xrange(
                _stream_key(task_id), min=start, max="+", count=count,
            )
            return [_decode_xrange_entry(eid, fields) for (eid, fields) in entries]
        except Exception as exc:
            logger.warning(
                "[event_stream] XRANGE 失败, 退到本地 ring task=%s err=%s",
                task_id, exc,
            )

    ring = list(_local_rings.get(task_id, ()))
    if inclusive:
        return ring[:count]
    out: list[dict] = []
    for ev in ring:
        if str(ev.get("id", "")) > after_id:
            out.append(ev)
            if len(out) >= count:
                break
    return out


async def replay_tail(task_id: str, *, count: int = 1000) -> list[dict]:
    """返回 Stream 尾部最后 ``count`` 条事件 (时间正序), 用于 WS 首连回放。

    与 ``replay(after_id="0")[-count:]`` 语义等价, 但用 ``XREVRANGE COUNT n``
    只读最后 n 条, 避免 ``XRANGE`` 全量再切片。结果反转为时间正序返回,
    结构与 ``replay`` 一致 (list[dict], 每条含 id)。
    """
    if count <= 0:
        return []
    count = min(count, 5000)  # 与 replay 的上限一致
    r = await _get_redis_or_none()
    if r is not None:
        try:
            entries = await r.xrevrange(
                _stream_key(task_id), max="+", min="-", count=count,
            )
            entries = list(reversed(entries))  # 降序 -> 时间正序
            return [_decode_xrange_entry(eid, fields) for (eid, fields) in entries]
        except Exception as exc:
            logger.warning(
                "[event_stream] XREVRANGE 失败, 退到本地 ring task=%s err=%s",
                task_id, exc,
            )

    ring = list(_local_rings.get(task_id, ()))
    return ring[-count:]


def _decode_xrange_entry(stream_id, fields) -> dict:
    sid = stream_id.decode() if isinstance(stream_id, bytes) else str(stream_id)
    raw = fields.get("data") if isinstance(fields, dict) else None
    if raw is None and isinstance(fields, dict):
        raw = fields.get(b"data")
    if raw is None:
        raw = "{}"
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        body = json.loads(raw)
    except Exception:
        body = {"type": "error", "payload": {"raw": raw}}
    body["id"] = sid
    return body


async def subscribe(
    task_id: str,
    *,
    last_id: str = "$",
) -> AsyncIterator[dict]:
    """异步生成器: 持续读取 Stream 新事件直到调用方取消。

    ``last_id``:
        - ``"$"`` (默认) -> 只读 ``订阅时刻之后`` 的新事件 (与 PUBSUB 一致)
        - 具体 id        -> 从该 ID 之后开始 (用于 ``replay`` 衔接)

    实现:
        * Redis 模式: 纯 ``XREAD BLOCK 25000`` 循环。一次 XREAD 后推进 ``cur``,
          下次只读新事件; 超时返回空 -> 重新 BLOCK。被 cancel 时 redis-py 会
          抛 CancelledError 自动退出。
        * 降级模式: 监听本地 ``asyncio.Queue`` fanout, ``publish`` 时 put_nowait。
    """
    r = await _get_redis_xread_or_none()
    if r is None:
        queue: asyncio.Queue = asyncio.Queue(maxsize=2000)
        _local_subscribers[task_id].append(queue)
        try:
            while True:
                ev = await queue.get()
                if not last_id or last_id == "$":
                    yield ev
                else:
                    if str(ev.get("id", "")) > last_id:
                        yield ev
        finally:
            try:
                _local_subscribers[task_id].remove(queue)
            except ValueError:
                pass
            if not _local_subscribers[task_id]:
                _local_subscribers.pop(task_id, None)
        return

    cur = last_id or "$"
    while True:
        try:
            result = await r.xread(
                {_stream_key(task_id): cur},
                block=XREAD_BLOCK_MS,
                count=200,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug(
                "[event_stream] XREAD 异常 task=%s err=%s", task_id, exc,
            )
            await asyncio.sleep(0.5)
            continue

        if not result:
            continue

        for _key, entries in result:
            for eid, fields in entries:
                ev = _decode_xrange_entry(eid, fields)
                sid = str(ev.get("id") or "")
                if sid:
                    cur = sid
                yield ev


async def drop(task_id: str) -> None:
    """删除某 task 的 Stream + 本地缓存 (任务删除接口调用)。"""
    r = await _get_redis_or_none()
    if r is not None:
        try:
            await r.delete(_stream_key(task_id))
        except Exception:
            pass
    _local_rings.pop(task_id, None)
    _local_seq.pop(task_id, None)


async def stream_length(task_id: str) -> int:
    """供监控面板查询当前 Stream 长度。"""
    r = await _get_redis_or_none()
    if r is not None:
        try:
            return int(await r.xlen(_stream_key(task_id)))
        except Exception:
            return 0
    return len(_local_rings.get(task_id, ()))


def is_redis_backed() -> bool:
    """供 health 接口判定当前事件总线运行模式。"""
    return bool(_redis_ok)
