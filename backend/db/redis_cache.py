"""
db/redis_cache.py —— Redis 缓存 & 任务状态快速读写

用途：
  1. 运行中任务的实时状态缓存（高频读写，避免打 PostgreSQL）
  2. 任务日志追加（使用 Redis List，天然支持追加 + 读取最新 N 条）
  3. 工具执行结果临时缓存
  4. 任务取消信号（通过 Redis PubSub 或标志位）
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

_pool: Optional[aioredis.Redis] = None

_xread_pool: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    """获取 Redis 连接池 — 短操作 (publish / cache / 工具结果)。"""
    global _pool
    if _pool is None:
        _pool = aioredis.from_url(
            REDIS_URL,
            decode_responses=True,
            max_connections=int(os.getenv("REDIS_MAX_CONNECTIONS", "100")),
        )
    return _pool


async def get_redis_xread() -> aioredis.Redis:
    """获取 Redis 连接池 — 专用于 XREAD BLOCK 长连接订阅。

    默认 500 条连接, 覆盖 ~400 个并发 WS Tab + 余量。如果仍然不够,
    通过环境变量 ``REDIS_XREAD_MAX_CONNECTIONS`` 调高。
    """
    global _xread_pool
    if _xread_pool is None:
        _xread_pool = aioredis.from_url(
            REDIS_URL,
            decode_responses=True,
            max_connections=int(os.getenv("REDIS_XREAD_MAX_CONNECTIONS", "500")),
        )
    return _xread_pool


async def close_redis():
    """关闭所有连接池"""
    global _pool, _xread_pool
    if _pool:
        await _pool.close()
        _pool = None
    if _xread_pool:
        await _xread_pool.close()
        _xread_pool = None



def _task_key(task_id: str) -> str:
    return f"task:{task_id}:state"


def _log_key(task_id: str) -> str:
    return f"task:{task_id}:logs"


def _cancel_key(task_id: str) -> str:
    return f"task:{task_id}:cancel"


async def cache_task_state(task_id: str, state_dict: dict, ttl: int = 86400) -> None:
    """缓存任务状态到 Redis（TTL 默认 24h）"""
    r = await get_redis()
    await r.set(_task_key(task_id), json.dumps(state_dict, ensure_ascii=False), ex=ttl)


async def get_cached_task_state(task_id: str) -> Optional[dict]:
    """从 Redis 读取任务状态"""
    r = await get_redis()
    data = await r.get(_task_key(task_id))
    if data:
        return json.loads(data)
    return None


async def delete_cached_task(task_id: str) -> None:
    """删除任务缓存"""
    r = await get_redis()
    await r.delete(_task_key(task_id), _log_key(task_id), _cancel_key(task_id))



async def append_task_log(task_id: str, log_entry: str) -> None:
    """追加一条日志到 Redis List"""
    r = await get_redis()
    await r.rpush(_log_key(task_id), log_entry)
    await r.expire(_log_key(task_id), 86400)


async def append_task_logs(task_id: str, entries: list[str]) -> None:
    """批量追加多条日志到 Redis List（单次 pipeline，减少 RPUSH 往返）。"""
    if not entries:
        return
    r = await get_redis()
    key = _log_key(task_id)
    pipe = r.pipeline()
    pipe.rpush(key, *entries)
    pipe.expire(key, 86400)
    await pipe.execute()


async def get_task_logs(task_id: str, start: int = 0, end: int = -1) -> list[str]:
    """获取任务日志（支持范围查询）"""
    r = await get_redis()
    return await r.lrange(_log_key(task_id), start, end)


async def get_recent_logs(task_id: str, count: int = 20) -> list[str]:
    """获取最新 N 条日志"""
    r = await get_redis()
    return await r.lrange(_log_key(task_id), -count, -1)



async def set_cancel_flag(task_id: str) -> None:
    """设置取消标志"""
    r = await get_redis()
    await r.set(_cancel_key(task_id), "1", ex=3600)


async def is_cancelled(task_id: str) -> bool:
    """检查任务是否已被取消"""
    r = await get_redis()
    return await r.exists(_cancel_key(task_id)) > 0



async def cache_tool_result(
    tool: str, target: str, result: str, ttl: int = 3600
) -> None:
    """缓存工具扫描结果（避免重复扫描）"""
    r = await get_redis()
    key = f"tool_cache:{tool}:{target}"
    await r.set(key, result, ex=ttl)


async def get_cached_tool_result(tool: str, target: str) -> Optional[str]:
    """获取缓存的工具结果"""
    r = await get_redis()
    return await r.get(f"tool_cache:{tool}:{target}")



async def incr_stat(key: str, amount: int = 1) -> int:
    """递增统计计数器"""
    r = await get_redis()
    return await r.incrby(f"stats:{key}", amount)


async def get_stat(key: str) -> int:
    """获取统计计数器"""
    r = await get_redis()
    val = await r.get(f"stats:{key}")
    return int(val) if val else 0
