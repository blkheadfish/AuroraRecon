"""Regression tests for ``backend.api.event_stream``.

走本地降级模式 (跳过 Redis 探测) 验证语义:
  - publish 返回单调递增的 ID
  - replay (after_id) 严格大于过滤
  - subscribe 在新事件到达时被唤醒
  - drop 清理本地 ring + 计数

Redis 模式由集成测试覆盖 (需要 docker-compose 起 redis), 单元测试只锁住
本地降级语义, 保证 Redis 不可用时任务节点仍能跑完。
"""
from __future__ import annotations

import asyncio

import pytest

from backend.api import event_stream


@pytest.fixture(autouse=True)
def _force_local_mode(monkeypatch):
    """所有测试强制走本地降级路径, 不依赖 Redis 容器。"""
    async def _fake_get_redis():
        return None

    monkeypatch.setattr(event_stream, "_get_redis_or_none", _fake_get_redis)
    monkeypatch.setattr(event_stream, "_get_redis_xread_or_none", _fake_get_redis)
    # 清理状态, 避免上一个 case 的 ring 串味
    event_stream._local_rings.clear()
    event_stream._local_seq.clear()
    event_stream._local_subscribers.clear()
    yield
    event_stream._local_rings.clear()
    event_stream._local_seq.clear()
    event_stream._local_subscribers.clear()


@pytest.mark.asyncio
async def test_publish_returns_monotonic_local_ids():
    a = await event_stream.publish("t1", type="log", payload={"line": "alpha"})
    b = await event_stream.publish("t1", type="log", payload={"line": "beta"})
    c = await event_stream.publish("t1", type="log", payload={"line": "gamma"})
    # 本地 ID 字典序单调递增
    assert a < b < c
    # ID 形如 "local-000000001"
    assert a.startswith("local-")


@pytest.mark.asyncio
async def test_replay_after_id_excludes_anchor():
    ids = []
    for i in range(5):
        ids.append(await event_stream.publish("t1", type="log", payload={"i": i}))

    # after_id = ids[1] 应只返回 ids[2], ids[3], ids[4]
    out = await event_stream.replay("t1", after_id=ids[1], count=10)
    got_ids = [ev["id"] for ev in out]
    assert got_ids == ids[2:]


@pytest.mark.asyncio
async def test_replay_from_zero_returns_all():
    for i in range(3):
        await event_stream.publish("t1", type="log", payload={"i": i})
    out = await event_stream.replay("t1", after_id="0", count=100)
    assert len(out) == 3
    assert all(ev["payload"]["i"] in (0, 1, 2) for ev in out)


@pytest.mark.asyncio
async def test_replay_count_limit():
    for i in range(20):
        await event_stream.publish("t1", type="log", payload={"i": i})
    out = await event_stream.replay("t1", after_id="0", count=5)
    assert len(out) == 5
    # 顺序应为最早的 5 条
    assert [ev["payload"]["i"] for ev in out] == [0, 1, 2, 3, 4]


@pytest.mark.asyncio
async def test_subscribe_wakes_on_publish():
    received: list[dict] = []

    async def _consumer():
        async for ev in event_stream.subscribe("t1", last_id="$"):
            received.append(ev)
            if len(received) >= 2:
                break

    consumer = asyncio.create_task(_consumer())
    # 让 subscribe 先注册到 _local_subscribers
    await asyncio.sleep(0.01)
    await event_stream.publish("t1", type="log", payload={"line": "hello"})
    await event_stream.publish("t1", type="log", payload={"line": "world"})
    await asyncio.wait_for(consumer, timeout=2.0)
    assert [ev["payload"]["line"] for ev in received] == ["hello", "world"]


@pytest.mark.asyncio
async def test_subscribe_with_last_id_filters_old_events():
    """订阅时若提供 last_id, 不应再收到 last_id 及之前的事件 -- 这套语义
    专门给"先 replay, 再 subscribe"的衔接场景, 确保不会重复送达。"""
    a = await event_stream.publish("t1", type="log", payload={"line": "old"})
    received: list[str] = []

    async def _consumer():
        async for ev in event_stream.subscribe("t1", last_id=a):
            received.append(ev["payload"]["line"])
            if received:
                break

    consumer = asyncio.create_task(_consumer())
    await asyncio.sleep(0.01)
    await event_stream.publish("t1", type="log", payload={"line": "new"})
    await asyncio.wait_for(consumer, timeout=2.0)
    assert received == ["new"]


@pytest.mark.asyncio
async def test_drop_clears_state():
    await event_stream.publish("t1", type="log", payload={"i": 0})
    await event_stream.publish("t1", type="log", payload={"i": 1})
    await event_stream.drop("t1")
    out = await event_stream.replay("t1", after_id="0", count=100)
    assert out == []
    # 重新 publish 后 seq 从头开始
    new_id = await event_stream.publish("t1", type="log", payload={"i": 2})
    assert new_id == "local-000000001"


@pytest.mark.asyncio
async def test_envelope_shape():
    sid = await event_stream.publish(
        "t1", type="decision_event",
        payload={"action": "thought", "message": "hi"},
        branch_id="b-abc",
    )
    out = await event_stream.replay("t1", after_id="0", count=10)
    assert len(out) == 1
    ev = out[0]
    assert ev["id"] == sid
    assert ev["task_id"] == "t1"
    assert ev["branch_id"] == "b-abc"
    assert ev["type"] == "decision_event"
    assert ev["v"] >= 2
    assert ev["payload"]["action"] == "thought"
    assert isinstance(ev["ts"], str) and "T" in ev["ts"]


@pytest.mark.asyncio
async def test_publish_handles_empty_task_id():
    sid = await event_stream.publish("", type="log", payload={"x": 1})
    assert sid == ""
