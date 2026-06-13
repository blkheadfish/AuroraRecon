"""Integration tests for the v2 realtime event pipeline.

Scenarios (from the refactor plan §6):
  1. 多 WS 客户端订阅同一 task: 全部收到, 顺序一致
  2. F5 刷新无损: replay(after_id) 只补差量
  3. 弱网断 30s 重连: 历史完整
  4. MAXLEN 裁剪后重连: 老事件丢失可检测, 触发"展开更早历史"
  5. 200 个 finding 批量: 全部送达, 无丢失, 顺序保证

All tests run in **local fallback mode** (no Redis) to keep them CI-friendly.
The Redis-backed integration (same semantic contract but over real XADD/XREAD)
should be validated in the docker-compose e2e suite.
"""
from __future__ import annotations

import asyncio

import pytest

pytestmark = pytest.mark.integration

from backend.api import event_stream


@pytest.fixture(autouse=True)
def _force_local_mode(monkeypatch):
    """Force local-ring fallback so tests don't need Redis."""
    async def _no_redis():
        return None

    monkeypatch.setattr(event_stream, "_get_redis_or_none", _no_redis)
    monkeypatch.setattr(event_stream, "_get_redis_xread_or_none", _no_redis)
    event_stream._local_rings.clear()
    event_stream._local_seq.clear()
    event_stream._local_subscribers.clear()
    yield
    event_stream._local_rings.clear()
    event_stream._local_seq.clear()
    event_stream._local_subscribers.clear()


# ── Scenario 1: Multiple subscribers receive all events in order ──

@pytest.mark.asyncio
async def test_multiple_subscribers_all_receive_same_events():
    """3 subscribers on the same task should each get every event, in order."""
    TASK = "integ-multi-sub"
    NUM_EVENTS = 20
    NUM_SUBSCRIBERS = 3

    buckets: list[list[dict]] = [[] for _ in range(NUM_SUBSCRIBERS)]

    async def _consumer(idx: int):
        async for ev in event_stream.subscribe(TASK, last_id="$"):
            buckets[idx].append(ev)
            if len(buckets[idx]) >= NUM_EVENTS:
                break

    consumers = [asyncio.create_task(_consumer(i)) for i in range(NUM_SUBSCRIBERS)]
    await asyncio.sleep(0.02)

    for i in range(NUM_EVENTS):
        await event_stream.publish(
            TASK, type="decision_event",
            payload={"seq": i, "action": "thought", "message": f"event-{i}"},
        )

    await asyncio.wait_for(
        asyncio.gather(*consumers), timeout=5.0,
    )

    for idx in range(NUM_SUBSCRIBERS):
        assert len(buckets[idx]) == NUM_EVENTS, f"subscriber {idx} missed events"
        got_seqs = [ev["payload"]["seq"] for ev in buckets[idx]]
        assert got_seqs == list(range(NUM_EVENTS)), f"subscriber {idx} order mismatch"

    # All subscribers see identical ID sequences
    id_seqs = [[ev["id"] for ev in b] for b in buckets]
    assert id_seqs[0] == id_seqs[1] == id_seqs[2]


# ── Scenario 2: F5 refresh → after_id only fills the gap ──

@pytest.mark.asyncio
async def test_f5_refresh_replay_fills_gap():
    """Simulates F5 refresh: client had last_event_id from before disconnect,
    reconnect with after_id should only return events after that point."""
    TASK = "integ-f5"

    # Phase 1: emit 50 events (simulate active session)
    ids = []
    for i in range(50):
        sid = await event_stream.publish(
            TASK, type="log", payload={"line": f"log-{i}", "seq": i},
        )
        ids.append(sid)

    # Client disconnects after receiving event #29 (index 29)
    last_seen = ids[29]

    # Phase 2: 20 more events arrive while client is away
    for i in range(50, 70):
        sid = await event_stream.publish(
            TASK, type="log", payload={"line": f"log-{i}", "seq": i},
        )
        ids.append(sid)

    # Phase 3: client reconnects with after_id=last_seen
    gap = await event_stream.replay(TASK, after_id=last_seen, count=5000)

    # Should get events 30..69 (40 events)
    assert len(gap) == 40
    gap_seqs = [ev["payload"]["seq"] for ev in gap]
    assert gap_seqs == list(range(30, 70))

    # IDs should be strictly increasing
    gap_ids = [ev["id"] for ev in gap]
    for a, b in zip(gap_ids, gap_ids[1:]):
        assert a < b


# ── Scenario 3: 30s disconnect → history fully recoverable ──

@pytest.mark.asyncio
async def test_long_disconnect_history_intact():
    """Simulate a 30s network outage: all events published during the gap
    are fully recoverable via replay(after_id)."""
    TASK = "integ-30s-gap"

    # Before disconnect: 100 events
    pre_ids = []
    for i in range(100):
        sid = await event_stream.publish(
            TASK, type="decision_event",
            payload={"i": i, "action": "tool_start"},
        )
        pre_ids.append(sid)

    last_before_disconnect = pre_ids[-1]

    # During "30s outage": 150 more events (a burst of tool activity)
    gap_ids = []
    for i in range(100, 250):
        sid = await event_stream.publish(
            TASK, type="decision_event",
            payload={"i": i, "action": "tool_result"},
        )
        gap_ids.append(sid)

    # Reconnect: replay from where we left off
    recovered = await event_stream.replay(
        TASK, after_id=last_before_disconnect, count=5000,
    )
    assert len(recovered) == 150
    recovered_indices = [ev["payload"]["i"] for ev in recovered]
    assert recovered_indices == list(range(100, 250))


# ── Scenario 4: MAXLEN trimming → stale events lost, detectable ──

@pytest.mark.asyncio
async def test_maxlen_trimming_detectable(monkeypatch):
    """When local ring capacity is exceeded, old events get evicted.
    Reconnecting client can detect the gap (first available ID > their last_id)
    and trigger "展开更早历史" UX."""
    TASK = "integ-maxlen"

    # Shrink the ring to 50 for testing
    monkeypatch.setattr(event_stream, "_LOCAL_RING_CAP", 50)
    event_stream._local_rings.clear()

    # Publish 120 events (ring only holds 50)
    all_ids = []
    for i in range(120):
        sid = await event_stream.publish(
            TASK, type="log", payload={"i": i},
        )
        all_ids.append(sid)

    # Client was at event #20 (long ago, trimmed by now)
    stale_last_id = all_ids[20]

    # Replay from stale position
    gap = await event_stream.replay(TASK, after_id=stale_last_id, count=5000)

    # Should only get the surviving 50 events (indices 70..119),
    # but all IDs > stale_last_id in the ring
    assert len(gap) < 100, "should have lost some events to trimming"
    assert len(gap) > 0

    # The earliest available event's payload.i should be > 20
    earliest_i = gap[0]["payload"]["i"]
    assert earliest_i > 20, "trimmed events should no longer be available"

    # Full replay from "0" should only have the ring's capacity
    full = await event_stream.replay(TASK, after_id="0", count=5000)
    assert len(full) == 50


# ── Scenario 5: 200 findings batch → zero loss, order preserved ──

@pytest.mark.asyncio
async def test_200_findings_batch_no_loss():
    """Simulate nuclei dumping 200 findings rapidly. All must be delivered
    to a subscriber and recoverable via replay, in strict order."""
    TASK = "integ-200-findings"
    TOTAL = 200

    received: list[dict] = []

    async def _consumer():
        async for ev in event_stream.subscribe(TASK, last_id="$"):
            received.append(ev)
            if len(received) >= TOTAL:
                break

    consumer = asyncio.create_task(_consumer())
    await asyncio.sleep(0.02)

    published_ids = []
    for i in range(TOTAL):
        sid = await event_stream.publish(
            TASK, type="decision_event",
            payload={
                "action": "tool_result",
                "tool": "nuclei",
                "display_tool": "nuclei",
                "finding_index": i,
                "message": f"[critical] CVE-2026-{1000+i} on target",
            },
        )
        published_ids.append(sid)

    await asyncio.wait_for(consumer, timeout=10.0)

    # Subscriber got all 200
    assert len(received) == TOTAL
    sub_indices = [ev["payload"]["finding_index"] for ev in received]
    assert sub_indices == list(range(TOTAL))

    # Replay also returns all 200
    replayed = await event_stream.replay(TASK, after_id="0", count=5000)
    assert len(replayed) == TOTAL
    replay_indices = [ev["payload"]["finding_index"] for ev in replayed]
    assert replay_indices == list(range(TOTAL))

    # IDs from subscriber match IDs from replay
    sub_ids = [ev["id"] for ev in received]
    replay_ids = [ev["id"] for ev in replayed]
    assert sub_ids == replay_ids


# ── Scenario 5b: Concurrent publish + subscribe race ──

@pytest.mark.asyncio
async def test_concurrent_publish_subscribe_no_loss():
    """Multiple publishers + single subscriber: no events lost or duplicated."""
    TASK = "integ-concurrent"
    PER_PUBLISHER = 50
    NUM_PUBLISHERS = 4
    TOTAL = PER_PUBLISHER * NUM_PUBLISHERS

    received: list[dict] = []

    async def _consumer():
        async for ev in event_stream.subscribe(TASK, last_id="$"):
            received.append(ev)
            if len(received) >= TOTAL:
                break

    consumer = asyncio.create_task(_consumer())
    await asyncio.sleep(0.02)

    async def _publisher(pub_id: int):
        for i in range(PER_PUBLISHER):
            await event_stream.publish(
                TASK, type="log",
                payload={"pub": pub_id, "seq": i},
            )

    publishers = [asyncio.create_task(_publisher(p)) for p in range(NUM_PUBLISHERS)]
    await asyncio.gather(*publishers)
    await asyncio.wait_for(consumer, timeout=10.0)

    assert len(received) == TOTAL

    # No duplicate IDs
    seen_ids = set()
    for ev in received:
        eid = ev["id"]
        assert eid not in seen_ids, f"duplicate event id: {eid}"
        seen_ids.add(eid)


# ── Scenario 6: Subscribe → replay handoff (no gap, no overlap) ──

@pytest.mark.asyncio
async def test_replay_then_subscribe_seamless_handoff():
    """The "replay then subscribe" pattern used by ws.py: replay returns
    events up to last_id, then subscribe(last_id=last_id) picks up exactly
    where replay left off with zero overlap or gap."""
    TASK = "integ-handoff"

    # Pre-populate 30 events
    pre_ids = []
    for i in range(30):
        sid = await event_stream.publish(
            TASK, type="log", payload={"i": i},
        )
        pre_ids.append(sid)

    # Step 1: replay from start
    history = await event_stream.replay(TASK, after_id="0", count=5000)
    assert len(history) == 30
    replay_last_id = history[-1]["id"]

    # Step 2: start subscriber from replay_last_id
    live: list[dict] = []

    async def _consumer():
        async for ev in event_stream.subscribe(TASK, last_id=replay_last_id):
            live.append(ev)
            if len(live) >= 10:
                break

    consumer = asyncio.create_task(_consumer())
    await asyncio.sleep(0.02)

    # Step 3: publish 10 more events
    post_ids = []
    for i in range(30, 40):
        sid = await event_stream.publish(
            TASK, type="log", payload={"i": i},
        )
        post_ids.append(sid)

    await asyncio.wait_for(consumer, timeout=5.0)

    # Subscriber should get exactly the 10 new events
    assert len(live) == 10
    live_indices = [ev["payload"]["i"] for ev in live]
    assert live_indices == list(range(30, 40))

    # No overlap with replay
    replay_ids_set = {ev["id"] for ev in history}
    for ev in live:
        assert ev["id"] not in replay_ids_set, "overlap between replay and subscribe"


# ── Scenario 7: Envelope shape contract ──

@pytest.mark.asyncio
async def test_envelope_wire_format_contract():
    """Verify every event from replay/subscribe carries the full v2 envelope."""
    TASK = "integ-envelope"

    await event_stream.publish(
        TASK, type="decision_event",
        payload={"action": "tool_start", "tool": "nmap", "display_tool": "nmap"},
        branch_id="b-test-123",
    )
    await event_stream.publish(
        TASK, type="log",
        payload={"line": "[12:00:00] [recon] scanning...", "seq": 0},
    )
    await event_stream.publish(
        TASK, type="phase_update",
        payload={"phase": "recon", "status": "running"},
    )

    events = await event_stream.replay(TASK, after_id="0", count=100)
    assert len(events) == 3

    for ev in events:
        assert isinstance(ev["id"], str) and ev["id"], "missing id"
        assert ev["task_id"] == TASK, "wrong task_id"
        assert isinstance(ev["branch_id"], str), "branch_id must be string"
        assert isinstance(ev["ts"], str) and "T" in ev["ts"], "ts must be ISO"
        assert ev["v"] >= 2, "protocol version must be >= 2"
        assert isinstance(ev["type"], str) and ev["type"], "missing type"
        assert isinstance(ev["payload"], dict), "payload must be dict"

    # Specific checks
    assert events[0]["type"] == "decision_event"
    assert events[0]["branch_id"] == "b-test-123"
    assert events[0]["payload"]["action"] == "tool_start"
    assert events[1]["type"] == "log"
    assert events[2]["type"] == "phase_update"


# ── Scenario 8: drop() cleans up + new task_id reuse is clean ──

@pytest.mark.asyncio
async def test_drop_then_reuse_task_id():
    """After drop(), a new session with the same task_id starts fresh."""
    TASK = "integ-drop-reuse"

    for i in range(10):
        await event_stream.publish(TASK, type="log", payload={"gen": 1, "i": i})

    await event_stream.drop(TASK)

    residual = await event_stream.replay(TASK, after_id="0", count=100)
    assert residual == [], "drop should clear all events"

    # New session
    for i in range(5):
        await event_stream.publish(TASK, type="log", payload={"gen": 2, "i": i})

    fresh = await event_stream.replay(TASK, after_id="0", count=100)
    assert len(fresh) == 5
    assert all(ev["payload"]["gen"] == 2 for ev in fresh)

    length = await event_stream.stream_length(TASK)
    assert length == 5
