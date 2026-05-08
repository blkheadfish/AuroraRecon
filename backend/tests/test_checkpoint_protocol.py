"""Regression tests for the generic Plan-style checkpoint protocol.

Covers the full contract surface:
  - ``state.open_checkpoint`` registers a pending checkpoint and emits a
    ``checkpoint_request`` decision event so the live timeline / Plan card
    can render immediately.
  - ``state.resolve_checkpoint`` archives the checkpoint, clears the pending
    slot, persists the user prompt to ``pending_user_prompt`` (soft-guidance
    consumed by the next node) and emits a ``checkpoint_resolved`` event.
  - ``to_detail_snapshot`` exposes ``pending_checkpoint`` /
    ``checkpoint_history`` / ``pending_user_prompt`` so a freshly-loaded
    detail page can rehydrate the confirmation card without polling.
  - ``node_human_approval`` opens an ``exploit_gate`` checkpoint when
    ``auto_approve=False`` and clears it once approval is granted.
"""
from __future__ import annotations

import asyncio

import pytest

from backend.agents.models import PentestState, TaskStatus, VulnFinding
from backend.agents.orchestrator import node_human_approval
from backend.api.event_bus import (
    set_task_sink, clear_task_sink,
    set_task_loop, clear_task_loop,
)
from backend.api.state import TaskStateManager


def _build_state(*, auto_approve: bool = False, exploitable: bool = True) -> PentestState:
    state = PentestState(task_id="cp-1", target="http://x")
    state.auto_approve = auto_approve
    state.status = TaskStatus.RUNNING
    if exploitable:
        state.findings.append(
            VulnFinding(
                name="LFI",
                target="http://x",
                severity="high",
                exploitable=True,
            )
        )
    return state


class _DecisionCapture:
    """协议 v2: ``push_decision`` 不再 append 到 state, 走 sink 投递。
    这个 helper 注册一个 sink 把投递到 EventBus 的事件捕获到 list 里, 测试
    再断言 list 内容。

    用法::

        with _DecisionCapture(state) as cap:
            asyncio.run(...)
        assert cap.events[-1]["action"] == ...

    必须在 ``asyncio.run`` 里调用 ``state.push_decision`` (或调用方法间接触发),
    因为 ``push_decision`` 派发用 ``loop.create_task``。
    """

    def __init__(self, state: PentestState) -> None:
        self.state = state
        self.events: list[dict] = []

    def __enter__(self) -> "_DecisionCapture":
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        set_task_loop(self.state.task_id, self._loop)

        async def _sink(ev: dict) -> None:
            self.events.append(dict(ev))

        set_task_sink(self.state.task_id, _sink)
        return self

    def __exit__(self, *exc) -> None:
        clear_task_sink(self.state.task_id)
        clear_task_loop(self.state.task_id)
        try:
            pending = asyncio.all_tasks(self._loop)
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        self._loop.close()
        asyncio.set_event_loop(None)

    def run(self, coro_factory):
        """在 capture loop 里跑一段协程, 同时跑两轮 sleep(0) 让 sink 落盘。"""
        async def _go():
            result = await coro_factory()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            return result
        return self._loop.run_until_complete(_go())

    def call_sync(self, fn, *args, **kwargs):
        """同步方法 (如 ``state.open_checkpoint``) 内会用 ``loop.create_task``
        派发 sink, 必须把这次调用放在 capture loop 上下文里执行, 然后跑两轮
        ``sleep(0)`` 让 sink 真正写入 events。"""
        async def _go():
            result = fn(*args, **kwargs)
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            return result
        return self._loop.run_until_complete(_go())


class TestCheckpointHelpers:
    def test_open_checkpoint_registers_pending_and_emits_decision(self):
        state = _build_state()
        with _DecisionCapture(state) as cap:
            ckpt = cap.call_sync(state.open_checkpoint, {
                "checkpoint_type": "exploit_gate",
                "summary": "approve before exploit",
                "thinking": "1 high finding",
                "recommendation": "approve",
                "risk": "高风险",
                "options": [
                    {"id": "approve", "label": "go", "action": "approve"},
                    {"id": "reject", "label": "stop", "action": "reject"},
                ],
            })

        assert state.pending_checkpoint is not None
        assert state.pending_checkpoint["checkpoint_id"] == ckpt["checkpoint_id"]
        assert state.pending_checkpoint["status"] == "pending"
        assert state.pending_checkpoint["risk"] == "高风险"

        emitted = [
            e for e in cap.events
            if e.get("action") == "checkpoint_request"
        ]
        assert len(emitted) == 1
        assert emitted[0]["checkpoint_id"] == ckpt["checkpoint_id"]
        assert emitted[0]["checkpoint_type"] == "exploit_gate"
        assert emitted[0]["tone"] == "warning"

    def test_resolve_checkpoint_archives_and_persists_user_prompt(self):
        state = _build_state()
        with _DecisionCapture(state) as cap:
            ckpt = cap.call_sync(state.open_checkpoint, {
                "checkpoint_type": "exploit_gate",
                "summary": "approve",
            })
            archived = cap.call_sync(state.resolve_checkpoint, {
                "action": "modify",
                "selected_option": "modify",
                "user_prompt": "先验证 LFI 再尝试 RCE",
            })

        assert archived is not None
        assert archived["status"] == "resolved"
        assert archived["response"]["action"] == "modify"
        assert archived["response"]["user_prompt"] == "先验证 LFI 再尝试 RCE"
        assert state.pending_checkpoint is None
        assert state.checkpoint_history[-1]["checkpoint_id"] == ckpt["checkpoint_id"]
        assert "先验证 LFI 再尝试 RCE" in state.pending_user_prompt
        assert state.user_messages[-1]["text"] == "先验证 LFI 再尝试 RCE"

        emitted = [
            e for e in cap.events
            if e.get("action") == "checkpoint_resolved"
        ]
        assert len(emitted) == 1
        assert emitted[0]["response"]["user_prompt"] == "先验证 LFI 再尝试 RCE"
        assert emitted[0]["tone"] == "info"

    def test_resolve_checkpoint_no_pending_returns_none(self):
        state = _build_state()
        archived = state.resolve_checkpoint({"action": "approve"})
        assert archived is None

    def test_resolve_appends_prompts_when_called_back_to_back(self):
        state = _build_state()
        with _DecisionCapture(state) as cap:
            cap.call_sync(state.open_checkpoint, {"checkpoint_type": "exploit_gate"})
            cap.call_sync(state.resolve_checkpoint, {"action": "modify", "user_prompt": "first"})
            cap.call_sync(state.open_checkpoint, {"checkpoint_type": "post_foothold_gate"})
            cap.call_sync(state.resolve_checkpoint, {"action": "modify", "user_prompt": "second"})

        assert "first" in state.pending_user_prompt
        assert "second" in state.pending_user_prompt
        assert state.pending_user_prompt.index("first") < state.pending_user_prompt.index("second")
        assert len(state.checkpoint_history) == 2


class TestSnapshotExposesCheckpointFields:
    def test_pending_checkpoint_visible_after_open(self):
        state = _build_state()
        state.open_checkpoint({
            "checkpoint_type": "exploit_gate",
            "summary": "approve before exploit",
        })
        sm = TaskStateManager()
        snap = sm.to_detail_snapshot(state)
        assert snap["pending_checkpoint"] is not None
        assert snap["pending_checkpoint"]["checkpoint_type"] == "exploit_gate"
        assert snap["checkpoint_history"] == []
        assert snap["pending_user_prompt"] == ""

    def test_history_visible_and_pending_cleared_after_resolve(self):
        state = _build_state()
        state.open_checkpoint({"checkpoint_type": "exploit_gate"})
        state.resolve_checkpoint({"action": "approve", "user_prompt": "go"})
        sm = TaskStateManager()
        snap = sm.to_detail_snapshot(state)
        assert snap["pending_checkpoint"] is None
        assert len(snap["checkpoint_history"]) == 1
        assert snap["checkpoint_history"][-1]["status"] == "resolved"
        assert snap["pending_user_prompt"] == "go"

    def test_full_detail_includes_full_checkpoint_history(self):
        state = _build_state()
        for _ in range(3):
            state.open_checkpoint({"checkpoint_type": "exploit_gate"})
            state.resolve_checkpoint({"action": "approve"})
        sm = TaskStateManager()
        full = sm.to_detail(state)
        assert len(full["checkpoint_history"]) == 3


class TestNodeHumanApprovalCheckpoint:
    @pytest.mark.asyncio
    async def test_manual_pending_opens_checkpoint(self):
        state = _build_state(auto_approve=False)
        await node_human_approval(state)
        assert state.pending_checkpoint is not None
        assert state.pending_checkpoint["checkpoint_type"] == "exploit_gate"
        assert any(opt.get("action") == "approve" for opt in state.pending_checkpoint["options"])
        ctx = state.pending_checkpoint["context"]
        assert ctx["exploitable_count"] == 1
        assert ctx["workflow_mode"] == "pentest_engineer"

    @pytest.mark.asyncio
    async def test_router_approve_then_node_clears_checkpoint(self):
        state = _build_state(auto_approve=False)
        await node_human_approval(state)
        assert state.pending_checkpoint is not None
        state.approved = True
        state.resolve_checkpoint({"action": "approve"})
        await node_human_approval(state)
        assert state.pending_checkpoint is None

    @pytest.mark.asyncio
    async def test_auto_approve_does_not_open_checkpoint(self):
        state = _build_state(auto_approve=True)
        await node_human_approval(state)
        assert state.pending_checkpoint is None
