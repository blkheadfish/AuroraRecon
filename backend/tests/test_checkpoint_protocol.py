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

import pytest

from backend.agents.models import PentestState, TaskStatus, VulnFinding
from backend.agents.orchestrator import node_human_approval
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


class TestCheckpointHelpers:
    def test_open_checkpoint_registers_pending_and_emits_decision(self):
        state = _build_state()

        ckpt = state.open_checkpoint({
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
            e for e in state.live_decision_events
            if e.get("action") == "checkpoint_request"
        ]
        assert len(emitted) == 1
        assert emitted[0]["checkpoint_id"] == ckpt["checkpoint_id"]
        assert emitted[0]["checkpoint_type"] == "exploit_gate"
        assert emitted[0]["tone"] == "warning"

    def test_resolve_checkpoint_archives_and_persists_user_prompt(self):
        state = _build_state()
        ckpt = state.open_checkpoint({
            "checkpoint_type": "exploit_gate",
            "summary": "approve",
        })

        archived = state.resolve_checkpoint({
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
        # Soft-guidance: pending_user_prompt should now carry the modify text
        assert "先验证 LFI 再尝试 RCE" in state.pending_user_prompt
        # The user prompt should also be appended to user_messages timeline
        assert state.user_messages[-1]["text"] == "先验证 LFI 再尝试 RCE"

        emitted = [
            e for e in state.live_decision_events
            if e.get("action") == "checkpoint_resolved"
        ]
        assert len(emitted) == 1
        assert emitted[0]["response"]["user_prompt"] == "先验证 LFI 再尝试 RCE"
        assert emitted[0]["tone"] == "info"  # modify → info tone

    def test_resolve_checkpoint_no_pending_returns_none(self):
        state = _build_state()
        archived = state.resolve_checkpoint({"action": "approve"})
        assert archived is None

    def test_resolve_appends_prompts_when_called_back_to_back(self):
        state = _build_state()
        state.open_checkpoint({"checkpoint_type": "exploit_gate"})
        state.resolve_checkpoint({"action": "modify", "user_prompt": "first"})
        state.open_checkpoint({"checkpoint_type": "post_foothold_gate"})
        state.resolve_checkpoint({"action": "modify", "user_prompt": "second"})

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
        # 选项 + 默认动作 + 上下文都应该存在
        assert any(opt.get("action") == "approve" for opt in state.pending_checkpoint["options"])
        ctx = state.pending_checkpoint["context"]
        assert ctx["exploitable_count"] == 1
        assert ctx["workflow_mode"] == "pentest_engineer"

    @pytest.mark.asyncio
    async def test_router_approve_then_node_clears_checkpoint(self):
        state = _build_state(auto_approve=False)
        # 第一遍:节点产生 pending checkpoint
        await node_human_approval(state)
        assert state.pending_checkpoint is not None
        # 模拟 router 通过 /checkpoint/respond 把 approved=True 写回, 再 resume
        state.approved = True
        state.resolve_checkpoint({"action": "approve"})
        await node_human_approval(state)
        assert state.pending_checkpoint is None

    @pytest.mark.asyncio
    async def test_auto_approve_does_not_open_checkpoint(self):
        state = _build_state(auto_approve=True)
        await node_human_approval(state)
        assert state.pending_checkpoint is None
