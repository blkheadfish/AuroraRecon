"""
Regression tests for TaskStateManager.

Covers the refactored surface:
  - to_summary / to_detail expose workflow_mode + per-task fields
    and drop the deprecated operator_role.
  - register_bg_task / cancel_bg_task / unregister_bg_task behave as a
    proper ownership registry (cancel previous handle on re-register,
    cancel returns False after task is done, unregister is idempotent).
"""
from __future__ import annotations

import asyncio

import pytest

from backend.agents.models import PentestState, apply_mode_defaults
from backend.api.state import TaskStateManager


class TestSummaryAndDetailFields:
    def test_summary_includes_workflow_mode_and_auto_approve(self):
        sm = TaskStateManager()
        state = PentestState(
            task_id="t1",
            target="http://example.com",
            workflow_mode="ctf_expert",
        )
        apply_mode_defaults(state)
        summary = sm.to_summary(state)

        assert summary["task_id"] == "t1"
        assert summary["workflow_mode"] == "ctf_expert"
        assert summary["auto_approve"] is True
        assert "operator_role" not in summary

    def test_detail_exposes_per_task_runtime_params(self):
        sm = TaskStateManager()
        state = PentestState(
            task_id="t2",
            target="http://example.com",
            workflow_mode="pentest_engineer",
        )
        apply_mode_defaults(
            state,
            overrides={"max_react_rounds": 11, "risk_budget": 2},
        )
        detail = sm.to_detail(state)

        assert detail["workflow_mode"] == "pentest_engineer"
        assert detail["auto_approve"] is False
        assert detail["max_react_rounds"] == 11
        assert detail["risk_budget"] == 2
        for key in (
            "success_gate_level",
            "max_explore_rounds",
            "skill_min_score",
            "skill_weak_boost",
        ):
            assert key in detail, f"detail missing per-task key {key}"
        assert "operator_role" not in detail


class TestBackgroundTaskRegistry:
    @pytest.mark.asyncio
    async def test_register_then_cancel(self):
        sm = TaskStateManager()

        async def _work():
            await asyncio.sleep(10)

        task = asyncio.create_task(_work())
        sm.register_bg_task("t1", task)

        assert sm.cancel_bg_task("t1") is True, (
            "cancel_bg_task must return True when the task is live"
        )
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled()

    @pytest.mark.asyncio
    async def test_cancel_unknown_returns_false(self):
        sm = TaskStateManager()
        assert sm.cancel_bg_task("never-registered") is False

    @pytest.mark.asyncio
    async def test_register_replaces_and_cancels_previous(self):
        sm = TaskStateManager()

        async def _hold():
            await asyncio.sleep(10)

        first = asyncio.create_task(_hold())
        sm.register_bg_task("same", first)

        second = asyncio.create_task(_hold())
        sm.register_bg_task("same", second)

        with pytest.raises(asyncio.CancelledError):
            await first
        assert first.cancelled()
        assert not second.done()

        sm.cancel_bg_task("same")
        with pytest.raises(asyncio.CancelledError):
            await second

    @pytest.mark.asyncio
    async def test_unregister_is_idempotent(self):
        sm = TaskStateManager()

        async def _quick():
            return "done"

        task = asyncio.create_task(_quick())
        sm.register_bg_task("t2", task)
        await task

        assert sm.cancel_bg_task("t2") is False
        sm.unregister_bg_task("t2")
        sm.unregister_bg_task("t2")
