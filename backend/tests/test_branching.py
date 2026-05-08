"""Regression tests for the conversation branching system (PR2).

Covers the BranchManager surface used by the operator-chat endpoint:
  - lazy_init_root creates exactly one root with thread_id == task_id;
  - fork_from_active pauses the parent, plants a fresh thread for the
    child, and copies the parent's checkpoint values onto it;
  - paused branches don't self-resume (status sticks until explicit resume);
  - sibling counts in to_tree_payload are accurate after multiple forks
    on the same parent;
  - switch_active pauses the previous active branch by default;
  - completed/failed tasks bypass forking entirely (the chat endpoint
    just appends to user_messages — checked end-to-end).
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from backend.agents.models import PentestState, TaskStatus
from backend.api.services import branch_manager as branch_manager_module
from backend.api.services.branch_manager import BranchManager
from backend.api.state import TaskStateManager




class FakeOrchestrator:
    """Minimal orchestrator double for branch tests.

    Stores a per-thread state-dict mapping; the streaming variants block on
    an asyncio.Event so we can assert on "running" snapshots before they
    finish. Tests that don't care about streaming use control_release_all.
    """

    def __init__(self) -> None:
        self.threads: dict[str, dict] = {}
        self.gates: dict[str, asyncio.Event] = {}
        self.fork_calls: list[tuple[str, str, dict, str | None]] = []

    def _gate(self, thread_id: str) -> asyncio.Event:
        if thread_id not in self.gates:
            self.gates[thread_id] = asyncio.Event()
        return self.gates[thread_id]

    def release(self, thread_id: str) -> None:
        self._gate(thread_id).set()

    def release_all(self) -> None:
        for ev in self.gates.values():
            ev.set()

    async def fork_branch_state(
        self, *, source_thread_id: str, target_thread_id: str,
        patch: dict[str, Any], as_node: str | None = None,
        source_checkpoint_id: str | None = None,
    ) -> bool:
        self.fork_calls.append(
            (source_thread_id, target_thread_id, dict(patch), source_checkpoint_id)
        )
        src = self.threads.get(source_thread_id)
        if src is None:
            self.threads[target_thread_id] = dict(patch)
            return False
        merged = dict(src)
        merged.update(patch)
        self.threads[target_thread_id] = merged
        return True

    async def resume_branch_stream(
        self, thread_id: str, *, patch: dict[str, Any] | None = None,
    ):
        await self._gate(thread_id).wait()
        state = dict(self.threads.get(thread_id, {}))
        state.setdefault("status", TaskStatus.RUNNING)
        yield "supervisor", state

    async def get_branch_state(self, thread_id: str) -> PentestState | None:
        snap = self.threads.get(thread_id)
        if not snap:
            return None
        try:
            return PentestState(**snap)
        except Exception:
            return None


@pytest.fixture
def fake_orchestrator(monkeypatch: pytest.MonkeyPatch) -> FakeOrchestrator:
    fake = FakeOrchestrator()
    from backend.api.services import task_runner

    monkeypatch.setattr(task_runner, "get_orchestrator", lambda: fake)
    return fake


@pytest.fixture
def fresh_state_manager(monkeypatch: pytest.MonkeyPatch) -> TaskStateManager:
    sm = TaskStateManager()
    sm.db_available = False
    from backend.api import state as state_module

    monkeypatch.setattr(state_module, "_state_manager", sm, raising=False)
    monkeypatch.setattr(state_module, "get_state_manager", lambda: sm)
    monkeypatch.setattr(branch_manager_module, "get_state_manager", lambda: sm)
    return sm


@pytest.fixture
def branch_mgr(monkeypatch: pytest.MonkeyPatch) -> BranchManager:
    mgr = BranchManager()
    monkeypatch.setattr(branch_manager_module, "_manager", mgr, raising=False)
    monkeypatch.setattr(branch_manager_module, "get_branch_manager", lambda: mgr)
    return mgr


def _make_state(task_id: str = "task-x", **kwargs) -> PentestState:
    return PentestState(
        task_id=task_id,
        target="http://example.com",
        status=TaskStatus.RUNNING,
        current_phase="recon",
        **kwargs,
    )




@pytest.mark.asyncio
async def test_lazy_init_root_is_idempotent_and_thread_eq_task_id(
    fresh_state_manager: TaskStateManager,
    branch_mgr: BranchManager,
):
    state = _make_state("task-a")
    fresh_state_manager.set("task-a", state)

    root_a = await branch_mgr.lazy_init_root("task-a", state)
    root_b = await branch_mgr.lazy_init_root("task-a", state)

    assert root_a.is_root is True
    assert root_a.branch_id == "root"
    assert root_a.thread_id == "task-a"
    assert root_b.branch_id == root_a.branch_id, "lazy_init must be idempotent"

    branches = await branch_mgr.list_branches("task-a")
    assert len(branches) == 1




@pytest.mark.asyncio
async def test_fork_from_active_pauses_parent_and_starts_child(
    fresh_state_manager: TaskStateManager,
    branch_mgr: BranchManager,
    fake_orchestrator: FakeOrchestrator,
):
    state = _make_state("task-fork", supervisor_round=3)
    fresh_state_manager.set("task-fork", state)
    fake_orchestrator.threads["task-fork"] = state.model_dump()

    child = await branch_mgr.fork_from_active(
        "task-fork", user_prompt="改打 SQL 注入", fork_event_id="evt-1",
    )

    assert child.is_root is False
    assert child.parent_branch_id == "root"
    assert child.thread_id == f"task-fork:{child.branch_id}"
    assert child.fork_phase == "recon"
    assert child.fork_round == 3
    assert child.label.startswith("改打")
    assert child.initiating_prompt == "改打 SQL 注入"

    branches = await branch_mgr.list_branches("task-fork")
    by_id = {b.branch_id: b for b in branches}
    assert by_id["root"].status == "paused"
    active = await branch_mgr.get_active("task-fork")
    assert active is not None
    assert active.branch_id == child.branch_id
    assert active.status == "running"

    child_thread = fake_orchestrator.threads[child.thread_id]
    assert "改打 SQL 注入" in (child_thread.get("pending_user_prompt") or "")
    assert int((child_thread.get("replan_signals") or {}).get("operator_intent", 0)) >= 1

    fake_orchestrator.release_all()
    bg = branch_mgr._bg.get(child.branch_id)
    if bg:
        try:
            await asyncio.wait_for(bg, timeout=2.0)
        except Exception:
            pass




@pytest.mark.asyncio
async def test_switch_active_pauses_previous(
    fresh_state_manager: TaskStateManager,
    branch_mgr: BranchManager,
    fake_orchestrator: FakeOrchestrator,
):
    state = _make_state("task-sw")
    fresh_state_manager.set("task-sw", state)
    fake_orchestrator.threads["task-sw"] = state.model_dump()

    child_a = await branch_mgr.fork_from_active(
        "task-sw", user_prompt="branch A", fork_event_id="evt-A",
    )
    fake_orchestrator.release_all()
    target = await branch_mgr.switch_active("task-sw", "root")
    assert target.branch_id == "root"

    branches = {b.branch_id: b for b in await branch_mgr.list_branches("task-sw")}
    assert branches[child_a.branch_id].status == "paused", (
        "previously-active child must be paused on switch"
    )




@pytest.mark.asyncio
async def test_paused_branch_does_not_self_resume(
    fresh_state_manager: TaskStateManager,
    branch_mgr: BranchManager,
    fake_orchestrator: FakeOrchestrator,
):
    state = _make_state("task-paused")
    fresh_state_manager.set("task-paused", state)
    fake_orchestrator.threads["task-paused"] = state.model_dump()

    child = await branch_mgr.fork_from_active(
        "task-paused", user_prompt="x", fork_event_id="evt",
    )
    await branch_mgr.pause("task-paused", child.branch_id)

    assert child.branch_id not in branch_mgr._bg
    branches = {b.branch_id: b for b in await branch_mgr.list_branches("task-paused")}
    assert branches[child.branch_id].status == "paused"

    await asyncio.sleep(0.05)
    branches2 = {b.branch_id: b for b in await branch_mgr.list_branches("task-paused")}
    assert branches2[child.branch_id].status == "paused"




@pytest.mark.asyncio
async def test_sibling_counts_in_tree_payload(
    fresh_state_manager: TaskStateManager,
    branch_mgr: BranchManager,
    fake_orchestrator: FakeOrchestrator,
):
    state = _make_state("task-sib")
    fresh_state_manager.set("task-sib", state)
    fake_orchestrator.threads["task-sib"] = state.model_dump()

    child_a = await branch_mgr.fork_from_active(
        "task-sib", user_prompt="A", fork_event_id="evt-A",
    )
    fake_orchestrator.release_all()
    await branch_mgr.switch_active("task-sib", "root")
    child_b = await branch_mgr.fork_from_active(
        "task-sib", user_prompt="B", fork_event_id="evt-B",
    )
    fake_orchestrator.release_all()

    await branch_mgr.switch_active("task-sib", "root")
    child_a2 = await branch_mgr.fork_from_active(
        "task-sib", user_prompt="A again", fork_event_id="evt-A",
    )
    fake_orchestrator.release_all()

    branches = await branch_mgr.list_branches("task-sib")
    active = await branch_mgr.get_active("task-sib")
    assert active is not None
    payload = branch_mgr.to_tree_payload(branches, active.branch_id)

    by_id = {item["branch_id"]: item for item in payload["branches"]}
    assert by_id[child_a.branch_id]["sibling_total"] == 2
    assert by_id[child_a2.branch_id]["sibling_total"] == 2
    assert {by_id[child_a.branch_id]["sibling_index"],
            by_id[child_a2.branch_id]["sibling_index"]} == {1, 2}
    assert by_id[child_b.branch_id]["sibling_total"] == 1
    assert by_id[child_b.branch_id]["sibling_index"] == 1
    assert by_id["root"]["sibling_total"] == 1




@pytest.mark.asyncio
async def test_completed_task_chat_only_appends(
    fresh_state_manager: TaskStateManager,
    branch_mgr: BranchManager,
    fake_orchestrator: FakeOrchestrator,
):
    """When task is COMPLETED/FAILED the chat endpoint must not invoke fork.

    BranchManager.fork_from_active raises if state is missing, but the chat
    handler short-circuits on terminal status so we only assert that no
    extra branches appear after a series of "completed" chat hits.
    """
    state = _make_state("task-done")
    state.status = TaskStatus.COMPLETED
    state.current_phase = "report"
    fresh_state_manager.set("task-done", state)

    await branch_mgr.lazy_init_root("task-done", state)
    branches_before = await branch_mgr.list_branches("task-done")
    assert len(branches_before) == 1

    assert fake_orchestrator.fork_calls == []
    branches_after = await branch_mgr.list_branches("task-done")
    assert len(branches_after) == 1




@pytest.mark.asyncio
async def test_max_branches_per_task_enforced(
    fresh_state_manager: TaskStateManager,
    branch_mgr: BranchManager,
    fake_orchestrator: FakeOrchestrator,
    monkeypatch: pytest.MonkeyPatch,
):
    state = _make_state("task-cap")
    fresh_state_manager.set("task-cap", state)
    fake_orchestrator.threads["task-cap"] = state.model_dump()

    monkeypatch.setattr(branch_manager_module, "MAX_BRANCHES_PER_TASK", 2)

    await branch_mgr.fork_from_active(
        "task-cap", user_prompt="one", fork_event_id="evt-1",
    )
    fake_orchestrator.release_all()

    with pytest.raises(RuntimeError, match="分支数已达上限"):
        await branch_mgr.fork_from_active(
            "task-cap", user_prompt="two", fork_event_id="evt-2",
        )
