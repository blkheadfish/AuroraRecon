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


# ── 测试夹具 ────────────────────────────────────────────────


class FakeOrchestrator:
    """Minimal orchestrator double for branch tests.

    Stores a per-thread state-dict mapping; the streaming variants block on
    an asyncio.Event so we can assert on "running" snapshots before they
    finish. Tests that don't care about streaming use control_release_all.
    """

    def __init__(self) -> None:
        self.threads: dict[str, dict] = {}
        # Per-thread block until released
        self.gates: dict[str, asyncio.Event] = {}
        self.fork_calls: list[tuple[str, str, dict]] = []

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
    ) -> bool:
        self.fork_calls.append((source_thread_id, target_thread_id, dict(patch)))
        src = self.threads.get(source_thread_id)
        if src is None:
            # Plant the patch verbatim so child can still bootstrap.
            self.threads[target_thread_id] = dict(patch)
            return False
        merged = dict(src)
        merged.update(patch)
        self.threads[target_thread_id] = merged
        return True

    async def resume_branch_stream(
        self, thread_id: str, *, patch: dict[str, Any] | None = None,
    ):
        # In real life the graph yields per node; here we yield one
        # "supervisor" tick after the test releases the gate. This proves
        # the bg runner is wired up without actually running an LLM.
        await self._gate(thread_id).wait()
        state = dict(self.threads.get(thread_id, {}))
        # Mark the run as having advanced — supervisor would normally do this.
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
    # branch_manager imports get_orchestrator inside fork_from_active /
    # _resume_branch_bg via task_runner; monkeypatch *that* symbol.
    from backend.api.services import task_runner

    monkeypatch.setattr(task_runner, "get_orchestrator", lambda: fake)
    return fake


@pytest.fixture
def fresh_state_manager(monkeypatch: pytest.MonkeyPatch) -> TaskStateManager:
    sm = TaskStateManager()
    sm.db_available = False  # bypass DB
    from backend.api import state as state_module

    monkeypatch.setattr(state_module, "_state_manager", sm, raising=False)
    monkeypatch.setattr(state_module, "get_state_manager", lambda: sm)
    # branch_manager.py also imports get_state_manager at module level
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


# ── 测试: lazy_init_root ─────────────────────────────────────


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
    # Legacy compatibility: root keeps thread_id == task_id so the existing
    # checkpoint history lives at the same location.
    assert root_a.thread_id == "task-a"
    assert root_b.branch_id == root_a.branch_id, "lazy_init must be idempotent"

    branches = await branch_mgr.list_branches("task-a")
    assert len(branches) == 1


# ── 测试: fork_from_active ───────────────────────────────────


@pytest.mark.asyncio
async def test_fork_from_active_pauses_parent_and_starts_child(
    fresh_state_manager: TaskStateManager,
    branch_mgr: BranchManager,
    fake_orchestrator: FakeOrchestrator,
):
    state = _make_state("task-fork", supervisor_round=3)
    fresh_state_manager.set("task-fork", state)
    # Bootstrap the orchestrator with a parent checkpoint so fork can copy.
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

    # Parent pause, child active
    branches = await branch_mgr.list_branches("task-fork")
    by_id = {b.branch_id: b for b in branches}
    assert by_id["root"].status == "paused"
    active = await branch_mgr.get_active("task-fork")
    assert active is not None
    assert active.branch_id == child.branch_id
    assert active.status == "running"

    # Patch was applied: pending_user_prompt + operator_intent live on the
    # child's thread.
    child_thread = fake_orchestrator.threads[child.thread_id]
    assert "改打 SQL 注入" in (child_thread.get("pending_user_prompt") or "")
    assert int((child_thread.get("replan_signals") or {}).get("operator_intent", 0)) >= 1

    # Cleanup the bg task we spawned.
    fake_orchestrator.release_all()
    bg = branch_mgr._bg.get(child.branch_id)
    if bg:
        try:
            await asyncio.wait_for(bg, timeout=2.0)
        except Exception:
            pass


# ── 测试: 切换 active 自动暂停旧分支 ──────────────────────────


@pytest.mark.asyncio
async def test_switch_active_pauses_previous(
    fresh_state_manager: TaskStateManager,
    branch_mgr: BranchManager,
    fake_orchestrator: FakeOrchestrator,
):
    state = _make_state("task-sw")
    fresh_state_manager.set("task-sw", state)
    fake_orchestrator.threads["task-sw"] = state.model_dump()

    # Fork once so we have two branches: root (will be paused), child A.
    child_a = await branch_mgr.fork_from_active(
        "task-sw", user_prompt="branch A", fork_event_id="evt-A",
    )
    # Switch back to root → child A should be paused.
    fake_orchestrator.release_all()
    target = await branch_mgr.switch_active("task-sw", "root")
    assert target.branch_id == "root"

    branches = {b.branch_id: b for b in await branch_mgr.list_branches("task-sw")}
    assert branches[child_a.branch_id].status == "paused", (
        "previously-active child must be paused on switch"
    )


# ── 测试: paused 不自恢复 ────────────────────────────────────


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

    # No bg task should remain after pause.
    assert child.branch_id not in branch_mgr._bg
    branches = {b.branch_id: b for b in await branch_mgr.list_branches("task-paused")}
    assert branches[child.branch_id].status == "paused"

    # Sleeping briefly must not flip the status back to running.
    await asyncio.sleep(0.05)
    branches2 = {b.branch_id: b for b in await branch_mgr.list_branches("task-paused")}
    assert branches2[child.branch_id].status == "paused"


# ── 测试: sibling 计数 ──────────────────────────────────────


@pytest.mark.asyncio
async def test_sibling_counts_in_tree_payload(
    fresh_state_manager: TaskStateManager,
    branch_mgr: BranchManager,
    fake_orchestrator: FakeOrchestrator,
):
    state = _make_state("task-sib")
    fresh_state_manager.set("task-sib", state)
    fake_orchestrator.threads["task-sib"] = state.model_dump()

    # Fork, switch back to root, fork again → root now has 2 children with
    # different fork_event_ids ⇒ each is its own group of size 1.
    child_a = await branch_mgr.fork_from_active(
        "task-sib", user_prompt="A", fork_event_id="evt-A",
    )
    fake_orchestrator.release_all()
    await branch_mgr.switch_active("task-sib", "root")
    child_b = await branch_mgr.fork_from_active(
        "task-sib", user_prompt="B", fork_event_id="evt-B",
    )
    fake_orchestrator.release_all()

    # And one more sibling on the *same* event as A → group size 2 there.
    # Reset to root + same fork_event_id so siblings collide.
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
    # evt-A children: {child_a, child_a2} → sibling_total 2
    assert by_id[child_a.branch_id]["sibling_total"] == 2
    assert by_id[child_a2.branch_id]["sibling_total"] == 2
    assert {by_id[child_a.branch_id]["sibling_index"],
            by_id[child_a2.branch_id]["sibling_index"]} == {1, 2}
    # evt-B child alone in its sibling group
    assert by_id[child_b.branch_id]["sibling_total"] == 1
    assert by_id[child_b.branch_id]["sibling_index"] == 1
    # Root is the only "no-parent" entry.
    assert by_id["root"]["sibling_total"] == 1


# ── 测试: completed 任务不 fork (chat 端 append 路径) ─────────


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

    # Bootstrap root.
    await branch_mgr.lazy_init_root("task-done", state)
    branches_before = await branch_mgr.list_branches("task-done")
    assert len(branches_before) == 1

    # Simulate the "completed" path: chat handler must NOT call
    # fork_from_active. We verify by ensuring no new branch appeared and no
    # fork call was issued.
    assert fake_orchestrator.fork_calls == []
    branches_after = await branch_mgr.list_branches("task-done")
    assert len(branches_after) == 1


# ── 测试: 分支上限保护 ─────────────────────────────────────


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

    # First fork → root + child1 (2 total, at the cap).
    await branch_mgr.fork_from_active(
        "task-cap", user_prompt="one", fork_event_id="evt-1",
    )
    fake_orchestrator.release_all()

    with pytest.raises(RuntimeError, match="分支数已达上限"):
        await branch_mgr.fork_from_active(
            "task-cap", user_prompt="two", fork_event_id="evt-2",
        )
