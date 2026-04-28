"""branch_manager.py — 任务对话分支(Claude/Kimi 风格)的协调中心。

设计:
  - 每个 ``TaskBranch`` 拥有独立的 ``thread_id``;LangGraph checkpointer
    把每个 thread 的执行历史隔离, fork 后两条分支不会互相干扰。
  - root branch 兼容老任务: ``thread_id == task_id``, ``is_root=True``。
    第一次 fork 时若该任务还没有分支记录, 就先 ``lazy_init_root`` 把现有的
    内存/DB 任务包装成 root, 然后再 fork。
  - 持久化: 优先写到 ``task_branches`` 表(StateManager.db_available=True
    时), 失败/不可用回退到进程内字典(StateManager 内置)。
  - 切换分支默认 *不* 自动恢复运行, 用户在前端点"继续运行" 才会真正
    ``ainvoke`` 旧分支(避免误打目标 / 起冲突 session)。
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Optional

from backend.agents.interrupt_registry import (
    check_interrupt,
    request_interrupt,
)
from backend.agents.models import PentestState, TaskBranch, TaskStatus
from backend.api.event_bus import get_event_bus, set_task_sink
from backend.api.state import TaskStateManager, get_state_manager

logger = logging.getLogger(__name__)


# Bound for total branches per task; configurable via env.
import os as _os
MAX_BRANCHES_PER_TASK = max(2, int(_os.getenv("MAX_BRANCHES_PER_TASK", "12")))

# How long to wait for the active branch to gracefully yield before we hard
# cancel the bg task. Cooperative interrupts usually flip in <1s, but the
# ReAct LLM call may be in flight.
FORK_INTERRUPT_TIMEOUT_SEC = float(_os.getenv("FORK_INTERRUPT_TIMEOUT_SEC", "8.0"))


def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def _label_from_prompt(text: str, fallback: str = "") -> str:
    text = (text or "").strip().replace("\n", " ")
    if not text:
        return fallback
    return text[:30] + ("…" if len(text) > 30 else "")


class BranchManager:
    """Per-process branch service. Single instance accessed via ``get_branch_manager()``."""

    def __init__(self) -> None:
        # In-memory tree; persisted to ``task_branches`` table when available.
        # Map: task_id -> branch_id -> TaskBranch
        self._branches: dict[str, dict[str, TaskBranch]] = {}
        # Per-task active branch id pointer.
        self._active: dict[str, str] = {}
        # Per-branch background asyncio.Task (run / resume coroutines).
        self._bg: dict[str, asyncio.Task] = {}
        # Loaded-from-DB flag so we hydrate at most once per process.
        self._loaded: set[str] = set()
        self._lock = asyncio.Lock()

    # ── 持久化 ────────────────────────────────────────────────

    async def _hydrate_from_db(self, task_id: str) -> None:
        if task_id in self._loaded:
            return
        sm = get_state_manager()
        if not sm.db_available:
            self._loaded.add(task_id)
            return
        try:
            from backend.db.database import list_branches_by_task
            rows = await list_branches_by_task(task_id)
        except Exception as exc:
            logger.warning(
                f"[BranchManager] DB hydrate failed task={task_id}: {exc}"
            )
            rows = []
        bucket = self._branches.setdefault(task_id, {})
        for row in rows:
            br = TaskBranch(**{k: v for k, v in row.items() if k in TaskBranch.model_fields})
            bucket[br.branch_id] = br
            if br.is_root and not self._active.get(task_id):
                self._active[task_id] = br.branch_id
        # Pick most-recent running, else most-recent paused, as active fallback
        if task_id not in self._active and bucket:
            ordered = sorted(bucket.values(), key=lambda b: b.created_at)
            running = [b for b in ordered if b.status == "running"]
            self._active[task_id] = (running or ordered)[-1].branch_id
        self._loaded.add(task_id)

    async def _persist(self, branch: TaskBranch) -> None:
        sm = get_state_manager()
        if not sm.db_available:
            return
        try:
            from backend.db.database import upsert_branch
            await upsert_branch(branch.model_dump())
        except Exception as exc:
            logger.warning(
                f"[BranchManager] DB upsert failed branch={branch.branch_id}: {exc}"
            )

    # ── 公开 API ──────────────────────────────────────────────

    async def list_branches(self, task_id: str) -> list[TaskBranch]:
        await self._hydrate_from_db(task_id)
        bucket = self._branches.get(task_id, {})
        return sorted(bucket.values(), key=lambda b: b.created_at)

    async def get_active(self, task_id: str) -> Optional[TaskBranch]:
        await self._hydrate_from_db(task_id)
        bid = self._active.get(task_id)
        if not bid:
            return None
        return self._branches.get(task_id, {}).get(bid)

    async def get(self, task_id: str, branch_id: str) -> Optional[TaskBranch]:
        await self._hydrate_from_db(task_id)
        return self._branches.get(task_id, {}).get(branch_id)

    async def lazy_init_root(
        self, task_id: str, state: Optional[PentestState] = None,
    ) -> TaskBranch:
        """Ensure the task has a root branch.

        For legacy tasks the root's ``thread_id`` is set equal to ``task_id``
        — this means the existing LangGraph checkpoint history is not lost
        (it lives under that thread already). New tasks created via
        ``run_task`` may also rely on this when no explicit thread_id is
        passed.
        """
        await self._hydrate_from_db(task_id)
        bucket = self._branches.setdefault(task_id, {})
        for b in bucket.values():
            if b.is_root:
                self._active.setdefault(task_id, b.branch_id)
                return b

        bid = "root"
        # Pick a status by current state.
        if state is not None:
            if state.status == TaskStatus.RUNNING:
                status = "running"
            elif state.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                status = "completed" if state.status == TaskStatus.COMPLETED else "failed"
            else:
                status = "paused"
        else:
            status = "running"
        branch = TaskBranch(
            branch_id=bid,
            task_id=task_id,
            parent_branch_id=None,
            fork_event_id=None,
            fork_phase="",
            fork_round=None,
            thread_id=task_id,  # legacy: thread_id == task_id
            status=status,
            label="root",
            initiating_prompt="",
            is_root=True,
        )
        bucket[bid] = branch
        self._active[task_id] = bid
        if state is not None:
            try:
                state.active_branch_id = bid
                state.root_branch_id = bid
            except Exception:
                pass
        await self._persist(branch)
        return branch

    async def fork_from_active(
        self,
        task_id: str,
        *,
        user_prompt: str,
        fork_event_id: Optional[str] = None,
    ) -> TaskBranch:
        """Create a new branch from the currently-active branch's head.

        Sequence:
          1. Mark active branch ``paused`` (after sending interrupt + waiting
             for the bg run loop to yield, with a hard-cancel timeout).
          2. Copy the LangGraph checkpoint of the active branch into the new
             branch's ``thread_id``, applying a state patch that injects the
             new ``user_prompt`` into ``pending_user_prompt`` /
             ``user_messages`` and bumps ``replan_signals['operator_intent']``.
          3. Schedule a background ``resume_branch`` so the supervisor
             routes the new branch by the operator's intent.
          4. Update the active pointer to the new branch and return it.
        """
        async with self._lock:
            await self._hydrate_from_db(task_id)
            bucket = self._branches.setdefault(task_id, {})

            sm = get_state_manager()
            state = sm.get(task_id)
            if not state:
                raise RuntimeError(f"task {task_id} not found")

            # Ensure root exists for legacy tasks.
            if not bucket:
                await self.lazy_init_root(task_id, state)

            parent = await self.get_active(task_id)
            if parent is None:
                # Defensive — should never happen after lazy_init_root.
                parent = await self.lazy_init_root(task_id, state)

            if len(bucket) >= MAX_BRANCHES_PER_TASK:
                raise RuntimeError(
                    f"分支数已达上限 ({MAX_BRANCHES_PER_TASK}); 请先删除 paused 叶节点"
                )

            # 1) Pause the parent branch.
            await self._pause_branch(task_id, parent.branch_id, reason="fork")

            # 2) Build new branch metadata.
            new_id = _short_id()
            new_thread = f"{task_id}:{new_id}"
            label = _label_from_prompt(user_prompt, fallback=f"branch-{new_id}")
            now = datetime.utcnow().isoformat()
            child = TaskBranch(
                branch_id=new_id,
                task_id=task_id,
                parent_branch_id=parent.branch_id,
                fork_event_id=fork_event_id,
                fork_phase=state.current_phase or "",
                fork_round=int(state.supervisor_round or 0) or None,
                thread_id=new_thread,
                status="running",
                created_at=now,
                updated_at=now,
                label=label,
                initiating_prompt=(user_prompt or "")[:2000],
                is_root=False,
            )
            bucket[new_id] = child
            await self._persist(child)

            # 3) Plant the parent's checkpoint into the new thread, with patch.
            from backend.api.services.task_runner import get_orchestrator
            orchestrator = get_orchestrator()

            joined_prompt = (state.pending_user_prompt or "").strip()
            joined_prompt = (
                f"{joined_prompt}\n{user_prompt}".strip()
                if joined_prompt
                else (user_prompt or "").strip()
            )
            new_messages = list(state.user_messages or []) + [{
                "role": "user",
                "text": (user_prompt or "").strip(),
                "timestamp": now,
                "branch_id": new_id,
            }]
            new_signals = dict(state.replan_signals or {})
            new_signals["operator_intent"] = int(
                new_signals.get("operator_intent", 0)
            ) + 1

            patch: dict[str, Any] = {
                "active_branch_id": new_id,
                "root_branch_id": state.root_branch_id or parent.branch_id,
                "pending_user_prompt": joined_prompt,
                "user_messages": new_messages,
                "replan_signals": new_signals,
                # Re-use the running state for the new thread; reset interrupt
                # consumption flag by clearing operator_intent on parent's copy
                # is unnecessary — supervisor consumes per-thread.
                "status": TaskStatus.RUNNING,
            }
            forked = await orchestrator.fork_branch_state(
                source_thread_id=parent.thread_id,
                target_thread_id=new_thread,
                patch=patch,
            )
            if not forked:
                # No source checkpoint: planted state from scratch via run_task.
                logger.info(
                    f"[BranchManager] source thread {parent.thread_id} has no "
                    f"checkpoint; will start child {new_id} fresh"
                )

            # 4) Update in-memory state to reflect the active branch pointer
            # and advertise the fork on the timeline.
            state.active_branch_id = new_id
            sm.set(task_id, state)

            try:
                bus = get_event_bus()
                await bus.publish(task_id, {
                    "type": "branch_forked",
                    "branch": child.model_dump(),
                    "parent": parent.model_dump(),
                })
            except Exception:
                pass

            # 5) Schedule child execution.
            bg = asyncio.create_task(self._resume_branch_bg(task_id, child))
            self._bg[child.branch_id] = bg

            return child

    async def switch_active(
        self, task_id: str, branch_id: str, *, pause_current: bool = True,
    ) -> TaskBranch:
        await self._hydrate_from_db(task_id)
        bucket = self._branches.get(task_id, {})
        target = bucket.get(branch_id)
        if not target:
            raise KeyError(f"branch {branch_id} not found in task {task_id}")

        cur_id = self._active.get(task_id)
        if pause_current and cur_id and cur_id != branch_id:
            await self._pause_branch(task_id, cur_id, reason="switch")

        self._active[task_id] = branch_id
        sm = get_state_manager()
        state = sm.get(task_id)
        if state:
            state.active_branch_id = branch_id
            sm.set(task_id, state)

        try:
            bus = get_event_bus()
            await bus.publish(task_id, {
                "type": "branch_switched",
                "branch": target.model_dump(),
            })
        except Exception:
            pass
        return target

    async def resume(self, task_id: str, branch_id: str) -> TaskBranch:
        """Explicitly resume a paused branch (idempotent)."""
        await self._hydrate_from_db(task_id)
        branch = self._branches.get(task_id, {}).get(branch_id)
        if not branch:
            raise KeyError(f"branch {branch_id} not found")
        if branch.status == "running":
            return branch
        branch.status = "running"
        branch.updated_at = datetime.utcnow().isoformat()
        await self._persist(branch)
        # Make this branch active when resuming.
        self._active[task_id] = branch_id

        bg = asyncio.create_task(self._resume_branch_bg(task_id, branch))
        self._bg[branch.branch_id] = bg

        try:
            bus = get_event_bus()
            await bus.publish(task_id, {
                "type": "branch_status_changed",
                "branch": branch.model_dump(),
            })
        except Exception:
            pass
        return branch

    async def pause(self, task_id: str, branch_id: str) -> TaskBranch:
        await self._hydrate_from_db(task_id)
        branch = self._branches.get(task_id, {}).get(branch_id)
        if not branch:
            raise KeyError(f"branch {branch_id} not found")
        await self._pause_branch(task_id, branch_id, reason="manual")
        return branch

    # ── 内部 helper ──────────────────────────────────────────

    async def _pause_branch(
        self, task_id: str, branch_id: str, *, reason: str,
    ) -> None:
        """Gracefully stop a branch's bg task and mark it paused.

        Will block up to ``FORK_INTERRUPT_TIMEOUT_SEC`` waiting for the
        cooperative interrupt to flip; if the bg task is still alive after
        that we cancel it.
        """
        bucket = self._branches.get(task_id, {})
        branch = bucket.get(branch_id)
        if not branch:
            return
        if branch.status != "running":
            branch.status = "paused"
            branch.updated_at = datetime.utcnow().isoformat()
            await self._persist(branch)
            return

        # Trigger cooperative interrupt scoped by task_id (interrupt_registry
        # is keyed on task_id since all branches share the operator surface).
        request_interrupt(task_id, reason=f"branch_pause:{reason}",
                          payload={"branch_id": branch_id})

        bg = self._bg.get(branch_id)
        if bg and not bg.done():
            try:
                await asyncio.wait_for(asyncio.shield(bg), timeout=FORK_INTERRUPT_TIMEOUT_SEC)
            except asyncio.TimeoutError:
                logger.warning(
                    f"[BranchManager] branch {branch_id} did not yield in "
                    f"{FORK_INTERRUPT_TIMEOUT_SEC}s — cancelling"
                )
                bg.cancel()
                try:
                    await asyncio.wait_for(bg, timeout=2.0)
                except Exception:
                    pass
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.debug(f"[BranchManager] bg await error: {exc}")

        self._bg.pop(branch_id, None)
        branch.status = "paused"
        branch.updated_at = datetime.utcnow().isoformat()
        await self._persist(branch)

        try:
            bus = get_event_bus()
            await bus.publish(task_id, {
                "type": "branch_status_changed",
                "branch": branch.model_dump(),
            })
        except Exception:
            pass

    async def _resume_branch_bg(self, task_id: str, branch: TaskBranch) -> None:
        """Background runner for a branch — wires sink + state mirroring."""
        sm = get_state_manager()
        bus = get_event_bus()
        from backend.api.services.task_runner import get_orchestrator
        orchestrator = get_orchestrator()

        async def _decision_sink(ev: dict):
            await bus.publish(task_id, {"type": "decision_event", "data": ev})

        set_task_sink(task_id, _decision_sink)
        sm.mark_running(task_id)
        try:
            async for node_name, raw_state in orchestrator.resume_branch_stream(
                branch.thread_id,
            ):
                if isinstance(raw_state, dict):
                    try:
                        state = PentestState(**raw_state)
                    except Exception as exc:
                        logger.warning(
                            f"[BranchManager] state decode failed branch="
                            f"{branch.branch_id}: {exc}"
                        )
                        continue
                else:
                    state = raw_state

                # Only mirror to TaskStateManager when this branch is still
                # the active one — otherwise we'd clobber another branch's
                # in-memory state.
                if self._active.get(task_id) == branch.branch_id:
                    state.active_branch_id = branch.branch_id
                    sm.set(task_id, state)
                    await bus.publish(task_id, {
                        "type": "phase_update",
                        **sm.ws_phase_payload(state, log_tail=5),
                    })
        except asyncio.CancelledError:
            logger.info(f"[BranchManager] branch {branch.branch_id} cancelled")
            raise
        except Exception as exc:
            logger.error(
                f"[BranchManager] branch {branch.branch_id} crashed: {exc}",
                exc_info=True,
            )
            branch.status = "failed"
            branch.updated_at = datetime.utcnow().isoformat()
            await self._persist(branch)
        else:
            # Natural completion: branch is done, status flips to completed
            # only when the underlying state is COMPLETED/FAILED.
            final = await orchestrator.get_branch_state(branch.thread_id)
            if final and final.status == TaskStatus.COMPLETED:
                branch.status = "completed"
            elif final and final.status == TaskStatus.FAILED:
                branch.status = "failed"
            else:
                branch.status = "paused"
            branch.updated_at = datetime.utcnow().isoformat()
            await self._persist(branch)
        finally:
            sm.mark_stopped(task_id)
            self._bg.pop(branch.branch_id, None)

    def to_tree_payload(self, branches: list[TaskBranch], active_id: str) -> dict[str, Any]:
        """Compute sibling counts & active flags for the API tree response."""
        # Sibling key = (parent_branch_id, fork_event_id)
        from collections import defaultdict
        groups: dict[tuple[Optional[str], Optional[str]], list[TaskBranch]] = defaultdict(list)
        for b in branches:
            key = (b.parent_branch_id, b.fork_event_id)
            groups[key].append(b)
        for siblings in groups.values():
            siblings.sort(key=lambda b: b.created_at)

        items: list[dict[str, Any]] = []
        for b in sorted(branches, key=lambda x: x.created_at):
            siblings = groups[(b.parent_branch_id, b.fork_event_id)]
            try:
                idx = siblings.index(b) + 1
            except ValueError:
                idx = 1
            payload = b.model_dump()
            payload.update({
                "sibling_index": idx,
                "sibling_total": len(siblings),
                "is_active": (b.branch_id == active_id),
                "children": [
                    c.branch_id for c in branches if c.parent_branch_id == b.branch_id
                ],
            })
            items.append(payload)
        return {
            "branches": items,
            "active_branch_id": active_id,
            "max_branches_per_task": MAX_BRANCHES_PER_TASK,
        }


# ── Singleton ────────────────────────────────────────────

_manager: Optional[BranchManager] = None


def get_branch_manager() -> BranchManager:
    global _manager
    if _manager is None:
        _manager = BranchManager()
    return _manager
