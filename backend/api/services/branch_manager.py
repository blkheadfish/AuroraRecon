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
from backend.api import event_stream
from backend.api.event_bus import (
    set_task_sink,
    set_log_sink,
    clear_log_sink,
    clear_task_sink,
    get_log_sink,
    get_task_sink,
    set_task_loop,
    clear_task_loop,
)
from backend.api.state import TaskStateManager, get_state_manager

logger = logging.getLogger(__name__)


import os as _os
MAX_BRANCHES_PER_TASK = max(2, int(_os.getenv("MAX_BRANCHES_PER_TASK", "12")))

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
        self._branches: dict[str, dict[str, TaskBranch]] = {}
        self._active: dict[str, str] = {}
        self._bg: dict[str, asyncio.Task] = {}
        self._loaded: set[str] = set()
        self._lock = asyncio.Lock()


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
            thread_id=task_id,
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
        from_event_ts: Optional[str] = None,
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

            if not bucket:
                await self.lazy_init_root(task_id, state)

            parent = await self.get_active(task_id)
            if parent is None:
                parent = await self.lazy_init_root(task_id, state)

            if len(bucket) >= MAX_BRANCHES_PER_TASK:
                raise RuntimeError(
                    f"分支数已达上限 ({MAX_BRANCHES_PER_TASK}); 请先删除 paused 叶节点"
                )

            await self._pause_branch(task_id, parent.branch_id, reason="fork")

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
                "status": TaskStatus.RUNNING,
            }

            replan_plan = None
            try:
                merged_messages = list(state.user_messages or [])
                if not merged_messages or merged_messages[-1].get("text") != (user_prompt or "").strip():
                    merged_messages = list(merged_messages) + [{
                        "role": "user",
                        "text": (user_prompt or "").strip(),
                        "timestamp": now,
                    }]
                _stash_pending = state.pending_user_prompt
                _stash_messages = state.user_messages
                state.pending_user_prompt = joined_prompt
                state.user_messages = merged_messages
                try:
                    from backend.agents.operator_replanner import (
                        llm_replan,
                        plan_to_decision_event,
                    )
                    replan_plan = await llm_replan(state)
                finally:
                    state.pending_user_prompt = _stash_pending
                    state.user_messages = _stash_messages

                if replan_plan is not None:
                    derived = dict(replan_plan.derived_replan_signals or {})
                    merged_sig = dict(new_signals)
                    for k, v in derived.items():
                        merged_sig[k] = max(
                            int(merged_sig.get(k, 0) or 0), int(v or 0),
                        )
                    patch["replan_signals"] = merged_sig
                    patch["operator_plan"] = replan_plan.model_dump()
                    patch["operator_plan_history"] = (
                        [p.model_dump() for p in (state.operator_plan_history or [])]
                        + [replan_plan.model_dump()]
                    )[-20:]
            except Exception as exc:
                logger.warning(
                    f"[BranchManager] operator replan 失败 task={task_id}: {exc}",
                    exc_info=True,
                )
            source_checkpoint_id: Optional[str] = None
            if from_event_ts:
                try:
                    source_checkpoint_id = await orchestrator.find_checkpoint_at_or_before(
                        parent.thread_id, from_event_ts,
                    )
                except Exception as exc:
                    logger.warning(
                        f"[BranchManager] find_checkpoint_at_or_before failed "
                        f"task={task_id} ts={from_event_ts}: {exc}"
                    )
                if not source_checkpoint_id:
                    logger.info(
                        f"[BranchManager] from_event_ts={from_event_ts} 找不到对应"
                        f" checkpoint, 回落到最新 checkpoint 分叉"
                    )

            explicit_as_node: Optional[str] = None
            if replan_plan is not None and (
                replan_plan.next_phase or replan_plan.rerun_current
            ):
                explicit_as_node = "__start__"

            forked = await orchestrator.fork_branch_state(
                source_thread_id=parent.thread_id,
                target_thread_id=new_thread,
                patch=patch,
                source_checkpoint_id=source_checkpoint_id,
                as_node=explicit_as_node,
            )
            if not forked:
                logger.info(
                    f"[BranchManager] source thread {parent.thread_id} has no "
                    f"checkpoint; planting fresh state for child {new_id}"
                )
                try:
                    fresh_values = state.model_dump()
                    fresh_values.update(patch)
                    dst_cfg = {"configurable": {"thread_id": new_thread}}
                    await orchestrator._graph.aupdate_state(
                        dst_cfg, fresh_values, as_node="__start__",
                    )
                    forked = True
                except Exception as exc:
                    logger.error(
                        f"[BranchManager] fresh-plant for child {new_id} "
                        f"failed: {exc}",
                        exc_info=True,
                    )

            state.active_branch_id = new_id
            sm.set(task_id, state)

            self._active[task_id] = new_id

            try:
                await event_stream.publish(
                    task_id, type="branch_forked",
                    payload={
                        "branch": child.model_dump(),
                        "parent": parent.model_dump(),
                    },
                    branch_id=new_id,
                )
                if replan_plan is not None:
                    from backend.agents.operator_replanner import plan_to_decision_event
                    event_data = plan_to_decision_event(replan_plan)
                    event_data.update({
                        "id": f"replan-{replan_plan.plan_id}",
                        "timestamp": now,
                        "branch_id": new_id,
                    })
                    await event_stream.publish(
                        task_id, type="decision_event",
                        payload=event_data, branch_id=new_id,
                    )
            except Exception:
                pass

            bg = asyncio.create_task(self._resume_branch_bg(task_id, child))
            self._bg[child.branch_id] = bg
            sm.register_bg_task(task_id, bg)

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
            await event_stream.publish(
                task_id, type="branch_switched",
                payload={"branch": target.model_dump()},
                branch_id=branch_id,
            )
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
        self._active[task_id] = branch_id

        bg = asyncio.create_task(self._resume_branch_bg(task_id, branch))
        self._bg[branch.branch_id] = bg
        get_state_manager().register_bg_task(task_id, bg)

        try:
            await event_stream.publish(
                task_id, type="branch_status_changed",
                payload={"branch": branch.model_dump()},
                branch_id=branch_id,
            )
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
                except (asyncio.CancelledError, Exception):
                    pass
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.debug(f"[BranchManager] bg await error: {exc}")

        self._bg.pop(branch_id, None)

        sm = get_state_manager()
        if self._active.get(task_id) == branch_id:
            sm_bg = sm._bg_tasks.get(task_id)
            if sm_bg and not sm_bg.done():
                sm.unregister_bg_task(task_id)
                sm_bg.cancel()
                try:
                    await asyncio.wait_for(
                        sm_bg, timeout=FORK_INTERRUPT_TIMEOUT_SEC,
                    )
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                except Exception as exc:
                    logger.debug(
                        f"[BranchManager] sm bg await error task={task_id}: {exc}"
                    )

        branch.status = "paused"
        branch.updated_at = datetime.utcnow().isoformat()
        await self._persist(branch)

        try:
            await event_stream.publish(
                task_id, type="branch_status_changed",
                payload={"branch": branch.model_dump()},
                branch_id=branch_id,
            )
        except Exception:
            pass

    async def _resume_branch_bg(self, task_id: str, branch: TaskBranch) -> None:
        """Background runner for a branch — wires sink + state mirroring."""
        sm = get_state_manager()
        from backend.api.services.task_runner import get_orchestrator
        orchestrator = get_orchestrator()

        async def _decision_sink(ev: dict):
            ev = dict(ev)
            ev.setdefault("branch_id", branch.branch_id)
            await event_stream.publish(
                task_id, type="decision_event",
                payload=ev, branch_id=branch.branch_id,
            )

        async def _log_sink(line: str, seq: int):
            await event_stream.publish(
                task_id, type="log",
                payload={"line": line, "seq": seq},
                branch_id=branch.branch_id,
            )

        set_task_sink(task_id, _decision_sink)
        set_log_sink(task_id, _log_sink)
        try:
            set_task_loop(task_id, asyncio.get_running_loop())
        except RuntimeError:
            pass
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

                if self._active.get(task_id) == branch.branch_id:
                    state.active_branch_id = branch.branch_id
                    sm.set(task_id, state)
                    payload = sm.ws_phase_payload(state, log_tail=5)
                    await event_stream.publish(
                        task_id, type="phase_update",
                        payload=payload,
                        branch_id=payload.get("branch_id", "") or branch.branch_id,
                    )
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
            try:
                await event_stream.publish(
                    task_id, type="branch_status_changed",
                    payload={"branch": branch.model_dump()},
                    branch_id=branch.branch_id,
                )
            except Exception:
                pass
        else:
            final = await orchestrator.get_branch_state(branch.thread_id)
            if final and final.status == TaskStatus.COMPLETED:
                branch.status = "completed"
            elif final and final.status == TaskStatus.FAILED:
                branch.status = "failed"
            elif final and final.status == TaskStatus.RUNNING:
                from backend.api.services.task_runner import _handle_graph_interrupt
                state_for_sm = sm.get(task_id) or final
                handled = await _handle_graph_interrupt(task_id, state_for_sm)
                sm.set(task_id, state_for_sm)
                branch.status = "running" if (handled and state_for_sm.auto_approve) else "paused"
            else:
                branch.status = "paused"
            branch.updated_at = datetime.utcnow().isoformat()
            await self._persist(branch)
            try:
                await event_stream.publish(
                    task_id, type="branch_status_changed",
                    payload={"branch": branch.model_dump()},
                    branch_id=branch.branch_id,
                )
            except Exception:
                pass
        finally:
            sm.mark_stopped(task_id)
            self._bg.pop(branch.branch_id, None)
            if get_log_sink(task_id) is _log_sink:
                clear_log_sink(task_id)
            if get_task_sink(task_id) is _decision_sink:
                clear_task_sink(task_id)
            try:
                current_owner = sm._bg_tasks.get(task_id)
                if current_owner is asyncio.current_task():
                    sm.unregister_bg_task(task_id)
                    clear_task_loop(task_id)
            except RuntimeError:
                pass

    def to_tree_payload(self, branches: list[TaskBranch], active_id: str) -> dict[str, Any]:
        """Compute sibling counts & active flags for the API tree response."""
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



_manager: Optional[BranchManager] = None


def get_branch_manager() -> BranchManager:
    global _manager
    if _manager is None:
        _manager = BranchManager()
    return _manager
