"""
services/task_runner.py —— 任务执行 + 审批后恢复

性能优化：
  1. DB 写入节流（5s 间隔 + fire-and-forget），不阻塞主循环
  2. Redis 日志增量追加（cursor 追踪，避免重复 RPUSH）
  3. 通过 EventBus publish 推送事件，0 延迟
"""
from __future__ import annotations

import asyncio
import logging
import time

from backend.agents.models import PentestState, TaskStatus
from backend.agents.orchestrator import Orchestrator
from backend.api.state import get_state_manager
from backend.api import event_stream
from backend.api.event_bus import (
    set_task_sink, clear_task_sink,
    set_log_sink, clear_log_sink,
    set_task_loop, clear_task_loop,
)

logger = logging.getLogger(__name__)

# ── Orchestrator 单例 ─────────────────────────────────────
_orchestrator: Orchestrator | None = None


def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator


# ── DB 节流写入 ───────────────────────────────────────────
_last_db_save: dict[str, float] = {}
DB_SAVE_INTERVAL = 5.0


async def _maybe_save_db(task_id: str, state: PentestState, force: bool = False):
    sm = get_state_manager()
    if not sm.db_available:
        return
    now = time.monotonic()
    last = _last_db_save.get(task_id, 0)
    if not force and (now - last) < DB_SAVE_INTERVAL:
        return
    _last_db_save[task_id] = now
    asyncio.create_task(_save_db_fire_and_forget(state))


async def _save_db_fire_and_forget(state: PentestState):
    try:
        from backend.db.database import save_task, save_task_facts
        await save_task(state)
        await save_task_facts(state)
    except Exception as e:
        logger.warning(f"[DB] 异步保存失败: {e}")


# ── Redis 增量日志 ────────────────────────────────────────
_redis_log_cursor: dict[str, int] = {}


async def _cache_redis_incremental(task_id: str, state: PentestState):
    sm = get_state_manager()
    if not sm.redis_available:
        return
    try:
        from backend.db.redis_cache import cache_task_state, append_task_log
        await cache_task_state(task_id, {
            "status": state.status.value,
            "current_phase": state.current_phase,
            "findings_count": len(state.findings),
            "got_shell": state.got_shell,
        })
        prev_cursor = _redis_log_cursor.get(task_id, 0)
        new_logs = state.phase_log[prev_cursor:]
        for log_entry in new_logs:
            await append_task_log(task_id, log_entry)
        _redis_log_cursor[task_id] = len(state.phase_log)
    except Exception:
        pass


# ── 通用: LangGraph interrupt_before 暂停检测 + 审批上下文 ───


async def _auto_resume_task(task_id: str) -> None:
    """auto_approve 任务碰到 interrupt_before 暂停后自动恢复执行。"""
    sm = get_state_manager()
    sm.register_bg_task(task_id, asyncio.current_task())
    try:
        await resume_task(task_id, approved=True)
    except Exception as e:
        logger.error(f"[API] auto_resume {task_id} 失败: {e}", exc_info=True)


async def _handle_graph_interrupt(task_id: str, state: PentestState) -> bool:
    """检测 LangGraph interrupt_before 暂停并处理。

    当 graph 因 interrupt_before (human_approval / post_foothold_approval)
    暂停时, state.status 保持 RUNNING。本函数根据 auto_approve 分两路:

      - auto_approve=True: 自动设置审批标志并后台恢复执行 (返回 True)。
      - auto_approve=False: 创建审批上下文 + checkpoint + 事件 (返回 True)。

    Returns True when interrupt handling was applied, False otherwise.
    """
    if not state or state.status != TaskStatus.RUNNING:
        return False

    from datetime import datetime as _dt
    from backend.agents.orchestrator import _CHAIN_PHASE_ORDER

    sm = get_state_manager()

    # 推断被中断的阶段: 根据 chain_visited 最后一项在 _CHAIN_PHASE_ORDER
    # 中的位置, 下一个就是被 interrupt_before 挡住的阶段。
    visited = list(state.chain_visited or [])
    last_visited = visited[-1] if visited else ""
    interrupted_phase = ""
    for i, p in enumerate(_CHAIN_PHASE_ORDER):
        if p == last_visited and i + 1 < len(_CHAIN_PHASE_ORDER):
            interrupted_phase = _CHAIN_PHASE_ORDER[i + 1]
            break
    if not interrupted_phase:
        interrupted_phase = state.current_phase or "unknown"

    # auto_approve: 自动通过审批暂停，后台恢复执行
    if state.auto_approve:
        state.approved = True
        state.post_approved = True
        sm.set(task_id, state)
        state.log(f"✅ auto_approve: 自动通过 {interrupted_phase} 审批暂停，继续执行")
        asyncio.ensure_future(_auto_resume_task(task_id))
        return True

    PHASE_LABELS: dict[str, str] = {
        "recon": "侦察", "surface_enum": "攻击面枚举", "intel_harvest": "情报收集",
        "vuln_scan": "漏洞扫描", "exploit_decision": "利用决策",
        "awaiting_approval": "等待审批", "foothold_attempt": "立足点尝试",
        "secondary_attack": "二次攻击", "post_foothold_enum": "立足后枚举",
        "post_foothold_approval": "立足后确认", "internal_scan": "内网扫描",
        "privesc_attempt": "提权尝试", "lateral_movement": "横向移动",
        "persistence": "持久化", "objective_collect": "目标收集", "report": "报告",
    }
    phase_label = PHASE_LABELS.get(interrupted_phase, interrupted_phase)

    # 构建摘要 —— 汇总当前已知事实, 让用户知道"走到哪了"
    summary_parts: list[str] = []
    open_ports_count = len(state.open_ports or [])
    if open_ports_count:
        ports_str = ", ".join(str(p.port) for p in (state.open_ports or [])[:5])
        summary_parts.append(f"已发现 {open_ports_count} 个开放端口: {ports_str}")
    web_paths_count = len(state.web_paths or [])
    if web_paths_count:
        summary_parts.append(f"已枚举 {web_paths_count} 条 Web 路径")
    exploitable_findings = [f for f in (state.findings or []) if f.exploitable]
    if exploitable_findings:
        summary_parts.append(f"已识别 {len(exploitable_findings)} 个可利用漏洞")

    summary = (
        f"即将进入「{phase_label}」阶段。{' '.join(summary_parts)}"
        if summary_parts
        else f"即将进入「{phase_label}」阶段，请确认是否继续。"
    )

    # 构建 thinking 行 (漏洞详情)
    thinking_lines: list[str] = []
    if open_ports_count:
        thinking_lines.append(f"- 开放端口: {open_ports_count} 个")
    if web_paths_count:
        thinking_lines.append(f"- Web 路径: {web_paths_count} 条")
    for f in exploitable_findings[:5]:
        line = f"- {f.severity.upper()} | {f.name}"
        if f.cve:
            line += f" ({f.cve})"
        thinking_lines.append(line)

    state.current_phase = "awaiting_approval"
    state.log(f"⏸ 暂停在 {phase_label} 阶段前，等待确认继续")
    sm.set(task_id, state)

    # 如果已经有 pending_checkpoint (来自 node_human_approval 的 exploit_gate
    # 或 node_post_foothold_approval 的 post_foothold_gate), 不创建新的, 避免
    # 覆盖更丰富的审批上下文。
    has_existing_checkpoint = bool(
        state.pending_checkpoint
        and state.pending_checkpoint.get("checkpoint_type")
        in ("exploit_gate", "post_foothold_gate")
    )
    if not has_existing_checkpoint:
        state.open_checkpoint({
            "checkpoint_type": "interactive_gate",
            "phase": interrupted_phase,
            "summary": summary,
            "thinking": "\n".join(thinking_lines) or f"当前阶段: {phase_label}",
            "recommendation": f"点击「继续」进入 {phase_label} 阶段；点击「跳过」则跳过此阶段。",
            "risk": (
                "高风险" if any(f.severity in ("critical", "high") for f in exploitable_findings)
                else ("中等风险" if exploitable_findings else "低风险")
            ),
            "default_action": "approve",
            "options": [
                {
                    "id": "approve", "label": f"继续 → {phase_label}",
                    "tone": "primary", "action": "approve",
                },
                {
                    "id": "modify", "label": "提交建议(补充指令后继续)",
                    "tone": "info", "action": "modify", "wants_prompt": True,
                },
                {
                    "id": "reject", "label": f"跳过 {phase_label}",
                    "tone": "danger", "action": "reject",
                },
            ],
            "context": {
                "interrupted_phase": interrupted_phase,
                "chain_visited": list(state.chain_visited or []),
                "open_ports_count": open_ports_count,
                "web_paths_count": web_paths_count,
                "findings_count": len(state.findings or []),
                "exploitable_count": len(exploitable_findings),
                "workflow_mode": state.workflow_mode,
            },
        })

    # 兼容旧版前端: 仍然推送 approval_required 事件
    risk_note = (
        "高风险" if any(f.severity in ("critical", "high") for f in exploitable_findings)
        else ("中等风险" if exploitable_findings else "低风险")
    )
    top_targets = [
        {
            "name": f.name, "severity": f.severity,
            "vuln_id": f.vuln_id, "cve": f.cve or "",
            "port": getattr(f, "port", None),
            "description": (f.description or "")[:120],
        }
        for f in exploitable_findings[:5]
    ]
    await event_stream.publish(
        task_id, type="approval_required",
        payload={
            "phase": interrupted_phase,
            "status": "running",
            "server_iso": _dt.utcnow().isoformat(),
            "logs": state.phase_log[-3:],
            "findings_count": len(state.findings or []),
            "got_shell": state.got_shell,
            "exploitable_count": len(exploitable_findings),
            "top_targets": top_targets,
            "risk": risk_note,
        },
        branch_id=state.active_branch_id or "",
    )
    return True


# ── 主任务执行 ────────────────────────────────────────────

async def run_task(
    task_id: str,
    initial_state: PentestState,
    *,
    thread_id: str | None = None,
):
    """
    运行一个任务的主协程。

    调用方(tasks.create_task)负责把 workflow_mode 默认值和 per-task 覆盖项
    已经填入 initial_state;本函数只负责把它交给 Orchestrator 并把流式更新
    推给事件总线 / DB / Redis。

    ``thread_id`` 默认等于 ``task_id`` (旧行为)。开启对话分支后, BranchManager
    会传入 ``f"{task_id}:{branch_id}"`` 让 LangGraph checkpoint 落到独立 thread。
    """
    sm = get_state_manager()
    sm.mark_running(task_id)
    orchestrator = get_orchestrator()
    # Ownership token: BranchManager.fork_from_active swaps in a new
    # coroutine handle on ``sm._bg_tasks[task_id]`` to claim ownership of
    # the task. We compare against this in ``finally`` so that, when fork
    # has already taken over, we skip the cleanup tail (publish ``done`` /
    # stop container / clear sinks) — otherwise we'd silently tear down
    # the new branch's resources and the user would only see "branch
    # forked, no further logs".
    my_task = asyncio.current_task()

    # 协议 v2: sink 直接把事件写进 Stream。前端不再依赖 phase_log 派生事件,
    # 因此 ``state.log()`` 触发的也走 ``type=log`` 单独 envelope, 而不是
    # 依附在 phase_update 里。
    async def _decision_sink(ev: dict):
        cur = sm.get(task_id)
        bid = (
            ev.get("branch_id")
            or (cur.active_branch_id if cur else "")
            or ""
        )
        await event_stream.publish(
            task_id, type="decision_event", payload=ev, branch_id=bid,
        )

    async def _log_sink(line: str, seq: int):
        cur = sm.get(task_id)
        bid = (cur.active_branch_id if cur else "") or ""
        await event_stream.publish(
            task_id, type="log",
            payload={"line": line, "seq": seq},
            branch_id=bid,
        )

    set_task_sink(task_id, _decision_sink)
    set_log_sink(task_id, _log_sink)
    # 跨线程 sink fallback: 把当前 main loop 登记进 _TASK_LOOP, 让
    # ``PentestState.log / push_decision`` 在 worker 线程命中时
    # 能 ``run_coroutine_threadsafe`` 把事件投递回这里, 避免
    # ``RuntimeError: no running event loop`` 让事件被静默吞掉。
    try:
        set_task_loop(task_id, asyncio.get_running_loop())
    except RuntimeError:
        pass

    is_owner = True
    try:
        async for node_name, raw_state in orchestrator.run_stream(
            initial_state, thread_id=thread_id,
        ):
            # 检查取消
            if sm.redis_available:
                try:
                    from backend.db.redis_cache import is_cancelled
                    if await is_cancelled(task_id):
                        logger.info(f"[API] 任务 {task_id} 已被取消")
                        break
                except Exception:
                    pass

            if isinstance(raw_state, dict):
                try:
                    state = PentestState(**raw_state)
                except Exception as e:
                    logger.warning(f"[API] State 反序列化失败: {e}")
                    continue
            else:
                state = raw_state

            sm.set(task_id, state)

            # 异步 Redis（增量）
            asyncio.create_task(_cache_redis_incremental(task_id, state))

            # 异步 DB（节流）
            await _maybe_save_db(task_id, state)

            # 即时事件推送 (协议 v2: phase_update envelope)
            payload = sm.ws_phase_payload(state, log_tail=5)
            await event_stream.publish(
                task_id, type="phase_update",
                payload=payload,
                branch_id=payload.get("branch_id", ""),
            )

    except asyncio.CancelledError:
        logger.info(f"[API] 任务 {task_id} 被取消(CancelledError)")
    except Exception as e:
        logger.error(f"[API] 任务 {task_id} 执行异常: {e}", exc_info=True)
        state = sm.get(task_id)
        if state:
            state.status = TaskStatus.FAILED
            state.error_msg = str(e)
            await _maybe_save_db(task_id, state, force=True)
    finally:
        sm.mark_stopped(task_id)
        # Ownership check: BranchManager.fork_from_active replaces the
        # value of ``sm._bg_tasks[task_id]`` with the child branch's
        # coroutine before we get here. If we're no longer the owner,
        # someone else (the new branch) has claimed the task_id-scoped
        # resources (sink / docker container) and we MUST NOT proceed
        # with the cleanup tail below.
        is_owner = sm._bg_tasks.get(task_id) is my_task
        if is_owner:
            sm.unregister_bg_task(task_id)

    if not is_owner:
        logger.info(
            f"[API] 任务 {task_id} 已被分支管理器接管, run_task 跳过收尾"
        )
        return

    # 检测 LangGraph interrupt 暂停 (human_approval / post_foothold_approval)。
    # auto_approve=True 时 _handle_graph_interrupt 会自动恢复执行。
    state = sm.get(task_id)
    if await _handle_graph_interrupt(task_id, state):
        await _maybe_save_db(task_id, state, force=True)
        logger.info(f"[API] 任务 {task_id} 等待审批/自动恢复 (phase={state.current_phase})")
        return

    # 正常完成 / 失败 / 取消 → 统一关容器
    try:
        from backend.tools.executor import TaskContainerManager
        await TaskContainerManager.stop(task_id)
    except Exception:
        pass

    if state:
        await _maybe_save_db(task_id, state, force=True)
        await event_stream.publish(
            task_id, type="done",
            payload={
                "status": state.status.value,
                "findings_count": len(state.findings),
                "got_shell": state.got_shell,
            },
            branch_id=state.active_branch_id or "",
        )

    _last_db_save.pop(task_id, None)
    _redis_log_cursor.pop(task_id, None)
    clear_task_sink(task_id)
    clear_log_sink(task_id)
    clear_task_loop(task_id)
    logger.info(f"[API] 任务 {task_id} 完成")


# ── 审批后恢复执行 ────────────────────────────────────────

async def resume_task(
    task_id: str,
    approved: bool,
    *,
    thread_id: str | None = None,
):
    sm = get_state_manager()
    sm.mark_running(task_id)
    orchestrator = get_orchestrator()
    # See ``run_task`` for why we capture ownership: when a chat message
    # forks mid-resume, the new branch claims ``sm._bg_tasks[task_id]``;
    # cleanup logic below must be skipped in that case.
    my_task = asyncio.current_task()

    async def _decision_sink(ev: dict):
        cur = sm.get(task_id)
        bid = (
            ev.get("branch_id")
            or (cur.active_branch_id if cur else "")
            or ""
        )
        await event_stream.publish(
            task_id, type="decision_event", payload=ev, branch_id=bid,
        )

    async def _log_sink(line: str, seq: int):
        cur = sm.get(task_id)
        bid = (cur.active_branch_id if cur else "") or ""
        await event_stream.publish(
            task_id, type="log",
            payload={"line": line, "seq": seq},
            branch_id=bid,
        )

    set_task_sink(task_id, _decision_sink)
    set_log_sink(task_id, _log_sink)
    try:
        set_task_loop(task_id, asyncio.get_running_loop())
    except RuntimeError:
        pass

    is_owner = True
    try:
        async for node_name, raw_state in orchestrator.resume_stream(
            task_id=task_id, approved=approved, thread_id=thread_id,
        ):
            if isinstance(raw_state, dict):
                try:
                    state = PentestState(**raw_state)
                except Exception as e:
                    logger.warning(f"[API] Resume state 反序列化失败: {e}")
                    continue
            else:
                state = raw_state

            sm.set(task_id, state)

            await _maybe_save_db(task_id, state)
            asyncio.create_task(_cache_redis_incremental(task_id, state))

            payload = sm.ws_phase_payload(state, log_tail=5)
            await event_stream.publish(
                task_id, type="phase_update",
                payload=payload,
                branch_id=payload.get("branch_id", ""),
            )

    except asyncio.CancelledError:
        logger.info(f"[API] Resume 任务 {task_id} 被取消(CancelledError)")
    except Exception as e:
        logger.error(f"[API] Resume 任务 {task_id} 异常: {e}", exc_info=True)
        state = sm.get(task_id)
        if state:
            state.status = TaskStatus.FAILED
            state.error_msg = f"Resume 异常: {e}"
            sm.set(task_id, state)
            await _maybe_save_db(task_id, state, force=True)
    finally:
        sm.mark_stopped(task_id)
        sm.clear_approval_inflight(task_id)
        # Ownership-aware cleanup: don't tear down task_id-scoped
        # resources (container, sinks, bg slot) when a fork has already
        # claimed them.
        is_owner = sm._bg_tasks.get(task_id) is my_task
        if is_owner:
            sm.unregister_bg_task(task_id)

    if not is_owner:
        logger.info(
            f"[API] 任务 {task_id} resume 已被分支管理器接管, 跳过收尾"
        )
        return

    # 检测 resume 后图是否再次暂停 (例如 post_foothold_approval 的 interrupt_before)
    state = sm.get(task_id)
    if await _handle_graph_interrupt(task_id, state):
        await _maybe_save_db(task_id, state, force=True)
        logger.info(f"[API] 任务 {task_id} resume 后再次等待审批 (phase={state.current_phase})")
        return

    # Stop container only when we're the legitimate lifecycle owner.
    try:
        from backend.tools.executor import TaskContainerManager
        await TaskContainerManager.stop(task_id)
    except Exception:
        pass

    # 最终持久化
    state = sm.get(task_id)
    if state:
        await _maybe_save_db(task_id, state, force=True)
        await event_stream.publish(
            task_id, type="done",
            payload={
                "status": state.status.value,
                "findings_count": len(state.findings),
                "got_shell": state.got_shell,
            },
            branch_id=state.active_branch_id or "",
        )

    _last_db_save.pop(task_id, None)
    _redis_log_cursor.pop(task_id, None)
    clear_task_sink(task_id)
    clear_log_sink(task_id)
    clear_task_loop(task_id)
    logger.info(f"[API] 任务 {task_id} resume 完成")


def is_msf_available() -> bool:
    """供 exploit_agent / post_agent 调用。"""
    return get_state_manager().msf_available
