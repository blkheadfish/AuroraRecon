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
from backend.api.event_bus import get_event_bus

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


# ── 主任务执行 ────────────────────────────────────────────

async def run_task(task_id: str, initial_state: PentestState):
    """
    运行一个任务的主协程。

    调用方(tasks.create_task)负责把 workflow_mode 默认值和 per-task 覆盖项
    已经填入 initial_state;本函数只负责把它交给 Orchestrator 并把流式更新
    推给事件总线 / DB / Redis。
    """
    sm = get_state_manager()
    bus = get_event_bus()
    sm.mark_running(task_id)
    orchestrator = get_orchestrator()

    try:
        async for node_name, raw_state in orchestrator.run_stream(initial_state):
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

            # 即时事件推送
            await bus.publish(task_id, {
                "type": "phase_update",
                **sm.ws_phase_payload(state, log_tail=5),
            })

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
        sm.unregister_bg_task(task_id)

    # 检测 LangGraph interrupt 暂停(等待人工审批)
    # auto_approve=True 的任务不会走到这里:edge_should_exploit 已经直通 foothold_attempt
    state = sm.get(task_id)
    if state and state.status == TaskStatus.RUNNING and not state.auto_approve:
        state.current_phase = "awaiting_approval"
        state.log("⏸ 等待人工审批,请在前端点击「授权并继续」")
        sm.set(task_id, state)
        await bus.publish(task_id, {
            "type": "approval_required",
            "phase": "awaiting_approval",
            "status": "running",
            "logs": state.phase_log[-3:],
            "findings_count": len(state.findings),
            "got_shell": state.got_shell,
        })
        await _maybe_save_db(task_id, state, force=True)
        logger.info(f"[API] 任务 {task_id} 等待人工审批")
        # 待审批期间不关容器:恢复后继续利用还要用同一个工具环境
        return

    # 正常完成 / 失败 / 取消 → 统一关容器
    try:
        from backend.tools.executor import TaskContainerManager
        await TaskContainerManager.stop(task_id)
    except Exception:
        pass

    if state:
        await _maybe_save_db(task_id, state, force=True)
        await bus.publish(task_id, {
            "type": "done",
            "status": state.status.value,
            "findings_count": len(state.findings),
            "got_shell": state.got_shell,
        })

    _last_db_save.pop(task_id, None)
    _redis_log_cursor.pop(task_id, None)
    logger.info(f"[API] 任务 {task_id} 完成")


# ── 审批后恢复执行 ────────────────────────────────────────

async def resume_task(task_id: str, approved: bool):
    sm = get_state_manager()
    bus = get_event_bus()
    sm.mark_running(task_id)
    orchestrator = get_orchestrator()

    try:
        async for node_name, raw_state in orchestrator.resume_stream(
            task_id=task_id, approved=approved,
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

            await bus.publish(task_id, {
                "type": "phase_update",
                **sm.ws_phase_payload(state, log_tail=5),
            })

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
        sm.unregister_bg_task(task_id)
        try:
            from backend.tools.executor import TaskContainerManager
            await TaskContainerManager.stop(task_id)
        except Exception:
            pass

    # 最终持久化
    state = sm.get(task_id)
    if state:
        await _maybe_save_db(task_id, state, force=True)
        await bus.publish(task_id, {
            "type": "done",
            "status": state.status.value,
            "findings_count": len(state.findings),
            "got_shell": state.got_shell,
        })

    _last_db_save.pop(task_id, None)
    _redis_log_cursor.pop(task_id, None)
    logger.info(f"[API] 任务 {task_id} resume 完成")


def is_msf_available() -> bool:
    """供 exploit_agent / post_agent 调用。"""
    return get_state_manager().msf_available
