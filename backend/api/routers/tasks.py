"""
routers/tasks.py —— 任务 CRUD + 审批 + 对话
"""
from __future__ import annotations

import asyncio
import logging
import time as _time
import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, BackgroundTasks, Request, Depends

from backend.agents.models import PentestState, TaskStatus
from backend.api.schemas import (
    CreateTaskRequest, TaskSummary, TaskStats, ApproveRequest, ChatMessageRequest,
)
from backend.api.state import get_state_manager, TaskStateManager
from backend.api.event_bus import get_event_bus, TaskEventBus
from backend.api.deps import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tasks"])


def _get_sm() -> TaskStateManager:
    return get_state_manager()


def _get_bus() -> TaskEventBus:
    return get_event_bus()


async def _resolve_state(task_id: str) -> PentestState | None:
    sm = _get_sm()
    state = sm.get(task_id)
    if state:
        return state
    if sm.db_available:
        try:
            from backend.db.database import load_task
            state = await load_task(task_id)
            if state:
                sm.set(task_id, state)
                return state
        except Exception:
            pass
    return None


# ── CRUD ──────────────────────────────────────────────────

@router.post("/tasks", response_model=TaskSummary)
async def create_task(req: CreateTaskRequest, background_tasks: BackgroundTasks, request: Request):
    sm = _get_sm()
    task_id = str(uuid.uuid4())

    owner_id = getattr(request.state, "user_id", "")
    state = PentestState(
        task_id=task_id,
        target=req.target,
        scope_note=req.scope_note,
        extra_hint=req.extra_hint,
        user_prompt=req.user_prompt,
        workflow_mode=req.workflow_mode or "standard",
        owner_id=owner_id,
    )
    sm.set(task_id, state)

    if sm.db_available:
        try:
            from backend.db.database import save_task
            await save_task(state)
        except Exception as e:
            logger.warning(f"[DB] 保存失败: {e}")

    from backend.api.services.task_runner import run_task
    background_tasks.add_task(
        run_task,
        task_id,
        req.target,
        req.scope_note,
        req.extra_hint,
        req.user_prompt,
        req.workflow_mode or "standard",
    )
    return sm.to_summary(state)


@router.get("/tasks/stats", response_model=TaskStats)
async def get_stats():
    sm = _get_sm()
    if sm.db_available:
        try:
            from backend.db.database import get_task_stats
            return TaskStats(**(await get_task_stats()))
        except Exception as e:
            logger.warning(f"[DB] 统计查询失败: {e}")

    tasks_list = sm.all_states()
    return TaskStats(
        total=len(tasks_list),
        running=sum(1 for t in tasks_list if t.status == TaskStatus.RUNNING),
        completed=sum(1 for t in tasks_list if t.status == TaskStatus.COMPLETED),
        failed=sum(1 for t in tasks_list if t.status == TaskStatus.FAILED),
        pending=sum(1 for t in tasks_list if t.status == TaskStatus.PENDING),
        shells_obtained=sum(1 for t in tasks_list if t.got_shell),
        root_reached=sum(
            1 for t in tasks_list
            if (t.privilege_level or "").lower() == "root"
            or (t.objective_status or {}).get("root_reached")
        ),
        total_findings=sum(len(t.findings) for t in tasks_list),
    )


@router.get("/tasks", response_model=list[TaskSummary])
async def list_tasks():
    sm = _get_sm()
    if sm.db_available:
        try:
            from backend.db.database import list_tasks_from_db
            db_list = await list_tasks_from_db()
            result = []
            seen = set()
            for t in db_list:
                tid = t["task_id"]
                seen.add(tid)
                state = sm.get(tid)
                if state:
                    result.append(sm.to_summary(state))
                else:
                    result.append(TaskSummary(**t).model_dump())
            for tid, state in sm.items():
                if tid not in seen:
                    result.append(sm.to_summary(state))
            return result
        except Exception as e:
            logger.warning(f"[DB] 查询失败: {e}")

    return [sm.to_summary(s) for s in sm.all_states()]


@router.get("/tasks/{task_id}")
async def get_task(task_id: str):
    state = await _resolve_state(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    sm = _get_sm()
    return sm.to_detail(state)


@router.get("/tasks/{task_id}/report")
async def get_report(task_id: str):
    state = await _resolve_state(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not state.report_md:
        raise HTTPException(status_code=404, detail="报告尚未生成")
    return {"markdown": state.report_md, "path": state.report_path}


@router.get("/tasks/{task_id}/logs")
async def get_logs(task_id: str):
    sm = _get_sm()
    if sm.redis_available:
        try:
            from backend.db.redis_cache import get_task_logs
            logs = await get_task_logs(task_id)
            if logs:
                return {"logs": logs}
        except Exception:
            pass
    state = sm.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"logs": state.phase_log}


@router.post("/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    sm = _get_sm()
    bus = _get_bus()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    if state.status not in (TaskStatus.RUNNING, TaskStatus.PENDING):
        raise HTTPException(status_code=400, detail="任务不在运行状态")

    state.status = TaskStatus.FAILED
    state.error_msg = "用户手动取消"
    state.log("任务被用户取消")

    if sm.redis_available:
        try:
            from backend.db.redis_cache import set_cancel_flag
            await set_cancel_flag(task_id)
        except Exception:
            pass
    if sm.db_available:
        try:
            from backend.db.database import save_task
            await save_task(state)
        except Exception:
            pass

    sm.mark_stopped(task_id)
    await bus.publish(task_id, {"type": "done", "status": "failed", "message": "任务已取消"})
    return {"status": "cancelled", "task_id": task_id}


@router.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    sm = _get_sm()
    state = sm.get(task_id)
    if state and state.status in (TaskStatus.RUNNING, TaskStatus.PENDING):
        raise HTTPException(status_code=400, detail="运行中的任务不能删除，请先取消")

    sm.pop(task_id)

    if sm.db_available:
        try:
            from backend.db.database import delete_task_from_db
            await delete_task_from_db(task_id)
        except Exception as e:
            logger.warning(f"[DB] 删除失败: {e}")
    if sm.redis_available:
        try:
            from backend.db.redis_cache import delete_cached_task
            await delete_cached_task(task_id)
        except Exception:
            pass
    try:
        from backend.storage.minio_client import get_storage
        get_storage().delete_task_files(task_id)
    except Exception:
        pass

    return {"status": "deleted", "task_id": task_id}


# ── 审批 ──────────────────────────────────────────────────

@router.post("/tasks/{task_id}/approve")
async def approve_task(task_id: str, req: ApproveRequest):
    sm = _get_sm()
    bus = _get_bus()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")

    inflight_ts = sm.get_approval_inflight(task_id)
    if inflight_ts is not None:
        elapsed = _time.time() - inflight_ts
        if elapsed < sm.APPROVAL_INFLIGHT_TIMEOUT:
            return {"status": "ok", "approved": req.approved, "note": "审批已在执行中"}
        logger.warning(f"[审批] inflight 超时 ({elapsed:.0f}s)，清除锁并允许重新审批: {task_id}")
        sm.clear_approval_inflight(task_id)

    if state.current_phase != "awaiting_approval":
        raise HTTPException(
            status_code=400,
            detail=f"任务当前阶段 '{state.current_phase}' 不需要审批",
        )

    state.current_phase = "foothold_attempt" if req.approved else "report"
    state.log(f"[审批] {'已授权，继续利用' if req.approved else '已拒绝，跳过利用'}")
    sm.set(task_id, state)
    sm.set_approval_inflight(task_id, _time.time())

    from backend.api.services.task_runner import resume_task
    asyncio.create_task(resume_task(task_id, req.approved))

    await bus.publish(task_id, {
        "type": "phase_update",
        **sm.ws_phase_payload(state, log_tail=3),
        "status": "running",
    })
    return {"status": "ok", "approved": req.approved}


# ── 用户-代理对话 ─────────────────────────────────────────

@router.post("/tasks/{task_id}/chat")
@router.post("/api/tasks/{task_id}/chat")
async def send_chat_message(task_id: str, req: ChatMessageRequest):
    sm = _get_sm()
    bus = _get_bus()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    msg = {
        "role": "user",
        "text": req.text.strip(),
        "timestamp": datetime.utcnow().isoformat(),
    }
    state.user_messages.append(msg)
    sm.set(task_id, state)
    await bus.publish(task_id, {
        "type": "decision_event",
        "data": {
            "id": f"chat-user-{len(state.user_messages)}",
            "timestamp": msg["timestamp"],
            "phase": state.current_phase,
            "action": "user_chat",
            "message": msg["text"],
            "tone": "primary",
        },
    })
    return {"status": "sent", "message": msg}


@router.get("/tasks/{task_id}/chat")
@router.get("/api/tasks/{task_id}/chat")
async def get_chat_history(task_id: str):
    sm = _get_sm()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    timeline = []
    for m in state.user_messages:
        timeline.append({**m, "role": "user"})
    for m in state.agent_replies:
        timeline.append({**m, "role": "agent"})
    timeline.sort(key=lambda x: x.get("timestamp", ""))
    return {"messages": timeline}
