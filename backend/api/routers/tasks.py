"""
routers/tasks.py —— 任务 CRUD + 审批 + 对话
"""
from __future__ import annotations

import asyncio
import logging
import time as _time
import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, BackgroundTasks, Request

from backend.agents.models import PentestState, TaskStatus, apply_mode_defaults
from backend.api.schemas import (
    CreateTaskRequest, TaskSummary, TaskStats, ApproveRequest, ChatMessageRequest,
)
from backend.api.state import get_state_manager, TaskStateManager
from backend.api.event_bus import get_event_bus, TaskEventBus

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tasks"])


async def _stop_task_container(task_id: str) -> None:
    """Cancel/delete 时统一清理工具容器,避免残留。"""
    try:
        from backend.tools.executor import TaskContainerManager
        await TaskContainerManager.stop(task_id)
    except Exception as e:
        logger.warning(f"[Container] 停止 {task_id} 失败: {e}")


def _get_sm() -> TaskStateManager:
    return get_state_manager()


def _get_bus() -> TaskEventBus:
    return get_event_bus()


def _enforce_task_owner(state: PentestState, request: Request, action: str) -> None:
    owner_id = getattr(request.state, "user_id", "") or ""
    tenant_id = getattr(request.state, "tenant_id", "") or "default"
    if not owner_id:
        raise HTTPException(status_code=401, detail="未登录")
    if not (state.owner_id or ""):
        # legacy task migration path: bind once when first accessed by authenticated owner
        state.owner_id = owner_id
        logger.info(f"[AuthZ] legacy task owner bound: task={state.task_id}, owner={owner_id}")
        return
    if (state.owner_id or "") != owner_id:
        logger.warning(
            f"[AuthZ] blocked cross-owner access action={action}, "
            f"task={state.task_id}, owner={state.owner_id}, actor={owner_id}"
        )
        raise HTTPException(status_code=403, detail="无权访问该任务")


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
async def create_task(req: CreateTaskRequest, request: Request):
    """
    创建一个新任务。

    参数来源优先级:
      1. 请求体里显式非 None 字段(per-task 覆盖)
      2. workflow_mode 对应的默认值(见 models._MODE_DEFAULTS)
    router 不再从 os.environ 读取工作流策略,settings 里不再下发这些变量。

    BackgroundTasks 不能承载长耗时任务(FastAPI 会在 response 发出前 awaited
    完,导致任务被延迟触发),因此统一改用 asyncio.create_task 并通过
    TaskStateManager 注册后台 handle,方便 cancel/delete 时精确终止。
    """
    sm = _get_sm()
    task_id = str(uuid.uuid4())

    owner_id = getattr(request.state, "user_id", "") or ""
    tenant_id = getattr(request.state, "tenant_id", "") or "default"
    
    state = PentestState(
        task_id=task_id,
        target=req.target,
        scope_note=req.scope_note,
        extra_hint=req.extra_hint,
        user_prompt=req.user_prompt,
        workflow_mode=req.workflow_mode,
        owner_id=owner_id,
        tenant_id=tenant_id,
        trace_id=getattr(request.state, "trace_id", "") or "",
    )
    # 填入 workflow_mode 默认值,并用请求里显式传入的覆盖项替换
    apply_mode_defaults(
        state,
        overrides={
            "auto_approve":        req.auto_approve,
            "success_gate_level":  req.success_gate_level,
            "risk_budget":         req.risk_budget,
            "max_react_rounds":    req.max_react_rounds,
            "max_explore_rounds":  req.max_explore_rounds,
            "skill_min_score":     req.skill_min_score,
            "skill_weak_boost":    req.skill_weak_boost,
        },
    )
    sm.set(task_id, state)

    if sm.db_available:
        try:
            from backend.db.database import save_task
            await save_task(state)
        except Exception as e:
            logger.warning(f"[DB] 保存失败: {e}")

    from backend.api.services.task_runner import run_task
    task_handle = asyncio.create_task(run_task(task_id, state))
    sm.register_bg_task(task_id, task_handle)

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
async def list_tasks(request: Request):
    """仅返回当前登录用户自己创建的任务。"""
    sm = _get_sm()
    owner_id = getattr(request.state, "user_id", "") or ""

    if sm.db_available:
        try:
            from backend.db.database import list_tasks_from_db
            db_list = await list_tasks_from_db(owner_id=owner_id or None)
            result = []
            seen = set()
            for t in db_list:
                tid = t["task_id"]
                seen.add(tid)
                state = sm.get(tid)
                if state:
                    result.append(sm.to_summary(state))
                else:
                    # DB 行缺少 workflow_mode/auto_approve,用 TaskSummary 默认值补齐
                    result.append(TaskSummary(**t).model_dump())
            # 兜底:内存中有但 DB 还没落盘的任务(限定 owner)
            for tid, state in sm.items():
                if tid in seen:
                    continue
                if owner_id and (state.owner_id or "") != owner_id:
                    continue
                result.append(sm.to_summary(state))
            return result
        except Exception as e:
            logger.warning(f"[DB] 查询失败: {e}")

    # 无 DB 时按 owner 过滤内存任务
    return [
        sm.to_summary(s) for s in sm.all_states()
        if not owner_id or (s.owner_id or "") == owner_id
    ]


@router.get("/tasks/{task_id}")
async def get_task(task_id: str, request: Request):
    state = await _resolve_state(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "get_task")
    sm = _get_sm()
    return sm.to_detail(state)


@router.get("/tasks/{task_id}/report")
async def get_report(task_id: str, request: Request):
    state = await _resolve_state(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "get_report")
    if not state.report_md:
        raise HTTPException(status_code=404, detail="报告尚未生成")
    return {"markdown": state.report_md, "path": state.report_path}


@router.get("/tasks/{task_id}/logs")
async def get_logs(task_id: str, request: Request):
    sm = _get_sm()
    state = await _resolve_state(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "get_logs")
    if sm.redis_available:
        try:
            from backend.db.redis_cache import get_task_logs
            logs = await get_task_logs(task_id)
            if logs:
                return {"logs": logs}
        except Exception:
            pass
    return {"logs": state.phase_log}


@router.post("/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, request: Request):
    sm = _get_sm()
    bus = _get_bus()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "cancel_task")
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

    # 主动取消后台协程 + 停掉工具容器,避免继续消耗资源
    sm.cancel_bg_task(task_id)
    await _stop_task_container(task_id)

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
async def delete_task(task_id: str, request: Request):
    sm = _get_sm()
    state = sm.get(task_id)
    if state:
        _enforce_task_owner(state, request, "delete_task")
    else:
        state = await _resolve_state(task_id)
        if state:
            _enforce_task_owner(state, request, "delete_task")
    if state and state.status in (TaskStatus.RUNNING, TaskStatus.PENDING):
        raise HTTPException(status_code=400, detail="运行中的任务不能删除,请先取消")

    # 不管任务是否仍在运行(前端已阻塞这种情况),统一确保容器/后台协程被清理
    sm.cancel_bg_task(task_id)
    await _stop_task_container(task_id)

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
async def approve_task(task_id: str, req: ApproveRequest, request: Request):
    """
    人工审批端点。

    正确顺序(避免与 LangGraph 状态机竞态):
      1. 校验 current_phase 必须是 awaiting_approval
      2. 先设置 inflight 锁 + 持久化 approved 标记 + 调用 resume_task
      3. 最后由 LangGraph 的 node_human_approval / 后续节点自己推进
         current_phase,router 不再抢在 LangGraph 之前手改 phase,
         避免 UI 和引擎看到不一致的状态。
    """
    sm = _get_sm()
    bus = _get_bus()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "approve_task")

    inflight_ts = sm.get_approval_inflight(task_id)
    if inflight_ts is not None:
        elapsed = _time.time() - inflight_ts
        if elapsed < sm.APPROVAL_INFLIGHT_TIMEOUT:
            return {"status": "ok", "approved": req.approved, "note": "审批已在执行中"}
        logger.warning(f"[审批] inflight 超时 ({elapsed:.0f}s),清除锁并允许重新审批: {task_id}")
        sm.clear_approval_inflight(task_id)

    if state.current_phase != "awaiting_approval":
        raise HTTPException(
            status_code=400,
            detail=f"任务当前阶段 '{state.current_phase}' 不需要审批",
        )

    # 先锁,再记一条日志(phase 保持 awaiting_approval,交给引擎节点去更新)
    sm.set_approval_inflight(task_id, _time.time())
    state.approved = bool(req.approved)
    state.log(f"[审批] {'已授权,继续利用' if req.approved else '已拒绝,跳过利用'}")
    sm.set(task_id, state)

    # 触发 resume,让 LangGraph 从 interrupt 处继续运行
    from backend.api.services.task_runner import resume_task
    task_handle = asyncio.create_task(resume_task(task_id, req.approved))
    sm.register_bg_task(task_id, task_handle)

    await bus.publish(task_id, {
        "type": "phase_update",
        **sm.ws_phase_payload(state, log_tail=3),
        "status": "running",
    })
    return {"status": "ok", "approved": req.approved}


# ── 用户-代理对话 ─────────────────────────────────────────

@router.post("/tasks/{task_id}/chat")
async def send_chat_message(task_id: str, req: ChatMessageRequest, request: Request):
    sm = _get_sm()
    bus = _get_bus()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    _enforce_task_owner(state, request, "send_chat_message")
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
async def get_chat_history(task_id: str, request: Request):
    sm = _get_sm()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    _enforce_task_owner(state, request, "get_chat_history")
    timeline = []
    for m in state.user_messages:
        timeline.append({**m, "role": "user"})
    for m in state.agent_replies:
        timeline.append({**m, "role": "agent"})
    timeline.sort(key=lambda x: x.get("timestamp", ""))
    return {"messages": timeline}
