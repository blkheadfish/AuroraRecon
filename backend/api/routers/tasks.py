"""
routers/tasks.py —— 任务 CRUD + 审批 + 对话
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time as _time
import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, BackgroundTasks, Request

from backend.agents.models import PentestState, TaskStatus, apply_mode_defaults, parse_target
from backend.api.schemas import (
    CreateTaskRequest, TaskSummary, TaskStats, ApproveRequest,
    CheckpointDecisionRequest, ChatMessageRequest,
    ParseIntentRequest, ParseIntentResponse,
)
from backend.api.state import get_state_manager, TaskStateManager
from backend.api import event_stream

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


async def _resolve_active_thread_id(task_id: str, state: PentestState) -> str:
    """Return the thread_id LangGraph should target for this task right now.

    Defaults to ``task_id`` (legacy / root behaviour). When the branch tree
    has been bootstrapped, returns the active branch's ``thread_id``. Failures
    are logged and we fall back to ``task_id`` so the legacy path keeps
    working even if BranchManager is unhealthy.
    """
    try:
        from backend.api.services.branch_manager import get_branch_manager
        bm = get_branch_manager()
        await bm.lazy_init_root(task_id, state)
        active = await bm.get_active(task_id)
        if active and active.thread_id:
            return active.thread_id
    except Exception as exc:
        logger.warning(f"[branches] resolve active thread failed: {exc}")
    return task_id


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


# ── 意图解析 (LLM 驱动) ───────────────────────────────────

# 与前端 TaskCreateChat.vue 的 extractTarget 对齐的兜底正则集合
_FALLBACK_TARGET_PATTERNS = [
    re.compile(r"https?://[^\s,;'\"，。、）)]+", re.IGNORECASE),
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b"),
    re.compile(
        r"(?<![./@\w])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,}(?::\d{1,5})?(?![\w./])"
    ),
]


def _fallback_extract_target(prompt: str) -> str:
    """LLM 不可用时的目标提取兜底,逻辑与前端 extractTarget 一致。"""
    if not prompt:
        return ""
    for pattern in _FALLBACK_TARGET_PATTERNS:
        match = pattern.search(prompt)
        if not match:
            continue
        candidate = match.group(0).rstrip(".,;'\"，。、)）")
        if not candidate:
            continue
        try:
            parsed = parse_target(candidate)
        except Exception:
            continue
        if parsed.host:
            return candidate
    return ""


def _validate_target_candidate(raw: str) -> str:
    """对 LLM 返回的 target 做安全 + 合法性校验,失败返回空串。"""
    if not raw:
        return ""
    candidate = raw.strip().rstrip(".,;'\"，。、)）")
    if not candidate or len(candidate) > 256:
        return ""
    if re.search(r"[;\|`$&<>(){}\[\]!\s]", candidate):
        return ""
    try:
        parsed = parse_target(candidate)
    except Exception:
        return ""
    return candidate if parsed.host else ""


_INTENT_SYSTEM_PROMPT = """你是一名渗透测试任务意图解析器。
你的输入是用户用自然语言描述的一段渗透测试需求,你需要从中抽取结构化信息。

只输出纯 JSON,不要 markdown 代码块、不要任何解释,严格遵守以下 schema:

{
  "target": "<从描述中提取的第一个目标地址 (IP / 域名 / URL),没有就留空串>",
  "suggested_workflow_mode": "<pentest_engineer 或 ctf_expert,根据语境推断>",
  "priority_vulns": ["<漏洞类型简标签,如 sqli / rce / lfi / xss / ssrf / auth_bypass / file_upload / deserialization 等>"],
  "scope_note": "<对授权范围/场景的一句话归纳,例如 'CTF/授权靶场测试' 或 '内网授权红队评估'>",
  "extra_hint": "<对 Agent 的额外行动建议,简短一句话,例如 '优先低噪声,避开 IDS' 或 '先打 web 攻击面,拿 flag 优先'>",
  "summary": "<一句话用中文复述用户意图,不超过 30 字>",
  "intents": ["<语义标签,如 stealth / get_flag / low_noise / prefer_msf / chain_attack / web_only 等>"],
  "confidence": <0~1 的小数,你对自己解析结果的把握度>
}

提取规则:
1. target 必须是单一字符串,不要包含中文标点和空格;只要找到一个有效的就停止
2. 如果用户提到 "CTF / flag / 靶场",倾向 ctf_expert;明确说 "渗透 / 红队 / 内网" 倾向 pentest_engineer
3. priority_vulns 用全小写英文短标签,数量最多 6 个
4. scope_note / extra_hint 不要原样照搬用户原话,做语义提炼
5. 没有把握的字段宁可留空 / 空数组,也不要编造"""


def _build_intent_user_prompt(user_prompt: str, current_mode: str) -> str:
    return (
        f"当前默认 workflow_mode = {current_mode}\n"
        f"用户描述:\n```\n{user_prompt.strip()}\n```\n"
        "请按 schema 输出 JSON。"
    )


def _coerce_intent_payload(data: dict) -> dict:
    """规整 LLM 输出的字段,过滤异常类型。"""
    target = _validate_target_candidate(str(data.get("target") or ""))
    mode_raw = str(data.get("suggested_workflow_mode") or "").strip().lower()
    if mode_raw not in ("pentest_engineer", "ctf_expert"):
        mode_raw = ""

    def _clean_list(values, max_items: int = 6, max_len: int = 32) -> list[str]:
        if not isinstance(values, list):
            return []
        out: list[str] = []
        for item in values:
            if not isinstance(item, str):
                continue
            tag = item.strip().lower()
            if not tag or len(tag) > max_len:
                continue
            if tag not in out:
                out.append(tag)
            if len(out) >= max_items:
                break
        return out

    confidence_raw = data.get("confidence", 0.0)
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    return {
        "target": target,
        "suggested_workflow_mode": mode_raw,
        "priority_vulns": _clean_list(data.get("priority_vulns")),
        "scope_note": str(data.get("scope_note") or "").strip()[:120],
        "extra_hint": str(data.get("extra_hint") or "").strip()[:200],
        "summary": str(data.get("summary") or "").strip()[:120],
        "intents": _clean_list(data.get("intents"), max_items=8, max_len=24),
        "confidence": confidence,
    }


@router.post("/tasks/parse-intent", response_model=ParseIntentResponse)
async def parse_task_intent(req: ParseIntentRequest, request: Request):
    """
    用 LLM 解析用户的自然语言任务描述,返回结构化的目标/工作流/漏洞偏好。

    - 调用 ``LLMRouter.chat(response_format='json')``,8s 超时
    - LLM 不可用 / 返回不合法 JSON / target 校验失败时,自动回退到正则
      提取(等价于前端老逻辑),并把 ``fallback=True``
    - 该接口 **只读**,不会创建任务,也不依赖任务状态
    """
    user_id = getattr(request.state, "user_id", "") or ""
    if not user_id:
        raise HTTPException(status_code=401, detail="未登录")

    user_prompt = req.user_prompt
    current_mode = req.workflow_mode

    fallback_target = _fallback_extract_target(user_prompt)

    try:
        from backend.llm.router import LLMRouter
        llm = LLMRouter()
        raw = await asyncio.wait_for(
            llm.chat(
                _build_intent_user_prompt(user_prompt, current_mode),
                system_prompt=_INTENT_SYSTEM_PROMPT,
                response_format="json",
                temperature=0.1,
                max_tokens=512,
            ),
            timeout=8.0,
        )
    except asyncio.TimeoutError:
        logger.info("[parse_intent] LLM 超时,回退正则")
        return ParseIntentResponse(target=fallback_target, fallback=True, error="LLM 超时")
    except Exception as e:
        logger.warning(f"[parse_intent] LLM 调用异常: {e}")
        return ParseIntentResponse(target=fallback_target, fallback=True, error=str(e)[:120])

    try:
        data = json.loads(raw if isinstance(raw, str) else str(raw))
        if not isinstance(data, dict):
            raise ValueError("LLM 返回不是对象")
    except Exception as e:
        logger.info(f"[parse_intent] LLM JSON 解析失败,回退正则: {e}")
        return ParseIntentResponse(target=fallback_target, fallback=True, error=f"JSON 解析失败: {e}")

    payload = _coerce_intent_payload(data)
    # 即便 LLM 没解析出 target,也尽量回填正则结果,前端体验更平滑
    if not payload["target"] and fallback_target:
        payload["target"] = fallback_target

    return ParseIntentResponse(**payload, fallback=False)


# ── CRUD ──────────────────────────────────────────────────

@router.post("/tasks", response_model=TaskSummary)
async def create_task(req: CreateTaskRequest, request: Request):
    """
    创建一个新任务。

    支持两种模式:
      1. 传统模式: 直接传 target (IP/域名/CIDR)，兼容旧接口
      2. 自然语言模式: 传 raw_prompt，系统自动解析意图 + 安全卡口

    状态机:
      POST /tasks →
        if SafetyGate.blocked → 400 + reason
        if SafetyGate.warnings 且 user_confirmed_risks 未覆盖 → 202 pending_confirmation
        if ambiguity partial/vague 且缺关键信息 → 202 pending_clarification
        else → 创建任务 201 + task_id

    二次 POST 附带 user_confirmed_risks 完成确认，避免意外执行。
    """
    sm = _get_sm()
    owner_id = getattr(request.state, "user_id", "") or ""
    tenant_id = getattr(request.state, "tenant_id", "") or "default"

    # ── 第一步：意图解析 + 目标推导 ───────────────────────
    raw_prompt = req.raw_prompt.strip() or req.user_prompt.strip()
    raw_target = req.target.strip()

    parsed_intent_dict: dict | None = None
    effective_target = raw_target

    if raw_prompt:
        from backend.agents.intent_parser import parse_intent_deterministic

        parsed_intent = parse_intent_deterministic(raw_prompt)
        parsed_intent_dict = parsed_intent.model_dump()

        # 如果 target 为空，从 raw_prompt 提取
        if not effective_target and parsed_intent.targets:
            effective_target = parsed_intent.targets[0]
            logger.info(
                f"[create_task] 从 raw_prompt 提取目标: {effective_target} "
                f"(type={parsed_intent.target_type})"
            )

        # 如果 target 和 raw_prompt 都为空 → 400
        if not effective_target:
            raise HTTPException(
                status_code=400,
                detail={
                    "status": "pending_clarification",
                    "message": "无法从描述中提取目标地址",
                    "clarification_needed": parsed_intent.clarification_needed,
                    "parsed_intent": parsed_intent_dict,
                }
            )
    elif not effective_target:
        raise HTTPException(
            status_code=400,
            detail="target 和 raw_prompt 至少需要提供一个"
        )

    # ── 第二步：安全卡口检查（确定性规则，不依赖 LLM）────
    from backend.agents.safety_gate import get_safety_gate
    from backend.agents.intent_parser import parse_intent_deterministic

    # 复用已解析的 intent 或重新解析
    if parsed_intent_dict is None:
        safety_intent = parse_intent_deterministic(
            raw_prompt or f"对 {effective_target} 进行渗透测试"
        )
    else:
        from backend.agents.models import ParsedIntent
        safety_intent = ParsedIntent(**parsed_intent_dict)

    gate = get_safety_gate()
    safety_result = gate.check(
        safety_intent,
        authorization_token=req.authorization_token,
        user_id=owner_id,
    )

    # ── BLOCK：直接拒绝 ──────────────────────────────────
    if safety_result.risk_level == "blocked":
        raise HTTPException(
            status_code=400,
            detail={
                "status": "blocked",
                "message": safety_result.block_reason or "安全卡口拦截",
                "parsed_intent": parsed_intent_dict or safety_intent.model_dump(),
            }
        )

    # ── WARNING：检查用户是否已确认 ──────────────────────
    if safety_result.risk_level == "warning":
        pending_confirmations = [
            c for c in safety_result.required_confirmations
            if c not in req.user_confirmed_risks
        ]
        if pending_confirmations:
            return {
                "status": "pending_confirmation",
                "task_id": "",
                "target": effective_target,
                "warnings": safety_result.warnings,
                "required_confirmations": pending_confirmations,
                "parsed_intent": parsed_intent_dict or safety_intent.model_dump(),
                "message": "需要确认以下风险项后再提交",
            }

    # ── PENDING_CLARIFICATION：目标不明确 ────────────────
    if safety_intent.ambiguity_level in ("partial", "vague") and \
       safety_intent.clarification_needed:
        raise HTTPException(
            status_code=400,
            detail={
                "status": "pending_clarification",
                "message": "目标信息不完整，需要补充",
                "questions": safety_intent.clarification_needed,
                "parsed_intent": safety_intent.model_dump(),
            }
        )

    # ── 第三步：通过所有检查，创建任务 ─────────────────────
    task_id = str(uuid.uuid4())

    # 验证最终 target 的合法性
    try:
        from backend.agents.models import parse_target
        parsed = parse_target(effective_target)
        if not parsed.host:
            raise HTTPException(status_code=400, detail=f"无法解析目标: {effective_target}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"目标格式错误: {e}")

    state = PentestState(
        task_id=task_id,
        target=effective_target,
        raw_prompt=raw_prompt,
        scope_note=req.scope_note,
        extra_hint=req.extra_hint,
        user_prompt=req.user_prompt or raw_prompt,
        workflow_mode=req.workflow_mode,
        owner_id=owner_id,
        tenant_id=tenant_id,
        trace_id=getattr(request.state, "trace_id", "") or "",
        authorization_token=req.authorization_token,
        parsed_intent=parsed_intent_dict or safety_intent.model_dump(),
        safety_check_result=safety_result.model_dump(),
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
    from backend.api.services.branch_manager import get_branch_manager
    # 注册 root 分支(thread_id == task_id 兼容老逻辑)
    try:
        await get_branch_manager().lazy_init_root(task_id, state)
    except Exception as exc:
        logger.warning(f"[create_task] lazy_init_root failed: {exc}")
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
async def list_tasks(request: Request, all: bool = False):
    """返回任务列表。admin 传 ?all=true 可获取全部用户的任务。"""
    sm = _get_sm()
    owner_id = getattr(request.state, "user_id", "") or ""

    is_admin_all = False
    if all and owner_id:
        from backend.api.deps import get_current_user_role
        role = await get_current_user_role(owner_id)
        if role == "admin":
            is_admin_all = True

    effective_owner = None if is_admin_all else (owner_id or None)

    if sm.db_available:
        try:
            from backend.db.database import list_tasks_from_db
            db_list = await list_tasks_from_db(owner_id=effective_owner)
            result = []
            seen = set()
            for t in db_list:
                tid = t["task_id"]
                seen.add(tid)
                state = sm.get(tid)
                if state:
                    summary = sm.to_summary(state)
                    summary["owner_id"] = state.owner_id or ""
                    result.append(summary)
                else:
                    summary = TaskSummary(**t).model_dump()
                    summary["owner_id"] = t.get("owner_id", "")
                    result.append(summary)
            for tid, state in sm.items():
                if tid in seen:
                    continue
                if effective_owner and (state.owner_id or "") != effective_owner:
                    continue
                summary = sm.to_summary(state)
                summary["owner_id"] = state.owner_id or ""
                result.append(summary)
            return result
        except Exception as e:
            logger.warning(f"[DB] 查询失败: {e}")

    return [
        {**sm.to_summary(s), "owner_id": s.owner_id or ""}
        for s in sm.all_states()
        if not effective_owner or (s.owner_id or "") == effective_owner
    ]


@router.get("/tasks/{task_id}")
async def get_task(task_id: str, request: Request, full: bool = False):
    """返回任务详情。

    默认走轻量快照(``to_detail_snapshot``),只附带最近 N 条 phase_log
    与 decision_events,完整日志/报告/工具记录走专用接口,避免运行很久
    的任务首屏接口返回上 MB 数据导致前端卡顿。

    ``?full=true`` 仍可拿到旧版完整 ``to_detail`` 结果,用于「原始数据」
    Tab 等需要整棵 state 的场景。
    """
    state = await _resolve_state(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "get_task")
    sm = _get_sm()
    if full:
        return sm.to_detail(state)
    return sm.to_detail_snapshot(state)


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
async def get_logs(
    task_id: str,
    request: Request,
    offset: int = 0,
    limit: int = 500,
    tail: int | None = None,
    after_seq: int | None = None,
):
    """分页/增量读取任务日志。

    协议:
      * 不传参数 → 兼容旧前端,返回最近 ``limit`` (默认 500) 条
        作为 ``tail`` 行为,避免一次性下发数万行 phase_log。
      * ``tail=N``        → 返回最后 N 行(N 上限 5000)。
      * ``after_seq=K``   → 返回 index > K 的所有行(增量,WS 重连用)。
      * ``offset=O&limit=L`` → 经典分页(向前回滚历史日志用)。

    响应:
      ``logs``        : list[str]
      ``offset``      : 本次返回起始 index (含)
      ``limit``       : 服务端真实使用的 limit
      ``total``       : 服务端 phase_log 总条数
      ``next_seq``    : 下一次增量读起点(等于 offset+len(logs))
      ``has_more``    : 是否还有更早的历史可向前翻
    """
    sm = _get_sm()
    state = await _resolve_state(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "get_logs")

    # 合并 Redis(若可用) 与内存 phase_log,Redis 优先(更完整);
    # Redis 不可用或为空时回退到内存数组。
    source: list[str] = []
    if sm.redis_available:
        try:
            from backend.db.redis_cache import get_task_logs
            redis_logs = await get_task_logs(task_id)
            if redis_logs:
                source = list(redis_logs)
        except Exception:
            source = []
    if not source:
        source = list(state.phase_log or [])

    total = len(source)
    LIMIT_MAX = 5000

    if after_seq is not None:
        start = max(0, int(after_seq))
        end = total
        sliced = source[start:end]
        return {
            "logs": sliced,
            "offset": start,
            "limit": len(sliced),
            "total": total,
            "next_seq": start + len(sliced),
            "has_more": False,
        }

    if tail is not None:
        n = max(0, min(int(tail), LIMIT_MAX))
        start = max(0, total - n)
        sliced = source[start:]
        return {
            "logs": sliced,
            "offset": start,
            "limit": len(sliced),
            "total": total,
            "next_seq": total,
            "has_more": start > 0,
        }

    if offset == 0 and limit == 500:
        # 默认行为(不带参数):返回最近 500 条,避免大日志全量下发。
        n = min(500, LIMIT_MAX)
        start = max(0, total - n)
        sliced = source[start:]
        return {
            "logs": sliced,
            "offset": start,
            "limit": len(sliced),
            "total": total,
            "next_seq": total,
            "has_more": start > 0,
        }

    start = max(0, int(offset))
    n = max(0, min(int(limit), LIMIT_MAX))
    end = min(total, start + n)
    sliced = source[start:end]
    return {
        "logs": sliced,
        "offset": start,
        "limit": len(sliced),
        "total": total,
        "next_seq": end,
        "has_more": end < total,
    }


@router.get("/tasks/{task_id}/events")
async def get_task_events(
    task_id: str,
    request: Request,
    after_id: str = "",
    count: int = 500,
):
    """协议 v2 历史事件分页接口。

    用法:
        * 首次进入页面: ``after_id=""`` 拿最早的 ``count`` 条;
        * 翻历史: 把第一帧的 ``first_id`` 当作下一次 ``before_id`` 用 (本期暂未
          实现 before_id 翻向更早, 通过分批 ``after_id`` 拉到尾后再切往前看)。
        * WS 重连补差量: ``after_id=<lastEventId>`` 拿大于该 id 的事件。

    返回:
        events     : envelope list (按 stream id 升序)
        first_id   : 本批最早的 id
        last_id    : 本批最末的 id (前端可推进 ``lastEventId``)
        has_more   : 当前批次满 ``count`` 时为 true, 提示前端继续往后翻
    """
    sm = _get_sm()
    state = sm.get(task_id)
    if not state and sm.db_available:
        try:
            from backend.db.database import load_task
            state = await load_task(task_id)
        except Exception:
            state = None
    if state is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "get_task_events")

    safe_count = max(1, min(int(count or 500), 2000))
    try:
        events = await event_stream.replay(
            task_id, after_id=(after_id or "0"), count=safe_count,
        )
    except Exception as exc:
        logger.warning(
            "[events] replay failed task=%s after_id=%s err=%s",
            task_id, after_id, exc,
        )
        events = []

    return {
        "events": events,
        "count": len(events),
        "first_id": events[0]["id"] if events else "",
        "last_id": events[-1]["id"] if events else "",
        "has_more": len(events) >= safe_count,
    }


@router.post("/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, request: Request):
    sm = _get_sm()
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
    await event_stream.publish(
        task_id, type="done",
        payload={"status": "failed", "message": "任务已取消"},
        branch_id=state.active_branch_id or "",
    )
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
    # 协议 v2: 把 task 的 Stream 连同本地降级 ring 一起回收, 避免新建的同 id
    # 任务读到老事件污染界面。
    try:
        await event_stream.drop(task_id)
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
    from backend.api.services.branch_manager import get_branch_manager
    bm = get_branch_manager()
    try:
        active_branch = await bm.lazy_init_root(task_id, state)
    except Exception as exc:
        logger.warning(f"[approve] lazy_init_root failed: {exc}")
        active_branch = None
    thread_id = active_branch.thread_id if active_branch else task_id
    task_handle = asyncio.create_task(
        resume_task(task_id, req.approved, thread_id=thread_id)
    )
    sm.register_bg_task(task_id, task_handle)

    payload = sm.ws_phase_payload(state, log_tail=3)
    payload["status"] = "running"
    await event_stream.publish(
        task_id, type="phase_update",
        payload=payload,
        branch_id=payload.get("branch_id", ""),
    )
    return {"status": "ok", "approved": req.approved}


# ── 通用 checkpoint 响应 ──────────────────────────────────

@router.post("/tasks/{task_id}/checkpoint/respond")
async def respond_checkpoint(
    task_id: str, req: CheckpointDecisionRequest, request: Request,
):
    """统一处理 Plan 模式确认框的响应。

    它是 ``/approve`` 的超集:
      * 没有 pending checkpoint 但任务确实在 awaiting_approval,会回退到
        旧逻辑(仅设置 approved/post_approved)。
      * 存在 pending checkpoint 时,根据 ``action`` 解析:
          - approve / modify / skip → 视为同意继续(approved=True)
          - reject                 → 视为拒绝(approved=False)
      * ``user_prompt`` 会被写进 state.pending_user_prompt,后续节点可消费。
    """
    sm = _get_sm()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "respond_checkpoint")

    if state.current_phase not in ("awaiting_approval", "post_foothold_approval"):
        raise HTTPException(
            status_code=400,
            detail=f"任务当前阶段 '{state.current_phase}' 不需要确认",
        )

    inflight_ts = sm.get_approval_inflight(task_id)
    if inflight_ts is not None:
        elapsed = _time.time() - inflight_ts
        if elapsed < sm.APPROVAL_INFLIGHT_TIMEOUT:
            return {"status": "ok", "note": "审批已在执行中"}
        sm.clear_approval_inflight(task_id)

    archived = state.resolve_checkpoint({
        "action": req.action,
        "selected_option": req.selected_option,
        "user_prompt": req.user_prompt,
        "note": req.note,
    })

    approved = req.action != "reject"
    sm.set_approval_inflight(task_id, _time.time())
    if state.current_phase == "post_foothold_approval":
        state.post_approved = approved
    else:
        state.approved = approved

    state.log(
        f"[Checkpoint] action={req.action}"
        + (f" prompt='{req.user_prompt[:40]}'" if req.user_prompt else "")
    )
    sm.set(task_id, state)

    from backend.api.services.task_runner import resume_task
    from backend.api.services.branch_manager import get_branch_manager
    bm = get_branch_manager()
    try:
        active_branch = await bm.lazy_init_root(task_id, state)
    except Exception as exc:
        logger.warning(f"[checkpoint] lazy_init_root failed: {exc}")
        active_branch = None
    thread_id = active_branch.thread_id if active_branch else task_id
    task_handle = asyncio.create_task(
        resume_task(task_id, approved, thread_id=thread_id)
    )
    sm.register_bg_task(task_id, task_handle)

    payload = sm.ws_phase_payload(state, log_tail=3)
    payload["status"] = "running"
    await event_stream.publish(
        task_id, type="phase_update",
        payload=payload,
        branch_id=payload.get("branch_id", ""),
    )
    return {
        "status": "ok",
        "approved": approved,
        "action": req.action,
        "checkpoint": archived,
    }


# ── 用户-代理对话 ─────────────────────────────────────────

@router.post("/tasks/{task_id}/chat")
async def send_chat_message(task_id: str, req: ChatMessageRequest, request: Request):
    """Operator chat endpoint (PR2 — branching).

    Behaviour matrix::

        running              → fork a new branch from the active branch's
                                LangGraph checkpoint; the old branch is
                                cooperatively paused (snapshot kept for
                                later resume); the new branch starts with
                                ``pending_user_prompt`` + ``operator_intent``
                                injected so the supervisor reroutes by the
                                operator's intent.
        awaiting_approval    → also fork: the parent's checkpoint is
                                preserved (so the operator can return to it
                                via "switch + resume"), and the new branch
                                inherits the snapshot but is released
                                immediately for the supervisor to act.
        completed / failed   → no fork, just append to user_messages
                                (laboratory-notebook semantics — branching
                                from a finalized run isn't useful since the
                                attack chain has terminated).
    """
    sm = _get_sm()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    _enforce_task_owner(state, request, "send_chat_message")

    text = (req.text or "").strip()
    if not text:
        raise HTTPException(400, "消息不能为空")

    now_iso = datetime.utcnow().isoformat()
    msg = {
        "role": "user",
        "text": text,
        "timestamp": now_iso,
    }

    # ``state.status`` 是"业务状态"(running / awaiting_approval / completed),
    # 但当某个分支被 ``_resume_branch_bg`` 错误标记为 paused 后, 任务仍然在
    # 进行中(_running_tasks 集合 = 真正的 lifecycle 标识), 此时我们仍然要
    # 允许 fork — 否则用户的"80端口有什么目录?"消息会落到 else 分支被
    # 当成"终态追加"丢弃, 表现为 root 已暂停 + 没有新分支启动。
    fork_active = (
        state.status in (TaskStatus.RUNNING, TaskStatus.AWAITING_APPROVAL)
        or sm.is_running(task_id)
    )

    # ── user_messages 写入责任划分 ──────────────────────────
    # fork 路径: 此处不 append 到 ``sm.state.user_messages``。
    #   ``BranchManager.fork_from_active`` 内部已经基于父分支 user_messages
    #   构造 ``new_messages = parent_msgs + [new_msg]`` 写到 child thread
    #   的 LangGraph checkpoint 里; 如果这里又往 sm.state 追加, fork 出
    #   的子分支 user_messages 就会出现"父历史 + 当前 + 当前"的双写,
    #   前端按 branch_id 过滤后会显示同一条用户消息出现两次。
    # 终态路径(completed/failed): 不会 fork, 这里写入是唯一记录点。
    new_branch_payload = None
    if fork_active:
        from backend.api.services.branch_manager import get_branch_manager
        bm = get_branch_manager()
        # Ensure root exists (lazy bootstrap for legacy tasks).
        try:
            await bm.lazy_init_root(task_id, state)
        except Exception as exc:
            logger.warning(
                f"[chat] lazy_init_root failed task={task_id}: {exc}"
            )

        # Persist message + state *before* fork so the snapshot we copy
        # already contains the operator instruction.
        joined = (state.pending_user_prompt or "").strip()
        state.pending_user_prompt = (
            f"{joined}\n{text}" if joined else text
        )
        signals = dict(state.replan_signals or {})
        signals["operator_intent"] = int(signals.get("operator_intent", 0)) + 1
        state.replan_signals = signals
        sm.set(task_id, state)

        # Forking handles cooperative interrupt of the parent + checkpoint
        # copy + bg task scheduling for the child.
        # Claude 风格: 若前端指定了 ``from_event_id`` (在某条历史消息处分叉),
        # 把它当作 ``TaskBranch.fork_event_id`` 落库, 并用 ``from_event_ts``
        # 作为时间锚点交给 ``find_checkpoint_at_or_before`` 找对应 checkpoint。
        fork_event_id = (
            req.from_event_id
            if req.from_event_id
            else f"chat-{len(state.user_messages) + 1}"
        )
        try:
            child = await bm.fork_from_active(
                task_id,
                user_prompt=text,
                fork_event_id=fork_event_id,
                from_event_ts=req.from_event_ts,
            )
            new_branch_payload = child.model_dump()
        except Exception as exc:
            logger.error(
                f"[chat] fork_from_active failed task={task_id}: {exc}",
                exc_info=True,
            )
            # Fall back to PR1 behaviour: at least flip operator_intent +
            # request_interrupt so the in-flight branch reroutes itself.
            try:
                from backend.agents.interrupt_registry import request_interrupt
                request_interrupt(
                    task_id, reason="operator_chat",
                    payload={"text": text, "fallback": True},
                )
            except Exception:
                pass
    else:
        # 终态/无 fork 场景下唯一的写入点。
        state.user_messages.append(msg)
        sm.set(task_id, state)

    chat_branch_id = (
        (new_branch_payload or {}).get("branch_id")
        or state.active_branch_id
        or ""
    )
    await event_stream.publish(
        task_id, type="decision_event",
        payload={
            "id": f"chat-user-{len(state.user_messages)}",
            "timestamp": msg["timestamp"],
            "phase": state.current_phase,
            "action": "user_chat",
            "message": msg["text"],
            "tone": "primary",
            "branch_id": chat_branch_id,
        },
        branch_id=chat_branch_id,
    )
    if new_branch_payload is not None:
        await event_stream.publish(
            task_id, type="decision_event",
            payload={
                "id": f"branch-fork-{new_branch_payload['branch_id']}",
                "timestamp": now_iso,
                "phase": state.current_phase,
                "action": "branch_forked",
                "message": (
                    f"已从此处分叉新分支 ({new_branch_payload['label']});"
                    " 老分支已暂停, 可随时切回继续运行"
                ),
                "tone": "primary",
                "branch_id": new_branch_payload["branch_id"],
            },
            branch_id=new_branch_payload["branch_id"],
        )
    return {
        "status": "sent",
        "message": msg,
        "task_status": state.status.value,
        "fork_active": fork_active,
        "branch": new_branch_payload,
    }


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


# ── 任务分支 (Claude/Kimi 风格 branch tree) ────────────────

@router.get("/tasks/{task_id}/branches")
async def list_task_branches(task_id: str, request: Request):
    """Return the full branch tree of a task plus sibling/active metadata."""
    sm = _get_sm()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    _enforce_task_owner(state, request, "list_task_branches")

    from backend.api.services.branch_manager import get_branch_manager
    bm = get_branch_manager()
    # Lazy bootstrap so the legacy task always shows at least its root.
    try:
        await bm.lazy_init_root(task_id, state)
    except Exception as exc:
        logger.warning(f"[branches] lazy_init_root failed: {exc}")

    branches = await bm.list_branches(task_id)
    active = await bm.get_active(task_id)
    active_id = active.branch_id if active else (state.active_branch_id or "")
    return bm.to_tree_payload(branches, active_id)


@router.post("/tasks/{task_id}/branches/{branch_id}/activate")
async def activate_task_branch(
    task_id: str, branch_id: str, request: Request,
):
    """Switch the *active* branch (the one mirrored to TaskStateManager).

    By default the previously-active branch is paused so we never have two
    branches actively touching the target at once.
    """
    sm = _get_sm()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    _enforce_task_owner(state, request, "activate_task_branch")

    from backend.api.services.branch_manager import get_branch_manager
    bm = get_branch_manager()
    try:
        target = await bm.switch_active(task_id, branch_id, pause_current=True)
    except KeyError:
        raise HTTPException(404, f"分支 {branch_id} 不存在")
    return {"status": "ok", "branch": target.model_dump()}


@router.post("/tasks/{task_id}/branches/{branch_id}/resume")
async def resume_task_branch(
    task_id: str, branch_id: str, request: Request,
):
    """Resume a paused branch.

    If the branch was previously paused (e.g. user forked away from it),
    this re-schedules a background runner so it can continue from its
    last LangGraph checkpoint.
    """
    sm = _get_sm()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    _enforce_task_owner(state, request, "resume_task_branch")

    from backend.api.services.branch_manager import get_branch_manager
    bm = get_branch_manager()
    try:
        branch = await bm.resume(task_id, branch_id)
    except KeyError:
        raise HTTPException(404, f"分支 {branch_id} 不存在")
    return {"status": "ok", "branch": branch.model_dump()}


@router.post("/tasks/{task_id}/branches/{branch_id}/pause")
async def pause_task_branch(
    task_id: str, branch_id: str, request: Request,
):
    """Cooperatively pause a running branch."""
    sm = _get_sm()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(404, f"任务 {task_id} 不存在")
    _enforce_task_owner(state, request, "pause_task_branch")

    from backend.api.services.branch_manager import get_branch_manager
    bm = get_branch_manager()
    try:
        branch = await bm.pause(task_id, branch_id)
    except KeyError:
        raise HTTPException(404, f"分支 {branch_id} 不存在")
    return {"status": "ok", "branch": branch.model_dump()}
