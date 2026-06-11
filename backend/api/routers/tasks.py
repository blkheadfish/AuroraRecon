"""
routers/tasks.py —— 任务 CRUD + 审批 + 对话
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
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
    PendingConfirmationResponse, TaskCreateResponse,
    PlanRequest, PlanResponse, PentestPlan, PlanPhase, PlanStep,
    ConfirmPlanRequest,
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


def _repair_truncated_json(raw: str) -> dict:
    """尝试修复被截断的 JSON，关闭未闭合的字符串和括号。

    处理 LLM 因 max_tokens 不足而截断 JSON 的场景。
    修复失败时抛出原始 json.JSONDecodeError。
    """
    s = raw.strip()

    # ---- 第一遍扫描：记录字符串状态 + 括号栈
    in_string = False
    escape = False
    stack: list[str] = []  # '{' or '['

    for ch in s:
        if escape:
            escape = False
            continue
        if ch == '\\':
            escape = not escape
            continue
        if ch == '"' and not escape:
            in_string = not in_string
        elif not in_string:
            if ch in '{[':
                stack.append(ch)
            elif ch == '}':
                if stack and stack[-1] == '{':
                    stack.pop()
            elif ch == ']':
                if stack and stack[-1] == '[':
                    stack.pop()

    # ---- 修复：闭合字符串
    if in_string:
        s = s + '"'

    # ---- 修复：去掉末尾不完整的 key:value 结构
    s = s.rstrip()
    while s.endswith(','):
        s = s[:-1].rstrip()
    if s.endswith(':'):
        bracket_count = 0
        cut_pos = len(s) - 1
        for i in range(len(s) - 1, -1, -1):
            if s[i] == '"':
                bracket_count += 1
            if s[i] == ',' and bracket_count % 2 == 0:
                cut_pos = i
                break
        else:
            cut_pos = s.find('"')
        s = s[:cut_pos].rstrip().rstrip(',').rstrip()

    # ---- 修复：闭合括号
    closer = {'{': '}', '[': ']'}
    while stack:
        s = s + closer[stack.pop()]

    # ---- 尝试解析
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass

    # ---- 渐进回退：从末尾逐字符裁剪，每裁剪一次就重新闭合括号再试
    #     处理 "partial_key" 变成裸字符串 或 其他复杂截断场景
    for cut in range(len(s) - 1, max(0, len(s) - 500), -1):
        candidate = s[:cut].rstrip().rstrip(',').rstrip()
        # 重新计算括号栈
        st2: list[str] = []
        in_str = False
        esc = False
        for ch in candidate:
            if esc:
                esc = False
                continue
            if ch == '\\':
                esc = True
                continue
            if ch == '"' and not esc:
                in_str = not in_str
            elif not in_str:
                if ch in '{[':
                    st2.append(ch)
                elif ch == '}':
                    if st2 and st2[-1] == '{':
                        st2.pop()
                elif ch == ']':
                    if st2 and st2[-1] == '[':
                        st2.pop()
        if in_str:
            candidate = candidate + '"'
        while st2:
            candidate = candidate + closer[st2.pop()]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    raise json.JSONDecodeError("无法修复截断的 JSON", raw, 0)


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
            timeout=20.0,
        )
    except asyncio.TimeoutError:
        logger.info("[parse_intent] LLM 超时(20s),回退正则")
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
    if not payload["target"] and fallback_target:
        payload["target"] = fallback_target

    return ParseIntentResponse(**payload, fallback=False)



def _load_available_tools() -> list[dict[str, str]]:
    """遍历 tools/definitions/ 目录，提取所有已注册工具的名称与描述。
    返回列表，每个元素为 {"name": "...", "category": "...", "description": "..."}
    """
    import glob as _glob
    import yaml as _yaml

    tools_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "tools", "definitions",
    )
    tools: list[dict[str, str]] = []
    if not os.path.isdir(tools_dir):
        return tools
    for yaml_path in sorted(_glob.glob(os.path.join(tools_dir, "*.yaml"))):
        try:
            with open(yaml_path, "r", encoding="utf-8") as fh:
                docs = list(_yaml.safe_load_all(fh))
            for doc in docs:
                if not isinstance(doc, list):
                    continue
                for item in doc:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name") or "").strip()
                    if not name:
                        continue
                    tools.append({
                        "name": name,
                        "category": str(item.get("category") or "").strip(),
                        "description": str(item.get("description") or "").strip(),
                    })
        except Exception as e:
            logger.warning(f"[plan] skip tool file {yaml_path}: {e}")
    return tools


def _load_available_skills() -> list[dict[str, str]]:
    """遍历 skills/ 目录，提取所有已注册 Skill 名称与触发条件。
    返回列表，每个元素为 {"skill_id": "...", "name": "...", "category": "...", "match_rules": "..."}
    """
    import glob as _glob
    import yaml as _yaml

    skills_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "skills",
    )
    skills: list[dict[str, str]] = []
    if not os.path.isdir(skills_dir):
        return skills
    for yaml_path in sorted(_glob.glob(os.path.join(skills_dir, "**/*.yaml"), recursive=True)):
        try:
            with open(yaml_path, "r", encoding="utf-8") as fh:
                doc = _yaml.safe_load(fh)
            if not isinstance(doc, dict):
                continue
            skill_id = str(doc.get("skill_id") or "").strip()
            if not skill_id:
                continue
            match_rules = ""
            match_block = doc.get("match")
            if isinstance(match_block, dict):
                rules = match_block.get("rules", [])
                rule_parts: list[str] = []
                for rule in rules if isinstance(rules, list) else []:
                    if isinstance(rule, dict):
                        for k, v in rule.items():
                            rule_parts.append(f"{k}: {json.dumps(v)}")
                    elif isinstance(rule, str):
                        rule_parts.append(rule)
                match_rules = "; ".join(rule_parts[:3])
            skills.append({
                "skill_id": skill_id,
                "name": str(doc.get("name") or "").strip(),
                "category": str(doc.get("category") or "").strip(),
                "match_rules": match_rules,
            })
        except Exception as e:
            logger.warning(f"[plan] skip skill file {yaml_path}: {e}")
    return skills


def _build_available_tools_text(tools: list[dict[str, str]]) -> str:
    """将工具列表格式化为 prompt 可读文本。"""
    if not tools:
        return "（暂无已注册工具）"
    categories: dict[str, list[str]] = {}
    for t in tools:
        cat = t.get("category", "other")
        categories.setdefault(cat, []).append(
            f"  - {t['name']}: {t.get('description', '无描述')}"
        )
    lines: list[str] = []
    for cat in sorted(categories):
        lines.append(f"### {cat}")
        lines.extend(categories[cat])
        lines.append("")
    return "\n".join(lines)


def _build_available_skills_text(skills: list[dict[str, str]]) -> str:
    """将 Skill 列表格式化为 prompt 可读文本。"""
    if not skills:
        return "（暂无已注册 Skill）"
    categories: dict[str, list[str]] = {}
    for s in skills:
        cat = s.get("category", "other")
        match = s.get("match_rules", "")
        entry = f"  - {s['skill_id']}: {s.get('name', '')}"
        if match:
            entry += f" [触发条件: {match}]"
        categories.setdefault(cat, []).append(entry)
    lines: list[str] = []
    for cat in sorted(categories):
        lines.append(f"### {cat}")
        lines.extend(categories[cat])
        lines.append("")
    return "\n".join(lines)



@router.post("/tasks/plan", response_model=PlanResponse)
async def generate_pentest_plan(req: PlanRequest, request: Request):
    """
    生成渗透策略（不创建任务，不执行任何工具）。

    流程:
      1. 动态读取已注册工具列表和 Skill 列表
      2. 将列表注入 PLAN_GENERATION_PROMPT
      3. 调用 LLM 在可用能力范围内生成完整渗透策略
      4. 返回策略供前端展示，用户可审查/修改/确认

    注意:
      - 该接口**只读**，不创建任务，不执行任何工具
      - 生成的策略中的每个工具名/Skill 名都保证来自已注册列表
    """
    user_id = getattr(request.state, "user_id", "") or ""
    if not user_id:
        raise HTTPException(status_code=401, detail="未登录")

    user_prompt = req.user_prompt
    if not user_prompt.strip():
        raise HTTPException(status_code=400, detail="user_prompt 不能为空")

    available_tools = _load_available_tools()
    available_skills = _load_available_skills()

    tools_text = _build_available_tools_text(available_tools)
    skills_text = _build_available_skills_text(available_skills)

    logger.info(
        f"[plan] 加载了 {len(available_tools)} 个工具, "
        f"{len(available_skills)} 个 Skill"
    )

    from backend.llm.router import LLMRouter
    from backend.llm.prompts.templates import PLAN_GENERATION_PROMPT

    prompt = PLAN_GENERATION_PROMPT.format(
        user_prompt=user_prompt,
        available_tools=tools_text,
        available_skills=skills_text,
    )

    llm = LLMRouter()

    async def _call_and_parse(max_tokens: int, prompt_override: str = "") -> tuple[dict, str]:
        """调用 LLM 并解析 JSON，返回 (data, raw_text)。"""
        raw = await llm.chat(
            prompt_override or prompt,
            response_format="json",
            temperature=0.2,
            max_tokens=max_tokens,
        )
        raw_str = raw if isinstance(raw, str) else str(raw)
        try:
            data = json.loads(raw_str)
        except json.JSONDecodeError:
            # 尝试修复截断的 JSON（LLM 输出被 max_tokens 截断）
            try:
                data = _repair_truncated_json(raw_str)
                logger.warning(
                    f"[plan] JSON 被截断，已修复 (max_tokens={max_tokens})"
                )
            except Exception:
                raise  # 重新抛出原始异常，由外层处理
        if not isinstance(data, dict):
            raise ValueError("LLM 返回不是 JSON 对象")
        return data, raw_str

    raw_str = ""
    try:
        data, raw_str = await asyncio.wait_for(
            _call_and_parse(4096),
            timeout=180.0,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="LLM 策略生成超时，请重试")
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(
            f"[plan] 首次调用 JSON 解析失败 (max_tokens=4096): {e}, "
            f"raw_tail={raw_str[-300:] if raw_str else ''}"
        )
        # 重试：更大 token 预算 + 强调完整性
        try:
            retry_prompt = (
                prompt
                + "\n\n【重要提醒】上一次你的回复因为输出过长被截断了。"
                "这次请务必将 JSON 输出完整，不要省略任何字段。"
            )
            data, raw_str = await asyncio.wait_for(
                _call_and_parse(8192, prompt_override=retry_prompt),
                timeout=180.0,
            )
            logger.info("[plan] 重试成功 (max_tokens=8192)")
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="LLM 策略生成超时，请重试")
        except Exception as e2:
            logger.error(
                f"[plan] 重试仍失败: {e2}, raw_tail={raw_str[-500:] if raw_str else ''}"
            )
            raise HTTPException(status_code=502, detail=f"策略解析失败（重试后仍无效）: {e2}")
    except Exception as e:
        logger.error(f"[plan] LLM 调用失败: {e}")
        raise HTTPException(status_code=502, detail=f"LLM 调用失败: {e}")

    valid_tool_names = {t["name"] for t in available_tools}
    valid_skill_ids = {s["skill_id"] for s in available_skills}

    unknown_tools: list[str] = []
    unknown_skills: list[str] = []
    for phase in data.get("phases", []):
        for step in phase.get("steps", []):
            tool_name = (step.get("tool") or "").strip()
            skill_name = (step.get("skill") or "").strip()
            if tool_name and tool_name not in valid_tool_names:
                unknown_tools.append(f"{tool_name} (phase={phase.get('phase', '?')})")
            if skill_name and skill_name not in valid_skill_ids:
                unknown_skills.append(f"{skill_name} (phase={phase.get('phase', '?')})")

    if unknown_tools or unknown_skills:
        warning_parts = []
        if unknown_tools:
            warning_parts.append(f"未知工具: {', '.join(unknown_tools)}")
        if unknown_skills:
            warning_parts.append(f"未知 Skill: {', '.join(unknown_skills)}")
        logger.warning(f"[plan] LLM 生成了未注册的能力: {'; '.join(warning_parts)}")

    plan_id = str(uuid.uuid4())
    plan_obj = PentestPlan(
        target_understanding=str(data.get("target_understanding") or ""),
        phases=[
            PlanPhase(
                phase=str(p.get("phase", "")),
                description=str(p.get("description", "")),
                steps=[
                    PlanStep(
                        tool=str(s.get("tool") or ""),
                        skill=str(s.get("skill") or ""),
                        purpose=str(s.get("purpose") or ""),
                        command_hint=str(s.get("command_hint") or ""),
                        expected_output=str(s.get("expected_output") or ""),
                        trigger_condition=str(s.get("trigger_condition") or ""),
                        expected_impact=str(s.get("expected_impact") or ""),
                        fallback=str(s.get("fallback") or ""),
                        depends_on=str(s.get("depends_on") or ""),
                        enabled=True,
                    )
                    for s in (p.get("steps") or []) if isinstance(s, dict)
                ],
            )
            for p in (data.get("phases") or []) if isinstance(p, dict)
        ],
        unsupported_hints=[
            str(h) for h in (data.get("unsupported_hints") or []) if h
        ],
        risk_notes=[
            str(r) for r in (data.get("risk_notes") or []) if r
        ],
    )
    return PlanResponse(
        plan_id=plan_id,
        plan=plan_obj,
        available_tools_count=len(available_tools),
        available_skills_count=len(available_skills),
    )



async def _push_initial_plan_event(
    task_id: str,
    state: "PentestState",
    req: CreateTaskRequest,
    parsed_intent_dict: dict | None,
    effective_target: str,
) -> None:
    """任务创建后立即推送一条初始策略事件到前端, 让用户在任务开始执行前
    就能看到 Agent 对目标的理解和即将遵循的路径。

    这条事件会被 ``TaskChat.vue`` 的 ``action='initial_plan'`` 分支渲染成
    高亮策略卡片, 与后续 ``operator_replan`` 卡片保持一致的视觉语言。
    """
    try:
        from backend.agents.models import WorkflowMode

        mode_label = {
            "pentest_engineer": "渗透工程师",
            "ctf_expert": "CTF 选手",
        }.get(req.workflow_mode, req.workflow_mode)

        plan_steps: list[str] = []
        core_phases = ["recon", "surface_enum", "vuln_scan", "exploit_decision"]
        if req.auto_approve:
            core_phases.append("foothold_attempt")
        else:
            core_phases.append("human_approval")
            core_phases.append("foothold_attempt")
        plan_steps.append("阶段序列: " + " → ".join(core_phases) + " → ...")

        plan_steps.append(f"工作模式: {mode_label}")
        if req.auto_approve:
            plan_steps.append("自动审批: 已启用 (关键节点不暂停)")
        else:
            plan_steps.append("人工审批: 关键节点将暂停等待确认")

        if req.scope_note:
            plan_steps.append(f"授权说明: {req.scope_note[:120]}")
        if req.extra_hint:
            plan_steps.append(f"额外提示: {req.extra_hint[:200]}")

        if parsed_intent_dict:
            intents = parsed_intent_dict.get("intents", []) or []
            if intents:
                plan_steps.append(f"攻击倾向: {', '.join(intents[:6])}")
            priority_vulns = parsed_intent_dict.get("priority_vulns", []) or []
            if priority_vulns:
                plan_steps.append(f"重点关注: {', '.join(priority_vulns[:6])}")
            summary = parsed_intent_dict.get("summary", "")
        else:
            summary = ""

        target_understanding = summary or (
            f"目标: {effective_target}, "
            f"授权范围: {req.scope_note or 'CTF/靶场测试'}"
        )

        await event_stream.publish(
            task_id,
            type="decision_event",
            payload={
                "action": "initial_plan",
                "phase": "init",
                "thinking": target_understanding,
                "purpose": "初始渗透策略",
                "plan": plan_steps,
                "message": (
                    f"已生成初始策略: 目标={effective_target}, "
                    f"模式={mode_label}"
                ),
                "tone": "primary",
                "workflow_mode": req.workflow_mode,
                "auto_approve": req.auto_approve,
            },
        )
    except Exception as exc:
        logger.warning(f"[create_task] 推送初始策略事件失败: {exc}")


def _derive_authorized_scope(state, safety_intent):
    """从 parsed_intent.targets + scope_note 推导 authorized_scope，写入 state。

    只进不出原则：运行期新发现 host 不自动并入 scope（并入走 W0-T5/WS2 审批）。
    """
    if not safety_intent:
        return
    scope_entries: list[str] = []
    targets = getattr(safety_intent, "targets", None) or []
    for t in targets:
        target_str = ""
        if isinstance(t, dict):
            target_str = (t.get("host") or t.get("ip") or t.get("target") or "").strip()
        elif isinstance(t, str):
            target_str = t.strip()
        if target_str:
            scope_entries.append(target_str)
    parsed = state.parsed_intent or {}
    extra_targets = parsed.get("targets", []) or []
    for t in extra_targets:
        target_str = ""
        if isinstance(t, dict):
            target_str = (t.get("host") or t.get("ip") or t.get("target") or "").strip()
        elif isinstance(t, str):
            target_str = t.strip()
        if target_str and target_str not in scope_entries:
            scope_entries.append(target_str)
    if state.target_host and state.target_host not in scope_entries:
        scope_entries.append(state.target_host)
    state.authorized_scope = scope_entries


@router.post("/tasks", response_model=TaskCreateResponse)
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

    raw_prompt = req.raw_prompt.strip() or req.user_prompt.strip()
    raw_target = req.target.strip()

    parsed_intent_dict: dict | None = None
    effective_target = raw_target

    if raw_prompt:
        from backend.agents.intent_parser import parse_intent_deterministic

        parsed_intent = parse_intent_deterministic(raw_prompt)
        parsed_intent_dict = parsed_intent.model_dump()

        if req.parsed_intent_extra:
            extra = req.parsed_intent_extra
            if not parsed_intent_dict.get("intents"):
                parsed_intent_dict["intents"] = extra.get("intents", [])
            if not parsed_intent_dict.get("extra_hint"):
                parsed_intent_dict["extra_hint"] = extra.get("extra_hint", "")
            if not parsed_intent_dict.get("scope_note"):
                parsed_intent_dict["scope_note"] = extra.get("scope_note", "")
            llm_vulns = extra.get("priority_vulns") or []
            if isinstance(llm_vulns, list):
                existing = set(parsed_intent_dict.get("priority_vulns") or [])
                for v in llm_vulns:
                    if isinstance(v, str) and v.strip() and v.strip() not in existing:
                        parsed_intent_dict.setdefault("priority_vulns", []).append(v.strip())
                        existing.add(v.strip())

        if not effective_target and parsed_intent.targets:
            effective_target = parsed_intent.targets[0]
            logger.info(
                f"[create_task] 从 raw_prompt 提取目标: {effective_target} "
                f"(type={parsed_intent.target_type})"
            )

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

    from backend.agents.safety_gate import get_safety_gate
    from backend.agents.intent_parser import parse_intent_deterministic

    if parsed_intent_dict is None:
        safety_intent = parse_intent_deterministic(
            raw_prompt or f"对 {effective_target} 进行渗透测试"
        )
    else:
        from backend.agents.models import ParsedIntent
        safety_intent = ParsedIntent(**parsed_intent_dict)

    if not safety_intent.targets:
        enrichment_text = ""
        if req.target and req.target.strip():
            enrichment_text = req.target.strip()
        elif req.confirmed_plan and isinstance(req.confirmed_plan, dict):
            enrichment_text = str(req.confirmed_plan.get("target_understanding", "") or "")

        if enrichment_text:
            enriched = parse_intent_deterministic(enrichment_text)
            if enriched.targets:
                safety_intent.targets = enriched.targets
                safety_intent.target_type = enriched.target_type
                safety_intent.ambiguity_level = "clear"
                logger.info(
                    f"[create_task] 从 plan/target 补充提取目标: "
                    f"targets={safety_intent.targets} type={safety_intent.target_type}"
                )

    gate = get_safety_gate()
    safety_result = gate.check(
        safety_intent,
        authorization_token=req.authorization_token,
        user_id=owner_id,
    )

    if safety_result.risk_level == "blocked":
        raise HTTPException(
            status_code=400,
            detail={
                "status": "blocked",
                "message": safety_result.block_reason or "安全卡口拦截",
                "parsed_intent": parsed_intent_dict or safety_intent.model_dump(),
            }
        )

    if safety_result.risk_level == "warning":
        pending_confirmations = [
            c for c in safety_result.required_confirmations
            if c not in req.user_confirmed_risks
        ]
        if pending_confirmations:
            return PendingConfirmationResponse(
                status="pending_confirmation",
                task_id="",
                target=effective_target,
                warnings=safety_result.warnings,
                required_confirmations=pending_confirmations,
                parsed_intent=parsed_intent_dict or safety_intent.model_dump(),
                message="需要确认以下风险项后再提交",
            )

    if not effective_target and \
       safety_intent.ambiguity_level in ("partial", "vague") and \
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

    task_id = str(uuid.uuid4())

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
        pentest_plan=req.confirmed_plan,
    )
    apply_mode_defaults(
        state,
        overrides={
            "auto_approve":        req.auto_approve,
            "autonomy_level":      req.autonomy_level,
            "success_gate_level":  req.success_gate_level,
            "risk_budget":         req.risk_budget,
            "max_react_rounds":    req.max_react_rounds,
            "max_explore_rounds":  req.max_explore_rounds,
            "skill_min_score":     req.skill_min_score,
            "skill_weak_boost":    req.skill_weak_boost,
        },
    )

    _derive_authorized_scope(state, safety_intent)

    sm.set(task_id, state)

    if sm.db_available:
        try:
            from backend.db.database import save_task
            await save_task(state)
        except Exception as e:
            logger.warning(f"[DB] 保存失败: {e}")

    await _push_initial_plan_event(task_id, state, req, parsed_intent_dict, effective_target)

    from backend.api.services.task_runner import run_task
    from backend.api.services.branch_manager import get_branch_manager
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

    result = sm.to_detail_snapshot(state)

    try:
        envelopes = await event_stream.replay(task_id, count=120)
        if envelopes:
            decision_events: list[dict] = []
            for ev in envelopes:
                payload = ev.get("payload", {}) if isinstance(ev.get("payload"), dict) else {}
                decision_events.append({
                    "id": ev.get("id", ""),
                    "timestamp": ev.get("ts", ""),
                    **payload,
                })
            result["decision_events"] = decision_events
            result["decision_events_tail"] = decision_events
            result["decision_events_total"] = await event_stream.stream_length(task_id)
    except Exception:
        pass

    return result


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


@router.post("/tasks/{task_id}/abort")
async def abort_task(task_id: str, request: Request):
    """紧急停止任务——立即清场停容器，区别于优雅 /cancel。"""
    sm = _get_sm()
    state = sm.get(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "abort_task")
    if state.status not in (TaskStatus.RUNNING, TaskStatus.PENDING, TaskStatus.WAITING_USER, TaskStatus.AWAITING_APPROVAL):
        raise HTTPException(status_code=400, detail="任务不在运行/等待状态")

    from backend.agents.abort_registry import request_abort
    reason = "用户紧急停止"
    request_abort(task_id, reason=reason)

    state.status = TaskStatus.ABORTED
    state.error_msg = reason
    state.log(f"任务被紧急停止 (abort): {reason}")

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
        payload={"status": "aborted", "message": reason},
        branch_id=state.active_branch_id or "",
    )
    return {"status": "aborted", "task_id": task_id}


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
        await event_stream.drop(task_id)
    except Exception:
        pass
    try:
        from backend.storage.minio_client import get_storage
        get_storage().delete_task_files(task_id)
    except Exception:
        pass

    return {"status": "deleted", "task_id": task_id}



@router.post("/tasks/{task_id}/recover")
async def recover_task(task_id: str, request: Request):
    """手动恢复因服务重启而中断的任务。

    仅允许 FAILED（且 error_msg 提示重启）或 RUNNING（无后台协程）的任务。
    恢复后重新调度 resume_stream，从 LangGraph checkpoint 继续。
    """
    sm = _get_sm()
    state = await _resolve_state(task_id)
    if not state:
        raise HTTPException(status_code=404, detail="任务不存在")
    _enforce_task_owner(state, request, "recover_task")

    is_failed_by_restart = (
        state.status == TaskStatus.FAILED
        and state.error_msg
        and "重启" in (state.error_msg or "")
    )
    is_orphan_running = (
        state.status == TaskStatus.RUNNING
        and not sm.is_running(task_id)
    )

    if not (is_failed_by_restart or is_orphan_running):
        raise HTTPException(
            status_code=400,
            detail="仅支持恢复因重启中断的任务（FAILED+重启原因 或 RUNNING+无后台协程）",
        )

    state.status = TaskStatus.RUNNING
    state.error_msg = ""
    state.log("[恢复] 用户手动恢复任务")
    sm.set(task_id, state)

    if sm.db_available:
        try:
            from backend.db.database import save_task
            await save_task(state)
        except Exception as e:
            logger.warning(f"[DB] recover save failed: {e}")

    from backend.api.services.task_runner import resume_task
    from backend.api.services.branch_manager import get_branch_manager
    bm = get_branch_manager()
    try:
        active_branch = await bm.lazy_init_root(task_id, state)
    except Exception as exc:
        logger.warning(f"[recover] lazy_init_root failed: {exc}")
        active_branch = None
    thread_id = active_branch.thread_id if active_branch else task_id
    task_handle = asyncio.create_task(
        resume_task(task_id, approved=True, thread_id=thread_id)
    )
    sm.register_bg_task(task_id, task_handle)

    return {"status": "recovered", "task_id": task_id}


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

    if state.current_phase != "awaiting_approval" and not state.pending_checkpoint:
        raise HTTPException(
            status_code=400,
            detail=f"任务当前阶段 '{state.current_phase}' 不需要审批",
        )

    sm.set_approval_inflight(task_id, _time.time())
    state.approved = bool(req.approved)
    state.log(f"[审批] {'已授权,继续利用' if req.approved else '已拒绝,跳过利用'}")
    sm.set(task_id, state)

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

    if state.current_phase not in ("awaiting_approval", "post_foothold_approval") and not state.pending_checkpoint:
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
        "next_action": req.next_action,
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

    fork_active = (
        state.status in (TaskStatus.RUNNING, TaskStatus.AWAITING_APPROVAL)
        or sm.is_running(task_id)
    )

    new_branch_payload = None
    if fork_active:
        from backend.api.services.branch_manager import get_branch_manager
        bm = get_branch_manager()
        try:
            await bm.lazy_init_root(task_id, state)
        except Exception as exc:
            logger.warning(
                f"[chat] lazy_init_root failed task={task_id}: {exc}"
            )

        joined = (state.pending_user_prompt or "").strip()
        state.pending_user_prompt = (
            f"{joined}\n{text}" if joined else text
        )
        signals = dict(state.replan_signals or {})
        signals["operator_intent"] = int(signals.get("operator_intent", 0)) + 1
        state.replan_signals = signals
        sm.set(task_id, state)

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
            try:
                from backend.agents.interrupt_registry import request_interrupt
                request_interrupt(
                    task_id, reason="operator_chat",
                    payload={"text": text, "fallback": True},
                )
            except Exception:
                pass
    else:
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
