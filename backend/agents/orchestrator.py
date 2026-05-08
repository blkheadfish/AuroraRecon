"""
orchestrator.py  ── 改进版
主要改进：
  1. PostgreSQL checkpointer    → 持久化断点续跑，MemorySaver 作回退
  2. @retry_node 装饰器         → 工具调用失败自动重试（最多3次）
  3. human_approval 节点        → 利用前强制人工确认（竞赛演示亮点）
  4. interrupt_before=["human_approval"] → LangGraph 原生中断机制
  5. task_id 透传               → 所有 agent.run() 都传入 task_id
  6. parse_target 统一解析       → 创建 state 后立即解析，全链路使用 target_host/target_port

流程（主机攻链优先）：
  START → recon → surface_enum → intel_harvest → vuln_scan → exploit_decision
        → human_approval（interrupt_before 暂停等待审批）
        → foothold_attempt → secondary_attack（可选）→ post_foothold_enum
        → internal_scan → privesc_attempt（可循环）→ lateral_movement
        → persistence → objective_collect → report → END
        ↓（无可利用漏洞）
        report → END
"""
from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import re
import uuid
from datetime import datetime
from typing import Any, Optional

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

try:
    from psycopg_pool import AsyncConnectionPool
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    _HAS_PG_SAVER = True
except ImportError as _pg_import_err:
    _HAS_PG_SAVER = False
    logging.getLogger(__name__).info(
        "[Orchestrator] PostgreSQL checkpointer 依赖缺失 (%s)，"
        "请安装 psycopg[binary] psycopg_pool langgraph-checkpoint-postgres",
        _pg_import_err,
    )

from backend.agents.models import (
    CommandExecutionRecord,
    ExploitResult,
    ParsedTarget,
    PentestState,
    PortInfo,
    TaskStatus,
    VulnFinding,
    parse_target,
)

logger = logging.getLogger(__name__)

TASK_TIMEOUT = int(os.getenv("TASK_TIMEOUT_SECONDS", "7200"))

ATTACK_CHAIN_MODE_ENV = "ATTACK_CHAIN_MODE"
_VALID_CHAIN_MODES = {"linear", "feedback", "supervisor"}


def _current_chain_mode() -> str:
    mode = (os.getenv(ATTACK_CHAIN_MODE_ENV, "linear") or "linear").strip().lower()
    if mode not in _VALID_CHAIN_MODES:
        logger.warning(
            "[Orchestrator] 非法 ATTACK_CHAIN_MODE=%r，回退 linear", mode,
        )
        return "linear"
    return mode

_CHAIN_PHASE_ORDER: list[str] = [
    "recon",
    "surface_enum",
    "intel_harvest",
    "vuln_scan",
    "exploit_decision",
    "awaiting_approval",
    "foothold_attempt",
    "secondary_attack",
    "post_foothold_enum",
    "post_foothold_approval",
    "internal_scan",
    "privesc_attempt",
    "lateral_movement",
    "persistence",
    "objective_collect",
    "report",
]

_INTERACTIVE_INTERRUPT_NODES: list[str] = [
    "surface_enum",
    "intel_harvest",
    "vuln_scan",
    "exploit_decision",
    "foothold_attempt",
    "secondary_attack",
    "post_foothold_enum",
    "privesc_attempt",
    "objective_collect",
]


def _record_chain_visit(state: PentestState, phase_name: str) -> None:
    if phase_name not in state.chain_visited:
        state.chain_visited.append(phase_name)


def _consume_risk_budget(state: PentestState, cost: int = 1) -> bool:
    """Try to consume *cost* from the risk budget.

    Returns True if the budget was sufficient (operation allowed),
    False if the budget is exhausted (operation should be blocked).
    """
    if state.risk_budget_used + cost > state.risk_budget:
        state.log(
            f"⚠ 风险预算耗尽 (used={state.risk_budget_used}, "
            f"limit={state.risk_budget})，跳过高风险操作"
        )
        return False
    state.risk_budget_used += cost
    return True



def _apply_parsed_target(state: PentestState) -> None:
    """
    在任务创建后、recon 前，将用户原始 target 统一解析并写回 state。

    之后所有 agent 都通过 state.target_host / state.target_port 使用，
    不再各自解析 state.target，确保单一真相。
    """
    parsed: ParsedTarget = parse_target(state.target)
    state.target_host = parsed.host
    state.target_port = parsed.port
    state.target_scheme = parsed.scheme
    state.target_path = parsed.path
    state.target_raw = parsed.raw or state.target

    if parsed.host:
        port_info = f":{parsed.port}" if parsed.port else ""
        scheme_info = f" (scheme={parsed.scheme})" if parsed.scheme else ""
        state.log(
            f"目标解析: host={parsed.host}{port_info}{scheme_info}"
        )
    else:
        state.log(f"⚠ 目标解析失败，原始输入: {state.target}")



_INTENT_TAG_TO_AVOIDED_TOOLS: dict[str, list[str]] = {
    "stealth":     ["masscan", "nuclei", "nikto"],
    "low_noise":   ["masscan", "nikto", "wpscan"],
    "no_brute":    ["hydra", "medusa", "john", "hashcat"],
    "web_only":    ["enum4linux", "smbclient"],
    "prefer_msf":  [],
}

_INTENT_TAG_TO_PREFERRED_TOOLS: dict[str, list[str]] = {
    "prefer_msf":    ["metasploit"],
    "ctf_fast":      ["gobuster", "ffuf"],
    "web_only":      ["ffuf", "gobuster", "httpx", "whatweb"],
    "get_flag":      ["gobuster", "ffuf", "nuclei"],
}

_VULN_TO_RECON_TOOLS: dict[str, list[str]] = {
    "shiro":           ["whatweb", "httpx"],
    "fastjson":        ["whatweb", "httpx"],
    "log4j":           ["nuclei"],
    "struts2":         ["nuclei", "httpx"],
    "thinkphp":        ["whatweb", "gobuster"],
    "weblogic":        ["httpx", "whatweb"],
    "jboss":           ["httpx", "whatweb"],
    "wordpress":       ["wpscan", "gobuster"],
    "sqli":            ["sqlmap", "gobuster"],
    "lfi":             ["ffuf", "gobuster"],
    "weak_password":   ["hydra"],
    "default_creds":   ["hydra"],
}

_VULN_TO_NUCLEI_TAGS: dict[str, str] = {
    "shiro":       "apache-shiro",
    "fastjson":    "fastjson",
    "log4j":       "log4j",
    "struts2":     "apache-struts",
    "thinkphp":    "thinkphp",
    "weblogic":    "oracle-weblogic",
    "jboss":       "jboss",
    "wordpress":   "wordpress",
    "sqli":        "sqli",
    "lfi":         "lfi",
}


def _intent_to_operator_plan(state: PentestState) -> None:
    """把 parsed_intent 策略字段转换成 OperatorPlan 写入 state.operator_plan。

    设计原则：
    - 仅当 state.operator_plan 为 None 时执行（不覆盖用户通过 /chat 下发的实时计划）
    - 仅当 parsed_intent 包含有效策略约束时执行（避免无意义空计划）
    - pentest_plan 中明确列出的工具优先级 > parsed_intent 推断的工具偏好

    消费链路（已有，无需修改）：
      OperatorPlan.preferred_tools → ToolCoveragePlanner.build_plan() → 置顶 must_run
      OperatorPlan.avoided_tools   → ToolCoveragePlanner.build_plan() → 直接剔除
      OperatorPlan.keyword_hints   → VulnAgent / ReconAgent LLM prompt 注入
    """
    from backend.agents.models import OperatorPlan, OperatorFocusTarget

    if state.operator_plan is not None:
        return

    parsed: dict = state.parsed_intent or {}
    if not parsed:
        return

    intents: list[str] = parsed.get("intents", []) or []
    priority_vulns: list[str] = parsed.get("priority_vulns", []) or []
    pentest_phases: list[str] = parsed.get("pentest_phase", []) or []
    extra_hint: str = (state.extra_hint or "").strip()
    scope_note: str = (state.scope_note or "").strip()

    preferred: list[str] = []
    avoided: list[str] = []
    for tag in intents:
        tag_lc = tag.lower().strip()
        for tool in _INTENT_TAG_TO_AVOIDED_TOOLS.get(tag_lc, []):
            if tool not in avoided:
                avoided.append(tool)
        for tool in _INTENT_TAG_TO_PREFERRED_TOOLS.get(tag_lc, []):
            if tool not in preferred:
                preferred.append(tool)

    keyword_hints: list[str] = []
    for vuln_tag in priority_vulns:
        tag_lc = vuln_tag.lower().strip()
        for tool in _VULN_TO_RECON_TOOLS.get(tag_lc, []):
            if tool not in preferred:
                preferred.append(tool)
        nuclei_tag = _VULN_TO_NUCLEI_TAGS.get(tag_lc)
        if nuclei_tag and nuclei_tag not in keyword_hints:
            keyword_hints.append(nuclei_tag)

    plan: dict = state.pentest_plan or {}
    if plan:
        for phase in plan.get("phases", []):
            for step in phase.get("steps", []):
                if not step.get("enabled", True):
                    continue
                tool = (step.get("tool") or "").strip()
                if tool and tool not in preferred:
                    preferred.append(tool)

    next_phase: str | None = None
    exploit_with_known_vuln = bool(priority_vulns) and "exploit" in pentest_phases

    _needs_ports = {"surface_enum", "vuln_scan", "intel_harvest"}
    if exploit_with_known_vuln:
        next_phase = "vuln_scan" if state.open_ports else "recon"
    elif pentest_phases and "full_chain" in pentest_phases:
        next_phase = "recon"
    elif pentest_phases and "exploit" not in pentest_phases:
        last_phase = pentest_phases[-1] if pentest_phases else ""
        phase_sequence = ["recon", "surface_enum", "intel_harvest", "vuln_scan"]
        if last_phase in phase_sequence:
            if last_phase in _needs_ports and not state.open_ports:
                next_phase = "recon"
            else:
                next_phase = last_phase

    has_constraints = preferred or avoided or keyword_hints or next_phase or extra_hint
    if not has_constraints:
        return

    summary_parts: list[str] = []
    if intents:
        summary_parts.append(f"意图标签: {', '.join(intents[:6])}")
    if priority_vulns:
        summary_parts.append(f"重点漏洞: {', '.join(priority_vulns[:6])}")
    if extra_hint:
        summary_parts.append(f"附加提示: {extra_hint[:80]}")
    if scope_note:
        summary_parts.append(f"授权范围: {scope_note[:80]}")

    state.operator_plan = OperatorPlan(
        source_phase="init",
        intent_summary=" | ".join(summary_parts) or "由 parsed_intent 自动推断",
        next_phase=next_phase,
        preferred_tools=preferred[:12],
        avoided_tools=avoided[:8],
        keyword_hints=keyword_hints[:8],
    )
    state.log(
        f"[策略落实] parsed_intent → OperatorPlan: "
        f"preferred={preferred[:6]}, avoided={avoided[:4]}, "
        f"keyword_hints={keyword_hints[:4]}"
    )



def get_intent_skill_boost(parsed_intent: dict | None) -> dict[str, int]:
    """意图驱动：从 parsed_intent 中提取漏洞类型优先级权重。

    返回 {vuln_tag: boost_score}，供 Skills 匹配评分时加权。
    例如 priority_vulns=["shiro", "fastjson"] →
         {"shiro": +20, "fastjson": +20, "deserialization": +15}

    由 ExploitAgent 在调用 SkillRegistry.match() 时通过 kb_hits 参数传入。
    """
    if not parsed_intent:
        return {}
    priority_vulns: list[str] = parsed_intent.get("priority_vulns", []) or []
    boosts: dict[str, int] = {}
    base_boost = 15
    for tag in priority_vulns:
        tag_lower = tag.lower().strip()
        if tag_lower and tag_lower not in boosts:
            boosts[tag_lower] = base_boost
    return boosts


def _append_tool_record(
    state: PentestState,
    record: dict,
    *,
    default_phase: str,
) -> None:
    """将执行器结构化记录写入 state.tool_records（去重）并推送 command_exec 事件。"""
    payload = dict(record or {})
    payload.setdefault("phase", default_phase)
    payload.setdefault("timestamp", datetime.utcnow().isoformat())
    payload.setdefault("id", uuid.uuid4().hex[:16])
    payload.setdefault("truncated", False)
    if payload.get("total_len") is None:
        payload["total_len"] = len(str(payload.get("stdout") or "")) + len(str(payload.get("stderr") or ""))
    rec = CommandExecutionRecord(**payload)
    if rec.id and any(item.id == rec.id for item in state.tool_records):
        return
    state.tool_records.append(rec)
    if len(state.tool_records) > 2000:
        state.tool_records = state.tool_records[-1000:]

    exit_code = payload.get("exit_code", -1)
    stdout = payload.get("stdout", "") or ""
    stderr = payload.get("stderr", "") or ""
    tool = payload.get("tool", "") or payload.get("display_tool", "") or "script"
    command = payload.get("command", "") or payload.get("runtime_command", "") or ""
    purpose = payload.get("purpose", "") or ""
    state.push_decision({
        "action": "command_exec",
        "phase": payload.get("phase", default_phase),
        "tool": tool,
        "display_tool": tool,
        "command": command[:2000],
        "runtime_command": payload.get("runtime_command", ""),
        "purpose": purpose,
        "stdout": stdout[:8000],
        "stderr": stderr[:4000],
        "exit_code": exit_code,
        "elapsed_ms": int(round((payload.get("elapsed") or 0) * 1000)),
        "truncated": payload.get("truncated", False),
        "total_len": payload.get("total_len", 0),
        "tone": "success" if exit_code == 0 else "danger",
    })


def _operator_chat_block(state: PentestState) -> str:
    """决策对话中用户最近的实时指令(含 pending_user_prompt + user_messages)。

    现在直接复用 ``prompt_utils.operator_guidance_block``,这样所有节点 /
    Skill / ReAct 看到的都是同一份格式化后的"操作员指令"块,且 pending_user_prompt
    也会被一起拼进去——之前这个字段写了没人读的 bug 顺带修掉。
    """
    from backend.agents.prompt_utils import operator_guidance_block
    block = operator_guidance_block(state)
    return ("\n" + block) if block else ""


def _yield_if_interrupted(state: PentestState, node_name: str) -> bool:
    """Cooperative-interrupt poll for LangGraph node functions.

    Each ``node_*`` body should call this as the very first thing. When the
    operator has tapped /chat or /branches/.../activate from the HTTP side,
    ``check_interrupt`` returns a payload here; we write a decision_event
    and the caller is expected to ``return state`` immediately so LangGraph
    routes back to supervisor (in supervisor mode) or to the next node
    (linear/feedback mode, where the new pending_user_prompt will at least
    be visible to the next LLM call).

    Returns True when the node should yield. Does *not* consume the
    interrupt — supervisor's ``_llm_decide`` is the single consumer.
    """
    try:
        from backend.agents.interrupt_registry import check_interrupt
    except Exception:
        return False
    entry = check_interrupt(state.task_id)
    if not entry:
        return False
    text_preview = (entry.get("payload") or {}).get("text", "")
    if isinstance(text_preview, str) and len(text_preview) > 120:
        text_preview = text_preview[:120] + "…"
    state.push_decision({
        "action": "node_yielded_to_operator",
        "phase": node_name,
        "message": (
            f"[{node_name}] 检测到操作员实时指令, 暂停本节点交回 supervisor 重路由"
            + (f": {text_preview}" if text_preview else "")
        ),
        "tone": "warning",
        "purpose": "operator interrupt",
        "thinking": (
            f"interrupt.reason={entry.get('reason', '')}, "
            f"count={entry.get('count', 0)}"
        ),
    })
    state.log(
        f"[{node_name}] 让步给操作员指令(reason={entry.get('reason','')})"
    )
    return True


def _read_last_user_action(state: PentestState) -> str:
    """从最近一次 checkpoint 响应中读取用户的下步动作。

    返回: "continue" | "skip" | "finish" | "continue"
    默认返回 "continue"（安全默认值，不阻塞流程）。
    """
    history = state.checkpoint_history or []
    if not history:
        return "continue"
    last = history[-1]
    resp = last.get("response", {}) if isinstance(last, dict) else {}
    action = str(resp.get("action") or "").strip().lower()
    next_action = str(resp.get("next_action") or "").strip().lower()
    if next_action in ("continue", "skip", "finish"):
        return next_action
    if action == "reject":
        return "skip"
    return "continue"


def _push_phase_checkpoint(state: PentestState, phase_name: str,
                            summary: str, findings_count: int = 0) -> None:
    """在阶段完成后推送 phase_completed checkpoint，触发前端交互。

    这个 checkpoint 不阻塞 LangGraph 执行——阻塞由 interrupt_before 负责。
    它的作用是将阶段结果摘要推送到前端，让用户看到并决策。
    """
    state.open_checkpoint({
        "checkpoint_type": "phase_completed",
        "phase": phase_name,
        "summary": summary,
        "thinking": f"阶段 {phase_name} 已完成，等待你的指令",
        "recommendation": (
            f"{phase_name} 阶段已完成"
            + (f"，发现 {findings_count} 个漏洞" if findings_count else "")
            + "。请选择: 继续 / 跳过下一阶段 / 结束任务"
        ),
        "options": [
            {"value": "continue", "label": "继续下一阶段", "action": "continue"},
            {"value": "skip", "label": "跳过下一阶段", "action": "skip"},
            {"value": "finish", "label": "结束任务，生成报告", "action": "finish"},
        ],
        "risk": "info",
        "requires_input": True,
        "default_action": "continue",
    })
    state.status = TaskStatus.WAITING_USER
    logger.info(
        f"[phase_checkpoint] {phase_name} 完成, 等待用户指令 "
        f"(task={state.task_id})"
    )


def _maybe_skip_or_finish(state: PentestState, phase_name: str) -> bool:
    """在阶段节点开头调用，检查用户是否要求跳过或结束。

    返回 True 表示本节点应该直接 return（跳过/结束），False 表示正常执行。
    """
    action = _read_last_user_action(state)
    if action == "finish":
        state.log(f"[交互] 用户要求结束任务，跳过 {phase_name}，直接进入报告")
        state.push_decision({
            "action": "user_requested_finish",
            "phase": phase_name,
            "message": f"用户要求结束任务，跳过 {phase_name}",
            "tone": "info",
        })
        return True
    if action == "skip":
        state.log(f"[交互] 用户跳过阶段: {phase_name}")
        state.push_decision({
            "action": "user_skipped_phase",
            "phase": phase_name,
            "message": f"用户跳过阶段: {phase_name}",
            "tone": "info",
        })
        return True
    return False


def _should_finish(state: PentestState) -> bool:
    """判断用户是否要求结束任务（finish 动作）。"""
    return _read_last_user_action(state) == "finish"


def _consume_operator_plan_for_phase(
    state: PentestState,
    consumer_label: str,
    tool_plan: list[dict] | None = None,
) -> None:
    """战术层(planner / agent run)消费 ``state.operator_plan`` 后调用本函数,
    干两件事:

    1. 给前端推一条 ``operator_plan_applied`` decision event, 告诉用户"你说
       的工具偏好已经体现到本阶段的工具列表里了" —— 解决用户那条 "确实切了
       策略, 但我看不出工具是不是真的换了" 的反馈。
    2. 在 plan.consumed_by 上追加 consumer label, 这样多次消费可观测, 后续
       supervisor 也能凭此判断"是否还需要再为同一个 plan 走一次重规划"。
    """
    plan_obj = getattr(state, "operator_plan", None)
    if not plan_obj:
        return

    try:
        consumed = list(getattr(plan_obj, "consumed_by", None) or [])
        if consumer_label not in consumed:
            consumed.append(consumer_label)
            plan_obj.consumed_by = consumed
    except Exception:
        pass

    preferred = list(getattr(plan_obj, "preferred_tools", None) or [])
    avoided = list(getattr(plan_obj, "avoided_tools", None) or [])
    keywords = list(getattr(plan_obj, "keyword_hints", None) or [])

    if not (preferred or avoided or keywords):
        return

    plan_lines: list[str] = []
    if preferred:
        plan_lines.append(f"优先工具: {', '.join(preferred[:6])}")
    if avoided:
        plan_lines.append(f"禁用工具: {', '.join(avoided[:6])}")
    if keywords:
        plan_lines.append(f"关键词字典+ {', '.join(keywords[:8])}")

    selected_names: list[str] = []
    skipped_names: list[str] = []
    if tool_plan:
        for spec in tool_plan[:8]:
            name = spec.get("name", "?")
            if spec.get("operator_preferred"):
                selected_names.append(f"⭐{name}")
            else:
                selected_names.append(name)
        if avoided:
            avoided_set = {a.lower() for a in avoided}
            for a in avoided:
                if a.lower() in avoided_set:
                    skipped_names.append(a)
        if selected_names:
            plan_lines.append("本阶段执行序列: " + " → ".join(selected_names))

    state.push_decision({
        "action": "operator_plan_applied",
        "phase": state.current_phase or consumer_label,
        "message": (
            f"操作员战术计划已注入到 {consumer_label}: "
            f"{plan_obj.intent_summary or '(未命名意图)'}"
        ),
        "tone": "primary",
        "thinking": plan_obj.rationale or plan_obj.intent_summary or "",
        "purpose": "operator_plan -> 战术层",
        "plan": plan_lines,
        "consumer": consumer_label,
    })


def _plan_get_phase_steps(state: PentestState, phase_name: str) -> list[dict]:
    """从 ``state.pentest_plan`` 中提取指定阶段已启用的步骤列表。

    返回每个步骤的 dict（含 tool/skill/purpose 等字段），
    只返回 enabled=True 的步骤。没有 plan 或该阶段无步骤时返回空列表。
    """
    plan = state.pentest_plan or {}
    if not plan:
        return []
    phases = plan.get("phases", [])
    for phase in phases:
        if phase.get("phase") != phase_name:
            continue
        steps = phase.get("steps", [])
        return [s for s in steps if s.get("enabled", True)]
    return []


def _plan_should_skip_phase(state: PentestState, phase_name: str) -> tuple[bool, str]:
    """检查 pentest_plan 是否指示跳过该阶段。

    当策略存在时，未被策略覆盖的阶段一律跳过——确保执行流严格按策略走。

    phase_name 可以是策略阶段名（recon/exploit/post_exploit）或攻击链节点名
    （surface_enum/foothold_attempt 等），本函数统一处理映射。
    """
    plan = state.pentest_plan or {}
    if not plan:
        return False, ""
    phases = plan.get("phases", [])
    if not phases:
        return False, ""

    _PLAN_COVERS: dict[str, set[str]] = {
        "recon":        {"recon"},
        "surface_enum": {"surface_enum"},
        "intel_harvest":{"intel_harvest"},
        "vuln_scan":    {"vuln_scan"},
        "exploit":      {"exploit_decision", "foothold_attempt", "secondary_attack"},
        "post_exploit": {"post_foothold_enum", "internal_scan", "privesc_attempt",
                         "lateral_movement", "persistence", "objective_collect"},
        "report":       {"report"},
    }

    plan_phase_names = {p.get("phase") for p in phases}

    if phase_name in plan_phase_names:
        steps = _plan_get_phase_steps(state, phase_name)
        if not steps:
            return True, f"策略中 {phase_name} 阶段无启用步骤，跳过"
        return False, ""

    for pp in plan_phase_names:
        covered = _PLAN_COVERS.get(pp, {pp})
        if phase_name in covered:
            return False, ""

    return True, f"策略未包含 {phase_name} 阶段，跳过"


def _plan_get_step_tools(state: PentestState, phase_name: str) -> list[str]:
    """获取策略中某个阶段启用的步骤中指定的工具名列表（用于 recon/vuln 阶段）。"""
    steps = _plan_get_phase_steps(state, phase_name)
    tools = []
    for s in steps:
        t = (s.get("tool") or "").strip()
        if t and t not in tools:
            tools.append(t)
    return tools


def _plan_get_step_skills(state: PentestState, phase_name: str) -> list[str]:
    """获取策略中某个阶段启用的步骤中指定的 Skill 名列表（用于 exploit/post 阶段）。"""
    steps = _plan_get_phase_steps(state, phase_name)
    skills = []
    for s in steps:
        sid = (s.get("skill") or "").strip()
        if sid and sid not in skills:
            skills.append(sid)
    return skills


def _plan_log_phase_steps(state: PentestState, phase_name: str) -> None:
    """记录 Plan 模式下当前阶段将执行的步骤。"""
    steps = _plan_get_phase_steps(state, phase_name)
    if not steps:
        return
    state.log(f"[Plan] {phase_name} 阶段将执行以下步骤:")
    for i, s in enumerate(steps, 1):
        tool = s.get("tool", "")
        skill = s.get("skill", "")
        label = tool or skill or "?"
        purpose = s.get("purpose", "")[:80]
        state.log(f"  [{i}] {label}: {purpose}")


def _build_dir_intel(state: PentestState) -> dict[str, Any]:
    """Build structured directory intelligence from web_paths_inventory and related state."""
    intel: dict[str, Any] = {
        "high_value_paths": [],
        "potential_entry_points": [],
        "exposed_files": [],
        "backup_files": [],
        "api_endpoints": [],
        "dir_listings": [],
        "git_exposed": False,
    }
    _hv_hints = {"admin", "login", "upload", "info_disclosure"}
    _api_hints = {"api"}
    _backup_hints = {"backup"}
    _config_hints = {"config", "leak"}

    for item in (state.web_paths_inventory or []):
        path = item.get("path", "")
        hints = set(item.get("hints", []))
        if not path:
            continue
        if hints & _hv_hints:
            intel["high_value_paths"].append(path)
        if hints & _api_hints:
            intel["api_endpoints"].append(path)
        if hints & _backup_hints:
            intel["backup_files"].append(path)
        if hints & _config_hints:
            intel["exposed_files"].append(path)
        if "?" in path or "=" in path:
            intel["potential_entry_points"].append(path)

    for p in (state.web_paths or []):
        lower = p.lower()
        if ".git" in lower:
            intel["git_exposed"] = True
        if any(lower.endswith(ext) for ext in (".bak", ".old", ".backup", ".swp", ".orig")):
            if p not in intel["backup_files"]:
                intel["backup_files"].append(p)

    if state.dirlist_tree:
        for dl_path in (state.dirlist_interesting_files or [])[:10]:
            if dl_path not in intel["dir_listings"]:
                intel["dir_listings"].append(dl_path)

    for key in intel:
        if isinstance(intel[key], list):
            intel[key] = intel[key][:20]

    return intel


def _build_exploit_context(state: PentestState) -> dict[str, Any]:
    _normalize_and_dedupe_state_facts(state, source_node="build_exploit_context")
    path_contents = state.path_contents or []
    path_content_summary = "无"
    if path_contents:
        summary_lines = []
        for item in path_contents[:12]:
            keywords = item.get("keywords", [])
            summary_lines.append(
                f"{item.get('path', '')} "
                f"(status={item.get('status', 0)}, "
                f"title={item.get('title', '')[:50]}, "
                f"tech={','.join(item.get('tech_clues', [])[:4])}"
                + (f", keywords={','.join(keywords[:4])}" if keywords else "")
                + ")"
            )
        path_content_summary = "\n".join(summary_lines)

    web_paths_str = ", ".join(state.web_paths[:30]) if state.web_paths else "无"

    dirlist_info = ""
    if state.dirlist_tree:
        dirlist_info = f"\n目录列表文件树:\n{state.dirlist_tree}"
    if state.dirlist_interesting_files:
        dirlist_info += f"\n有价值文件: {', '.join(state.dirlist_interesting_files[:15])}"

    dir_intel: dict[str, Any] = state.dir_intel or {}
    if not dir_intel:
        dir_intel = _build_dir_intel(state)

    kb_hits = list(state.kb_probe_hits) if state.kb_probe_hits else []

    _INTENT_VULN_TO_SKILL: dict[str, str] = {
        "shiro": "shiro_rce",
        "fastjson": "fastjson_rce",
        "log4j": "log4shell_rce",
        "struts2": "struts2_rce",
        "thinkphp": "thinkphp_rce",
        "weblogic": "weblogic_rce",
        "jboss": "jboss_rce",
        "tomcat": "tomcat_exploit",
        "wordpress": "wordpress_exploit",
        "sql_injection": "sql_injection",
        "sqli": "sql_injection",
        "lfi": "lfi_rfi",
        "ssti": "flask_ssti",
        "weak_password": "credential_bruteforce",
        "default_creds": "tomcat_exploit",
    }
    parsed = state.parsed_intent or {}
    for tag in parsed.get("priority_vulns", []) or []:
        tag_lower = tag.lower().strip()
        skill_id = _INTENT_VULN_TO_SKILL.get(tag_lower)
        if skill_id:
            kb_hits.append({
                "vuln_id": f"intent_{tag_lower}",
                "dispatch_skill": skill_id,
                "confidence": 0.5,
                "base_url": f"http://{state.target_host}" if state.target_host else "",
                "port": state.target_port,
                "cves": [],
                "finding_vuln_id": "",
                "source": "parsed_intent",
            })

    ctx: dict[str, Any] = {
        "ports_summary": ", ".join(
            f"{p.port}/{p.service}({p.version[:30]})" for p in state.open_ports[:20]
            if p.state == "open"
        ),
        "web_paths": web_paths_str,
        "path_contents": path_content_summary,
        "dirlist_info": dirlist_info,
        "dir_intel": dir_intel,
        "fingerprint": state.raw_recon.get("raw_nmap", "")[:500],
        "fingerprints": state.fingerprints,
        "extra_hint": state.extra_hint,
        "user_prompt": state.user_prompt,
        "workflow_mode": state.workflow_mode,
        "auto_approve": state.auto_approve,
        "success_gate_level": state.success_gate_level,
        "risk_budget": state.risk_budget,
        "max_react_rounds": state.max_react_rounds,
        "max_explore_rounds": state.max_explore_rounds,
        "skill_min_score": state.skill_min_score,
        "skill_weak_boost": state.skill_weak_boost,
        "php_runtime": state.php_runtime or {},
        "runtime_facts": state.runtime_facts or {},
        "confirmed_facts": state.confirmed_facts or {},
        "prior_probe_variables": state.exploit_probe_variables or {},
        "prior_failed_commands": state.failed_commands_by_vuln or {},
        "kb_probe_hits": kb_hits,
        "attack_chain_mode": True,
        "attack_chain_hint": (
            "主机攻链优先：以「立足点→枚举→提权→目标」为主线；"
            "单漏洞利用只是战术动作，需在链路上推进而非只追求命中一条 CVE。"
        ),
    }

    if state.intel_files:
        intel_lines = []
        for f in state.intel_files[:10]:
            intel = f.get("intel", {})
            if intel.get("risk_level") in ("critical", "high"):
                intel_lines.append(f"{f['path']}: {intel.get('summary', '')}")
        if intel_lines:
            ctx["intel_harvest_summary"] = "\n".join(intel_lines)

    if state.page_params:
        param_lines = []
        for p in state.page_params:
            status = "已验证" if p.get("verified") else "待验证"
            param_lines.append(
                f"{p['url']} [{p['vuln_type']}] param={p['param_name']} ({status})"
            )
        ctx["discovered_params"] = "\n".join(param_lines)

    oc = _operator_chat_block(state)
    if oc:
        ctx["operator_chat"] = oc
    return ctx


def _sync_foothold_state(state: PentestState) -> None:
    """根据 exploit 结果同步 foothold_status（区分 RCE 与 file_read）。"""
    if not state.got_shell:
        file_read_results = [
            r for r in state.exploit_results
            if r.success and r.exploit_level == "file_read"
        ]
        if file_read_results:
            state.foothold_status = "file_read"
        else:
            state.foothold_status = "none"
        return
    successes = [r for r in state.exploit_results if r.success]
    if not successes:
        state.foothold_status = "none"
        return
    first = successes[0]
    si = first.session_info or {}
    if si.get("session_id"):
        st = (first.shell_type or "").lower()
        state.foothold_status = "meterpreter" if "meterpreter" in st else "shell"
    elif (si.get("method") or "").lower() == "react":
        st = (first.shell_type or "").lower()
        if any(x in st for x in ("reverse", "bind", "tty")):
            state.foothold_status = "shell"
        else:
            state.foothold_status = "web_rce"
    else:
        state.foothold_status = "shell"


def _enrich_finding_names_from_exploits(state: PentestState) -> None:
    """Backfill generic VulnFinding names (e.g. "HTTP Service") with the
    actual exploit type that succeeded (e.g. "fastjson_rce").

    Extracts the exploit identifier from multiple sources in priority order:
      1. ``session_info.skill_id``   (Skill engine / ReAct / MSF)
      2. ``session_info.method``     e.g. "skill:fastjson_rce:llm_freeform"
      3. ``shell_type`` / ``exploit_level``  e.g. "rce", "meterpreter"
    """
    for result in state.exploit_results:
        if not result.success:
            continue
        si = result.session_info or {}
        exploit_name = (si.get("skill_id") or "").strip()
        if not exploit_name:
            method = si.get("method", "")
            if method.startswith("skill:"):
                parts = method.split(":")
                exploit_name = parts[1] if len(parts) >= 2 else ""
        if not exploit_name:
            exploit_name = result.shell_type.strip() or result.exploit_level.strip()
        if not exploit_name or exploit_name.lower() in ("rce", "shell", "info_leak"):
            continue

        for f in state.findings:
            if f.vuln_id == result.vuln_id:
                display = exploit_name.replace("_", " ").strip()
                if display.lower() not in f.name.lower():
                    f.name = f"{exploit_name} ({f.name})"
                break


def _merge_attack_steps(state: PentestState, steps: list | None) -> None:
    existing = {(s.get("stage"), s.get("action")) for s in (state.attack_next_steps or [])}
    for s in steps or []:
        if not isinstance(s, dict):
            continue
        key = (s.get("stage"), s.get("action"))
        if key not in existing:
            state.attack_next_steps.append(s)
            existing.add(key)


def _flatten_post_findings_for_report(state: PentestState) -> None:
    """兼容报告模板对 post_findings['findings'] 的遍历。"""
    pf = dict(state.post_findings or {})
    flat: dict[str, Any] = {}
    if isinstance(pf.get("post_foothold"), dict):
        flat["post_foothold"] = pf["post_foothold"].get("findings", {})
    if isinstance(pf.get("privesc_latest"), dict):
        flat["privesc"] = pf["privesc_latest"].get("findings", {})
    if isinstance(pf.get("objective"), dict):
        flat["objective"] = pf["objective"].get("findings", {})
    pf["findings"] = flat
    state.post_findings = pf



def retry_node(max_attempts: int = 3, delay: float = 2.0):
    def decorator(fn):
        @functools.wraps(fn)
        async def wrapper(state: PentestState) -> PentestState:
            last_exc: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await fn(state)
                except Exception as exc:
                    last_exc = exc
                    state.log(f"{fn.__name__} 第 {attempt}/{max_attempts} 次失败: {exc}")
                    if attempt < max_attempts:
                        await asyncio.sleep(delay * attempt)
            state.error_msg = f"{fn.__name__} 在 {max_attempts} 次重试后仍失败: {last_exc}"
            state.status = TaskStatus.FAILED
            state.log(state.error_msg)
            return state
        return wrapper
    return decorator



async def _run_host_discovery(state: PentestState) -> list[str]:
    """意图驱动：使用 nmap -sn 做存活主机发现（在 toolbox 容器中执行）。

    从 parsed_intent.targets 中提取 CIDR/网段信息作为扫描范围。
    返回发现的存活主机 IP 列表。

    安全注意：
    - 仅扫描 parsed_intent 中明确指定的网段，不自作主张扩大范围
    - 使用 ToolExecutor 在 Docker toolbox 容器中执行，避免 API 容器无 nmap 的问题
    - 仅做 ping 扫描（-sn），不做端口扫描
    """
    from backend.tools.executor import ToolExecutor
    import re

    parsed = state.parsed_intent or {}
    targets = parsed.get("targets", [])

    cidr_targets = [t for t in targets if "/" in t]
    if not cidr_targets:
        state.log("[意图驱动] 无法确定主机发现范围（无 CIDR 目标），跳过")
        return []

    executor = ToolExecutor()
    discovered: list[str] = []

    for cidr in cidr_targets[:3]:
        try:
            state.log(f"[意图驱动] 执行主机发现: nmap -sn -T4 --max-retries 1 {cidr}")

            result = await executor.run(
                tool="nmap",
                args=["-sn", "-T4", "--max-retries", "1", cidr],
                timeout=120,
            )
            output = (result.stdout or "") + (result.stderr or "")

            ip_pattern = re.compile(
                r"Nmap scan report for (?:\S+ )?\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?"
            )
            for match in ip_pattern.finditer(output):
                ip = match.group(1)
                if ip not in discovered:
                    discovered.append(ip)

            state.log(f"[意图驱动] {cidr} 发现 {len(discovered)} 个存活主机")

        except Exception as e:
            state.log(f"[意图驱动] 主机发现失败: {cidr}: {e}")

    return discovered


@retry_node(max_attempts=3, delay=2.0)
async def node_recon(state: PentestState) -> PentestState:
    from backend.agents.recon_agent import ReconAgent
    from backend.tools.executor import ToolExecutor
    state.current_phase = "recon"
    _record_chain_visit(state, "recon")
    state.status = TaskStatus.RUNNING

    skip_plan, skip_plan_reason = _plan_should_skip_phase(state, "recon")
    if skip_plan:
        state.log(f"[Plan] {skip_plan_reason}")
        return state
    _plan_log_phase_steps(state, "recon")

    if _yield_if_interrupted(state, "recon"):
        return state

    parsed_intent_raw = state.parsed_intent or {}
    requires_discovery = parsed_intent_raw.get("requires_discovery", False)
    if requires_discovery and state.phase_visit_count.get("recon", 0) == 0:
        state.log("[意图驱动] 检测到主机发现需求，先执行 masscan 存活扫描")
        discovery_targets = await _run_host_discovery(state)
        if discovery_targets:
            seeds = state.pending_seeds or {}
            existing_hosts = list(seeds.get("hosts", []))
            for host in discovery_targets:
                if host not in existing_hosts and host != state.target_host:
                    existing_hosts.append(host)
            seeds["hosts"] = existing_hosts
            state.pending_seeds = seeds
            state.log(
                f"[意图驱动] masscan 发现 {len(discovery_targets)} 个存活主机: "
                f"{', '.join(discovery_targets[:10])}"
                + (f"... 等共 {len(discovery_targets)} 个" if len(discovery_targets) > 10 else "")
            )
        else:
            state.log("[意图驱动] masscan 未发现存活主机")

    seed_hosts = _consume_pending_seeds(state, "hosts")
    targets: list[str] = []
    if state.target_host:
        targets.append(state.target_host)
    elif state.target:
        targets.append(state.target)
    for h in seed_hosts:
        if isinstance(h, str) and h and h not in targets:
            targets.append(h)
    sig = _compute_phase_signature({"targets": targets})
    skip, skip_reason = _should_skip_phase(state, "recon", sig)
    if skip:
        state.log(f"recon 跳过：{skip_reason}（visit={state.phase_visit_count.get('recon', 0)}）")
        _consume_replan_signal(state, "re_recon_for_hosts")
        _mark_phase_visited(state, "recon", sig)
        return state

    try:
        _exec = ToolExecutor()
        await _exec.start_task_container(state.task_id)
        if state.phase_visit_count.get("recon", 0) == 0:
            state.log(f"工具容器已就绪: pentest_task_{state.task_id[:12]}")
    except Exception as _ce:
        state.log(f"⚠ 工具容器启动失败，降级为临时容器模式: {_ce}")

    revisit = state.phase_visit_count.get("recon", 0) > 0
    if revisit and seed_hosts:
        state.log(f"recon 重入：消费 {len(seed_hosts)} 个种子主机 → {seed_hosts}")
    state.log(f"开始侦察目标: {state.target_host or state.target}")
    agent = ReconAgent()
    async def _on_tool_log(line: str):
        state.log(line)
    async def _on_exec_record(record: dict):
        _append_tool_record(state, record, default_phase="recon")
    async def _on_decision(event: dict):
        state.push_decision(event)
    from backend.agents.prompt_utils import operator_guidance_block
    _op_block = operator_guidance_block(state)
    _op_plan = getattr(state, "operator_plan", None)
    _recon_plan_tools = _plan_get_step_tools(state, "recon") or None
    agent._plan_steps = _plan_get_phase_steps(state, "recon") or None
    result = await agent.run(
        target=state.target_host or state.target,
        target_port=state.target_port,
        task_id=state.task_id,
        log_callback=_on_tool_log,
        record_callback=_on_exec_record,
        decision_callback=_on_decision,
        operator_block=_op_block,
        operator_plan=_op_plan,
        plan_tools=_recon_plan_tools,
    )
    if _op_plan is not None:
        _consume_operator_plan_for_phase(state, "recon_dir_scan", None)
    state.open_ports = result.get("ports", [])
    state.os_info = _stringify_dict_keys(result.get("os_info", {}))
    state.web_paths = result.get("web_paths", [])
    state.path_contents = _stringify_dict_keys(result.get("path_contents", []))
    state.subdomains = result.get("subdomains", [])
    state.raw_recon = _stringify_dict_keys(result)
    state.target_os = _infer_os(state.open_ports, state.os_info)
    state.dir_scan_strategy = _stringify_dict_keys(result.get("scan_strategy", {}))

    dir_cov = result.get("dir_coverage")
    if dir_cov:
        state.push_decision({
            "action": "tool_coverage_report",
            "phase": "recon",
            "message": (
                f"目录发现覆盖率{'达标' if dir_cov.get('satisfied') else '未达标'}: "
                f"扫描 {dir_cov.get('total_paths', 0)} 路径, "
                f"工具: {dir_cov.get('category_counts', {})}"
            ),
            "tone": "info" if dir_cov.get("satisfied") else "warn",
            "raw": json.dumps(dir_cov, ensure_ascii=False),
        })
        for t in dir_cov.get("tools", []):
            if t["status"] == "skipped":
                state.push_decision({
                    "action": "tool_skipped",
                    "phase": "recon",
                    "tool": t["name"],
                    "message": f"跳过 {t['name']}: {t.get('skip_reason', 'N/A')}",
                    "tone": "warn",
                })
            elif t["status"] in ("executed", "failed", "timeout"):
                state.push_decision({
                    "action": "tool_executed",
                    "phase": "recon",
                    "tool": t["name"],
                    "message": (
                        f"{t['name']}: {t['status']} "
                        f"(+{t.get('paths', 0)} 路径, {t.get('elapsed', 0):.1f}s)"
                    ),
                    "tone": "info" if t["status"] == "executed" else "warn",
                })

    llm_hints = result.get("llm_recon_hints") or {}
    if llm_hints:
        vectors = llm_hints.get("potential_attack_vectors", [])
        rec_tools = llm_hints.get("recommended_next_tools", [])
        state.push_decision({
            "action": "thought",
            "phase": "recon",
            "thinking": (
                f"LLM 侦察分析: OS推测={llm_hints.get('os_guess', 'N/A')}, "
                f"攻击向量: {'; '.join(vectors[:5]) if vectors else '无'}"
            ),
            "purpose": "LLM 侦察智能分析",
            "plan": [f"推荐工具: {', '.join(rec_tools[:5])}"] if rec_tools else [],
            "message": f"LLM 分析: {len(vectors)} 攻击向量, 推荐 {', '.join(rec_tools[:3]) if rec_tools else '无'}",
        })

    state.log(f"侦察完成: {len(state.open_ports)} 端口, OS={state.target_os}")

    ports_summary = ", ".join(
        f"{p.port}/{p.service}" for p in state.open_ports[:15]
    )
    web_count = len(state.web_paths or [])
    sub_count = len(state.subdomains or [])
    state.push_decision({
        "action": "thought",
        "phase": "recon",
        "thinking": (
            f"侦察完成: 发现 {len(state.open_ports)} 个开放端口 ({ports_summary}), "
            f"OS推断={state.target_os}, 发现 {web_count} 条Web路径. "
            f"路径内容探测采集 {len(state.path_contents or [])} 条."
            + (f" 子域名: {sub_count} 个." if sub_count else "")
        ),
        "purpose": "侦察阶段总结",
        "plan": [
            f"开放端口: {len(state.open_ports)} 个",
            f"Web路径: {web_count} 条",
            *([ f"子域名: {sub_count} 个"] if sub_count else []),
            f"下一步: 漏洞扫描",
        ],
        "message": f"侦察完成: {len(state.open_ports)} 端口, {web_count} 路径, OS={state.target_os}",
    })
    try:
        host = state.target_host or state.target
        _attach_host_to_graph(state, host, discovered_by="recon")
        for p in state.open_ports:
            if p.state != "open":
                continue
            _attach_service_to_graph(
                state, host, p.port,
                service=p.service or "", version=p.version or "",
                discovered_by="recon",
            )
    except Exception as _ag_exc:
        logger.debug(f"[node_recon] attack_graph upsert skipped: {_ag_exc}")
    _consume_replan_signal(state, "re_recon_for_hosts")
    _mark_phase_visited(state, "recon", sig)
    return state


@retry_node(max_attempts=2, delay=3.0)
async def node_vuln_scan(state: PentestState) -> PentestState:
    from backend.agents.vuln_agent import VulnAgent
    state.current_phase = "vuln_scan"
    _record_chain_visit(state, "vuln_scan")

    skip_plan, skip_plan_reason = _plan_should_skip_phase(state, "vuln_scan")
    if skip_plan:
        state.log(f"[Plan] {skip_plan_reason}")
        return state
    _plan_log_phase_steps(state, "vuln_scan")

    if _yield_if_interrupted(state, "vuln_scan"):
        return state
    if _maybe_skip_or_finish(state, "vuln_scan"):
        return state

    if state.intel_discovered_paths:
        existing = set(state.web_paths or [])
        new_count = 0
        for p in state.intel_discovered_paths:
            if p not in existing:
                state.web_paths.append(p)
                existing.add(p)
                new_count += 1
        if new_count:
            state.log(f"情报回注: intel_harvest 新增 {new_count} 条路径到攻击面")

    seed_paths = _consume_pending_seeds(state, "web_paths")
    seed_creds = _consume_pending_seeds(state, "credentials")
    seed_ports = _consume_pending_seeds(state, "ports")
    if seed_paths:
        existing = set(state.web_paths or [])
        added = 0
        for p in seed_paths:
            if isinstance(p, str) and p and p not in existing:
                state.web_paths.append(p)
                existing.add(p)
                added += 1
        if added:
            state.log(f"vuln_scan 重入: 注入 {added} 条种子路径")

    sig_payload = {
        "ports": [p.port for p in state.open_ports if p.state == "open"],
        "web_paths_count": len(state.web_paths or []),
        "intel_count": len(state.intel_discovered_paths or []),
        "seed_creds_count": len(seed_creds),
    }
    sig = _compute_phase_signature(sig_payload)
    skip, skip_reason = _should_skip_phase(state, "vuln_scan", sig)
    if skip:
        state.log(f"vuln_scan 跳过：{skip_reason}")
        _consume_replan_signal(state, "re_vuln_scan_for_creds")
        _consume_replan_signal(state, "re_vuln_scan_for_ports")
        _mark_phase_visited(state, "vuln_scan", sig)
        return state

    revisit = state.phase_visit_count.get("vuln_scan", 0) > 0
    if revisit:
        state.log(
            f"vuln_scan 重入：seed_creds={len(seed_creds)}, seed_ports={len(seed_ports)}, "
            f"signals={state.replan_signals}"
        )
    state.log("开始漏洞扫描...")
    agent = VulnAgent()
    async def _on_tool_log(line: str):
        state.log(line)
    async def _on_exec_record(record: dict):
        _append_tool_record(state, record, default_phase="vuln_scan")
    async def _on_decision(event: dict):
        state.push_decision(event)
    nmap_vuln_hints = state.raw_recon.get("nmap_vuln_hints", [])

    merged_seed_creds: list[dict] = []
    seen_cred_keys: set[str] = set()
    for src in (seed_creds, list(state.credential_store or [])):
        for c in src:
            if not isinstance(c, dict):
                continue
            key = json.dumps(c, sort_keys=True, default=str, ensure_ascii=False)
            if key in seen_cred_keys:
                continue
            seen_cred_keys.add(key)
            merged_seed_creds.append(c)

    seeds_payload: dict[str, list] = {}
    if merged_seed_creds:
        seeds_payload["credentials"] = merged_seed_creds
    if seed_paths:
        seeds_payload["web_paths"] = list(seed_paths)
    if seed_ports:
        seeds_payload["ports"] = list(seed_ports)

    from backend.agents.prompt_utils import operator_guidance_block
    _op_block = operator_guidance_block(state)
    _op_plan = getattr(state, "operator_plan", None)
    if _op_plan is not None:
        _consume_operator_plan_for_phase(state, "vuln_scan_tactic", None)
    result = await agent.run(
        target=state.target_host or state.target,
        ports=state.open_ports,
        web_paths=state.web_paths,
        path_contents=state.path_contents,
        target_os=state.target_os,
        target_port=state.target_port,
        target_scheme=state.target_scheme,
        task_id=state.task_id,
        log_callback=_on_tool_log,
        record_callback=_on_exec_record,
        decision_callback=_on_decision,
        nmap_vuln_hints=nmap_vuln_hints,
        workflow_mode=state.workflow_mode,
        seeds=seeds_payload or None,
        operator_block=_op_block,
        operator_plan=_op_plan,
    )
    state.findings = result.get("findings", [])
    state.raw_vuln = _stringify_dict_keys(result)
    state.fingerprints = _stringify_dict_keys(result.get("fingerprints", {}))
    exploitable = [f for f in state.findings if f.exploitable]
    state.log(f"漏洞扫描完成: {len(state.findings)} 发现, {len(exploitable)} 可利用")
    try:
        for f in state.findings[-30:]:
            _attach_finding_to_graph(state, f, discovered_by="vuln_scan")
    except Exception as _ag_exc:
        logger.debug(f"[node_vuln_scan] attack_graph upsert skipped: {_ag_exc}")
    _consume_replan_signal(state, "re_vuln_scan_for_creds")
    _consume_replan_signal(state, "re_vuln_scan_for_ports")
    _mark_phase_visited(state, "vuln_scan", sig)
    return state


_TECH_SENSITIVE_MAP: dict[str, list[str]] = {
    "PHP": [
        "phpinfo.php", "config.php", "settings.php", "wp-config.php",
        "configuration.php", "local.php", "database.php",
    ],
    "WordPress": [
        "wp-config.php", "wp-login.php", "xmlrpc.php",
        "wp-content/debug.log", "wp-includes/version.php",
    ],
    "JSP": ["WEB-INF/web.xml", "WEB-INF/classes/", "status"],
    "Tomcat": [
        "manager/html", "host-manager/html", "WEB-INF/web.xml",
        "META-INF/context.xml", "status",
    ],
    "Spring": [
        "actuator", "actuator/env", "actuator/health", "actuator/info",
        "actuator/mappings", "actuator/configprops", "actuator/beans",
        "env", "trace", "heapdump",
    ],
    "Django": [
        "admin/", "settings.py", "__debug__/", "static/admin/",
    ],
    "Flask": [
        "console", "static/", "config.py",
    ],
    "IIS": [
        "web.config", "iisstart.htm", "aspnet_client/",
        "trace.axd", "elmah.axd",
    ],
    "ASP": [
        "web.config", "Global.asax", "App_Data/",
    ],
    "JBoss": [
        "jmx-console/", "web-console/", "invoker/JMXInvokerServlet",
        "status", "WEB-INF/web.xml",
    ],
    "WebLogic": [
        "console/", "wls-wsat/CoordinatorPortType",
        "bea_wls_internal/", "_async/AsyncResponseService",
    ],
    "Node": [
        "package.json", ".npmrc", "server.js", "app.js",
    ],
}

_BASE_SENSITIVE_PATHS = [
    ".env", "robots.txt", "sitemap.xml", ".htaccess", ".DS_Store",
    "server-status", "backup", "backup.sql", "dump", "dump.sql",
    "config", ".git/HEAD", ".git/config", ".svn/entries",
    "admin", "console",
]

_BACKUP_SUFFIXES = ["", ".bak", ".old", ".backup", ".swp", ".save", ".orig", "~", ".1"]


def _build_sensitive_paths(tech_hints: list[str]) -> list[str]:
    """Generate a de-duplicated sensitive path list tailored to detected tech stack."""
    hints_upper = {h.upper() for h in tech_hints if h}

    tech_specific: list[str] = []
    for tech_key, paths in _TECH_SENSITIVE_MAP.items():
        if tech_key.upper() in hints_upper or any(
            tech_key.upper() in h for h in hints_upper
        ):
            tech_specific.extend(paths)

    base_names = list(_BASE_SENSITIVE_PATHS) + tech_specific

    result: list[str] = []
    for b in base_names:
        for s in _BACKUP_SUFFIXES:
            result.append(f"/{b}{s}")

    seen: set[str] = set()
    deduped: list[str] = []
    for p in result:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped


async def node_surface_enum(state: PentestState) -> PentestState:
    """攻链：深度表面枚举 — planner-driven web probing + sensitive file detection."""
    import time as _time
    from backend.tools.executor import ToolExecutor
    from backend.tools.parsers.path_aggregator import PathAggregator
    from backend.tools.parsers.dirlist_crawler import crawl_directory_listings
    from backend.tools.tool_coverage_planner import ToolCoveragePlanner
    state.current_phase = "surface_enum"
    _record_chain_visit(state, "surface_enum")

    skip_plan, skip_plan_reason = _plan_should_skip_phase(state, "surface_enum")
    if skip_plan:
        state.log(f"[Plan] {skip_plan_reason}")
        return state

    if _yield_if_interrupted(state, "surface_enum"):
        return state
    if _maybe_skip_or_finish(state, "surface_enum"):
        return state

    seed_ports = _consume_pending_seeds(state, "ports")
    seed_paths = _consume_pending_seeds(state, "web_paths")
    if seed_paths:
        existing = set(state.web_paths or [])
        added = 0
        for p in seed_paths:
            if isinstance(p, str) and p and p not in existing:
                state.web_paths.append(p)
                existing.add(p)
                added += 1
        if added:
            state.log(f"surface_enum 重入: 注入 {added} 条种子路径")
    sig = _compute_phase_signature({
        "ports": [p.port for p in state.open_ports],
        "web_paths_count": len(state.web_paths or []),
        "seed_ports": list(seed_ports),
    })
    skip, skip_reason = _should_skip_phase(state, "surface_enum", sig)
    if skip:
        state.log(f"surface_enum 跳过：{skip_reason}")
        _consume_replan_signal(state, "re_surface_enum_for_paths")
        _mark_phase_visited(state, "surface_enum", sig)
        return state

    state.log("攻链: 表面枚举 — 多工具 Web 探测与敏感文件发现")
    aggregator = PathAggregator()
    aggregator.add_paths(state.web_paths or [], source="recon_phase")

    web_ports = [
        p for p in state.open_ports
        if p.state == "open" and (
            p.port in (80, 443, 8080, 8443, 8000, 8888, 8081, 8090, 9000, 9090)
            or "http" in (p.service or "").lower()
        )
    ]

    _raw_recon = state.raw_recon or {}
    _recon_tech_hints: list[str] = []
    for _pi in state.open_ports:
        for tok in ((_pi.version or "") + " " + (_pi.banner or "")).split():
            if tok and len(tok) > 2:
                _recon_tech_hints.append(tok)
    _llm_hints = _raw_recon.get("llm_recon_hints") or {}
    for _hv in _llm_hints.get("high_value_ports", []):
        if isinstance(_hv, dict):
            if _hv.get("service"):
                _recon_tech_hints.append(_hv["service"])
            if _hv.get("attack_surface"):
                _recon_tech_hints.append(_hv["attack_surface"])

    if web_ports:
        executor = ToolExecutor()
        host = state.target_host or state.target

        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="surface_enum")

        for wp in web_ports[:3]:
            scheme = "https" if wp.port in (443, 8443) else "http"
            base_url = f"{scheme}://{host}:{wp.port}"

            sensitive_paths = _build_sensitive_paths(_recon_tech_hints)
            probe_cmds = []
            for sp in sensitive_paths:
                probe_cmds.append(
                    f'CODE=$(curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 "{base_url}{sp}"); '
                    f'[ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "{sp} $CODE"'
                )
            probe_script = " ; ".join(probe_cmds)
            try:
                probe_result = await executor.run_script(
                    script_content=probe_script,
                    timeout=60,
                    log_callback=_on_tool_log,
                    record_callback=_on_exec_record,
                    record_phase="surface_enum",
                    record_purpose="sensitive_file_probe",
                )
                if probe_result.stdout:
                    for line in probe_result.stdout.strip().splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            path, code = parts[0], parts[1]
                            if code in ("200", "301", "302", "403", "500"):
                                aggregator.add_paths(
                                    [path], source="curl_probe", status=int(code),
                                )
                                state.log(f"敏感文件发现: {path} (HTTP {code})")
            except Exception as e:
                logger.warning(f"[SurfaceEnum] 敏感文件探测异常: {e}")

            existing_paths = aggregator.get_actionable_paths()

            def _looks_like_directory(p: str) -> bool:
                basename = p.rstrip("/").rsplit("/", 1)[-1]
                if not basename:
                    return True
                return "." not in basename

            dir_candidates = [p for p in existing_paths if _looks_like_directory(p)]

            dirlist_seeds_from_content: list[str] = []
            for pc in (state.path_contents or []):
                title = (pc.get("title") or "").lower()
                snippet = (pc.get("content_snippet") or "").lower()
                if (
                    "index of" in title
                    or "parent directory" in snippet
                    or pc.get("dir_listing")
                ):
                    dirlist_seeds_from_content.append(pc["path"])

            dir_candidates = dirlist_seeds_from_content + dir_candidates
            dir_candidates.append("/")
            dir_candidates = list(dict.fromkeys(dir_candidates))[:30]
            try:
                dirlist_result = await crawl_directory_listings(
                    base_url=base_url,
                    seed_paths=dir_candidates,
                    executor=executor,
                    max_depth=3,
                    max_total_entries=200,
                    log_callback=_on_tool_log,
                    record_callback=_on_exec_record,
                )
                if dirlist_result.entries:
                    new_paths = [e.path for e in dirlist_result.entries]
                    aggregator.add_paths(new_paths, source="dirlist_crawl")
                    interesting = [e for e in dirlist_result.entries if e.interesting]
                    state.log(
                        f"[SurfaceEnum] 目录列表爬取: "
                        f"发现 {len(dirlist_result.entries)} 条目 "
                        f"({len(interesting)} 个有价值文件), "
                        f"{len(dirlist_result.dir_listing_paths)} 个目录列表页"
                    )
                    state.dirlist_tree = dirlist_result.file_tree_text
                    state.dirlist_interesting_files = [
                        e.path for e in dirlist_result.entries if e.interesting
                    ][:30]
            except Exception as e:
                logger.warning(f"[SurfaceEnum] 目录列表爬取异常: {e}")

            planner = ToolCoveragePlanner(
                categories=["web_probe", "fuzz"],
                max_tools=4,
                max_stage_runtime=360,
            )
            _op_plan = getattr(state, "operator_plan", None)
            plan = planner.build_plan(
                base_url,
                existing_paths_count=aggregator.count,
                operator_plan=_op_plan,
            )
            _consume_operator_plan_for_phase(state, "surface_enum_tactic", plan)

            for tool_spec in plan:
                should, skip_reason = planner.should_run(tool_spec)
                if not should:
                    planner.record_result(
                        tool_spec["name"], "skipped", skip_reason=skip_reason,
                    )
                    state.log(f"[SurfaceEnum] 跳过 {tool_spec['name']}: {skip_reason}")
                    continue

                tool_name = tool_spec["name"]
                state.log(f"[SurfaceEnum] Web 探测: 执行 {tool_name}")
                t0 = _time.monotonic()
                try:
                    tool_result = await executor.run_script(
                        script_content=tool_spec["script"],
                        timeout=tool_spec["timeout"],
                        log_callback=_on_tool_log,
                        record_callback=_on_exec_record,
                        record_phase="surface_enum",
                        record_purpose=f"{tool_name}_probe",
                    )
                    elapsed = _time.monotonic() - t0
                    stdout = tool_result.stdout or ""
                    new_count = aggregator.ingest(tool_name, stdout, base_url)
                    planner.record_result(
                        tool_name, "executed",
                        paths_found=new_count, raw_len=len(stdout),
                        elapsed=elapsed,
                    )
                    state.log(
                        f"[SurfaceEnum] {tool_name}: +{new_count} 路径 "
                        f"(累计 {aggregator.count}), {elapsed:.1f}s"
                    )
                except Exception as e:
                    elapsed = _time.monotonic() - t0
                    planner.record_result(
                        tool_name, "failed",
                        skip_reason=str(e)[:200], elapsed=elapsed,
                    )
                    logger.warning(f"[SurfaceEnum] {tool_name} 异常: {e}")

            report = planner.coverage_report()
            report_dict = report.to_log_dict()
            state.push_decision({
                "action": "tool_coverage_report",
                "phase": "surface_enum",
                "message": (
                    f"Web 探测覆盖率{'达标' if report.satisfied else '未达标'}: "
                    f"{report_dict['category_counts']}"
                ),
                "tone": "info" if report.satisfied else "warn",
                "raw": json.dumps(report_dict, ensure_ascii=False),
            })

    full_inventory = aggregator.get_inventory(min_confidence=0.4)
    state.web_paths_inventory = full_inventory[:200]
    state.web_paths = [
        item["path"] for item in full_inventory
        if item.get("status") in (200, 403, 0)
    ][:200]
    inv = aggregator.summary()
    state.log(
        f"表面枚举完成: {inv['total_paths']} 条路径 "
        f"(高价值 {inv['high_value']}), "
        f"来源工具: {', '.join(inv['source_tools'])}"
    )

    high_value_paths = [
        p for p in state.web_paths[:30]
        if any(kw in p.lower() for kw in (
            "admin", "login", "config", "backup", ".git", ".env", "manager",
            "console", "upload", "api", "debug", "phpinfo",
        ))
    ]
    all_paths_truncated = state.web_paths[:150]
    path_list_text = "\n".join(f"  • {p}" for p in all_paths_truncated)
    path_overflow = "" if len(state.web_paths) <= 150 else f"\n  … 共 {len(state.web_paths)} 条, 仅展示前 150 条"
    thinking_text = (
        f"表面枚举完成: 共发现 {inv['total_paths']} 条路径, "
        f"其中高价值 {inv['high_value']} 条.\n"
        f"来源工具: {', '.join(inv['source_tools'])}.\n"
        + (f"高价值路径: {', '.join(high_value_paths[:10])}\n" if high_value_paths else "")
        + f"完整路径列表:\n{path_list_text}{path_overflow}"
    )
    state.push_decision({
        "action": "thought",
        "phase": "surface_enum",
        "thinking": thinking_text,
        "purpose": "表面枚举总结",
        "plan": [
            f"总路径: {inv['total_paths']}",
            f"高价值: {inv['high_value']}",
            f"下一步: 利用决策分析",
        ],
        "message": f"表面枚举完成: {inv['total_paths']} 路径, {inv['high_value']} 高价值",
        "discovered_paths": all_paths_truncated,
        "total_path_count": len(state.web_paths),
    })
    _consume_replan_signal(state, "re_surface_enum_for_paths")
    _mark_phase_visited(state, "surface_enum", sig)
    return state



_FILE_EXTS = {
    ".sql", ".conf", ".cfg", ".ini", ".xml", ".yaml", ".yml", ".json",
    ".properties", ".bak", ".old", ".backup", ".env", ".htpasswd",
    ".htaccess", ".log", ".txt", ".csv", ".key", ".pem",
}
_PAGE_EXTS = {".php", ".jsp", ".asp", ".aspx", ".py", ".cgi", ".do", ".action"}
_BINARY_EXTS = {".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".war", ".jar", ".class", ".exe", ".dll", ".so"}
_SENSITIVE_KEYWORDS = {"password", "passwd", "token", "secret", "credential", "key", "auth"}
_PAGE_KEYWORDS = {"login", "admin", "upload", "manager", "console"}
_MAX_FILE_TARGETS = 15
_MAX_PAGE_TARGETS = 15


def _classify_harvest_targets(state: PentestState) -> tuple[list[str], list[str]]:
    """Split discovered paths into file targets (Pipeline A) and page targets (Pipeline B)."""
    file_candidates: list[str] = []
    page_candidates: list[str] = []
    seen: set[str] = set()

    def _ext(p: str) -> str:
        lower = p.lower().rstrip("/")
        for ext in sorted(_FILE_EXTS | _PAGE_EXTS | _BINARY_EXTS, key=len, reverse=True):
            if lower.endswith(ext):
                return ext
        return ""

    for p in (state.dirlist_interesting_files or []):
        ext = _ext(p)
        if ext in _BINARY_EXTS or p in seen:
            continue
        seen.add(p)
        if ext in _FILE_EXTS:
            file_candidates.append(p)
        elif ext in _PAGE_EXTS:
            page_candidates.append(p)

    for p in (state.web_paths or []):
        if p in seen:
            continue
        ext = _ext(p)
        if ext in _BINARY_EXTS:
            continue
        seen.add(p)
        if ext in _FILE_EXTS:
            file_candidates.append(p)
        elif ext in _PAGE_EXTS:
            page_candidates.append(p)

    for pc in (state.path_contents or []):
        p = pc.get("path", "")
        if p in seen:
            continue
        kws = {k.lower() for k in (pc.get("keywords") or [])}
        tech = pc.get("tech_clues") or []
        if kws & _SENSITIVE_KEYWORDS:
            seen.add(p)
            file_candidates.append(p)
        elif tech or kws & _PAGE_KEYWORDS:
            seen.add(p)
            page_candidates.append(p)

    _intel_confirmed = {
        "high_risk_intel", "credential_confirmed", "secret_confirmed",
        "config_leak", "db_dump", "attack_lead",
    }
    for item in (state.web_paths_inventory or []):
        p = item.get("path", "")
        if p in seen:
            continue
        item_hints = set(item.get("hints", []))
        if item_hints & _intel_confirmed:
            seen.add(p)
            file_candidates.append(p)

    return file_candidates[:_MAX_FILE_TARGETS], page_candidates[:_MAX_PAGE_TARGETS]


def _build_harvest_script(base_url: str, file_targets: list[str], page_targets: list[str]) -> str:
    lines = [
        'set +e',
        f'BASE="{base_url}"',
        "while IFS='|' read -r TYPE HPATH; do",
        '  [ -z "$HPATH" ] && continue',
        '  LIMIT=$( [ "$TYPE" = "page" ] && echo 12288 || echo 8192 )',
        '  echo "__HARVEST_BEGIN__"',
        '  echo "TYPE:$TYPE"',
        '  echo "PATH:$HPATH"',
        '  TMP_H=$(mktemp); TMP_B=$(mktemp)',
        '  CODE=$(curl -sS -L --max-time 12 -D "$TMP_H" -o "$TMP_B" -w "%{http_code}" "$BASE$HPATH" 2>/dev/null || echo "000")',
        '  echo "CODE:$CODE"',
        '  HEADERS=$(head -c 1024 "$TMP_H" | tr \'\\r\' \' \')',
        '  echo "HEADERS:$HEADERS"',
        '  head -c $LIMIT "$TMP_B"',
        '  echo ""',
        '  echo "__HARVEST_END__"',
        '  rm -f "$TMP_H" "$TMP_B"',
        "done <<'EOF_TARGETS'",
    ]
    for p in file_targets:
        lines.append(f"file|{p}")
    for p in page_targets:
        lines.append(f"page|{p}")
    lines.append("EOF_TARGETS")
    return "\n".join(lines)


def _parse_harvest_output(raw: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    blocks = raw.split("__HARVEST_BEGIN__")
    for block in blocks[1:]:
        end_idx = block.find("__HARVEST_END__")
        if end_idx < 0:
            continue
        block = block[:end_idx]
        entry: dict[str, Any] = {"type": "", "path": "", "code": "000", "headers": "", "body": ""}
        body_lines: list[str] = []
        header_done = False
        for line in block.split("\n"):
            if not header_done:
                if line.startswith("TYPE:"):
                    entry["type"] = line[5:].strip()
                    continue
                elif line.startswith("PATH:"):
                    entry["path"] = line[5:].strip()
                    continue
                elif line.startswith("CODE:"):
                    entry["code"] = line[5:].strip()
                    continue
                elif line.startswith("HEADERS:"):
                    entry["headers"] = line[8:].strip()
                    header_done = True
                    continue
            body_lines.append(line)
        entry["body"] = "\n".join(body_lines).strip()
        if entry["path"]:
            results.append(entry)
    return results


_VULN_TYPE_NAMES = {
    "lfi": "文件包含漏洞 (LFI)",
    "sqli": "SQL 注入",
    "cmdi": "命令注入 (CMDi)",
    "ssti": "服务端模板注入 (SSTI)",
    "ssrf": "SSRF",
    "xss": "XSS",
    "rfi": "远程文件包含 (RFI)",
}


def _check_verify_result(stdout: str, vuln_type: str) -> bool:
    s = stdout.lower()
    if vuln_type == "lfi":
        return "root:x:0:0" in s or "/bin/bash" in s or "/bin/sh" in s
    if vuln_type == "sqli":
        sql_errors = ["sql syntax", "mysql", "sqlite", "postgresql", "ora-", "unclosed quotation"]
        return any(e in s for e in sql_errors)
    if vuln_type == "ssti":
        return "49" in stdout
    if vuln_type == "cmdi":
        return "uid=" in s
    return False


_INTEL_HINT_MAP = [
    ("credentials", "credential_confirmed"),
    ("secrets", "secret_confirmed"),
    ("config_intel", "config_leak"),
    ("attack_hints", "attack_lead"),
]


def _update_inventory_hints_from_intel(
    state: PentestState, path: str, intel: dict,
) -> None:
    """Reflect LLM file-analysis conclusions back into web_paths_inventory hints.

    Maps structured fields from FILE_INTEL_EXTRACT output to confirmed hint
    labels, only trusting items with confidence high/medium.
    """
    new_hints: list[str] = []
    risk = intel.get("risk_level", "none")
    if risk in ("critical", "high"):
        new_hints.append("high_risk_intel")
    for intel_key, hint_label in _INTEL_HINT_MAP:
        items = intel.get(intel_key) or []
        if any(
            isinstance(i, dict) and i.get("confidence") in ("high", "medium")
            for i in items
        ):
            new_hints.append(hint_label)
    if intel.get("file_type") == "sql_dump":
        new_hints.append("db_dump")
    if not new_hints:
        return
    for inv_item in (state.web_paths_inventory or []):
        if inv_item.get("path") == path:
            existing = set(inv_item.get("hints", []))
            inv_item["hints"] = list(existing | set(new_hints))
            break


from backend.agents.fact_hooks import (
    apply_service_info_extraction as _apply_service_info_extraction,
    attach_finding_to_graph as _attach_finding_to_graph,
    attach_host_to_graph as _attach_host_to_graph,
    attach_service_to_graph as _attach_service_to_graph,
    compute_phase_signature as _compute_phase_signature,
    consume_pending_seeds as _consume_pending_seeds,
    consume_replan_signal as _consume_replan_signal,
    emit_replan_signals as _emit_replan_signals,
    make_fact_sink as _make_fact_sink,
    mark_phase_visited as _mark_phase_visited,
    normalize_and_dedupe_state_facts as _normalize_and_dedupe_state_facts,
    push_pending_seed as _push_pending_seed,
    should_skip_phase as _should_skip_phase,
    snapshot_facts as _snapshot_facts,
)


async def _run_kb_probe_scan(
    *,
    state: PentestState,
    executor: Any,
    host: str,
    web_ports: list[Any],
    log_callback: Any,
    record_callback: Any,
) -> None:
    """
    在 intel_harvest 末尾运行一轮 KB 探针扫描。

    设计目标：
      - 把 KB 从被动文本检索升级为主动指纹引擎；
      - KB 命中后产出 VulnFinding(tool="kb_probe")，并把 dispatch_skill 写到
        ``state.kb_probe_hits``，让后续 SkillRegistry.match() 直接命中对应 Skill；
      - 不替代 VulnAgent 的模糊匹配，只做"已知 CVE 快速确认"的补充。
    """
    from backend.knowledge import ProbeScanner, build_probe_targets_from_ports

    if not host or not web_ports:
        return

    targets = build_probe_targets_from_ports(host=host, ports=web_ports)
    if not targets:
        return

    scanner = ProbeScanner(executor=executor)
    try:
        hits = await scanner.scan(
            targets=targets,
            task_id=state.task_id,
            log_callback=log_callback,
            record_callback=record_callback,
        )
    except Exception as exc:
        logger.warning(f"[IntelHarvest:KBProbe] 扫描失败: {exc}")
        return

    if not hits:
        state.log("KB 探针扫描: 无命中")
        return

    existing_signatures = {
        (f.name, f.target, f.cve or "")
        for f in state.findings
    }

    new_findings = 0
    for hit in hits:
        cve = hit.cves[0] if hit.cves else None
        name = f"KB 命中: {hit.vuln_id}"
        target = hit.base_url
        sig = (name, target, cve or "")
        if sig in existing_signatures:
            continue
        existing_signatures.add(sig)

        severity = "high" if hit.confidence >= 0.85 else "medium"
        finding = VulnFinding(
            name=name,
            severity=severity,
            cve=cve,
            target=target,
            port=hit.port,
            description=hit.description or hit.vuln_id,
            evidence=hit.evidence[:800],
            exploitable=True,
            tool="kb_probe",
            confidence=int(round(hit.confidence * 100)),
        )
        state.findings.append(finding)
        new_findings += 1

        state.kb_probe_hits.append({
            "vuln_id": hit.vuln_id,
            "dispatch_skill": hit.dispatch_skill,
            "confidence": hit.confidence,
            "base_url": hit.base_url,
            "port": hit.port,
            "probe_id": hit.probe_id,
            "cves": list(hit.cves),
            "evidence": hit.evidence[:300],
            "finding_vuln_id": finding.vuln_id,
        })

    if new_findings:
        state.log(
            f"KB 探针扫描: 新增 {new_findings} 个 finding "
            f"({len(hits)} 命中, 其中 {sum(1 for h in hits if h.dispatch_skill)} 有 Skill 派发)"
        )
    else:
        state.log(f"KB 探针扫描: {len(hits)} 命中均已存在，未新增 finding")


@retry_node()
async def node_intel_harvest(state: PentestState) -> PentestState:
    """Pipeline between surface_enum and vuln_scan: download files + audit page source."""
    from backend.llm.router import LLMRouter
    from backend.llm.prompts.templates import FILE_INTEL_EXTRACT, PAGE_SOURCE_AUDIT
    from backend.tools.executor import ToolExecutor

    state.current_phase = "intel_harvest"
    _record_chain_visit(state, "intel_harvest")

    skip_plan, skip_plan_reason = _plan_should_skip_phase(state, "intel_harvest")
    if skip_plan:
        state.log(f"[Plan] {skip_plan_reason}")
        return state

    if _yield_if_interrupted(state, "intel_harvest"):
        return state
    if _maybe_skip_or_finish(state, "intel_harvest"):
        return state

    file_targets, page_targets = _classify_harvest_targets(state)
    sig = _compute_phase_signature({
        "files": sorted(file_targets), "pages": sorted(page_targets),
    })
    skip, skip_reason = _should_skip_phase(state, "intel_harvest", sig)
    if skip:
        state.log(f"intel_harvest 跳过：{skip_reason}")
        _consume_replan_signal(state, "re_intel_harvest_for_paths")
        _mark_phase_visited(state, "intel_harvest", sig)
        return state

    state.log("情报采集: 文件情报提取 + 页面源码审计")
    if not file_targets and not page_targets:
        state.log("情报采集: 无高价值目标，跳过")
        _mark_phase_visited(state, "intel_harvest", sig)
        return state

    state.log(f"情报采集: 文件目标 {len(file_targets)} 个, 页面目标 {len(page_targets)} 个")

    host = state.target_host or state.target
    web_ports = [
        p for p in state.open_ports
        if p.state == "open" and (
            p.port in (80, 443, 8080, 8443, 8000, 8888, 8081, 8090, 9000, 9090)
            or "http" in (p.service or "").lower()
        )
    ]
    if not web_ports:
        state.log("情报采集: 未发现 Web 端口，跳过")
        return state

    wp = web_ports[0]
    scheme = "https" if wp.port in (443, 8443) else "http"
    base_url = f"{scheme}://{host}:{wp.port}"

    executor = ToolExecutor()

    async def _on_tool_log(line: str):
        state.log(line)

    async def _on_exec_record(record: dict):
        _append_tool_record(state, record, default_phase="intel_harvest")

    script = _build_harvest_script(base_url, file_targets, page_targets)
    try:
        dl_result = await executor.run_script(
            script_content=script,
            timeout=max(30, 15 * (len(file_targets) + len(page_targets))),
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
            record_phase="intel_harvest",
            record_purpose="batch_download",
        )
    except Exception as e:
        state.log(f"情报采集: 批量下载失败 — {e}")
        return state

    harvested = _parse_harvest_output(dl_result.stdout or "")
    if not harvested:
        state.log("情报采集: 下载结果为空，跳过 LLM 分析")
        return state

    state.log(f"情报采集: 下载完成, 共 {len(harvested)} 个目标")

    _apply_service_info_extraction(state, harvested, base_url, wp.port)

    llm = LLMRouter()
    sem = asyncio.Semaphore(3)

    from backend.agents.prompt_utils import attach_operator_guidance

    async def _analyze_file(entry: dict) -> dict[str, Any] | None:
        if not entry["body"] or entry["code"] in ("000", "404"):
            return None
        prompt = FILE_INTEL_EXTRACT.format(
            target=state.target,
            file_path=entry["path"],
            status_code=entry["code"],
            file_content=entry["body"][:8192],
        )
        prompt = attach_operator_guidance(prompt, state)
        async with sem:
            try:
                raw = await llm.chat(prompt, response_format="json", temperature=0.1, max_tokens=2048)
                return json.loads(raw)
            except Exception as exc:
                logger.warning(f"[IntelHarvest] LLM file analysis failed for {entry['path']}: {exc}")
                return None

    async def _analyze_page(entry: dict) -> dict[str, Any] | None:
        if not entry["body"] or entry["code"] in ("000", "404"):
            return None
        prompt = PAGE_SOURCE_AUDIT.format(
            target=state.target,
            page_url=f"{base_url}{entry['path']}",
            status_code=entry["code"],
            response_headers=entry["headers"][:512],
            page_source=entry["body"][:12288],
        )
        prompt = attach_operator_guidance(prompt, state)
        async with sem:
            try:
                raw = await llm.chat(prompt, response_format="json", temperature=0.1, max_tokens=2048)
                return json.loads(raw)
            except Exception as exc:
                logger.warning(f"[IntelHarvest] LLM page audit failed for {entry['path']}: {exc}")
                return None

    file_entries = [e for e in harvested if e["type"] == "file"]
    page_entries = [e for e in harvested if e["type"] == "page"]

    file_tasks = [_analyze_file(e) for e in file_entries]
    page_tasks = [_analyze_page(e) for e in page_entries]
    all_results = await asyncio.gather(*(file_tasks + page_tasks), return_exceptions=True)

    file_results = all_results[:len(file_tasks)]
    page_results = all_results[len(file_tasks):]

    for entry, intel in zip(file_entries, file_results):
        if isinstance(intel, Exception) or intel is None:
            continue
        state.intel_files.append({
            "path": entry["path"],
            "content_snippet": entry["body"][:200],
            "intel": intel,
        })

        for cred in (intel.get("credentials") or []):
            if cred.get("confidence") != "low":
                state.credential_store.append(cred)

        for secret in (intel.get("secrets") or []):
            state.loot_store.append({"type": "secret", **secret})

        risk = intel.get("risk_level", "none")
        if risk in ("critical", "high"):
            state.findings.append(VulnFinding(
                name=f"信息泄露 - {entry['path']}",
                severity=risk,
                target=f"{base_url}{entry['path']}",
                port=wp.port,
                description=intel.get("summary", ""),
                evidence=entry["body"][:300],
                exploitable=True,
                tool="intel_harvest",
            ))

        for np in (intel.get("new_paths") or []):
            if np:
                if np not in state.web_paths:
                    state.web_paths.append(np)
                if np not in state.intel_discovered_paths:
                    state.intel_discovered_paths.append(np)

        _update_inventory_hints_from_intel(state, entry["path"], intel)

    for entry, audit in zip(page_entries, page_results):
        if isinstance(audit, Exception) or audit is None:
            continue

        page_url = f"{base_url}{entry['path']}"

        for hp in (audit.get("hidden_paths") or []):
            if hp:
                if hp not in state.web_paths:
                    state.web_paths.append(hp)
                if hp not in state.intel_discovered_paths:
                    state.intel_discovered_paths.append(hp)

        for leak in (audit.get("leaked_info") or []):
            state.loot_store.append({"source": entry["path"], **leak})

        for param in (audit.get("injectable_params") or []):
            param_url = param.get("url", "")
            if not param_url:
                continue

            verified = False
            verify_evidence = ""
            vtype = param.get("vuln_type", "unknown")
            conf = param.get("confidence", "low")

            if conf != "low":
                verify_cmd = None
                if vtype == "lfi":
                    verify_cmd = (
                        f'for d in 3 5 7; do '
                        f'TRAV=$(printf "../%.0s" $(seq 1 $d)); '
                        f'RESP=$(curl -sS --max-time 5 "{param_url}${{TRAV}}etc/passwd"); '
                        f'echo "DEPTH=$d"; echo "$RESP" | head -5; '
                        f'echo "---"; done'
                    )
                elif vtype == "sqli":
                    verify_cmd = f"curl -sS --max-time 5 \"{param_url}' OR '1'='1\""
                elif vtype == "ssti":
                    verify_cmd = f'curl -sS --max-time 5 "{param_url}{{{{7*7}}}}"'
                elif vtype == "cmdi":
                    verify_cmd = f'curl -sS --max-time 5 "{param_url}|id"'

                if verify_cmd:
                    try:
                        vr = await executor.run_script(
                            script_content=verify_cmd,
                            timeout=20,
                            log_callback=_on_tool_log,
                            record_callback=_on_exec_record,
                            record_phase="intel_harvest",
                            record_purpose=f"verify_{vtype}",
                        )
                        verify_evidence = (vr.stdout or "")[:500]
                        verified = _check_verify_result(vr.stdout or "", vtype)
                    except Exception as exc:
                        logger.debug(f"[IntelHarvest] verify failed for {param_url}: {exc}")

            param_record = {
                "url": param_url,
                "param_name": param.get("param_name", ""),
                "method": param.get("method", "GET"),
                "vuln_type": vtype,
                "confidence": conf,
                "source": param.get("source", ""),
                "evidence": param.get("evidence", ""),
                "verified": verified,
                "verify_evidence": verify_evidence,
            }
            state.page_params.append(param_record)

            if verified:
                vuln_label = _VULN_TYPE_NAMES.get(vtype, vtype.upper())
                state.findings.append(VulnFinding(
                    name=f"{vuln_label} - {param.get('param_name', '')}",
                    severity="high",
                    target=param_url,
                    port=wp.port,
                    description=f"页面 {page_url} 的 {param.get('param_name', '')} 参数存在{vuln_label}",
                    evidence=verify_evidence[:500],
                    exploitable=True,
                    tool="intel_harvest",
                ))
                state.log(f"情报采集: 已验证 {vuln_label} @ {param_url}")

    try:
        await _run_kb_probe_scan(
            state=state,
            executor=executor,
            host=host,
            web_ports=web_ports,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
        )
    except Exception as exc:
        logger.warning(f"[IntelHarvest] KB 探针扫描异常: {exc}")

    verified_count = sum(1 for p in state.page_params if p.get("verified"))
    state.log(
        f"情报采集完成: "
        f"文件情报 {len(state.intel_files)} 份, "
        f"发现参数 {len(state.page_params)} 个 "
        f"(已验证 {verified_count})"
        + (f", KB 探针命中 {len(state.kb_probe_hits)} 个" if state.kb_probe_hits else "")
    )
    kb_probe_lines: list[str] = []
    if state.kb_probe_hits:
        for h in state.kb_probe_hits[:20]:
            name = h.get("vuln_id", "")
            skill = h.get("dispatch_skill", "")
            conf = h.get("confidence", 0)
            evidence = (h.get("evidence", "") or "")[:120]
            kb_probe_lines.append(
                f"  • {name} (confidence={conf:.2f}"
                + (f", skill={skill}" if skill else "")
                + (f", evidence={evidence}" if evidence else "")
                + ")"
            )
    kb_probe_detail = (
        f"\nKB 探针命中 ({len(state.kb_probe_hits)} 个):\n" + "\n".join(kb_probe_lines)
        if kb_probe_lines else ""
    )

    intel_file_lines: list[str] = []
    for f in state.intel_files[:15]:
        path = f.get("path", "")
        intel = f.get("intel", {})
        risk = intel.get("risk_level", "")
        summary = (intel.get("summary", "") or "")[:80]
        intel_file_lines.append(
            f"  • {path}" + (f" [{risk}] {summary}" if risk or summary else "")
        )
    intel_file_detail = (
        f"\n文件情报 ({len(state.intel_files)} 份):\n" + "\n".join(intel_file_lines)
        if intel_file_lines else ""
    )

    param_lines: list[str] = []
    for p in state.page_params[:15]:
        verified_mark = "✓" if p.get("verified") else "?"
        param_lines.append(
            f"  • {p.get('url', '')} [{p.get('vuln_type', '')}] param={p.get('param_name', '')} ({verified_mark})"
        )
    param_detail = (
        f"\n发现参数 ({len(state.page_params)} 个, {verified_count} 已验证):\n" + "\n".join(param_lines)
        if param_lines else ""
    )

    thinking_text = (
        f"情报采集完成: 分析了 {len(file_entries)} 个文件和 {len(page_entries)} 个页面. "
        f"提取文件情报 {len(state.intel_files)} 份, "
        f"发现注入参数 {len(state.page_params)} 个, "
        f"其中已验证 {verified_count} 个."
        + kb_probe_detail
        + intel_file_detail
        + param_detail
    )

    state.push_decision({
        "action": "thought",
        "phase": "intel_harvest",
        "thinking": thinking_text,
        "purpose": "情报采集总结",
        "message": (
            f"情报采集: {len(state.intel_files)} 文件情报, "
            f"{len(state.page_params)} 参数 ({verified_count} 已验证)"
            + (f", KB 探针命中 {len(state.kb_probe_hits)} 个" if state.kb_probe_hits else "")
        ),
        "kb_probe_hits_count": len(state.kb_probe_hits),
        "intel_files_count": len(state.intel_files),
        "page_params_count": len(state.page_params),
    })
    _consume_replan_signal(state, "re_intel_harvest_for_paths")
    _mark_phase_visited(state, "intel_harvest", sig)
    return state


async def node_exploit_decision(state: PentestState) -> PentestState:
    from backend.llm.router import LLMRouter
    state.current_phase = "exploit_decision"
    _record_chain_visit(state, "exploit_decision")

    skip_plan, skip_plan_reason = _plan_should_skip_phase(state, "exploit")
    if skip_plan:
        state.log(f"[Plan] {skip_plan_reason}")
        return state
    _plan_log_phase_steps(state, "exploit")

    if _yield_if_interrupted(state, "exploit_decision"):
        return state
    if _maybe_skip_or_finish(state, "exploit_decision"):
        return state
    exploitable = [f for f in state.findings if f.exploitable]
    if not exploitable:
        plan = state.pentest_plan or {}
        has_exploit_plan = any(
            p.get("phase") == "exploit" for p in plan.get("phases", [])
        )
        priority_vulns = (state.parsed_intent or {}).get("priority_vulns", [])
        if has_exploit_plan and priority_vulns:
            state.log(
                f"[策略驱动] 无工具确认的漏洞，但策略指定利用阶段"
                f"且用户明确了漏洞类型 {priority_vulns}，继续执行"
            )
        else:
            state.log("无可利用漏洞，跳过利用阶段")
            return state

    if exploitable:
        state.log(f"LLM 分析 {len(exploitable)} 个漏洞的利用优先级...")
        try:
            from backend.agents.prompt_utils import attach_operator_guidance
            llm = LLMRouter()
            prompt = _build_exploit_decision_prompt(state)
            prompt = attach_operator_guidance(prompt, state)
            decision = await llm.chat(prompt, response_format="json")
            decision_data = json.loads(decision)

            priority_map: dict[str, dict] = {
                v["vuln_id"]: v for v in decision_data.get("targets", [])
            }
            for finding in state.findings:
                if finding.vuln_id in priority_map:
                    rec = priority_map[finding.vuln_id]
                    if not rec.get("should_exploit", True):
                        if finding.severity in ("low", "info"):
                            finding.exploitable = False
                            logger.info(
                                f"[ExploitDecision] 禁用低优先级: {finding.name} ({finding.severity})"
                            )
                        else:
                            logger.info(
                                f"[ExploitDecision] 保留 {finding.severity} 级别: {finding.name}"
                                f"（LLM 建议跳过但级别过高，强制保留）"
                            )

            remaining = sum(1 for f in state.findings if f.exploitable)
            state.log(f"LLM 决策完成，保留 {remaining} 个可利用漏洞")

            analysis = decision_data.get("analysis", "")
            targets_info = decision_data.get("targets", [])
            plan_steps = []
            for t in targets_info[:6]:
                vuln_id = t.get("vuln_id", "?")
                reason = t.get("reason", "")
                should = t.get("should_exploit", True)
                plan_steps.append(
                    f"{'[利用]' if should else '[跳过]'} {vuln_id}: {reason[:80]}"
                )
            state.push_decision({
                "action": "thought",
                "phase": "exploit_decision",
                "thinking": analysis or f"LLM 分析 {len(exploitable)} 个漏洞，保留 {remaining} 个可利用",
                "purpose": "利用优先级决策",
                "plan": plan_steps,
                "message": f"LLM 决策: {remaining}/{len(exploitable)} 个漏洞将被利用",
            })
        except Exception as e:
            state.log(f"LLM 决策异常（保留原始可利用标记）: {e}")
    return state


async def node_human_approval(state: PentestState) -> PentestState:
    """
    人工审批节点。

    - 当 state.auto_approve=True(例如 CTF 模式/用户显式勾选"自动通过")时,
      节点会直接把 approved 置为 True 并跳过人工等待。实际跳过发生在
      `build_graph` 的 `interrupt_before` 动态判定里,本节点只负责记录日志与
      推进状态。
    - 否则保持原行为:LangGraph 在本节点前中断,前端 /approve 设置 approved
      后再恢复执行。

    新版本同时使用 ``state.open_checkpoint`` 推送 Plan 风格确认卡片,把
    AI thinking、可选动作、风险提示一起暴露给前端;旧的 ``/approve`` 端点
    继续兼容(只更新 approved 字段)。
    """
    state.current_phase = "awaiting_approval"
    _record_chain_visit(state, "awaiting_approval")
    exploitable = [f for f in state.findings if f.exploitable]

    if state.approved_once and not state.approved:
        state.approved = True
        state.log("✅ 反馈循环：审批已在前序轮次通过，跳过人工审批")

    if state.auto_approve and not state.approved:
        state.approved = True
        state.log(f"✅ auto_approve 生效,跳过人工审批({len(exploitable)} 个待利用漏洞)")
    elif not state.approved:
        state.status = TaskStatus.AWAITING_APPROVAL
        state.log(f"⏸ 收到审批请求:{len(exploitable)} 个漏洞待利用")
        if not state.pending_checkpoint:
            top_targets = [
                {
                    "label": f.name,
                    "severity": f.severity,
                    "vuln_id": f.vuln_id,
                    "exploitable": True,
                    "reason": (f.description or "")[:120],
                }
                for f in exploitable[:5]
            ]
            risk_note = (
                "高风险" if any(f.severity in ("critical", "high") for f in exploitable)
                else "中等风险"
            )
            thinking_lines = []
            for f in exploitable[:6]:
                line = f"- {f.severity.upper()} | {f.name}"
                if f.cve:
                    line += f" ({f.cve})"
                thinking_lines.append(line)
            state.open_checkpoint({
                "checkpoint_type": "exploit_gate",
                "phase": "awaiting_approval",
                "summary": (
                    f"系统已识别 {len(exploitable)} 个可利用漏洞,等待你的授权再开始利用。"
                ),
                "thinking": "\n".join(thinking_lines) or "暂无可展开的推理",
                "recommendation": "批准后将进入立足点尝试阶段;拒绝则跳过利用并直接出报告。",
                "risk": risk_note,
                "default_action": "approve",
                "options": [
                    {
                        "id": "approve",
                        "label": "批准并继续利用",
                        "tone": "primary",
                        "action": "approve",
                    },
                    {
                        "id": "modify",
                        "label": "提交建议(继续利用前补充意图/约束)",
                        "tone": "info",
                        "action": "modify",
                        "wants_prompt": True,
                    },
                    {
                        "id": "reject",
                        "label": "拒绝利用,直接出报告",
                        "tone": "danger",
                        "action": "reject",
                    },
                ],
                "context": {
                    "exploitable_count": len(exploitable),
                    "top_targets": top_targets,
                    "workflow_mode": state.workflow_mode,
                    "auto_approve": state.auto_approve,
                },
            })

    if state.approved:
        state.status = TaskStatus.RUNNING
        state.approved_once = True
        state.log("✅ 已获授权,继续利用阶段")
        if state.pending_checkpoint and (
            state.pending_checkpoint.get("checkpoint_type") == "exploit_gate"
        ):
            state.pending_checkpoint = None
    else:
        state.log("⚠ 未获授权,跳过利用阶段")
        for f in state.findings:
            f.exploitable = False
    return state


async def node_foothold_attempt(state: PentestState) -> PentestState:
    from backend.agents.exploit_agent import ExploitAgent
    state.current_phase = "foothold_attempt"
    _record_chain_visit(state, "foothold_attempt")
    if _yield_if_interrupted(state, "foothold_attempt"):
        return state
    if _maybe_skip_or_finish(state, "foothold_attempt"):
        return state
    exploitable = [f for f in state.findings if f.exploitable]
    before_snapshot = _snapshot_facts(state)
    _normalize_and_dedupe_state_facts(state, source_node="foothold_attempt_pre")

    php_fpm = [
        f for f in state.findings
        if "11043" in (f.cve or "").lower() or "php-fpm" in (f.name or "").lower()
    ]
    if php_fpm:
        php_exploitable = [f for f in php_fpm if f.exploitable]
        logger.info(
            f"[Orchestrator] PHP-FPM findings: "
            f"total={len(php_fpm)}, exploitable={len(php_exploitable)}, "
            f"names={[f.name for f in php_fpm]}"
        )
        if not php_exploitable:
            state.log(
                f"PHP-FPM 发现 {len(php_fpm)} 个但均未确认可利用"
                f"（tool={php_fpm[0].tool}）"
            )

    existing_ports = {f.port for f in state.findings if f.port}
    for p in state.open_ports:
        if p.port in existing_ports:
            continue
        if p.service and p.service.lower() not in ("unknown", "tcpwrapped"):
            synthetic = VulnFinding(
                name=f"{p.service.upper()} Service",
                severity="low",
                port=p.port,
                target=f"{state.target_host or state.target}:{p.port}",
                description=f"Service: {p.service} {p.version}",
                evidence=f"nmap: {p.port}/{p.protocol} {p.service} {p.version}",
                exploitable=True,
                tool="service-sweep",
            )
            state.findings.append(synthetic)
            existing_ports.add(p.port)

    exploitable = [f for f in state.findings if f.exploitable]
    if not _consume_risk_budget(state, cost=1):
        state.log("风险预算不足，跳过 foothold_attempt 阶段")
        return state
    state.log(f"攻链: 立足点尝试 — 利用 {len(exploitable)} 个漏洞条目（含服务级 finding）")
    try:
        agent = ExploitAgent()
        exploit_context = _build_exploit_context(state)
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="foothold_attempt")
        async def _on_decision(event: dict):
            if (event or {}).get("action") == "guard_block":
                code = (event or {}).get("guard_code") or "unknown"
                key = f"guard_block:{code}"
                state.guard_stats[key] = int(state.guard_stats.get(key, 0)) + 1
            state.push_decision(event)
        from backend.agents.prompt_utils import operator_guidance_block
        _op_block = operator_guidance_block(state)
        _exploit_plan_skills = _plan_get_step_skills(state, "exploit") or None
        results = await agent.run(
            target=state.target_host or state.target,
            findings=exploitable,
            target_os=state.target_os,
            context=exploit_context,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
            decision_callback=_on_decision,
            fact_sink=_make_fact_sink(state),
            operator_block=_op_block,
            plan_skills=_exploit_plan_skills,
        )
        state.exploit_results = results
        successes = [r for r in results if r.success]
        rce_successes = [r for r in successes if r.exploit_level in ("rce", "")]
        state.got_shell = len(rce_successes) > 0
        if state.got_shell:
            si = rce_successes[0].session_info or {}
            state.privilege_level = si.get("privilege") or (
                "root" if "root" in str(si.get("current_user", "")).lower() else "user"
            )
            state.log(f"成功获取 shell，权限: {state.privilege_level}")
            state.secondary_elided = True
        else:
            file_reads = [r for r in successes if r.exploit_level == "file_read"]
            if file_reads:
                state.log(
                    f"LFI 文件读取已确认 ({len(file_reads)} 条), "
                    f"但未获得 RCE，继续深入利用"
                )
                state.foothold_status = "file_read"
            else:
                state.log("所有利用尝试均未成功")
        _sync_foothold_state(state)
        _enrich_finding_names_from_exploits(state)
        _normalize_and_dedupe_state_facts(state, source_node="foothold_attempt_post")
        try:
            after_snapshot = _snapshot_facts(state)
            _emit_replan_signals(
                state,
                before=before_snapshot,
                after=after_snapshot,
                source_node="foothold_attempt",
            )
        except Exception as _exc:
            logger.debug(f"[foothold_attempt] emit_replan_signals skipped: {_exc}")
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"利用阶段异常: {e}")
    return state


async def node_secondary_attack(state: PentestState) -> PentestState:
    """首轮利用未拿到 shell 时，对失败项再跑一轮（结合操作员对话中的新提示）。"""
    from backend.agents.exploit_agent import ExploitAgent
    state.current_phase = "secondary_attack"
    _record_chain_visit(state, "secondary_attack")
    if _yield_if_interrupted(state, "secondary_attack"):
        return state
    if _maybe_skip_or_finish(state, "secondary_attack"):
        return state
    state.secondary_attack_done = True
    state.secondary_attack_count = int(state.secondary_attack_count or 0) + 1
    before_snapshot = _snapshot_facts(state)
    _normalize_and_dedupe_state_facts(state, source_node="secondary_attack_pre")

    if state.got_shell:
        state.log("已有 shell，跳过二次攻击")
        return state

    exploitable = [f for f in state.findings if f.exploitable]
    if not exploitable:
        state.log("无可利用项，跳过二次攻击")
        return state

    failed_ids = {r.vuln_id for r in state.exploit_results if not r.success}
    if state.exploit_results and failed_ids:
        findings_retry = [f for f in exploitable if f.vuln_id in failed_ids]
    else:
        findings_retry = list(exploitable)

    if not findings_retry:
        state.log("二次攻击：没有需要重试的漏洞条目")
        return state

    state.log(f"二次攻击：对 {len(findings_retry)} 个漏洞再尝试一轮...")
    try:
        agent = ExploitAgent()
        exploit_context = _build_exploit_context(state)
        exploit_context["secondary_pass"] = True
        if state.foothold_status == "file_read":
            exploit_context["lfi_escalation"] = True
            exploit_context["lfi_hint"] = (
                "前序利用已通过 LFI 确认文件读取能力，但未获得 RCE。"
                "请集中尝试: PHP Wrappers → 日志注入 → 已读取凭据的复用"
            )
            file_read_results = [
                r for r in state.exploit_results
                if r.success and r.exploit_level == "file_read"
            ]
            if file_read_results:
                exploit_context["prior_file_reads"] = file_read_results[0].evidence[:2000]
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="secondary_attack")
        async def _on_decision(event: dict):
            if (event or {}).get("action") == "guard_block":
                code = (event or {}).get("guard_code") or "unknown"
                key = f"guard_block:{code}"
                state.guard_stats[key] = int(state.guard_stats.get(key, 0)) + 1
            state.push_decision(event)
        from backend.agents.prompt_utils import operator_guidance_block
        _op_block = operator_guidance_block(state)
        _exploit_plan_skills = _plan_get_step_skills(state, "exploit") or None
        new_results = await agent.run(
            target=state.target_host or state.target,
            findings=findings_retry,
            target_os=state.target_os,
            context=exploit_context,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
            decision_callback=_on_decision,
            fact_sink=_make_fact_sink(state),
            operator_block=_op_block,
            plan_skills=_exploit_plan_skills,
        )
        by_id: dict[str, ExploitResult] = {r.vuln_id: r for r in state.exploit_results}
        for nr in new_results:
            prev = by_id.get(nr.vuln_id)
            if prev is None:
                by_id[nr.vuln_id] = nr
            elif nr.success:
                by_id[nr.vuln_id] = nr
            elif not prev.success:
                by_id[nr.vuln_id] = nr
        state.exploit_results = list(by_id.values())
        successes = [r for r in state.exploit_results if r.success]
        rce_successes = [r for r in successes if r.exploit_level in ("rce", "")]
        state.got_shell = len(rce_successes) > 0
        if state.got_shell:
            si = rce_successes[0].session_info or {}
            state.privilege_level = si.get("privilege") or (
                "root" if "root" in str(si.get("current_user", "")).lower() else "user"
            )
            state.log(f"二次攻击后成功获取 shell，权限: {state.privilege_level}")
        else:
            file_reads = [r for r in successes if r.exploit_level == "file_read"]
            if file_reads:
                state.log("二次攻击: LFI 文件读取确认，但仍未获得 RCE")
            else:
                state.log("二次攻击仍未成功")
        _sync_foothold_state(state)
        _enrich_finding_names_from_exploits(state)
        _normalize_and_dedupe_state_facts(state, source_node="secondary_attack_post")
        try:
            after_snapshot = _snapshot_facts(state)
            _emit_replan_signals(
                state,
                before=before_snapshot,
                after=after_snapshot,
                source_node="secondary_attack",
            )
        except Exception as _exc:
            logger.debug(f"[secondary_attack] emit_replan_signals skipped: {_exc}")
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"二次攻击异常: {e}")
    return state


async def node_post_foothold_enum(state: PentestState) -> PentestState:
    from backend.agents.post_agent import PostExploitAgent
    state.current_phase = "post_foothold_enum"
    _record_chain_visit(state, "post_foothold_enum")

    skip_plan, skip_plan_reason = _plan_should_skip_phase(state, "post_exploit")
    if skip_plan:
        state.log(f"[Plan] {skip_plan_reason}")
        return state
    _plan_log_phase_steps(state, "post_exploit")

    if _yield_if_interrupted(state, "post_foothold_enum"):
        return state
    if _maybe_skip_or_finish(state, "post_foothold_enum"):
        return state
    before_snapshot = _snapshot_facts(state)
    state.log("攻链: 立足后枚举")
    try:
        agent = PostExploitAgent()
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="post_foothold_enum")
        res = await agent.run_post_foothold_enum(
            exploit_results=state.exploit_results,
            target_os=state.target_os,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
        )
        base = dict(state.post_findings or {})
        base["post_foothold"] = res
        state.post_findings = base
        for c in res.get("new_credentials") or []:
            if isinstance(c, dict):
                state.credential_store.append(c)
        for h in res.get("privesc_hypotheses") or []:
            if isinstance(h, dict):
                state.privesc_hypotheses.append(h)
        for l in res.get("loot_hints") or []:
            if isinstance(l, dict):
                state.loot_store.append(l)
        _merge_attack_steps(state, res.get("next_steps"))
        fp = res.get("final_privilege")
        if fp and fp != "unknown":
            state.privilege_level = fp
        state.log("立足后枚举完成")
        try:
            after_snapshot = _snapshot_facts(state)
            _emit_replan_signals(
                state,
                before=before_snapshot,
                after=after_snapshot,
                source_node="post_foothold_enum",
            )
        except Exception as _exc:
            logger.debug(f"[post_foothold_enum] emit_replan_signals skipped: {_exc}")
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"立足后枚举异常: {e}")
    _mark_phase_visited(
        state, "post_foothold_enum",
        _compute_phase_signature({"round": state.phase_visit_count.get('post_foothold_enum', 0)}),
    )
    return state


async def node_post_foothold_approval(state: PentestState) -> PentestState:
    """Approval gate before privesc/objective in strict (pentest_engineer) mode.

    Uses ``post_approved`` (independent of the first-gate ``approved``) so that
    the two interrupt_before gates never interfere with each other.
    """
    state.current_phase = "post_foothold_approval"
    _record_chain_visit(state, "post_foothold_approval")

    skip_plan, skip_plan_reason = _plan_should_skip_phase(state, "post_exploit")
    if skip_plan:
        state.post_approved = False
        state.log(f"[Plan] {skip_plan_reason}")
        return state

    if state.post_approved_once and not state.post_approved:
        state.post_approved = True
        state.log("✅ 反馈循环：立足后审批已在前序轮次通过，跳过人工审批")

    if state.auto_approve and not state.post_approved:
        state.post_approved = True
        state.log("✅ auto_approve 生效，跳过立足后审批")
    elif not state.post_approved:
        state.status = TaskStatus.AWAITING_APPROVAL
        state.log("⏸ 已获取 shell，等待人工确认是否继续提权/收集")
        if not state.pending_checkpoint:
            state.open_checkpoint({
                "checkpoint_type": "post_foothold_gate",
                "phase": "post_foothold_approval",
                "summary": (
                    f"目标已建立立足点(privilege={state.privilege_level or 'unknown'})。"
                    f" 是否继续提权与目标收集?"
                ),
                "thinking": (
                    f"foothold_status={state.foothold_status},"
                    f" privesc_attempt={state.privesc_attempt_count}/{state.max_privesc_rounds},"
                    f" exploit_results={len(state.exploit_results)}"
                ),
                "recommendation": "建议继续:执行提权 + 目标收集再出报告。",
                "risk": "中等风险",
                "default_action": "approve",
                "options": [
                    {
                        "id": "approve",
                        "label": "继续提权 / 收集",
                        "tone": "primary",
                        "action": "approve",
                    },
                    {
                        "id": "modify",
                        "label": "提交意见后继续(给提权更多约束)",
                        "tone": "info",
                        "action": "modify",
                        "wants_prompt": True,
                    },
                    {
                        "id": "reject",
                        "label": "停止提权,直接出报告",
                        "tone": "danger",
                        "action": "reject",
                    },
                ],
                "context": {
                    "foothold_status": state.foothold_status,
                    "privilege_level": state.privilege_level,
                    "privesc_round": state.privesc_attempt_count,
                    "max_privesc_rounds": state.max_privesc_rounds,
                    "workflow_mode": state.workflow_mode,
                },
            })

    if state.post_approved:
        state.status = TaskStatus.RUNNING
        state.post_approved_once = True
        state.log("✅ 已获授权，继续提权阶段")
        if state.pending_checkpoint and (
            state.pending_checkpoint.get("checkpoint_type") == "post_foothold_gate"
        ):
            state.pending_checkpoint = None
    else:
        state.log("⚠ 未获授权，跳过提权阶段，直接收集并出报告")
    return state


def edge_after_post_foothold_approval(state: PentestState) -> str:
    if state.post_approved:
        return "internal_scan"
    return "objective_collect"


async def node_privesc_attempt(state: PentestState) -> PentestState:
    from backend.agents.post_agent import PostExploitAgent
    state.current_phase = "privesc_attempt"
    _record_chain_visit(state, "privesc_attempt")
    if _yield_if_interrupted(state, "privesc_attempt"):
        return state
    if _maybe_skip_or_finish(state, "privesc_attempt"):
        return state
    state.privesc_attempt_count += 1
    before_snapshot = _snapshot_facts(state)
    if not _consume_risk_budget(state, cost=1):
        state.log("风险预算不足，跳过 privesc_attempt 阶段")
        return state
    state.log(f"攻链: 提权尝试 第 {state.privesc_attempt_count}/{state.max_privesc_rounds} 轮")
    try:
        agent = PostExploitAgent()
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="privesc_attempt")
        res = await agent.run_privesc_phase(
            exploit_results=state.exploit_results,
            target_os=state.target_os,
            task_id=state.task_id,
            round_num=state.privesc_attempt_count,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
        )
        base = dict(state.post_findings or {})
        base["privesc_latest"] = res
        state.post_findings = base
        state.privilege_level = res.get("final_privilege", state.privilege_level)
        _merge_attack_steps(state, res.get("next_steps"))
        pl = (state.privilege_level or "").lower()
        if pl == "root":
            state.objective_status["root_reached"] = True
        try:
            after_snapshot = _snapshot_facts(state)
            _emit_replan_signals(
                state,
                before=before_snapshot,
                after=after_snapshot,
                source_node="privesc_attempt",
            )
        except Exception as _exc:
            logger.debug(f"[privesc_attempt] emit_replan_signals skipped: {_exc}")
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"提权阶段异常: {e}")
    return state


async def node_internal_scan(state: PentestState) -> PentestState:
    """Discover internal subnets and hosts from the compromised target."""
    from backend.agents.post_agent import PostExploitAgent
    state.current_phase = "internal_scan"
    _record_chain_visit(state, "internal_scan")
    if _yield_if_interrupted(state, "internal_scan"):
        return state
    if _maybe_skip_or_finish(state, "internal_scan"):
        return state
    if not state.got_shell:
        state.log("攻链: 无立足点, 跳过内网扫描")
        return state
    state.log("攻链: 内网扫描 (发现内部网络 & 主机)")
    try:
        agent = PostExploitAgent()

        async def _on_tool_log(line: str):
            state.log(line)

        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="internal_scan")

        res = await agent.run_internal_scan(
            exploit_results=state.exploit_results,
            target_os=state.target_os,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
        )
        state.internal_network = res
        subnets = res.get("subnets", [])
        hosts = res.get("hosts", [])
        state.log(f"内网扫描完成: {len(subnets)} 子网, {len(hosts)} 主机")
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"内网扫描异常: {e}")
    return state


async def node_lateral_movement(state: PentestState) -> PentestState:
    """Attempt lateral movement using discovered credentials."""
    from backend.agents.post_agent import PostExploitAgent
    state.current_phase = "lateral_movement"
    _record_chain_visit(state, "lateral_movement")
    if _yield_if_interrupted(state, "lateral_movement"):
        return state
    if _maybe_skip_or_finish(state, "lateral_movement"):
        return state
    if not state.credential_store and not state.got_shell:
        state.log("攻链: 无凭据且无立足点, 跳过横向移动")
        return state
    state.log("攻链: 横向移动")
    try:
        agent = PostExploitAgent()

        async def _on_tool_log(line: str):
            state.log(line)

        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="lateral_movement")

        res = await agent.run_lateral_movement(
            exploit_results=state.exploit_results,
            credential_store=state.credential_store,
            target_os=state.target_os,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
        )
        state.lateral_results = res
        findings = res.get("findings", {})
        lateral_successes = findings.get("lateral_successes", [])
        if lateral_successes:
            state.log(f"横向移动成功: {len(lateral_successes)} 台主机")
        else:
            state.log("横向移动: 未发现可利用路径")
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"横向移动异常: {e}")
    return state


async def node_persistence(state: PentestState) -> PentestState:
    """Establish persistence on the compromised host."""
    from backend.agents.post_agent import PostExploitAgent
    state.current_phase = "persistence"
    _record_chain_visit(state, "persistence")
    if _yield_if_interrupted(state, "persistence"):
        return state
    if _maybe_skip_or_finish(state, "persistence"):
        return state
    if not state.got_shell:
        state.log("攻链: 无立足点, 跳过持久化")
        return state
    state.log("攻链: 持久化安装")
    try:
        agent = PostExploitAgent()

        async def _on_tool_log(line: str):
            state.log(line)

        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="persistence")

        res = await agent.run_persistence(
            exploit_results=state.exploit_results,
            target_os=state.target_os,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
        )
        methods = res.get("methods", [])
        state.persistence_entries = methods
        if methods:
            names = ", ".join(m.get("type", "?") for m in methods)
            state.log(f"持久化成功: {names}")
        else:
            state.log("持久化: 未成功安装任何方法")
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"持久化异常: {e}")
    return state


async def node_objective_collect(state: PentestState) -> PentestState:
    from backend.agents.post_agent import PostExploitAgent
    state.current_phase = "objective_collect"
    _record_chain_visit(state, "objective_collect")
    if _yield_if_interrupted(state, "objective_collect"):
        return state
    if _maybe_skip_or_finish(state, "objective_collect"):
        return state
    state.log("攻链: 目标收集（flag / proof 线索）")
    try:
        agent = PostExploitAgent()
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="objective_collect")
        res = await agent.run_objective_collect(
            exploit_results=state.exploit_results,
            target_os=state.target_os,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
        )
        base = dict(state.post_findings or {})
        base["objective"] = res
        state.post_findings = base
        findings = res.get("findings") or {}
        if findings.get("flag_hints"):
            state.objective_status["flag_hints"] = True
        if findings.get("root_context_hint"):
            state.objective_status["root_context_hint"] = True
        state.objective_status["report_ready"] = True
        _merge_attack_steps(state, res.get("next_steps"))
        state.chain_summary = (
            f"foothold={state.foothold_status}; privilege={state.privilege_level}; "
            f"privesc_rounds={state.privesc_attempt_count}"
        )
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"目标收集异常: {e}")
    return state


async def node_report(state: PentestState) -> PentestState:
    from backend.report.generator import ReportGenerator, _filter_phase_log
    state.current_phase = "report"
    _record_chain_visit(state, "report")
    state.log("开始生成报告...")

    _build_attack_timeline(state)

    state.executive_summary = _build_executive_summary(state)

    state.filtered_log = _filter_phase_log(state.phase_log)

    prior_status = state.status
    try:
        _flatten_post_findings_for_report(state)
        gen = ReportGenerator()
        report_md, report_path = await gen.generate(state)
        state.report_md = report_md
        state.report_path = report_path
        state.log(f"报告生成完成: {report_path}")
    except Exception as e:
        state.report_error = str(e)
        state.log(f"报告生成异常（不影响任务完成度）: {e}")
    finally:
        if prior_status != TaskStatus.FAILED:
            state.status = TaskStatus.COMPLETED
        else:
            state.status = TaskStatus.FAILED
        try:
            from backend.tools.executor import ToolExecutor
            _exec = ToolExecutor()
            await _exec.stop_task_container(state.task_id)
            state.log("工具容器已清理")
        except Exception:
            pass
    return state


def _build_attack_timeline(state: PentestState) -> None:
    """根据 chain_visited 和 findings/exploit_results 构建攻击时间线。"""
    phase_descriptions = {
        "recon": "侦察阶段：端口扫描与服务发现",
        "surface_enum": "攻击面枚举：Web 路径探测与指纹识别",
        "intel_harvest": "情报采集：解析响应体中的版本信息与敏感泄露",
        "vuln_scan": "漏洞扫描：Nuclei/Nikto 模板检测 + 指纹匹配",
        "exploit_decision": "攻链决策：评估可利用漏洞并制定利用计划",
        "awaiting_approval": "等待人工审批：确认高影响利用操作",
        "foothold_attempt": "立足点建立：执行漏洞利用 payload",
        "secondary_attack": "二次攻击：对初始利用失败后执行补充攻击",
        "post_foothold_enum": "后立足点枚举：收集系统信息与凭据",
        "privesc_attempt": "权限提升尝试",
        "objective_collect": "目标收集：提取 flag 与关键证据",
        "report": "报告生成",
    }

    entries: list[dict[str, str]] = []
    for phase in (state.chain_visited or []):
        desc = phase_descriptions.get(phase, phase)
        extra = ""

        if phase == "foothold_attempt":
            successes = [r for r in (state.exploit_results or []) if r.success]
            failures = [r for r in (state.exploit_results or []) if not r.success]
            if successes:
                extra = f"，成功利用 {len(successes)} 个漏洞"
            if failures:
                extra += f"，{len(failures)} 个漏洞利用失败"
        elif phase == "privesc_attempt":
            extra = f"（第 {state.privesc_attempt_count}/{state.max_privesc_rounds} 轮）"
        elif phase == "report":
            vuln_count = len([f for f in (state.findings or []) if getattr(f, 'exploitable', False)])
            total_count = len(state.findings or [])
            extra = f"，共生成了 {vuln_count} 个可利用漏洞和 {total_count} 个信息项"

        entries.append({"phase": phase, "summary": f"{desc}{extra}"})

    state.attack_timeline = entries


def _build_executive_summary(state: PentestState) -> str:
    """基于测试数据生成面向管理层的非技术性执行摘要。"""
    findings = state.findings or []
    critical = sum(1 for f in findings if getattr(f, 'severity', '') == 'critical')
    high = sum(1 for f in findings if getattr(f, 'severity', '') == 'high')
    medium = sum(1 for f in findings if getattr(f, 'severity', '') == 'medium')
    exploitable = [f for f in findings if getattr(f, 'exploitable', False)]

    shell_status = "成功获取" if state.got_shell else "未能获取"
    priv_level = state.privilege_level or "未获得"

    if critical > 0:
        risk_level = "严重"
    elif high > 0:
        risk_level = "高风险"
    elif medium > 0:
        risk_level = "中等风险"
    else:
        risk_level = "低风险"

    lines = [
        f"本次对目标 `{state.target}` 进行了自动化渗透测试，整体风险评级为**{risk_level}**。",
        "",
        f"测试共发现 **{len(findings)}** 个安全问题，其中严重 {critical} 个、高危 {high} 个、中危 {medium} 个，",
        f"含 **{len(exploitable)}** 个具有实际可利用性的漏洞。",
    ]

    if exploitable:
        top_vulns = sorted(exploitable, key=lambda f: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(getattr(f, 'severity', 'low'), 0), reverse=True)
        lines.append("")
        lines.append("**关键漏洞包括：**")
        for v in top_vulns[:3]:
            name = getattr(v, 'name', '未命名')
            sev = getattr(v, 'severity', 'unknown')
            sev_cn = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危'}.get(sev, sev)
            target = getattr(v, 'target', '')
            lines.append(f"- [{sev_cn}] {name} ({target})")

    lines.append("")
    lines.append(f"测试期间{shell_status}目标系统的交互式访问权限（当前权限级别：{priv_level}）。")
    lines.append("")
    lines.append("**建议：** 请安全团队优先处置严重和高危漏洞，参照报告中的修复建议在 7 个工作日内完成修复，")
    lines.append("并安排回归验证测试。同时建议将安全扫描纳入 CI/CD 流水线，实现常态化漏洞管理。")

    return "\n".join(lines)



def edge_should_exploit(state: PentestState) -> str:
    """
    决策阶段结束后的路由:
      - 任务已失败 → report
      - 意图驱动：仅侦察模式（pentest_phase 只有 recon）→ report
      - 无可利用 finding → report
      - 有可利用 finding 且 auto_approve=True → 直接进入 foothold_attempt,
        不经过 human_approval interrupt(避免 LangGraph 暂停等待)
      - 其余情况 → human_approval(会在 interrupt_before 处暂停)
    """
    if state.status == TaskStatus.FAILED:
        return "report"
    parsed = state.parsed_intent or {}
    phases = parsed.get("pentest_phase", [])
    EXPLOIT_PHASES = {"exploit", "full_chain", "post_exploit"}
    if phases and not any(p in EXPLOIT_PHASES for p in phases):
        state.log(
            f"[意图驱动] pentest_phase={phases!r} 不含利用阶段，"
            f"跳过 exploit → 直接出报告"
        )
        state.push_decision({
            "action": "intent_recon_only",
            "phase": "exploit_decision",
            "message": f"策略指定阶段 {phases}，跳过漏洞利用",
            "tone": "info",
        })
        return "report"
    has_exploitable = any(f.exploitable for f in state.findings)
    if not has_exploitable:
        plan = state.pentest_plan or {}
        has_exploit_plan = any(
            p.get("phase") == "exploit" for p in plan.get("phases", [])
        )
        priority_vulns = (state.parsed_intent or {}).get("priority_vulns", [])
        if not (has_exploit_plan and priority_vulns):
            return "report"
    if state.auto_approve:
        return "foothold_attempt"
    return "human_approval"


def edge_after_approval(state: PentestState) -> str:
    if state.status == TaskStatus.FAILED:
        return "report"
    if any(f.exploitable for f in state.findings):
        return "foothold_attempt"
    plan = state.pentest_plan or {}
    has_exploit_plan = any(
        p.get("phase") == "exploit" for p in plan.get("phases", [])
    )
    priority_vulns = (state.parsed_intent or {}).get("priority_vulns", [])
    if has_exploit_plan and priority_vulns:
        return "foothold_attempt"
    return "report"


def edge_after_foothold(state: PentestState) -> str:
    if state.status == TaskStatus.FAILED:
        return "report"
    if state.got_shell:
        return "post_foothold_enum"
    if state.foothold_status == "file_read":
        if not state.secondary_attack_done:
            return "secondary_attack"
        return "post_foothold_enum"
    if not state.secondary_attack_done and any(f.exploitable for f in state.findings):
        return "secondary_attack"
    return "report"


def edge_after_secondary(state: PentestState) -> str:
    if state.status == TaskStatus.FAILED:
        return "report"
    return "post_foothold_enum" if state.got_shell else "report"


def edge_after_privesc(state: PentestState) -> str:
    if state.status == TaskStatus.FAILED:
        return "objective_collect"
    pl = (state.privilege_level or "").lower()
    if pl == "root":
        return "objective_collect"
    if state.privesc_attempt_count >= state.max_privesc_rounds:
        return "objective_collect"
    return "privesc_again"



_LINEAR_CHAIN_SUCCESSORS: dict[str, list[str]] = {
    "recon":         ["surface_enum", "intel_harvest", "vuln_scan", "exploit_decision"],
    "surface_enum":  ["intel_harvest", "vuln_scan", "exploit_decision"],
    "intel_harvest": ["vuln_scan", "exploit_decision"],
    "vuln_scan":     ["exploit_decision"],
}


def _edge_plan_forward(state: PentestState, current_phase: str) -> str:
    """沿线性链向前走，跳过被策略排除的阶段。"""
    for nxt in _LINEAR_CHAIN_SUCCESSORS.get(current_phase, ["exploit_decision"]):
        skip, _ = _plan_should_skip_phase(state, nxt)
        if not skip:
            return nxt
    return "exploit_decision"


def _edge_after_recon(state: PentestState) -> str:
    return _edge_plan_forward(state, "recon")


def _edge_after_surface_enum(state: PentestState) -> str:
    return _edge_plan_forward(state, "surface_enum")


def _edge_after_intel_harvest(state: PentestState) -> str:
    return _edge_plan_forward(state, "intel_harvest")



def _can_replan(state: PentestState, target_phase: str) -> bool:
    if state.replan_count >= state.max_replan:
        return False
    skip, _ = _plan_should_skip_phase(state, target_phase)
    if skip:
        return False
    visits = state.phase_visit_count.get(target_phase, 0)
    cap = state.max_phase_visits.get(target_phase, 99)
    return visits < cap


def _do_replan(state: PentestState, target_phase: str, signal_key: str) -> str:
    state.replan_count += 1
    _consume_replan_signal(state, signal_key)
    state.log(
        f"[replan] {target_phase} ← 触发反馈 (#{state.replan_count}/{state.max_replan}, "
        f"signal={signal_key})"
    )
    state.push_decision({
        "action": "replan_route",
        "phase": state.current_phase,
        "thinking": f"signal {signal_key} 命中，回流到 {target_phase}",
        "message": f"replan → {target_phase}",
        "tone": "info",
    })
    return target_phase


def edge_after_foothold_v2(state: PentestState) -> str:
    """Foothold 出口：先看 replan signals，再走老逻辑。"""
    if state.status == TaskStatus.FAILED:
        return "report"
    sig = state.replan_signals or {}
    if state.got_shell:
        return "post_foothold_enum"
    if sig.get("re_vuln_scan_for_creds") and _can_replan(state, "vuln_scan"):
        return _do_replan(state, "vuln_scan", "re_vuln_scan_for_creds")
    if sig.get("re_surface_enum_for_paths") and _can_replan(state, "surface_enum"):
        return _do_replan(state, "surface_enum", "re_surface_enum_for_paths")
    if state.foothold_status == "file_read":
        if state.secondary_attack_count < state.max_secondary_attacks:
            return "secondary_attack"
        return "post_foothold_enum"
    if state.secondary_attack_count < state.max_secondary_attacks and any(
        f.exploitable for f in state.findings
    ):
        return "secondary_attack"
    return "report"


def edge_after_secondary_v2(state: PentestState) -> str:
    """Secondary 出口：成功 → post；产生凭据 → vuln_scan；产生路径 → surface_enum。"""
    if state.status == TaskStatus.FAILED:
        return "report"
    if state.got_shell:
        return "post_foothold_enum"
    sig = state.replan_signals or {}
    if sig.get("re_vuln_scan_for_creds") and _can_replan(state, "vuln_scan"):
        return _do_replan(state, "vuln_scan", "re_vuln_scan_for_creds")
    if sig.get("re_surface_enum_for_paths") and _can_replan(state, "surface_enum"):
        return _do_replan(state, "surface_enum", "re_surface_enum_for_paths")
    return "report"


def edge_after_post_foothold_enum_v2(state: PentestState) -> str:
    """立足后枚举出口：新主机 → recon；新凭据 → vuln_scan；否则继续 approval。"""
    if state.status == TaskStatus.FAILED:
        return "post_foothold_approval"
    sig = state.replan_signals or {}
    if sig.get("re_recon_for_hosts") and _can_replan(state, "recon"):
        return _do_replan(state, "recon", "re_recon_for_hosts")
    if sig.get("re_vuln_scan_for_creds") and _can_replan(state, "vuln_scan"):
        return _do_replan(state, "vuln_scan", "re_vuln_scan_for_creds")
    if sig.get("re_surface_enum_for_paths") and _can_replan(state, "surface_enum"):
        return _do_replan(state, "surface_enum", "re_surface_enum_for_paths")
    return "post_foothold_approval"


def edge_after_privesc_v2(state: PentestState) -> str:
    """提权出口：到 root / 达上限 / 失败 → objective_collect；产生新凭据 → vuln_scan。"""
    if state.status == TaskStatus.FAILED:
        return "objective_collect"
    pl = (state.privilege_level or "").lower()
    if pl == "root":
        return "objective_collect"
    sig = state.replan_signals or {}
    if sig.get("re_vuln_scan_for_creds") and _can_replan(state, "vuln_scan"):
        return _do_replan(state, "vuln_scan", "re_vuln_scan_for_creds")
    if state.privesc_attempt_count >= state.max_privesc_rounds:
        return "objective_collect"
    return "privesc_again"



_LINEAR_ENTRY_PHASES: set[str] = {
    "recon", "surface_enum", "intel_harvest", "vuln_scan",
    "exploit_decision", "foothold_attempt", "secondary_attack",
    "post_foothold_enum", "internal_scan", "privesc_attempt",
    "lateral_movement", "persistence", "objective_collect",
}


def edge_initial_route(state: PentestState) -> str:
    """linear / feedback 模式下的"入口 plan-aware 路由"。

    没有 ``state.operator_plan`` 时维持历史行为(START → recon)。一旦
    Operator Replanner 给出了带 ``next_phase`` 的结构化计划, 这里直接把
    新分支送到目标阶段, 并在 plan.consumed_by 上打标避免后续每次 START
    都重复同样的跳转。

    与 supervisor 模式的区别:
      - supervisor 模式有专用 supervisor 节点反复读 plan 路由
      - linear / feedback 没有 supervisor, plan 只在 START 这一跳生效;
        之后仍按 DAG 推进, plan 的 ``preferred_tools`` / ``focus_targets``
        等战术字段由各阶段节点自行消费
    """
    plan = getattr(state, "operator_plan", None)
    if plan is not None and "linear_entry" not in (
        getattr(plan, "consumed_by", None) or []
    ):
        nxt = (plan.next_phase or "").strip()
        if not nxt and getattr(plan, "rerun_current", False):
            nxt = (plan.source_phase or "").strip()
        if nxt in _LINEAR_ENTRY_PHASES:
            consumed = list(getattr(plan, "consumed_by", None) or [])
            consumed.append("linear_entry")
            try:
                plan.consumed_by = consumed
            except Exception:
                pass
            try:
                state.push_decision({
                    "action": "operator_plan_routed",
                    "phase": nxt,
                    "message": f"按操作员重规划路由到 {nxt}",
                    "thinking": (
                        f"linear_entry: 检测到 operator_plan(plan_id="
                        f"{getattr(plan, 'plan_id', '')}), next_phase="
                        f"{plan.next_phase!r}, 直接跳过 START → recon 默认链"
                    ),
                    "purpose": "operator plan 入口路由",
                    "tone": "primary",
                })
            except Exception:
                pass
            return nxt
    return "recon"


def build_graph(checkpointer=None):
    """根据 ATTACK_CHAIN_MODE 分发到对应的图构造器。

    - ``linear``    — 默认；与历史行为完全一致；
    - ``feedback``  — 在 secondary_attack / post_foothold_enum / privesc_attempt
                      出口加条件回流边；
    - ``supervisor``— 星形拓扑，全部节点回 supervisor 决定下一步。
    """
    mode = _current_chain_mode()
    logger.info("[Orchestrator] ATTACK_CHAIN_MODE=%s", mode)
    if mode == "supervisor":
        return _build_graph_supervisor(checkpointer)
    if mode == "feedback":
        return _build_graph_feedback(checkpointer)
    return _build_graph_linear(checkpointer)


def _build_graph_linear(checkpointer=None):
    graph = StateGraph(PentestState)

    graph.add_node("recon",               node_recon)
    graph.add_node("vuln_scan",           node_vuln_scan)
    graph.add_node("surface_enum",        node_surface_enum)
    graph.add_node("intel_harvest",       node_intel_harvest)
    graph.add_node("exploit_decision",    node_exploit_decision)
    graph.add_node("human_approval",      node_human_approval)
    graph.add_node("foothold_attempt",    node_foothold_attempt)
    graph.add_node("secondary_attack",    node_secondary_attack)
    graph.add_node("post_foothold_enum",  node_post_foothold_enum)
    graph.add_node("internal_scan",       node_internal_scan)
    graph.add_node("privesc_attempt",     node_privesc_attempt)
    graph.add_node("lateral_movement",    node_lateral_movement)
    graph.add_node("persistence",         node_persistence)
    graph.add_node("objective_collect",   node_objective_collect)
    graph.add_node("report",              node_report)

    graph.add_conditional_edges(
        START, edge_initial_route,
        {
            "recon":              "recon",
            "surface_enum":       "surface_enum",
            "intel_harvest":      "intel_harvest",
            "vuln_scan":          "vuln_scan",
            "exploit_decision":   "exploit_decision",
            "foothold_attempt":   "foothold_attempt",
            "secondary_attack":   "secondary_attack",
            "post_foothold_enum": "post_foothold_enum",
            "internal_scan":      "internal_scan",
            "privesc_attempt":    "privesc_attempt",
            "lateral_movement":   "lateral_movement",
            "persistence":        "persistence",
            "objective_collect":  "objective_collect",
        },
    )
    _PLAN_FWD_TARGETS_RECON = {
        "surface_enum": "surface_enum", "intel_harvest": "intel_harvest",
        "vuln_scan": "vuln_scan", "exploit_decision": "exploit_decision",
    }
    _PLAN_FWD_TARGETS_SURF = {
        "intel_harvest": "intel_harvest",
        "vuln_scan": "vuln_scan", "exploit_decision": "exploit_decision",
    }
    _PLAN_FWD_TARGETS_INTEL = {
        "vuln_scan": "vuln_scan", "exploit_decision": "exploit_decision",
    }
    graph.add_conditional_edges("recon", _edge_after_recon, _PLAN_FWD_TARGETS_RECON)
    graph.add_conditional_edges("surface_enum", _edge_after_surface_enum, _PLAN_FWD_TARGETS_SURF)
    graph.add_conditional_edges("intel_harvest", _edge_after_intel_harvest, _PLAN_FWD_TARGETS_INTEL)
    graph.add_edge("vuln_scan", "exploit_decision")
    graph.add_conditional_edges(
        "exploit_decision", edge_should_exploit,
        {
            "human_approval": "human_approval",
            "foothold_attempt": "foothold_attempt",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "human_approval", edge_after_approval,
        {"foothold_attempt": "foothold_attempt", "report": "report"},
    )
    graph.add_conditional_edges(
        "foothold_attempt", edge_after_foothold,
        {
            "post_foothold_enum": "post_foothold_enum",
            "secondary_attack": "secondary_attack",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "secondary_attack", edge_after_secondary,
        {"post_foothold_enum": "post_foothold_enum", "report": "report"},
    )
    graph.add_node("post_foothold_approval", node_post_foothold_approval)
    graph.add_edge("post_foothold_enum", "post_foothold_approval")
    graph.add_conditional_edges(
        "post_foothold_approval", edge_after_post_foothold_approval,
        {"internal_scan": "internal_scan", "objective_collect": "objective_collect"},
    )
    graph.add_edge("internal_scan", "privesc_attempt")
    graph.add_conditional_edges(
        "privesc_attempt", edge_after_privesc,
        {
            "lateral_movement": "lateral_movement",
            "privesc_again": "privesc_attempt",
            "objective_collect": "objective_collect",
        },
    )
    graph.add_edge("lateral_movement", "persistence")
    graph.add_edge("persistence", "objective_collect")
    graph.add_edge("objective_collect", "report")
    graph.add_edge("report", END)

    return graph.compile(
        checkpointer=checkpointer,
        interrupt_before=["human_approval", "post_foothold_approval"],
    )


def _build_graph_feedback(checkpointer=None):
    """Feedback DAG：在 secondary_attack / post_foothold_enum / privesc_attempt
    出口允许根据 replan_signals 回流到 recon / surface_enum / vuln_scan。

    与 linear 的差别仅在 4 条 conditional_edges 的目标集合。审批节点保持不变，
    但反馈循环回流到 vuln_scan/surface_enum/recon 时不再经过 human_approval（因为
    审批针对的是 exploit 决策，不针对前置阶段的重跑）。
    """
    graph = StateGraph(PentestState)

    graph.add_node("recon",               node_recon)
    graph.add_node("vuln_scan",           node_vuln_scan)
    graph.add_node("surface_enum",        node_surface_enum)
    graph.add_node("intel_harvest",       node_intel_harvest)
    graph.add_node("exploit_decision",    node_exploit_decision)
    graph.add_node("human_approval",      node_human_approval)
    graph.add_node("foothold_attempt",    node_foothold_attempt)
    graph.add_node("secondary_attack",    node_secondary_attack)
    graph.add_node("post_foothold_enum",  node_post_foothold_enum)
    graph.add_node("post_foothold_approval", node_post_foothold_approval)
    graph.add_node("internal_scan",       node_internal_scan)
    graph.add_node("privesc_attempt",     node_privesc_attempt)
    graph.add_node("lateral_movement",    node_lateral_movement)
    graph.add_node("persistence",         node_persistence)
    graph.add_node("objective_collect",   node_objective_collect)
    graph.add_node("report",              node_report)

    graph.add_conditional_edges(
        START, edge_initial_route,
        {
            "recon":              "recon",
            "surface_enum":       "surface_enum",
            "intel_harvest":      "intel_harvest",
            "vuln_scan":          "vuln_scan",
            "exploit_decision":   "exploit_decision",
            "foothold_attempt":   "foothold_attempt",
            "secondary_attack":   "secondary_attack",
            "post_foothold_enum": "post_foothold_enum",
            "internal_scan":      "internal_scan",
            "privesc_attempt":    "privesc_attempt",
            "lateral_movement":   "lateral_movement",
            "persistence":        "persistence",
            "objective_collect":  "objective_collect",
        },
    )
    graph.add_conditional_edges("recon", _edge_after_recon, {
        "surface_enum": "surface_enum", "intel_harvest": "intel_harvest",
        "vuln_scan": "vuln_scan", "exploit_decision": "exploit_decision",
    })
    graph.add_conditional_edges("surface_enum", _edge_after_surface_enum, {
        "intel_harvest": "intel_harvest",
        "vuln_scan": "vuln_scan", "exploit_decision": "exploit_decision",
    })
    graph.add_conditional_edges("intel_harvest", _edge_after_intel_harvest, {
        "vuln_scan": "vuln_scan", "exploit_decision": "exploit_decision",
    })
    graph.add_edge("vuln_scan", "exploit_decision")

    graph.add_conditional_edges(
        "exploit_decision", edge_should_exploit,
        {
            "human_approval": "human_approval",
            "foothold_attempt": "foothold_attempt",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "human_approval", edge_after_approval,
        {"foothold_attempt": "foothold_attempt", "report": "report"},
    )

    graph.add_conditional_edges(
        "foothold_attempt", edge_after_foothold_v2,
        {
            "post_foothold_enum": "post_foothold_enum",
            "secondary_attack": "secondary_attack",
            "vuln_scan": "vuln_scan",
            "surface_enum": "surface_enum",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "secondary_attack", edge_after_secondary_v2,
        {
            "post_foothold_enum": "post_foothold_enum",
            "vuln_scan": "vuln_scan",
            "surface_enum": "surface_enum",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "post_foothold_enum", edge_after_post_foothold_enum_v2,
        {
            "post_foothold_approval": "post_foothold_approval",
            "recon": "recon",
            "vuln_scan": "vuln_scan",
            "surface_enum": "surface_enum",
        },
    )
    graph.add_conditional_edges(
        "post_foothold_approval", edge_after_post_foothold_approval,
        {"internal_scan": "internal_scan", "objective_collect": "objective_collect"},
    )
    graph.add_edge("internal_scan", "privesc_attempt")
    graph.add_conditional_edges(
        "privesc_attempt", edge_after_privesc_v2,
        {
            "lateral_movement": "lateral_movement",
            "privesc_again": "privesc_attempt",
            "vuln_scan": "vuln_scan",
            "objective_collect": "objective_collect",
        },
    )
    graph.add_edge("lateral_movement", "persistence")
    graph.add_edge("persistence", "objective_collect")
    graph.add_edge("objective_collect", "report")
    graph.add_edge("report", END)

    return graph.compile(
        checkpointer=checkpointer,
        interrupt_before=["human_approval", "post_foothold_approval"],
    )


def _build_graph_supervisor(checkpointer=None):
    """Supervisor 模式：星形拓扑。

    所有阶段执行完毕后都返回 supervisor，由 supervisor 路由到下一阶段。
    interrupt_before 仍保留 human_approval / post_foothold_approval，但靠
    state.approved_once / post_approved_once 防止反复在审批门暂停。
    """
    from backend.agents.supervisor import (
        node_supervisor,
        supervisor_route,
    )

    graph = StateGraph(PentestState)

    graph.add_node("supervisor",          node_supervisor)
    graph.add_node("recon",               node_recon)
    graph.add_node("vuln_scan",           node_vuln_scan)
    graph.add_node("surface_enum",        node_surface_enum)
    graph.add_node("intel_harvest",       node_intel_harvest)
    graph.add_node("exploit_decision",    node_exploit_decision)
    graph.add_node("human_approval",      node_human_approval)
    graph.add_node("foothold_attempt",    node_foothold_attempt)
    graph.add_node("secondary_attack",    node_secondary_attack)
    graph.add_node("post_foothold_enum",  node_post_foothold_enum)
    graph.add_node("post_foothold_approval", node_post_foothold_approval)
    graph.add_node("internal_scan",       node_internal_scan)
    graph.add_node("privesc_attempt",     node_privesc_attempt)
    graph.add_node("lateral_movement",    node_lateral_movement)
    graph.add_node("persistence",         node_persistence)
    graph.add_node("objective_collect",   node_objective_collect)
    graph.add_node("report",              node_report)

    graph.add_edge(START, "supervisor")

    PHASE_NODES = [
        "recon", "surface_enum", "intel_harvest", "vuln_scan",
        "exploit_decision", "human_approval", "foothold_attempt",
        "secondary_attack", "post_foothold_enum", "post_foothold_approval",
        "internal_scan", "privesc_attempt", "lateral_movement",
        "persistence", "objective_collect",
    ]
    for p in PHASE_NODES:
        graph.add_edge(p, "supervisor")
    graph.add_edge("report", END)

    routing = {p: p for p in PHASE_NODES + ["report"]}
    graph.add_conditional_edges("supervisor", supervisor_route, routing)

    return graph.compile(
        checkpointer=checkpointer,
        interrupt_before=["human_approval", "post_foothold_approval"],
    )



class Orchestrator:
    def __init__(self):
        self._graph = None
        self._graph_lock = asyncio.Lock()

    async def _ensure_graph(self):
        if self._graph is not None:
            return
        async with self._graph_lock:
            if self._graph is None:
                checkpointer = await self._create_checkpointer()
                self._graph = build_graph(checkpointer=checkpointer)

    @staticmethod
    async def _create_checkpointer():
        """Build a persistent PostgreSQL checkpointer when available,
        falling back to in-memory MemorySaver for local development."""
        pg_url = os.getenv("DATABASE_URL", "")
        if not pg_url:
            logger.info(
                "[Orchestrator] DATABASE_URL 未配置，使用 MemorySaver"
            )
            return MemorySaver()
        if not _HAS_PG_SAVER:
            logger.warning(
                "[Orchestrator] DATABASE_URL 已配置但 psycopg 依赖缺失，"
                "回退到 MemorySaver。请安装: pip install 'psycopg[binary]' psycopg_pool"
            )
            return MemorySaver()
        conninfo = pg_url.replace(
            "postgresql+asyncpg://", "postgresql://"
        )
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            pool = None
            try:
                pool = AsyncConnectionPool(
                    conninfo=conninfo,
                    open=False,
                    kwargs={"autocommit": True},
                )
                await pool.open()
                saver = AsyncPostgresSaver(pool)
                await saver.setup()
                logger.info("[Orchestrator] 使用 PostgreSQL 持久化 checkpointer")
                return saver
            except Exception as exc:
                logger.warning(
                    "[Orchestrator] PostgreSQL checkpointer 连接失败 "
                    "(第 %d/%d 次): %s", attempt, max_retries, exc,
                )
                if pool is not None:
                    try:
                        await pool.close()
                    except Exception:
                        pass
                if attempt < max_retries:
                    await asyncio.sleep(2.0 * attempt)
        logger.error(
            "[Orchestrator] PostgreSQL checkpointer %d 次重试均失败，回退到 MemorySaver",
            max_retries,
        )
        return MemorySaver()

    def _prepare_state(self, initial_state: PentestState) -> PentestState:
        """
        对 Router 已构造好的 initial_state 做最后一次统一预处理:
          - 确保 task_id 存在
          - 解析 target 结构化信息
          - 记录启动日志,回显 workflow_mode 与关键策略字段
        不再读取任何 OPERATOR_ROLE/SUCCESS_GATE/RISK_BUDGET 环境变量。
        """
        if not initial_state.task_id:
            initial_state.task_id = str(uuid.uuid4())
        _apply_parsed_target(initial_state)
        initial_state.log(
            f"workflow_mode={initial_state.workflow_mode}, "
            f"auto_approve={initial_state.auto_approve}, "
            f"gate={initial_state.success_gate_level}, "
            f"risk_budget={initial_state.risk_budget}, "
            f"react_rounds={initial_state.max_react_rounds}, "
            f"explore_rounds={initial_state.max_explore_rounds}"
        )
        _intent_to_operator_plan(initial_state)
        return initial_state

    async def run(
        self, initial_state: PentestState, thread_id: Optional[str] = None,
    ) -> PentestState:
        await self._ensure_graph()
        initial_state = self._prepare_state(initial_state)
        config = self._make_run_config(thread_id or initial_state.task_id)
        initial_state.log(f"任务启动,目标: {initial_state.target}")
        try:
            final_state: PentestState = await asyncio.wait_for(
                self._graph.ainvoke(initial_state, config=config),
                timeout=TASK_TIMEOUT,
            )
        except asyncio.TimeoutError:
            initial_state.status = TaskStatus.FAILED
            initial_state.error_msg = f"任务超时(>{TASK_TIMEOUT}s)"
            initial_state.log(initial_state.error_msg)
            try:
                from backend.tools.executor import TaskContainerManager
                await TaskContainerManager.stop(initial_state.task_id)
                initial_state.log("超时后容器已清理")
            except Exception:
                pass
            return initial_state
        return final_state

    async def run_stream(
        self, initial_state: PentestState, thread_id: Optional[str] = None,
    ):
        await self._ensure_graph()
        initial_state = self._prepare_state(initial_state)
        config = self._make_run_config(thread_id or initial_state.task_id)

        async for event in self._graph.astream(initial_state, config=config):
            for node_name, state in event.items():
                yield node_name, state

    async def resume(
        self, task_id: str, approved: bool = True,
        thread_id: Optional[str] = None,
    ) -> None:
        await self._ensure_graph()
        config = self._make_run_config(thread_id or task_id)
        update = await self._build_approval_update(config, approved)
        await self._graph.aupdate_state(config, update)
        await self._graph.ainvoke(None, config=config)

    async def resume_stream(
        self, task_id: str, approved: bool = True,
        thread_id: Optional[str] = None,
    ):
        """
        流式恢复执行（审批后继续 exploit → post → report）。

        与 resume() 的区别：用 astream 代替 ainvoke，
        每个节点完成后 yield 状态更新，供 API 层实时推送。

        ``thread_id`` 默认 = task_id; 分支模式传 branch.thread_id。
        """
        await self._ensure_graph()
        config = self._make_run_config(thread_id or task_id)
        update = await self._build_approval_update(config, approved)
        await self._graph.aupdate_state(config, update)

        async for event in self._graph.astream(None, config=config):
            for node_name, state in event.items():
                yield node_name, state

    async def resume_branch(
        self,
        thread_id: str,
        *,
        patch: Optional[dict[str, Any]] = None,
    ) -> None:
        """Resume a *branch* thread without touching approval gates.

        Unlike :meth:`resume`, this does not write ``approved`` / ``post_approved``;
        it just optionally applies ``patch`` (e.g. injecting ``pending_user_prompt``
        or ``replan_signals``) and then invokes the graph to step through the
        remaining nodes.
        """
        await self._ensure_graph()
        config = self._make_run_config(thread_id)
        if patch:
            await self._graph.aupdate_state(config, patch)
        await self._graph.ainvoke(None, config=config)

    async def resume_branch_stream(
        self,
        thread_id: str,
        *,
        patch: Optional[dict[str, Any]] = None,
    ):
        """Streaming variant of ``resume_branch``."""
        await self._ensure_graph()
        config = self._make_run_config(thread_id)
        if patch:
            await self._graph.aupdate_state(config, patch)
        async for event in self._graph.astream(None, config=config):
            for node_name, state in event.items():
                yield node_name, state

    async def get_branch_state(self, thread_id: str) -> Optional[PentestState]:
        """Read PentestState from a specific LangGraph thread/checkpoint."""
        await self._ensure_graph()
        config = {"configurable": {"thread_id": thread_id}}
        snapshot = await self._graph.aget_state(config)
        if snapshot and snapshot.values:
            try:
                return PentestState(**snapshot.values)
            except Exception:
                return None
        return None

    async def fork_branch_state(
        self,
        *,
        source_thread_id: str,
        target_thread_id: str,
        patch: dict[str, Any],
        as_node: Optional[str] = None,
        source_checkpoint_id: Optional[str] = None,
    ) -> bool:
        """Copy a checkpoint of *source_thread_id* into *target_thread_id*
        and apply ``patch`` (e.g. ``pending_user_prompt`` / ``replan_signals``).

        ``source_checkpoint_id`` 可选: 指定从历史里某个具体 checkpoint 复制
        (Claude 风格"从任意历史节点分叉"); 不传时退化为复制最新 checkpoint
        (沿用旧 ``fork_from_active`` 的行为)。

        Returns True on success, False if the source thread has no matching
        checkpoint (例如指定了 checkpoint_id 但被裁剪了 / 源 thread 还没跑过
        任何节点)。
        """
        await self._ensure_graph()
        src_cfg: dict[str, Any]
        if source_checkpoint_id:
            src_cfg = {
                "configurable": {
                    "thread_id": source_thread_id,
                    "checkpoint_id": source_checkpoint_id,
                }
            }
        else:
            src_cfg = {"configurable": {"thread_id": source_thread_id}}
        snap = await self._graph.aget_state(src_cfg)
        if not snap or not snap.values:
            return False

        try:
            base = dict(snap.values)
        except Exception:
            base = {}
        merged = dict(base)
        for k, v in (patch or {}).items():
            merged[k] = v

        effective_as_node = as_node
        if not effective_as_node:
            try:
                meta = snap.metadata or {}
                writes = meta.get("writes") if isinstance(meta, dict) else None
                if isinstance(writes, dict) and writes:
                    effective_as_node = list(writes.keys())[-1]
            except Exception as _exc:
                logger.debug(
                    f"[Orchestrator] fork_branch_state: extract as_node "
                    f"failed: {_exc}"
                )

        dst_cfg = {"configurable": {"thread_id": target_thread_id}}
        if effective_as_node:
            await self._graph.aupdate_state(
                dst_cfg, merged, as_node=effective_as_node,
            )
        else:
            await self._graph.aupdate_state(dst_cfg, merged)
        return True

    async def find_checkpoint_at_or_before(
        self, source_thread_id: str, ts_iso: str,
    ) -> Optional[str]:
        """在 *source_thread_id* 的历史里找出 ``created_at <= ts_iso`` 的
        最新 checkpoint id, 用于"从某条历史 decision_event 处分叉"。

        decision_event 没有直接挂在某个 LangGraph checkpoint 上(事件可能
        在节点中途产生), 取"事件时间之前最近一次 checkpoint"作为最贴近
        用户期望的快照。找不到时返回 None, 调用方应回落到 ``fork_from_active``
        语义(从最新 checkpoint 分叉)。
        """
        await self._ensure_graph()
        cfg = {"configurable": {"thread_id": source_thread_id}}
        try:
            history = self._graph.aget_state_history(cfg)
        except Exception as exc:
            logger.warning(
                f"[Orchestrator] aget_state_history 失败 thread={source_thread_id}: {exc}"
            )
            return None
        try:
            async for snap in history:
                created = getattr(snap, "created_at", "") or ""
                if not created:
                    continue
                if created <= ts_iso:
                    cfg_part = (snap.config or {}).get("configurable", {}) or {}
                    cp_id = cfg_part.get("checkpoint_id")
                    if cp_id:
                        return str(cp_id)
        except Exception as exc:
            logger.warning(
                f"[Orchestrator] iterate state history 失败 thread={source_thread_id}: {exc}"
            )
        return None

    @staticmethod
    def _make_run_config(task_id: str) -> dict:
        """Build LangGraph run config with mode-aware recursion_limit.

        - linear   : 25 (LangGraph 默认即可)
        - feedback : 100  (容纳 max_replan * 阶段数)
        - supervisor: 200 (星形拓扑步数翻倍)
        """
        mode = _current_chain_mode()
        if mode == "supervisor":
            limit = 200
        elif mode == "feedback":
            limit = 100
        else:
            limit = 50
        return {
            "configurable": {"thread_id": task_id},
            "recursion_limit": limit,
        }

    async def _build_approval_update(self, config: dict, approved: bool) -> dict:
        """Return the correct state patch depending on which gate is pending."""
        snapshot = await self._graph.aget_state(config)
        phase = ""
        if snapshot and snapshot.values:
            phase = snapshot.values.get("current_phase", "")
        if phase == "post_foothold_approval":
            return {"post_approved": approved}
        return {"approved": approved}

    async def get_state(
        self, task_id: str, thread_id: Optional[str] = None,
    ) -> Optional[PentestState]:
        await self._ensure_graph()
        config = {"configurable": {"thread_id": thread_id or task_id}}
        snapshot = await self._graph.aget_state(config)
        if snapshot and snapshot.values:
            try:
                return PentestState(**snapshot.values)
            except Exception:
                return None
        return None



def _stringify_dict_keys(obj: Any) -> Any:
    """
    递归将 dict 的所有 key 转为 str。

    LangGraph checkpointer（MemorySaver/PostgresSaver）序列化 checkpoint，
    msgpack 默认 strict_map_key=True 不允许 int/float 作为 dict key。
    VulnAgent 的 fingerprints 用端口号(int)做 key，必须转换。
    """
    if isinstance(obj, dict):
        return {str(k): _stringify_dict_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_stringify_dict_keys(item) for item in obj]
    return obj


def _infer_os(ports: list[PortInfo], os_info: dict) -> str:
    open_ports = [p for p in ports if p.state == "open"]
    port_nums = {p.port for p in open_ports}
    linux_signs = port_nums & {22, 111, 2049}
    windows_signs = port_nums & {135, 139, 445, 3389, 5985}

    port_guess = "unknown"
    if linux_signs and not windows_signs:
        port_guess = "linux"
    elif windows_signs and not linux_signs:
        port_guess = "windows"

    service_guess = "unknown"
    for p in open_ports:
        combined = f"{p.service} {p.version} {p.banner}".lower()
        if any(k in combined for k in ["apache", "nginx", "openssh", "ubuntu", "debian"]):
            service_guess = "linux"
            break
        if any(k in combined for k in ["microsoft", "iis", "windows"]):
            service_guess = "windows"
            break

    nmap_guess = "unknown"
    if os_info.get("os_type") and os_info["os_type"] != "unknown":
        if int(os_info.get("accuracy", 0)) >= 90:
            return os_info["os_type"].lower()
        nmap_guess = os_info["os_type"].lower()

    for guess in [service_guess, port_guess, nmap_guess]:
        if guess != "unknown":
            return guess
    return "unknown"


def _build_exploit_decision_prompt(state: PentestState) -> str:
    from backend.llm.prompts.templates import EXPLOIT_DECISION
    findings_json = json.dumps(
        [f.model_dump() for f in state.findings if f.exploitable],
        ensure_ascii=False, indent=2,
    )
    ports_json = json.dumps(
        [p.model_dump() for p in state.open_ports[:20] if p.state == "open"],
        ensure_ascii=False,
    )
    dir_intel = state.dir_intel or _build_dir_intel(state)
    dir_intel_json = json.dumps(dir_intel, ensure_ascii=False, indent=2)
    base_prompt = EXPLOIT_DECISION.format(
        target=state.target,
        target_os=state.target_os,
        ports_json=ports_json,
        findings_json=findings_json,
        dir_intel_json=dir_intel_json,
    )
    extras: list[str] = []
    if state.workflow_mode and state.workflow_mode != "standard":
        extras.append(f"任务模式: {state.workflow_mode}")
    if state.extra_hint:
        extras.append(f"用户附加提示: {state.extra_hint}")
    if state.user_prompt:
        extras.append(f"用户偏好: {state.user_prompt}")
    op_chat = _operator_chat_block(state)
    if op_chat:
        extras.append(op_chat)
    if extras:
        base_prompt += "\n\n【补充上下文】\n" + "\n".join(extras)
    return base_prompt