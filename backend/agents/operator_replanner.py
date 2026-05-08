"""operator_replanner.py — 把"操作员的一句话"翻译成结构化战术计划。

设计目标
--------
1. **一次 LLM 调用** 把 ``state.pending_user_prompt`` + ``state.user_messages``
   连同当前事实快照, 转化为 :class:`OperatorPlan` 对象, 既给 supervisor 路由
   决策用, 也给阶段节点的 planner / tool 选择用。
2. **失败可降级**: LLM 抛异常或 JSON 解析失败时, ``_fallback_plan`` 永远返回一
   份合法的 plan(只携带原始用户文本 + ``rerun_current=True``), 保证流水线不
   会因为重规划失败而卡死。
3. **白名单约束**: ``next_phase`` 必须落在合法阶段集; 不在集合里的就丢弃。

调用点
------
- ``BranchManager.fork_from_active``  在 chat 触发 fork 时 *同步* 调一次,
  把 plan 写进新分支的 LangGraph checkpoint, 同时推 decision_event 让前端
  在 1~3 秒内渲染"已重规划"卡片。
- 后续节点入口(后续 PR)可以再调一次以应对"分支已经在跑、用户又追了一句"
  的场景, 但 P0 先只在 fork 处接入。
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Optional

from backend.agents.models import OperatorPlan, OperatorFocusTarget, PentestState
from backend.agents.prompt_utils import operator_guidance_block

logger = logging.getLogger(__name__)


ALLOWED_PHASES: set[str] = {
    "recon", "surface_enum", "intel_harvest", "vuln_scan",
    "exploit_decision", "human_approval", "foothold_attempt",
    "secondary_attack", "post_foothold_enum", "post_foothold_approval",
    "privesc_attempt", "objective_collect", "report",
}

KNOWN_TOOLS: set[str] = {
    "gobuster", "ffuf", "feroxbuster", "dirsearch", "wfuzz",
    "nuclei", "nikto", "hydra", "sqlmap", "nmap", "masscan",
    "whatweb", "httpx", "curl", "wget",
    "metasploit", "msfconsole", "exploit-db", "searchsploit",
    "john", "hashcat", "crackmapexec", "smbclient",
    "burpsuite", "zaproxy",
}



REPLAN_SYSTEM_PROMPT = """你是 PentestAI 的实时战术重规划器(Operator Replanner)。

任务: 把用户在任务执行过程中给出的新指令, 结合当前任务事实, 翻译成一份
**结构化战术计划**, 让下游确定性节点(supervisor / 各阶段节点 / Tool planner)
直接据此执行, 而不是各自再去解读用户原话一遍。

【硬性约束】
1. 输出**严格 JSON**, 字段名遵循 schema, 禁止 markdown 代码块或额外说明。
2. 安全护栏(human_approval / risk_budget)默认保留; 只有用户明确"我授权直接打"
   "跳过审批"等表述才能把 needs_human_approval 设为 false。
3. preferred_tools 优先从这些工具里挑(更安全): gobuster, ffuf, feroxbuster,
   dirsearch, wfuzz, nuclei, nikto, hydra, sqlmap, nmap, masscan, whatweb,
   httpx, curl, metasploit。
4. next_phase 必须在以下集合内, 否则置空:
   recon, surface_enum, intel_harvest, vuln_scan, exploit_decision,
   human_approval, foothold_attempt, secondary_attack, post_foothold_enum,
   post_foothold_approval, privesc_attempt, objective_collect, report。
5. focus_targets 用 [{"type":"port|path|host|service|cve","value":"..."}, ...]
   表示, 可省略, 但只要有就要类型 + 值都填齐。
6. intent_summary 用一句中文回放你听到的核心意图(不要复述用户原话, 不超过 80 字)。
7. rationale 解释为什么这么规划, 2~4 句。

【输出 schema】
{
  "intent_summary": str,
  "rationale": str,
  "next_phase": str | null,
  "target_phases": [str, ...],
  "skip_phases": [str, ...],
  "rerun_current": bool,
  "focus_targets": [{"type": str, "value": str}, ...],
  "preferred_tools": [str, ...],
  "avoided_tools": [str, ...],
  "keyword_hints": [str, ...],
  "extra_constraints": {"time_budget_sec": int?, "max_depth": int?},
  "needs_human_approval": bool
}

【小例子】
用户说"重点排查 80 端口下有什么目录, 看看有没有敏感文件"且当前阶段是 recon:
{
  "intent_summary": "聚焦 80 端口 Web 目录与敏感文件枚举",
  "rationale": "用户希望立即收敛 Web 攻击面; recon 已经识别了 80 端口, 应当推进到 surface_enum 并以目录/敏感文件爆破为主线",
  "next_phase": "surface_enum",
  "target_phases": ["surface_enum", "intel_harvest"],
  "skip_phases": [],
  "rerun_current": false,
  "focus_targets": [{"type": "port", "value": "80"}],
  "preferred_tools": ["gobuster", "ffuf", "feroxbuster"],
  "avoided_tools": [],
  "keyword_hints": ["admin", "backup", ".env", "config", "phpinfo"],
  "extra_constraints": {"max_depth": 3},
  "needs_human_approval": true
}"""




def _summarize_state(state: PentestState) -> dict[str, Any]:
    """提炼一份给 LLM 看的事实快照(避免把整个 state 塞进 prompt)。"""
    findings_brief: list[dict[str, Any]] = []
    for f in (state.findings or [])[:8]:
        findings_brief.append({
            "vuln_id": getattr(f, "vuln_id", ""),
            "name": getattr(f, "name", ""),
            "severity": getattr(f, "severity", ""),
            "cve": getattr(f, "cve", "") or "",
            "exploitable": bool(getattr(f, "exploitable", False)),
            "verification_status": getattr(f, "verification_status", ""),
        })
    open_ports = [
        f"{p.port}/{p.service}" if p.service else str(p.port)
        for p in (state.open_ports or [])[:20]
        if p.state == "open"
    ]
    web_paths_top = list((state.web_paths or [])[:20])
    return {
        "current_phase": state.current_phase or "",
        "target": state.target or "",
        "target_host": state.target_host or "",
        "open_ports": open_ports,
        "web_paths_top": web_paths_top,
        "web_paths_total": len(state.web_paths or []),
        "findings": findings_brief,
        "got_shell": bool(state.got_shell),
        "privilege_level": state.privilege_level or "",
        "phase_visit_count": dict(state.phase_visit_count or {}),
        "supervisor_history_tail": list((state.supervisor_history or [])[-5:]),
        "credentials_count": len(state.credential_store or []),
        "approved_once": bool(state.approved_once),
        "post_approved_once": bool(state.post_approved_once),
        "auto_approve": bool(state.auto_approve),
        "workflow_mode": state.workflow_mode,
    }


def _build_user_prompt(state: PentestState, op_block: str) -> str:
    facts = _summarize_state(state)
    return (
        "## 当前任务事实快照\n"
        + json.dumps(facts, ensure_ascii=False, indent=2)
        + "\n\n## 用户最新指令(最高优先级)\n"
        + (op_block.strip() or "(空)")
        + "\n\n请输出 OperatorPlan JSON, 严格遵循 schema, 不要包含 markdown 代码块。"
    )


def _derive_signals(plan: OperatorPlan, state: PentestState) -> dict[str, int]:
    """把 plan 里的"我想干什么"翻译成 ``replan_signals`` 桶, 让 feedback DAG /
    阶段节点的 ``_consume_replan_signal`` 链路天然复用现有重入通路。
    """
    sig: dict[str, int] = {}
    cur = state.current_phase or ""
    if plan.rerun_current and cur:
        sig[f"re_{cur}_for_operator"] = 1
    for ph in (plan.target_phases or []):
        sig[f"target_{ph}"] = 1

    target_types = {
        t.type for t in (plan.focus_targets or []) if isinstance(t, OperatorFocusTarget)
    }
    if "port" in target_types:
        sig["re_surface_enum_for_paths"] = 1
    if "path" in target_types:
        sig["re_intel_harvest_for_paths"] = 1
    if "host" in target_types:
        sig["re_recon_for_hosts"] = 1
    if {"cve", "service"} & target_types:
        sig["re_vuln_scan_for_ports"] = 1

    return sig


def _validate_plan(raw: dict[str, Any], state: PentestState, op_block: str) -> OperatorPlan:
    """把 LLM 原始输出约束到合法范围内, 越界字段一律剔除。"""
    next_phase = raw.get("next_phase") or None
    if next_phase and next_phase not in ALLOWED_PHASES:
        logger.info("[Replanner] 丢弃非法 next_phase=%r", next_phase)
        next_phase = None

    target_phases = [
        p for p in (raw.get("target_phases") or [])
        if isinstance(p, str) and p in ALLOWED_PHASES
    ][:6]
    skip_phases = [
        p for p in (raw.get("skip_phases") or [])
        if isinstance(p, str) and p in ALLOWED_PHASES
    ][:6]

    focus_targets: list[OperatorFocusTarget] = []
    for t in (raw.get("focus_targets") or []):
        if not isinstance(t, dict):
            continue
        ttype = str(t.get("type", "")).strip().lower()
        tval = str(t.get("value", "")).strip()
        if ttype and tval:
            focus_targets.append(OperatorFocusTarget(type=ttype, value=tval))
    focus_targets = focus_targets[:12]

    def _str_list(key: str, limit: int) -> list[str]:
        out: list[str] = []
        for x in (raw.get(key) or [])[:limit]:
            s = str(x).strip()
            if s:
                out.append(s)
        return out

    plan = OperatorPlan(
        plan_id=uuid.uuid4().hex[:8],
        created_at=datetime.utcnow().isoformat(),
        user_request=op_block[:2000],
        source_phase=state.current_phase or "",
        intent_summary=str(raw.get("intent_summary") or "").strip()[:300],
        rationale=str(raw.get("rationale") or "").strip()[:1200],
        next_phase=next_phase,
        target_phases=target_phases,
        skip_phases=skip_phases,
        rerun_current=bool(raw.get("rerun_current", False)),
        focus_targets=focus_targets,
        preferred_tools=_str_list("preferred_tools", 8),
        avoided_tools=_str_list("avoided_tools", 8),
        keyword_hints=_str_list("keyword_hints", 20),
        extra_constraints=dict(raw.get("extra_constraints") or {}),
        needs_human_approval=bool(raw.get("needs_human_approval", True)),
    )
    plan.derived_replan_signals = _derive_signals(plan, state)

    _needs_ports = {"surface_enum", "vuln_scan", "intel_harvest"}
    has_ports = bool(state.open_ports)
    redirected = False

    if plan.next_phase in _needs_ports and not has_ports:
        original = plan.next_phase
        plan.next_phase = "recon"
        if original not in (plan.target_phases or []):
            plan.target_phases = [original] + list(plan.target_phases or [])
        redirected = True

    cur_phase = (state.current_phase or "").strip()
    if (
        not redirected
        and cur_phase in ("", "init")
        and not has_ports
        and not plan.next_phase
        and not plan.rerun_current
    ):
        plan.next_phase = "recon"
        redirected = True

    if redirected:
        plan.rationale = (
            f"前置数据护栏: open_ports 为空, 必须先完成 recon 才能进入下游阶段。"
            f" 原始规划意图已保留。\n{plan.rationale}"
        )

    return plan


def _extract_raw_user_text(state: PentestState) -> str:
    """从 state 里挑出"原始用户文本"——优先取最后一条 user_message,
    回落到 pending_user_prompt。``operator_guidance_block`` 包了一层带
    header/footer 的 prompt, 不适合直接当 intent_summary 展示给用户。
    """
    msgs = list(getattr(state, "user_messages", None) or [])
    for m in reversed(msgs):
        text = (m.get("text") or "").strip() if isinstance(m, dict) else ""
        if text:
            return text
    return (getattr(state, "pending_user_prompt", "") or "").strip()


def _fallback_plan(
    state: PentestState, op_block: str, *, error: str = ""
) -> OperatorPlan:
    """LLM 不可用时的兜底: 至少把"重跑当前阶段 + 用户原话作为 sticky"落地。

    这条路径保证 ``llm_replan`` 在任何情况下都返回非 ``None`` 的 plan, 上游
    fork 流程不必额外做空指针保护。
    """
    raw_user_text = _extract_raw_user_text(state)
    user_request = (op_block or "").strip()[:2000]
    plan = OperatorPlan(
        plan_id=uuid.uuid4().hex[:8],
        created_at=datetime.utcnow().isoformat(),
        user_request=user_request,
        source_phase=state.current_phase or "",
        intent_summary=(raw_user_text[:120] or "(空指令)"),
        rationale=(
            f"LLM 重规划降级({error or 'unknown'}): "
            f"按用户原话作为最高优先 sticky 指令处理, 当前阶段建议重跑"
        ),
        next_phase=None,
        rerun_current=True,
    )
    plan.derived_replan_signals = _derive_signals(plan, state)
    return plan




async def llm_replan(state: PentestState) -> Optional[OperatorPlan]:
    """根据当前 state 里待消费的操作员指令生成 :class:`OperatorPlan`。

    返回 ``None`` 仅当 ``operator_guidance_block`` 为空 (没有任何待处理的用户
    指令), 此时调用方什么都不用做。
    其它任何错误路径都会通过 :func:`_fallback_plan` 返回**有效 plan**, 上游不
    必再写空保护。
    """
    op_block = operator_guidance_block(state)
    if not op_block:
        return None

    try:
        from backend.llm.router import LLMRouter
    except Exception as exc:
        logger.warning("[Replanner] 无法导入 LLMRouter: %s", exc)
        return _fallback_plan(state, op_block, error="llm_router_import_failed")

    user_prompt = _build_user_prompt(state, op_block)
    raw_text: str = ""
    try:
        llm = LLMRouter()
        result = await llm.chat(
            user_prompt,
            system_prompt=REPLAN_SYSTEM_PROMPT,
            response_format="json",
            temperature=0.2,
            max_tokens=1024,
        )
        raw_text = result[0] if isinstance(result, tuple) else str(result)
        data = json.loads(raw_text)
        if not isinstance(data, dict):
            raise ValueError(f"LLM 返回非 JSON object, type={type(data).__name__}")
        return _validate_plan(data, state, op_block)
    except json.JSONDecodeError as exc:
        logger.warning(
            "[Replanner] JSON 解析失败 err=%s raw=%r",
            exc, (raw_text[:500] if raw_text else None),
        )
        return _fallback_plan(state, op_block, error="json_decode")
    except Exception as exc:
        logger.warning("[Replanner] LLM 调用失败: %s", exc, exc_info=True)
        return _fallback_plan(state, op_block, error=str(exc))


def apply_plan_to_state(state: PentestState, plan: OperatorPlan) -> PentestState:
    """把 ``plan`` 写入 state, 把 derived signals 合并到 ``replan_signals``,
    并消费 ``operator_intent`` 标记 (避免下一节点重复触发同一指令)。
    """
    state.operator_plan = plan
    history = list(state.operator_plan_history or [])
    history.append(plan)
    state.operator_plan_history = history[-20:]

    sig = dict(state.replan_signals or {})
    for k, v in (plan.derived_replan_signals or {}).items():
        sig[k] = max(int(sig.get(k, 0) or 0), int(v or 0))
    sig.pop("operator_intent", None)
    state.replan_signals = sig

    try:
        from backend.agents.interrupt_registry import consume_interrupt
        consume_interrupt(state.task_id)
    except Exception:
        pass
    return state


def plan_to_decision_event(
    plan: OperatorPlan, *, phase: str = "operator_replan",
) -> dict[str, Any]:
    """把 plan 渲染成可推送给前端 timeline 的 decision_event payload。

    前端 ``TaskChat.vue`` 收到 ``action='operator_replan'`` 时按高亮卡片渲染
    (见 P0 同 batch 的前端改动)。
    """
    plan_steps: list[str] = []
    if plan.next_phase:
        plan_steps.append(f"下一阶段: {plan.next_phase}")
    if plan.rerun_current:
        plan_steps.append(
            f"重跑当前阶段: {plan.source_phase or '当前节点'}"
        )
    if plan.target_phases:
        plan_steps.append("阶段序列: " + " → ".join(plan.target_phases))
    if plan.skip_phases:
        plan_steps.append(f"跳过: {', '.join(plan.skip_phases)}")
    if plan.preferred_tools:
        plan_steps.append(f"工具偏好: {', '.join(plan.preferred_tools[:6])}")
    if plan.avoided_tools:
        plan_steps.append(f"禁用工具: {', '.join(plan.avoided_tools[:6])}")
    if plan.focus_targets:
        focus_repr = ", ".join(
            f"{t.type}={t.value}" for t in plan.focus_targets[:6]
        )
        plan_steps.append(f"聚焦目标: {focus_repr}")
    if plan.keyword_hints:
        plan_steps.append(f"关键词: {', '.join(plan.keyword_hints[:6])}")
    if plan.extra_constraints:
        kv = ", ".join(f"{k}={v}" for k, v in plan.extra_constraints.items())
        if kv:
            plan_steps.append(f"约束: {kv}")
    if not plan.needs_human_approval:
        plan_steps.append("用户授权: 跳过人工审批 (auto_approve)")

    return {
        "action": "operator_replan",
        "phase": phase,
        "thinking": plan.rationale or plan.intent_summary,
        "purpose": "操作员实时重规划",
        "plan": plan_steps,
        "message": (
            f"已重规划: {plan.intent_summary}"
            if plan.intent_summary
            else "已重规划"
        ),
        "tone": "primary",
        "operator_plan": plan.model_dump(),
    }
