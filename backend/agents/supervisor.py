"""
supervisor.py — Supervisor 节点 + 路由函数（attack chain mode = supervisor）

设计要点：
  1. 规则优先 + LLM 兜底：``_rule_decide`` 走完后若仍未给出明确动作再
     调用 ``_llm_decide``，避免每跳都烧 token。
  2. 收敛保护：``state.supervisor_round_limit``（默认 30），到达上限直接
     强制 ``report``；连续 3 轮选同一个 phase 且无新 fact 也强制 ``report``。
  3. 写入 supervisor_history（限长），既给 LLM 兜底当上下文，也给前端
     可视化攻击图所需的"路由轨迹"。
  4. 不直接修改图结构：图构造在 orchestrator._build_graph_supervisor，
     这里只暴露 ``node_supervisor`` 与 ``supervisor_route``。
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from backend.agents.fact_hooks import (
    compute_phase_signature,
    consume_replan_context as _consume_replan_context,
    consume_replan_signal as _consume_replan_signal,
    push_pending_seed as _push_pending_seed,
    snapshot_facts,
)
from backend.agents.models import PentestState, TaskStatus

logger = logging.getLogger(__name__)


SUPERVISOR_PHASES: list[str] = [
    "recon", "surface_enum", "intel_harvest", "smb_enum",
    "ldap_enum", "kerberos_attack", "cloud_enum", "cloud_exploit",
    "vuln_scan", "exploit_decision", "human_approval", "foothold_attempt",
    "secondary_attack", "post_foothold_enum", "post_foothold_approval",
    "privesc_attempt", "objective_collect",
]



def _has_visited(state: PentestState, phase: str) -> bool:
    return int((state.phase_visit_count or {}).get(phase, 0)) > 0


def _under_cap(state: PentestState, phase: str) -> bool:
    visits = int((state.phase_visit_count or {}).get(phase, 0))
    cap = int((state.max_phase_visits or {}).get(phase, 99))
    return visits < cap


def _has_exploitable(state: PentestState) -> bool:
    return any(getattr(f, "exploitable", False) for f in (state.findings or []))


def _high_value_path_seen(state: PentestState) -> bool:
    inv = state.web_paths_inventory or []
    high_value_hints = {
        "high_risk_intel", "credential_confirmed", "secret_confirmed",
        "config_leak", "db_dump", "attack_lead", "admin", "login",
        "info_disclosure",
    }
    for item in inv:
        hints = set(item.get("hints", []))
        if hints & high_value_hints:
            return True
    return False


def _is_plan_consumed_by(plan: Any, consumer: str) -> bool:
    """判断 ``plan`` 是否已经被 ``consumer`` 消费过。

    ``plan.consumed_by`` 是一个字符串列表(节点名 / 路由名), supervisor 第一次
    读完 plan 之后会把自己 append 进去, 防止后续每一轮 supervisor 都重复
    "按 plan 路由"造成死循环 — operator_plan 的语义是"在用户给出新指令的
    那一跳起作用", 不应永远 sticky 控制路由。
    """
    if plan is None:
        return False
    return consumer in (getattr(plan, "consumed_by", None) or [])


def _mark_plan_consumed_by(plan: Any, consumer: str) -> None:
    if plan is None:
        return
    consumed = list(getattr(plan, "consumed_by", None) or [])
    if consumer not in consumed:
        consumed.append(consumer)
        try:
            plan.consumed_by = consumed
        except Exception:
            pass


def _scene_has_no_attack_surface(state: PentestState) -> bool:
    """Recon 完成后，判断是否有任何可用攻击面。"""
    if state.open_ports:
        return False
    if state.web_paths:
        return False
    if state.web_paths_inventory:
        return False
    if state.subdomains:
        return False
    if state.raw_recon:
        # 有原始侦察数据但未解析 → 可能还有东西
        return False
    return True


def _no_new_facts(state: PentestState, k: int = 3) -> bool:
    """Check the last *k* supervisor rounds — if they produced no fact churn."""
    hist = list(state.supervisor_history or [])
    if len(hist) < k:
        return False
    last_k = hist[-k:]
    sigs = {h.get("fact_signature", "") for h in last_k}
    return len(sigs) == 1


def _inject_replan_context(state: PentestState, signal_key: str) -> None:
    """Consume structured replan context and push into pending_seeds.

    Called when ``_rule_decide`` routes on a replan signal, so the target
    phase node receives concrete data (credentials, hosts, ports, tools)
    instead of just a flag.
    """
    ctx = _consume_replan_context(state, signal_key)
    if ctx is None:
        return
    try:
        for cred in (ctx.credentials or []):
            _push_pending_seed(state, "credentials", cred)
        for host in (ctx.hosts or []):
            _push_pending_seed(state, "hosts", host)
        for port in (ctx.ports or []):
            _push_pending_seed(state, "ports", port)
        for path in (ctx.web_paths or []):
            _push_pending_seed(state, "web_paths", path)
        if ctx.preferred_tools or ctx.keyword_hints or ctx.focus_targets:
            rf = dict(state.runtime_facts or {})
            hints = dict(rf.get("operator_hints", {}))
            if ctx.preferred_tools:
                hints["preferred_tools"] = list(ctx.preferred_tools)
            if ctx.keyword_hints:
                hints["keyword_hints"] = list(ctx.keyword_hints)
            if ctx.focus_targets:
                hints["focus_targets"] = list(ctx.focus_targets)
            if ctx.operator_notes:
                hints["operator_notes"] = ctx.operator_notes
            rf["operator_hints"] = hints
            state.runtime_facts = rf
        detail: list[str] = []
        if ctx.credentials:
            detail.append(f"凭据{len(ctx.credentials)}条")
        if ctx.hosts:
            detail.append(f"主机={ctx.hosts}")
        if ctx.ports:
            detail.append(f"端口={ctx.ports}")
        if ctx.preferred_tools:
            detail.append(f"工具={ctx.preferred_tools[:4]}")
        if detail:
            state.log(f"[supervisor] replan 上下文注入 ({signal_key}): {', '.join(detail)}")
    except Exception as exc:
        logger.warning(f"[supervisor] 上下文注入失败 ({signal_key}): {exc}")


def _rule_decide(state: PentestState) -> Optional[dict[str, Any]]:
    """Deterministic routing rules, in priority order.

    Returns a dict ``{"next": phase, "reason": "...", "rule": "..."}`` or
    ``None`` to defer to the LLM.
    """
    if state.status == TaskStatus.FAILED:
        return {"next": "report", "reason": "task already failed", "rule": "guard.failed"}
    if state.supervisor_round >= state.supervisor_round_limit:
        return {"next": "report", "reason": "supervisor_round_limit reached", "rule": "guard.round_limit"}
    if state.objective_status.get("report_ready"):
        return {"next": "report", "reason": "objective_collect already produced report_ready", "rule": "guard.report_ready"}

    sig = state.replan_signals or {}

    plan = getattr(state, "operator_plan", None)
    if plan is not None and not _is_plan_consumed_by(plan, "supervisor"):
        nxt = (plan.next_phase or "").strip()
        if nxt:
            return {
                "next": nxt,
                "reason": (
                    f"operator_plan: {plan.intent_summary or '按操作员指令路由'}"
                ),
                "rule": "plan.next_phase",
            }
        if plan.rerun_current and (plan.source_phase or state.current_phase):
            target = plan.source_phase or state.current_phase
            return {
                "next": target,
                "reason": f"operator_plan: 重跑 {target}",
                "rule": "plan.rerun_current",
            }
        if plan.target_phases:
            return {
                "next": plan.target_phases[0],
                "reason": (
                    f"operator_plan: 阶段序列 {' → '.join(plan.target_phases)}"
                ),
                "rule": "plan.target_phases",
            }

    if int(sig.get("operator_intent", 0)) > 0:
        return None

    _exploit_pending = (
        _has_exploitable(state) and not _has_visited(state, "foothold_attempt")
    )
    if _exploit_pending:
        for _drain_key in (
            "re_surface_enum_for_paths",
            "re_intel_harvest_for_paths",
        ):
            if sig.get(_drain_key):
                _consume_replan_signal(state, _drain_key)
        sig = state.replan_signals or {}

    if sig.get("re_recon_for_hosts") and _under_cap(state, "recon"):
        _inject_replan_context(state, "re_recon_for_hosts")
        return {"next": "recon", "reason": "new hosts discovered", "rule": "replan.re_recon_for_hosts"}
    if sig.get("re_vuln_scan_for_creds") and _under_cap(state, "vuln_scan"):
        _inject_replan_context(state, "re_vuln_scan_for_creds")
        return {"next": "vuln_scan", "reason": "new credentials → re-scan with weak-cred angle", "rule": "replan.re_vuln_scan_for_creds"}
    if sig.get("re_vuln_scan_for_ports") and _under_cap(state, "vuln_scan"):
        _inject_replan_context(state, "re_vuln_scan_for_ports")
        return {"next": "vuln_scan", "reason": "new open ports → re-scan", "rule": "replan.re_vuln_scan_for_ports"}
    if sig.get("re_surface_enum_for_paths") and _under_cap(state, "surface_enum"):
        _inject_replan_context(state, "re_surface_enum_for_paths")
        return {"next": "surface_enum", "reason": "new web paths discovered", "rule": "replan.re_surface_enum_for_paths"}
    if sig.get("re_intel_harvest_for_paths") and _under_cap(state, "intel_harvest"):
        _inject_replan_context(state, "re_intel_harvest_for_paths")
        return {"next": "intel_harvest", "reason": "new intel paths to harvest", "rule": "replan.re_intel_harvest_for_paths"}

    if state.got_shell:
        if not _has_visited(state, "post_foothold_enum"):
            return {"next": "post_foothold_enum", "reason": "拿到 shell，开始立足后枚举", "rule": "phase.post_enum"}
        if not state.post_approved_once and not state.auto_approve and not state.post_approved:
            return {"next": "post_foothold_approval", "reason": "立足后审批", "rule": "phase.post_approval"}
        if (state.post_approved or state.auto_approve or state.post_approved_once):
            pl = (state.privilege_level or "").lower()
            if pl != "root" and state.privesc_attempt_count < state.max_privesc_rounds:
                return {"next": "privesc_attempt", "reason": "尝试提权", "rule": "phase.privesc"}
            if not _has_visited(state, "objective_collect"):
                return {"next": "objective_collect", "reason": "进入目标收集", "rule": "phase.objective"}

    if not _has_visited(state, "recon"):
        return {"next": "recon", "reason": "first run", "rule": "phase.recon_first"}

    if state.open_ports and not _has_visited(state, "surface_enum"):
        return {"next": "surface_enum", "reason": "ports discovered, surface enumeration pending", "rule": "phase.surface_first"}

    if _high_value_path_seen(state) and not _has_visited(state, "intel_harvest"):
        return {"next": "intel_harvest", "reason": "high-value paths → harvest intel", "rule": "phase.intel_first"}
    if not _has_visited(state, "intel_harvest") and len(state.web_paths_inventory or []) > 0:
        return {"next": "intel_harvest", "reason": "have web paths, run intel_harvest once", "rule": "phase.intel_default"}

    if not _has_visited(state, "vuln_scan") and (state.open_ports or state.web_paths):
        return {"next": "vuln_scan", "reason": "vuln_scan pending", "rule": "phase.vuln_scan_first"}

    if _has_exploitable(state) and not _has_visited(state, "exploit_decision"):
        return {"next": "exploit_decision", "reason": "exploitable findings → decide", "rule": "phase.exploit_decision"}

    if _has_exploitable(state) and not state.approved_once and not state.auto_approve and not state.approved:
        return {"next": "human_approval", "reason": "需要人工授权", "rule": "phase.human_approval"}

    if (state.approved or state.auto_approve or state.approved_once) and _has_exploitable(state):
        if not state.got_shell and not _has_visited(state, "foothold_attempt"):
            return {"next": "foothold_attempt", "reason": "授权完成，尝试立足点", "rule": "phase.foothold"}
        if not state.got_shell and state.foothold_status == "file_read" and state.secondary_attack_count < state.max_secondary_attacks:
            return {"next": "secondary_attack", "reason": "file_read 已确认，继续尝试 RCE", "rule": "phase.secondary"}

    # ── W2-T1: 世界模型 tie-break ──
    # 常规规则未命中时, 按 rank_frontier()/unreached_high_value() 路由,
    # 仍受 SUPERVISOR_PHASES 白名单 + visit cap 约束。
    try:
        wm = state.world_model() if hasattr(state, "world_model") else None
        if wm is not None:
            ranked = wm.rank_frontier() if hasattr(wm, "rank_frontier") else []
            if ranked and not _has_visited(state, "foothold_attempt"):
                top_node, top_score = ranked[0]
                if top_score > 2.0:
                    return {
                        "next": "exploit_decision" if not _has_visited(state, "exploit_decision") else "foothold_attempt",
                        "reason": f"世界模型: top frontier {top_node.label} (score={top_score:.1f})",
                        "rule": "wm.frontier",
                    }
            high_val = wm.unreached_high_value() if hasattr(wm, "unreached_high_value") else []
            if high_val and _has_visited(state, "foothold_attempt"):
                for hv in high_val:
                    if hv.type == "credential" and _under_cap(state, "vuln_scan"):
                        return {
                            "next": "vuln_scan",
                            "reason": f"世界模型: unreached credential {hv.label}",
                            "rule": "wm.unreached_credential",
                        }
    except Exception:
        pass

    if _no_new_facts(state, k=3):
        return {"next": "report", "reason": "连续 3 轮无新 fact，强制收敛", "rule": "guard.no_new_facts"}

    if _has_visited(state, "recon") and _scene_has_no_attack_surface(state) and not _has_exploitable(state):
        return {"next": "report", "reason": "recon 未发现任何开放端口或 Web 路径，无可攻击面", "rule": "guard.dead_end"}

    if not _has_visited(state, "objective_collect"):
        return {"next": "objective_collect", "reason": "收尾路径", "rule": "phase.objective_default"}

    return {"next": "report", "reason": "no further work", "rule": "guard.fallback_report"}


async def _llm_decide(state: PentestState) -> Optional[dict[str, Any]]:
    """Best-effort LLM tie-break used only when ``_rule_decide`` returns None.

    LLM 不必对 supervisor 的每一跳都参与，因此这里走 short-prompt 模式，
    并在异常时静默回退到 report，避免阻塞流水线。

    操作员实时指令(``replan_signals['operator_intent']``)被优先注入到 LLM
    prompt 里 — `prompt_utils.attach_operator_guidance` 把 pending_user_prompt
    与最近的 user_messages 包成"最高优先级"块贴到 prompt 首尾两端。LLM
    挑出的 next phase 仍受 SUPERVISOR_PHASES 白名单限制, 因此操作员说"直接
    打"也不会 bypass human_approval 等护栏。
    """
    try:
        from backend.agents.prompt_utils import attach_operator_guidance
        from backend.llm.router import LLMRouter

        base_prompt = (
            "You are a pentest workflow supervisor. Choose the next phase.\n"
            f"Available phases: {', '.join(SUPERVISOR_PHASES + ['report'])}\n"
            f"Current state summary:\n"
            f"  current_phase={state.current_phase}\n"
            f"  open_ports={len(state.open_ports)}\n"
            f"  findings={len(state.findings)} (exploitable={sum(1 for f in state.findings if f.exploitable)})\n"
            f"  got_shell={state.got_shell} privilege={state.privilege_level}\n"
            f"  phase_visit_count={state.phase_visit_count}\n"
            f"  replan_signals={state.replan_signals}\n"
            f"  approved_once={state.approved_once} post_approved_once={state.post_approved_once}\n"
            "Respond with strict JSON: {\"next\": \"<phase>\", \"reason\": \"<short>\"}"
        )
        prompt = attach_operator_guidance(base_prompt, state)
        llm = LLMRouter()
        raw = await llm.chat(prompt, response_format="json", temperature=0.1, max_tokens=256)
        decision = json.loads(raw)
        nxt = (decision.get("next") or "").strip()
        if nxt not in SUPERVISOR_PHASES + ["report"]:
            return {"next": "report", "reason": f"llm 给了非法 phase={nxt}", "rule": "llm.invalid"}
        rule = "llm.decide"
        if int((state.replan_signals or {}).get("operator_intent", 0)) > 0:
            rule = "llm.operator_intent"
        return {"next": nxt, "reason": decision.get("reason", "llm tie-break"), "rule": rule}
    except Exception as exc:
        logger.warning(f"[supervisor] LLM 决策失败，回退 report: {exc}")
        return {"next": "report", "reason": f"llm error: {exc}", "rule": "llm.error"}



async def node_supervisor(state: PentestState) -> PentestState:
    """Pure decider node: 决定下一阶段并写入 ``state.next_phase``。"""
    state.current_phase = "supervisor"
    state.supervisor_round = int(state.supervisor_round or 0) + 1

    operator_intent_pending = int(
        (state.replan_signals or {}).get("operator_intent", 0)
    ) > 0
    plan_pending = (
        getattr(state, "operator_plan", None) is not None
        and not _is_plan_consumed_by(state.operator_plan, "supervisor")
    )

    # ── W2-T1: 世界模型 readout ──
    try:
        wm = state.world_model() if hasattr(state, "world_model") else None
        if wm is not None:
            frontier = wm.rank_frontier() if hasattr(wm, "rank_frontier") else []
            high_val = wm.unreached_high_value() if hasattr(wm, "unreached_high_value") else []
            state.push_decision({
                "action": "world_model_readout",
                "phase": "supervisor",
                "thinking": f"frontier={len(frontier)}, unreached={len(high_val)}",
                "purpose": "世界模型快照",
                "message": (
                    f"可利用前沿: {', '.join(f'{n.label}({s:.1f})' for n, s in frontier[:3])}"
                    if frontier else "无可利用前沿"
                ),
                "frontier": [
                    {"id": n.id, "label": n.label, "type": n.type, "score": round(s, 2)}
                    for n, s in frontier[:5]
                ],
                "unreached": [
                    {"id": n.id, "label": n.label, "type": n.type}
                    for n in high_val[:5]
                ],
            })
    except Exception:
        pass

    decision = _rule_decide(state)
    if decision is None:
        decision = await _llm_decide(state)
    if decision is None:
        decision = {"next": "report", "reason": "fallback", "rule": "guard.no_decision"}

    if plan_pending:
        _mark_plan_consumed_by(state.operator_plan, "supervisor")

    if operator_intent_pending:
        signals = dict(state.replan_signals or {})
        signals.pop("operator_intent", None)
        state.replan_signals = signals
        try:
            from backend.agents.interrupt_registry import consume_interrupt
            consume_interrupt(state.task_id)
        except Exception:
            pass

    state.next_phase = decision["next"]

    fact_sig = compute_phase_signature(snapshot_facts(state))
    history_entry = {
        "round": state.supervisor_round,
        "next": decision["next"],
        "reason": decision.get("reason", ""),
        "rule": decision.get("rule", ""),
        "fact_signature": fact_sig,
    }
    history = list(state.supervisor_history or [])
    history.append(history_entry)
    state.supervisor_history = history[-50:]

    badges = []
    if operator_intent_pending:
        badges.append("[operator_intent]")
    if plan_pending:
        badges.append("[operator_plan]")
    badge_str = "".join(f" {b}" for b in badges)

    state.push_decision({
        "action": "supervisor_route",
        "phase": "supervisor",
        "thinking": (
            f"#{state.supervisor_round} → {decision['next']}"
            f" (rule={decision.get('rule', '')}); reason={decision.get('reason', '')}"
            + badge_str
        ),
        "purpose": "supervisor 路由决策",
        "message": f"supervisor: {decision['next']}",
        "tone": "info",
    })
    state.log(
        f"[supervisor] #{state.supervisor_round} 路由 → {decision['next']}"
        f" (rule={decision.get('rule', '')})"
        + badge_str
    )
    return state


def supervisor_route(state: PentestState) -> str:
    """Conditional-edge function for the supervisor → phase mapping."""
    nxt = (state.next_phase or "").strip()
    if not nxt:
        return "report"
    if nxt not in SUPERVISOR_PHASES + ["report"]:
        logger.warning(f"[supervisor_route] 非法 next_phase={nxt}, 回退 report")
        return "report"
    return nxt
