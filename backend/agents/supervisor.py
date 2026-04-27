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
    snapshot_facts,
)
from backend.agents.models import PentestState, TaskStatus

logger = logging.getLogger(__name__)


# 所有可被 supervisor 调度的"阶段节点"。报表节点是终态，不参与调度集合。
SUPERVISOR_PHASES: list[str] = [
    "recon", "surface_enum", "intel_harvest", "vuln_scan",
    "exploit_decision", "human_approval", "foothold_attempt",
    "secondary_attack", "post_foothold_enum", "post_foothold_approval",
    "privesc_attempt", "objective_collect",
]


# ─────────────────────────────────────────────────────────────
# 决策核心
# ─────────────────────────────────────────────────────────────

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


def _no_new_facts(state: PentestState, k: int = 3) -> bool:
    """Check the last *k* supervisor rounds — if they produced no fact churn."""
    hist = list(state.supervisor_history or [])
    if len(hist) < k:
        return False
    last_k = hist[-k:]
    sigs = {h.get("fact_signature", "") for h in last_k}
    return len(sigs) == 1


def _rule_decide(state: PentestState) -> Optional[dict[str, Any]]:
    """Deterministic routing rules, in priority order.

    Returns a dict ``{"next": phase, "reason": "...", "rule": "..."}`` or
    ``None`` to defer to the LLM.
    """
    # ── 0. 收敛保护 ────────────────────────────────────────────
    if state.status == TaskStatus.FAILED:
        return {"next": "report", "reason": "task already failed", "rule": "guard.failed"}
    if state.supervisor_round >= state.supervisor_round_limit:
        return {"next": "report", "reason": "supervisor_round_limit reached", "rule": "guard.round_limit"}
    if state.objective_status.get("report_ready"):
        return {"next": "report", "reason": "objective_collect already produced report_ready", "rule": "guard.report_ready"}

    # ── 1. 反馈循环 signals 优先于阶段递推 ──────────────────────
    sig = state.replan_signals or {}
    if sig.get("re_recon_for_hosts") and _under_cap(state, "recon"):
        return {"next": "recon", "reason": "new hosts discovered", "rule": "replan.re_recon_for_hosts"}
    if sig.get("re_vuln_scan_for_creds") and _under_cap(state, "vuln_scan"):
        return {"next": "vuln_scan", "reason": "new credentials → re-scan with weak-cred angle", "rule": "replan.re_vuln_scan_for_creds"}
    if sig.get("re_vuln_scan_for_ports") and _under_cap(state, "vuln_scan"):
        return {"next": "vuln_scan", "reason": "new open ports → re-scan", "rule": "replan.re_vuln_scan_for_ports"}
    if sig.get("re_surface_enum_for_paths") and _under_cap(state, "surface_enum"):
        return {"next": "surface_enum", "reason": "new web paths discovered", "rule": "replan.re_surface_enum_for_paths"}
    if sig.get("re_intel_harvest_for_paths") and _under_cap(state, "intel_harvest"):
        return {"next": "intel_harvest", "reason": "new intel paths to harvest", "rule": "replan.re_intel_harvest_for_paths"}

    # ── 2. 已拿 shell 时优先进入立足后链路 ─────────────────────
    # supervisor 可能从 checkpoint / 测试构造状态恢复，此时 got_shell=True
    # 本身就是强事实，不应因为 phase_visit_count 缺少 recon 而倒回侦察。
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

    # ── 3. 阶段递推（按"未访问且前置条件满足"的顺序） ─────────────
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

    # ── 4. 利用阶段 ────────────────────────────────────────────
    if _has_exploitable(state) and not state.approved_once and not state.auto_approve and not state.approved:
        return {"next": "human_approval", "reason": "需要人工授权", "rule": "phase.human_approval"}

    if (state.approved or state.auto_approve or state.approved_once) and _has_exploitable(state):
        if not state.got_shell and not _has_visited(state, "foothold_attempt"):
            return {"next": "foothold_attempt", "reason": "授权完成，尝试立足点", "rule": "phase.foothold"}
        if not state.got_shell and state.foothold_status == "file_read" and state.secondary_attack_count < state.max_secondary_attacks:
            return {"next": "secondary_attack", "reason": "file_read 已确认，继续尝试 RCE", "rule": "phase.secondary"}

    # ── 5. 兜底：连续多轮无新事实 → 直接出报告 ─────────────────
    if _no_new_facts(state, k=3):
        return {"next": "report", "reason": "连续 3 轮无新 fact，强制收敛", "rule": "guard.no_new_facts"}

    # ── 6. 默认：进入 objective_collect 收尾 ───────────────────
    if not _has_visited(state, "objective_collect"):
        return {"next": "objective_collect", "reason": "收尾路径", "rule": "phase.objective_default"}

    return {"next": "report", "reason": "no further work", "rule": "guard.fallback_report"}


async def _llm_decide(state: PentestState) -> Optional[dict[str, Any]]:
    """Best-effort LLM tie-break used only when ``_rule_decide`` returns None.

    LLM 不必对 supervisor 的每一跳都参与，因此这里走 short-prompt 模式，
    并在异常时静默回退到 report，避免阻塞流水线。
    """
    try:
        from backend.llm.router import LLMRouter

        prompt = (
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
        llm = LLMRouter()
        raw = await llm.chat(prompt, response_format="json", temperature=0.1, max_tokens=256)
        decision = json.loads(raw)
        nxt = (decision.get("next") or "").strip()
        if nxt not in SUPERVISOR_PHASES + ["report"]:
            return {"next": "report", "reason": f"llm 给了非法 phase={nxt}", "rule": "llm.invalid"}
        return {"next": nxt, "reason": decision.get("reason", "llm tie-break"), "rule": "llm.decide"}
    except Exception as exc:
        logger.warning(f"[supervisor] LLM 决策失败，回退 report: {exc}")
        return {"next": "report", "reason": f"llm error: {exc}", "rule": "llm.error"}


# ─────────────────────────────────────────────────────────────
# Supervisor 节点 + 路由函数
# ─────────────────────────────────────────────────────────────

async def node_supervisor(state: PentestState) -> PentestState:
    """Pure decider node: 决定下一阶段并写入 ``state.next_phase``。"""
    state.current_phase = "supervisor"
    state.supervisor_round = int(state.supervisor_round or 0) + 1

    decision = _rule_decide(state)
    if decision is None:
        decision = await _llm_decide(state)
    if decision is None:
        decision = {"next": "report", "reason": "fallback", "rule": "guard.no_decision"}

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

    state.push_decision({
        "action": "supervisor_route",
        "phase": "supervisor",
        "thinking": (
            f"#{state.supervisor_round} → {decision['next']}"
            f" (rule={decision.get('rule', '')}); reason={decision.get('reason', '')}"
        ),
        "purpose": "supervisor 路由决策",
        "message": f"supervisor: {decision['next']}",
        "tone": "info",
    })
    state.log(
        f"[supervisor] #{state.supervisor_round} 路由 → {decision['next']}"
        f" (rule={decision.get('rule', '')})"
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
