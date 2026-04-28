"""Supervisor 模式（阶段 C）路由 + 收敛性测试。

验证项：
  - ATTACK_CHAIN_MODE=supervisor 时编译成功；
  - _rule_decide 决策表的优先级（replan_signals > 阶段递推 > 收敛兜底）；
  - node_supervisor 正确填 next_phase / supervisor_round / supervisor_history；
  - supervisor_round_limit / 连续 N 轮无新 fact 强制 report；
  - 星形拓扑：每个 phase 都有边回 supervisor。
"""
from __future__ import annotations

import asyncio
import os
from contextlib import contextmanager

import pytest

from backend.agents.models import (
    PentestState,
    PortInfo,
    TaskStatus,
    VulnFinding,
)
from backend.agents.orchestrator import (
    Orchestrator,
    _build_graph_supervisor,
    _current_chain_mode,
    build_graph,
)
from backend.agents.supervisor import (
    SUPERVISOR_PHASES,
    _rule_decide,
    node_supervisor,
    supervisor_route,
)


@contextmanager
def _attack_mode(value: str):
    prev = os.environ.get("ATTACK_CHAIN_MODE")
    if value is None:
        os.environ.pop("ATTACK_CHAIN_MODE", None)
    else:
        os.environ["ATTACK_CHAIN_MODE"] = value
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("ATTACK_CHAIN_MODE", None)
        else:
            os.environ["ATTACK_CHAIN_MODE"] = prev


# ─── 模式分发 + 编译 ──────────────────────────────────────

def test_supervisor_mode_resolves():
    with _attack_mode("supervisor"):
        assert _current_chain_mode() == "supervisor"


def test_build_graph_supervisor_compiles():
    with _attack_mode("supervisor"):
        compiled = build_graph(checkpointer=None)
        assert compiled is not None


def test_direct_supervisor_builder_compiles():
    compiled = _build_graph_supervisor(checkpointer=None)
    assert compiled is not None


def test_supervisor_recursion_limit_doubled():
    with _attack_mode("supervisor"):
        cfg = Orchestrator._make_run_config("t-supervisor")
        assert cfg["recursion_limit"] >= 200


# ─── 星形拓扑：每个 phase 都回 supervisor ────────────────

def test_supervisor_topology_is_star():
    compiled = _build_graph_supervisor(checkpointer=None)
    drawn = compiled.get_graph()
    edge_pairs = {(e.source, e.target) for e in drawn.edges}
    # report 是终态, 不回 supervisor
    expected_back = [
        ("recon", "supervisor"),
        ("surface_enum", "supervisor"),
        ("intel_harvest", "supervisor"),
        ("vuln_scan", "supervisor"),
        ("foothold_attempt", "supervisor"),
        ("secondary_attack", "supervisor"),
        ("post_foothold_enum", "supervisor"),
        ("privesc_attempt", "supervisor"),
        ("objective_collect", "supervisor"),
    ]
    missing = [p for p in expected_back if p not in edge_pairs]
    assert not missing, f"supervisor 模式缺失回流边: {missing}"


# ─── _rule_decide 优先级 ────────────────────────────────

def test_rule_decide_failed_status_short_circuits_to_report():
    state = PentestState(target="x")
    state.status = TaskStatus.FAILED
    decision = _rule_decide(state)
    assert decision and decision["next"] == "report"
    assert decision["rule"].startswith("guard.failed")


def test_rule_decide_round_limit_short_circuits():
    state = PentestState(target="x")
    state.supervisor_round = 100
    state.supervisor_round_limit = 30
    decision = _rule_decide(state)
    assert decision and decision["next"] == "report"
    assert "round_limit" in decision["rule"]


def test_rule_decide_replan_creds_takes_precedence():
    """replan_signals 的优先级必须高于阶段递推。"""
    state = PentestState(target="x")
    # 第一次 recon 已访问，照阶段递推应该走 surface_enum，但 signals 优先
    state.phase_visit_count = {"recon": 1, "surface_enum": 1}
    state.open_ports.append(PortInfo(port=80, service="http"))
    state.replan_signals = {"re_vuln_scan_for_creds": 1}
    decision = _rule_decide(state)
    assert decision and decision["next"] == "vuln_scan"
    assert decision["rule"].startswith("replan.")


def test_rule_decide_first_run_goes_to_recon():
    state = PentestState(target="x")
    decision = _rule_decide(state)
    assert decision and decision["next"] == "recon"


def test_rule_decide_with_open_ports_goes_to_surface_enum():
    state = PentestState(target="x")
    state.phase_visit_count = {"recon": 1}
    state.open_ports.append(PortInfo(port=80, service="http"))
    decision = _rule_decide(state)
    assert decision and decision["next"] == "surface_enum"


def test_rule_decide_after_recon_intel_when_high_value_paths():
    state = PentestState(target="x")
    state.phase_visit_count = {"recon": 1, "surface_enum": 1}
    state.web_paths_inventory = [{"path": "/admin", "hints": ["admin"]}]
    decision = _rule_decide(state)
    assert decision and decision["next"] == "intel_harvest"


def test_rule_decide_routes_to_human_approval_when_exploitable():
    state = PentestState(target="x")
    state.phase_visit_count = {
        "recon": 1, "surface_enum": 1, "intel_harvest": 1,
        "vuln_scan": 1, "exploit_decision": 1,
    }
    state.findings = [
        VulnFinding(name="x", severity="high", target="x", port=80, exploitable=True),
    ]
    state.auto_approve = False
    state.approved = False
    state.approved_once = False
    decision = _rule_decide(state)
    assert decision and decision["next"] == "human_approval"


def test_rule_decide_skips_human_approval_when_auto_approve():
    state = PentestState(target="x")
    state.phase_visit_count = {
        "recon": 1, "surface_enum": 1, "intel_harvest": 1,
        "vuln_scan": 1, "exploit_decision": 1,
    }
    state.findings = [
        VulnFinding(name="x", severity="high", target="x", port=80, exploitable=True),
    ]
    state.auto_approve = True
    decision = _rule_decide(state)
    assert decision and decision["next"] == "foothold_attempt"


def test_rule_decide_skips_human_approval_after_approved_once():
    state = PentestState(target="x")
    state.phase_visit_count = {
        "recon": 1, "surface_enum": 1, "intel_harvest": 1,
        "vuln_scan": 1, "exploit_decision": 1,
    }
    state.findings = [
        VulnFinding(name="x", severity="high", target="x", port=80, exploitable=True),
    ]
    state.approved_once = True
    decision = _rule_decide(state)
    assert decision and decision["next"] == "foothold_attempt"


def test_rule_decide_post_enum_when_got_shell():
    state = PentestState(target="x")
    state.got_shell = True
    decision = _rule_decide(state)
    assert decision and decision["next"] == "post_foothold_enum"


def test_rule_decide_privesc_when_user_and_post_approved():
    state = PentestState(target="x")
    state.got_shell = True
    state.phase_visit_count = {"post_foothold_enum": 1}
    state.privilege_level = "user"
    state.post_approved_once = True
    decision = _rule_decide(state)
    assert decision and decision["next"] == "privesc_attempt"


def test_rule_decide_objective_when_root():
    state = PentestState(target="x")
    state.got_shell = True
    state.phase_visit_count = {"post_foothold_enum": 1}
    state.privilege_level = "root"
    state.post_approved_once = True
    decision = _rule_decide(state)
    assert decision and decision["next"] == "objective_collect"


def test_rule_decide_report_ready_routes_to_report():
    state = PentestState(target="x")
    state.objective_status["report_ready"] = True
    decision = _rule_decide(state)
    assert decision and decision["next"] == "report"


# ─── 收敛保护：连续 3 轮无新 fact 强制 report ─────────────

def test_rule_decide_no_new_facts_forces_report():
    """模拟连续 3 轮 supervisor 决策 fact_signature 完全相同 → 强制 report。"""
    state = PentestState(target="x")
    # 让先前的"阶段递推优先级"全部失效, 强制走到 _no_new_facts 分支
    state.phase_visit_count = {
        "recon": 1, "surface_enum": 1, "intel_harvest": 1,
        "vuln_scan": 1, "exploit_decision": 1, "objective_collect": 1,
    }
    # 连续 3 轮 fact_signature 一致
    state.supervisor_history = [
        {"round": i, "next": "objective_collect", "rule": "x", "fact_signature": "same"}
        for i in range(3)
    ]
    decision = _rule_decide(state)
    assert decision and decision["next"] == "report"
    assert "no_new_facts" in decision["rule"]


# ─── node_supervisor 写入状态 ────────────────────────────

def test_node_supervisor_increments_round_and_history():
    state = PentestState(target="x")
    state2 = asyncio.run(node_supervisor(state))
    assert state2.supervisor_round == 1
    assert state2.next_phase  # 必须给出一个决策
    assert len(state2.supervisor_history) == 1
    entry = state2.supervisor_history[0]
    assert entry["round"] == 1
    assert entry["next"] == state2.next_phase
    assert entry["fact_signature"]
    assert entry["rule"]


def test_node_supervisor_emits_decision_event():
    state = PentestState(target="x")
    state2 = asyncio.run(node_supervisor(state))
    actions = [e.get("action") for e in state2.live_decision_events]
    assert "supervisor_route" in actions


def test_node_supervisor_round_limit_forces_report():
    state = PentestState(target="x")
    state.supervisor_round = 30
    state.supervisor_round_limit = 30
    state2 = asyncio.run(node_supervisor(state))
    assert state2.next_phase == "report"


# ─── supervisor_route 路由函数 ──────────────────────────

def test_supervisor_route_returns_next_phase():
    state = PentestState(target="x")
    state.next_phase = "recon"
    assert supervisor_route(state) == "recon"


def test_supervisor_route_invalid_phase_falls_back_to_report():
    state = PentestState(target="x")
    state.next_phase = "bogus_phase"
    assert supervisor_route(state) == "report"


def test_supervisor_route_empty_next_phase_falls_back_to_report():
    state = PentestState(target="x")
    state.next_phase = ""
    assert supervisor_route(state) == "report"


def test_supervisor_phases_constant_includes_all_executable():
    """SUPERVISOR_PHASES 集合必须涵盖图里所有可调度节点（report 除外）。"""
    must_have = [
        "recon", "surface_enum", "intel_harvest", "vuln_scan",
        "exploit_decision", "human_approval", "foothold_attempt",
        "secondary_attack", "post_foothold_enum", "post_foothold_approval",
        "privesc_attempt", "objective_collect",
    ]
    for p in must_have:
        assert p in SUPERVISOR_PHASES
