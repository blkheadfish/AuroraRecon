"""Feedback 模式（阶段 A）集成测试。

模拟"LFI 利用 → 拿到凭据 → 反馈回 vuln_scan → 拿 shell"完整端到端：

  - 验证 ATTACK_CHAIN_MODE=feedback 时编译的图含反馈条件边；
  - 验证 emit_replan_signals 串联 edge_after_*_v2 后形成的路由序列；
  - 验证 recursion_limit 在 feedback 模式下提高到 100；
  - 验证 max_replan / phase_visit_count 防爆护栏。
"""
from __future__ import annotations

import os
from contextlib import contextmanager

from backend.agents.fact_hooks import emit_replan_signals, snapshot_facts
from backend.agents.models import PentestState, PortInfo, TaskStatus, VulnFinding
from backend.agents.orchestrator import (
    Orchestrator,
    _build_graph_feedback,
    _current_chain_mode,
    build_graph,
    edge_after_foothold_v2,
    edge_after_post_foothold_enum_v2,
    edge_after_privesc_v2,
    edge_after_secondary_v2,
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



def test_feedback_mode_resolves():
    with _attack_mode("feedback"):
        assert _current_chain_mode() == "feedback"


def test_build_graph_feedback_compiles():
    with _attack_mode("feedback"):
        compiled = build_graph(checkpointer=None)
        assert compiled is not None


def test_direct_feedback_builder_compiles():
    compiled = _build_graph_feedback(checkpointer=None)
    assert compiled is not None



def test_feedback_mode_recursion_limit_raised():
    with _attack_mode("feedback"):
        cfg = Orchestrator._make_run_config("t-feedback")
        assert cfg["recursion_limit"] == 100



def test_feedback_graph_topology_has_replan_edges():
    compiled = _build_graph_feedback(checkpointer=None)
    drawn = compiled.get_graph()
    edge_pairs = {(e.source, e.target) for e in drawn.edges}
    expected = [
        ("post_foothold_enum", "vuln_scan"),
        ("post_foothold_enum", "recon"),
        ("post_foothold_enum", "surface_enum"),
        ("secondary_attack", "vuln_scan"),
        ("secondary_attack", "surface_enum"),
        ("foothold_attempt", "vuln_scan"),
        ("foothold_attempt", "surface_enum"),
        ("privesc_attempt", "vuln_scan"),
    ]
    missing = [pair for pair in expected if pair not in edge_pairs]
    assert not missing, f"feedback 模式缺失反馈边: {missing}"



def test_e2e_lfi_creds_revuln_scan_shell():
    """
    模拟整条攻击链：

      1. foothold_attempt 通过 LFI 拿到 file_read 但没拿到 RCE
      2. fact_sink 把 wp-config.php 里的 mysql 密码灌进 credential_store
      3. emit_replan_signals 看到 +1 凭据 → re_vuln_scan_for_creds
      4. edge_after_foothold_v2 路由 → vuln_scan
      5. vuln_scan 重跑（pending_seeds 注入 22/SSH 后形成新 finding）
      6. foothold 重入 → 这次 SSH 弱口令拿到 shell
      7. edge_after_foothold_v2 看到 got_shell → post_foothold_enum
    """
    state = PentestState(target="http://x")
    state.target_host = "10.10.10.10"

    state.foothold_status = "file_read"
    state.findings = [
        VulnFinding(name="LFI via image", severity="high", target="http://x/info.php",
                    port=80, exploitable=True, vuln_id="lfi-1"),
    ]

    before = snapshot_facts(state)
    state.credential_store.append({"user": "wp", "value": "secret123",
                                    "source": "wp-config.php"})
    after = snapshot_facts(state)
    emit_replan_signals(state, before=before, after=after, source_node="foothold_attempt")
    assert state.replan_signals.get("re_vuln_scan_for_creds", 0) == 1

    nxt = edge_after_foothold_v2(state)
    assert nxt == "vuln_scan"
    assert state.replan_count == 1

    state.open_ports.append(PortInfo(port=22, service="ssh", state="open"))
    state.findings.append(
        VulnFinding(name="SSH weak credentials", severity="high",
                    target="10.10.10.10:22", port=22,
                    exploitable=True, vuln_id="ssh-weak"),
    )

    state.got_shell = True
    state.privilege_level = "user"

    nxt2 = edge_after_foothold_v2(state)
    assert nxt2 == "post_foothold_enum"


def test_e2e_post_enum_discovers_new_host_and_replan_recon():
    """post_foothold_enum 发现内网主机 → 路由回 recon。"""
    state = PentestState(target="http://x")
    state.target_host = "10.10.10.10"
    state.got_shell = True
    state.privilege_level = "user"

    before = snapshot_facts(state)
    state.subdomains.extend(["10.10.10.20", "10.10.10.30"])
    after = snapshot_facts(state)
    emit_replan_signals(state, before=before, after=after, source_node="post_foothold_enum")

    nxt = edge_after_post_foothold_enum_v2(state)
    assert nxt == "recon"
    assert state.replan_count == 1


def test_e2e_secondary_attack_creds_to_vuln_scan():
    """secondary_attack 拿到凭据 → 回流 vuln_scan。"""
    state = PentestState(target="http://x")
    before = snapshot_facts(state)
    state.credential_store.append({"user": "admin", "value": "admin"})
    after = snapshot_facts(state)
    emit_replan_signals(state, before=before, after=after, source_node="secondary_attack")
    nxt = edge_after_secondary_v2(state)
    assert nxt == "vuln_scan"


def test_e2e_privesc_failure_creds_to_vuln_scan():
    """privesc_attempt 中途拿到新凭据但仍未 root → 回流 vuln_scan 而不是死循环。"""
    state = PentestState(target="http://x")
    state.privilege_level = "user"
    state.privesc_attempt_count = 1
    state.max_privesc_rounds = 3
    before = snapshot_facts(state)
    state.credential_store.append({"user": "svcaccount", "value": "..."})
    after = snapshot_facts(state)
    emit_replan_signals(state, before=before, after=after, source_node="privesc_attempt")
    nxt = edge_after_privesc_v2(state)
    assert nxt == "vuln_scan"



def test_e2e_max_replan_prevents_infinite_loop():
    """连续触发反馈直到 replan_count == max_replan 后强制退出回流。"""
    state = PentestState(target="http://x")
    state.max_replan = 2

    for _ in range(state.max_replan):
        state.replan_signals = {"re_vuln_scan_for_creds": 1}
        nxt = edge_after_post_foothold_enum_v2(state)
        assert nxt == "vuln_scan"
    assert state.replan_count == state.max_replan

    state.replan_signals = {"re_vuln_scan_for_creds": 1}
    nxt = edge_after_post_foothold_enum_v2(state)
    assert nxt == "post_foothold_approval"


def test_e2e_phase_visit_cap_blocks_replan():
    state = PentestState(target="http://x")
    state.phase_visit_count = {"vuln_scan": state.max_phase_visits["vuln_scan"]}
    state.replan_signals = {"re_vuln_scan_for_creds": 5}
    nxt = edge_after_secondary_v2(state)
    assert nxt == "report"


def test_e2e_failed_status_short_circuits():
    """任务已失败时, 反馈回流必须立刻短路到 report/objective."""
    state = PentestState(target="http://x")
    state.status = TaskStatus.FAILED
    state.replan_signals = {"re_vuln_scan_for_creds": 5}
    assert edge_after_foothold_v2(state) == "report"
    assert edge_after_secondary_v2(state) == "report"
    assert edge_after_privesc_v2(state) == "objective_collect"
