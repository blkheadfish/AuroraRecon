"""Replan 信号 + 反馈条件边的单元测试。

阶段 A 验证项：

  1. ``emit_replan_signals`` 对 before/after 快照正确产出信号（凭据/路径/主机/端口）；
  2. 反馈条件边 ``edge_after_*_v2`` 在 signal 命中时回流到正确阶段；
  3. ``replan_count`` 触达 ``max_replan`` 后即使有信号也回退默认分支；
  4. ``phase_visit_count`` 触达上限时也不再 replan；
  5. ``approved_once`` / ``post_approved_once`` 让 ``node_human_approval`` /
     ``node_post_foothold_approval`` 在反馈循环里不重复挑起人工审批。
"""
from __future__ import annotations

import asyncio

from backend.agents.fact_hooks import (
    emit_replan_signals,
    snapshot_facts,
)
from backend.agents.models import PentestState, PortInfo, TaskStatus, VulnFinding
from backend.agents.orchestrator import (
    edge_after_foothold_v2,
    edge_after_post_foothold_enum_v2,
    edge_after_privesc_v2,
    edge_after_secondary_v2,
    node_human_approval,
    node_post_foothold_approval,
)


# ─── emit_replan_signals: snapshot diff ─────────────────────

def test_emit_replan_signals_credentials_diff():
    state = PentestState(target="http://x")
    before = snapshot_facts(state)
    state.credential_store.append({"user": "root", "value": "toor", "source": "config.php"})
    after = snapshot_facts(state)

    signals = emit_replan_signals(state, before=before, after=after, source_node="post_foothold_enum")
    assert signals.get("re_vuln_scan_for_creds", 0) == 1
    assert state.replan_signals == signals


def test_emit_replan_signals_paths_diff():
    state = PentestState(target="http://x")
    before = snapshot_facts(state)
    state.web_paths.extend(["/admin/login", "/api/v1/users"])
    after = snapshot_facts(state)

    signals = emit_replan_signals(state, before=before, after=after, source_node="post_foothold_enum")
    assert signals.get("re_surface_enum_for_paths", 0) == 2


def test_emit_replan_signals_hosts_diff():
    state = PentestState(target="http://x")
    state.target_host = "1.1.1.1"
    before = snapshot_facts(state)
    state.subdomains.append("admin.x.com")
    after = snapshot_facts(state)

    signals = emit_replan_signals(state, before=before, after=after, source_node="post_foothold_enum")
    assert signals.get("re_recon_for_hosts", 0) >= 1


def test_emit_replan_signals_ports_diff():
    state = PentestState(target="http://x")
    before = snapshot_facts(state)
    state.open_ports.append(PortInfo(port=22, service="ssh"))
    after = snapshot_facts(state)

    signals = emit_replan_signals(state, before=before, after=after, source_node="post_foothold_enum")
    assert signals.get("re_vuln_scan_for_ports", 0) == 1


def test_emit_replan_signals_no_diff_no_signal():
    state = PentestState(target="http://x")
    before = snapshot_facts(state)
    after = snapshot_facts(state)
    signals = emit_replan_signals(state, before=before, after=after, source_node="x")
    assert signals == {}


def test_emit_replan_signals_accumulates_across_calls():
    state = PentestState(target="http://x")
    s0 = snapshot_facts(state)
    state.credential_store.append({"user": "root", "value": "toor"})
    s1 = snapshot_facts(state)
    emit_replan_signals(state, before=s0, after=s1, source_node="round1")

    state.credential_store.append({"user": "admin", "value": "admin123"})
    s2 = snapshot_facts(state)
    emit_replan_signals(state, before=s1, after=s2, source_node="round2")

    assert state.replan_signals.get("re_vuln_scan_for_creds", 0) == 2


# ─── edge_after_*_v2: 信号驱动路由 ──────────────────────────

def test_edge_after_post_foothold_enum_v2_routes_to_vuln_scan_on_creds():
    state = PentestState(target="http://x")
    state.replan_signals = {"re_vuln_scan_for_creds": 1}
    nxt = edge_after_post_foothold_enum_v2(state)
    assert nxt == "vuln_scan"
    assert state.replan_count == 1
    # signal 应被消费
    assert "re_vuln_scan_for_creds" not in state.replan_signals


def test_edge_after_post_foothold_enum_v2_routes_to_recon_on_hosts():
    state = PentestState(target="http://x")
    state.replan_signals = {"re_recon_for_hosts": 1}
    nxt = edge_after_post_foothold_enum_v2(state)
    assert nxt == "recon"


def test_edge_after_post_foothold_enum_v2_default_to_approval():
    state = PentestState(target="http://x")
    nxt = edge_after_post_foothold_enum_v2(state)
    assert nxt == "post_foothold_approval"


def test_edge_after_secondary_v2_routes_to_vuln_scan_on_creds():
    state = PentestState(target="http://x")
    state.replan_signals = {"re_vuln_scan_for_creds": 1}
    nxt = edge_after_secondary_v2(state)
    assert nxt == "vuln_scan"


def test_edge_after_secondary_v2_shell_skips_replan():
    state = PentestState(target="http://x")
    state.got_shell = True
    state.replan_signals = {"re_vuln_scan_for_creds": 5}  # 即使有信号也优先 post
    nxt = edge_after_secondary_v2(state)
    assert nxt == "post_foothold_enum"


def test_edge_after_foothold_v2_replan_takes_precedence_over_secondary():
    state = PentestState(target="http://x")
    state.findings = [
        VulnFinding(name="dummy", severity="high", target="x", port=80, exploitable=True),
    ]
    state.replan_signals = {"re_vuln_scan_for_creds": 1}
    nxt = edge_after_foothold_v2(state)
    assert nxt == "vuln_scan"


def test_edge_after_privesc_v2_routes_to_vuln_scan_on_creds():
    state = PentestState(target="http://x")
    state.privesc_attempt_count = 1
    state.replan_signals = {"re_vuln_scan_for_creds": 1}
    nxt = edge_after_privesc_v2(state)
    assert nxt == "vuln_scan"


def test_edge_after_privesc_v2_root_skips_replan():
    state = PentestState(target="http://x")
    state.privilege_level = "root"
    state.replan_signals = {"re_vuln_scan_for_creds": 5}
    nxt = edge_after_privesc_v2(state)
    assert nxt == "objective_collect"


# ─── max_replan / phase cap 防爆 ───────────────────────────

def test_replan_blocked_when_max_replan_reached():
    state = PentestState(target="http://x")
    state.replan_count = state.max_replan  # 已达上限
    state.replan_signals = {"re_vuln_scan_for_creds": 1}
    nxt = edge_after_post_foothold_enum_v2(state)
    # 应回退默认分支, 不再 replan
    assert nxt == "post_foothold_approval"
    # signal 不应被消费(防止"假消费"假象)
    assert state.replan_signals.get("re_vuln_scan_for_creds") == 1


def test_replan_blocked_when_phase_visit_cap_reached():
    state = PentestState(target="http://x")
    state.phase_visit_count = {"vuln_scan": state.max_phase_visits["vuln_scan"]}
    state.replan_signals = {"re_vuln_scan_for_creds": 1}
    nxt = edge_after_post_foothold_enum_v2(state)
    assert nxt == "post_foothold_approval"


def test_replan_failed_status_short_circuits_to_report():
    state = PentestState(target="http://x")
    state.status = TaskStatus.FAILED
    state.replan_signals = {"re_vuln_scan_for_creds": 5}
    assert edge_after_secondary_v2(state) == "report"
    assert edge_after_foothold_v2(state) == "report"


# ─── approval_once: 反馈循环不再重复人工审批 ─────────────

def test_human_approval_skips_pending_when_approved_once():
    state = PentestState(target="http://x")
    state.findings = [
        VulnFinding(name="dummy", severity="high", target="x", port=80, exploitable=True),
    ]
    state.approved_once = True
    state.approved = False  # checkpoint 反序列化后 approved 是 False, 但 approved_once 仍保留

    asyncio.run(node_human_approval(state))

    assert state.approved is True
    # 不应再开 checkpoint
    assert state.pending_checkpoint is None


def test_post_foothold_approval_skips_when_post_approved_once():
    state = PentestState(target="http://x")
    state.got_shell = True
    state.privilege_level = "user"
    state.post_approved_once = True
    state.post_approved = False

    asyncio.run(node_post_foothold_approval(state))

    assert state.post_approved is True
    assert state.pending_checkpoint is None


def test_human_approval_auto_approve_skips():
    state = PentestState(target="http://x")
    state.auto_approve = True
    state.findings = [
        VulnFinding(name="dummy", severity="high", target="x", port=80, exploitable=True),
    ]
    asyncio.run(node_human_approval(state))
    assert state.approved is True
    assert state.approved_once is True


# ─── 端到端：post_foothold_enum 产生新凭据 → 路由到 vuln_scan ─

def test_post_foothold_diff_drives_route_to_vuln_scan():
    """模拟 post_foothold_enum 中后凭据增长 → emit_replan_signals → 边路由。"""
    state = PentestState(target="http://x")
    before = snapshot_facts(state)
    # 模拟 post 节点中拿到一条新凭据
    state.credential_store.append({"user": "dbuser", "value": "leaked", "source": "wp-config.php"})
    after = snapshot_facts(state)
    emit_replan_signals(state, before=before, after=after, source_node="post_foothold_enum")

    # 路由判定
    nxt = edge_after_post_foothold_enum_v2(state)
    assert nxt == "vuln_scan"
    assert state.replan_count == 1
