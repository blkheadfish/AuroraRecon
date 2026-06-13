"""目标选择测试 (W2-T1).

覆盖: rank_frontier 多因子评分 / node_exploit_decision 注入 /
supervisor tie-break / 空前沿回退 / push_decision target_selected.
"""

from __future__ import annotations

from backend.agents.models import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    PentestState,
    VulnFinding,
)
from backend.agents.fact_hooks import (
    attach_host_to_graph,
    attach_service_to_graph,
    attach_finding_to_graph,
    attach_credential_to_graph,
)
from backend.agents.world_model import WorldModelQuery, WorldModelWriter


def _make_state() -> PentestState:
    return PentestState(target="http://test.local")


def _multi_candidate_graph() -> tuple[AttackGraph, PentestState]:
    """构造多候选世界模型: 3 个 exploitable finding, 1 个通向 objective。"""
    state = _make_state()
    g = state.attack_graph

    host_id = attach_host_to_graph(state, "10.0.0.1", discovered_by="recon")
    attach_service_to_graph(state, "10.0.0.1", 80, service="http", version="nginx/1.18")
    attach_service_to_graph(state, "10.0.0.1", 22, service="ssh", version="OpenSSH_8.4")

    f1 = VulnFinding(
        vuln_id="CVE-2023-0001",
        name="SQL Injection",
        severity="critical",
        cve="CVE-2023-0001",
        port=80,
        target="http://10.0.0.1",
        exploitable=True,
    )
    attach_finding_to_graph(state, f1, discovered_by="vuln_scan")

    f2 = VulnFinding(
        vuln_id="CVE-2023-0002",
        name="XSS",
        severity="low",
        cve="",
        port=80,
        target="http://10.0.0.1",
        exploitable=True,
    )
    attach_finding_to_graph(state, f2, discovered_by="vuln_scan")

    f3 = VulnFinding(
        vuln_id="CVE-2023-0003",
        name="RCE",
        severity="high",
        cve="CVE-2023-0003",
        port=22,
        target="http://10.0.0.1",
        exploitable=True,
    )
    attach_finding_to_graph(state, f3, discovered_by="vuln_scan")

    # 建通向 objective 的边: f1 → credential → objective
    wm = WorldModelWriter(state)
    cid = wm.add_credential({
        "service": "ssh", "source": "10.0.0.1",
        "user": "admin", "password": "test123",
        "validated": False,
    })
    g.add_edge("finding:CVE-2023-0001", cid, relation="yields")
    oid = wm.upsert_node("objective", "objective:flag", label="flag.txt")
    g.add_edge(cid, oid, relation="enables")

    return g, state


def _empty_frontier_graph() -> tuple[AttackGraph, PentestState]:
    """空前沿: 无 exploitable finding。"""
    state = _make_state()
    g = state.attack_graph
    attach_host_to_graph(state, "10.0.0.2", discovered_by="recon")
    return g, state


class TestRankFrontierMultiFactor:
    """rank_frontier 多因子评分测试。"""

    def test_ranks_by_severity_and_cve(self):
        g, state = _multi_candidate_graph()
        wm = WorldModelQuery(g, state)
        ranked = wm.rank_frontier()
        assert len(ranked) == 3
        # critical + CVE 应最高
        assert ranked[0][0].id == "finding:CVE-2023-0001"
        assert ranked[0][1] > ranked[1][1]

    def test_leads_to_high_value_boosts_score(self):
        g, state = _multi_candidate_graph()
        wm = WorldModelQuery(g, state)
        # f1 通向 objective, 应有高价值加分
        assert wm._leads_to_high_value("finding:CVE-2023-0001") is True
        # f2 (low, no CVE, no path) 不应通向高价值
        assert wm._leads_to_high_value("finding:CVE-2023-0002") is False

    def test_top_score_matches_critical_with_path(self):
        g, state = _multi_candidate_graph()
        wm = WorldModelQuery(g, state)
        ranked = wm.rank_frontier()
        top_node, top_score = ranked[0]
        assert top_node.id == "finding:CVE-2023-0001"
        assert top_score > 20.0  # critical(10) + CVE(5) + leads_to_high_value(8) = ~23

    def test_exploited_penalty(self):
        g, state = _multi_candidate_graph()
        # 标记 f1 为已利用
        for n in g.nodes:
            if n.id == "finding:CVE-2023-0001":
                n.attrs["exploited"] = True
        wm = WorldModelQuery(g, state)
        ranked = wm.rank_frontier()
        # f1 应该因为 exploited 扣分而降级
        # f3 (high + CVE) 应该升到第一
        assert ranked[0][0].id == "finding:CVE-2023-0003"


class TestEmptyFrontier:
    """空前沿回退测试。"""

    def test_empty_frontier_returns_empty(self):
        g, state = _empty_frontier_graph()
        wm = WorldModelQuery(g, state)
        ranked = wm.rank_frontier()
        assert ranked == []

    def test_empty_unreached_high_value_returns_empty(self):
        g, state = _empty_frontier_graph()
        wm = WorldModelQuery(g, state)
        assert wm.unreached_high_value() == []


class TestLeadsToHighValue:
    """通向高价值判断测试。"""

    def test_no_path_returns_false(self):
        g, state = _multi_candidate_graph()
        wm = WorldModelQuery(g, state)
        # f2 无向外的 yields 边
        assert wm._leads_to_high_value("finding:CVE-2023-0002") is False

    def test_validated_credential_excluded(self):
        """已 validated 的 credential 不算 unreached 高价值。"""
        state = _make_state()
        g = state.attack_graph
        f1 = VulnFinding(vuln_id="CVE-X", name="RCE", severity="high",
                          cve="CVE-X", port=80, target="http://10.0.0.1",
                          exploitable=True)
        attach_finding_to_graph(state, f1)
        wm = WorldModelWriter(state)
        cid = wm.add_credential({"service": "ssh", "source": "10.0.0.1",
                                  "user": "admin", "password": "x", "validated": True})
        g.add_edge("finding:CVE-X", cid, relation="yields")

        wm_q = WorldModelQuery(g, state)
        # validated credential 不算 unreached
        assert wm_q._leads_to_high_value("finding:CVE-X") is False


class TestChainDepth:
    """链深度代价测试。"""

    def test_chain_depth_direct(self):
        state = _make_state()
        g = state.attack_graph
        f = VulnFinding(vuln_id="CVE-D", name="Direct RCE", severity="high",
                         cve="CVE-D", port=80, target="http://10.0.0.1",
                         exploitable=True)
        attach_finding_to_graph(state, f)
        # 直接加 session 节点和边
        g.upsert_node("session:10.0.0.1:root", type="session",
                        label="root@10.0.0.1",
                        attrs={"host": "10.0.0.1", "privilege": "root", "shell_type": "bash"})
        g.add_edge("finding:CVE-D", "session:10.0.0.1:root", relation="yields")

        wm = WorldModelQuery(g, state)
        assert wm._chain_depth("finding:CVE-D") == 1
