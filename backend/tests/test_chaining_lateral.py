"""横向链推理测试 (W2-T2).

覆盖: chains() 增强 / lateral_chains() / 链评分排序 / 凭据有效性加分 /
无链时回退行为 / 空图回退。
"""

from __future__ import annotations

from backend.agents.models import (
    AttackGraph,
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


def _lateral_scenario() -> tuple[AttackGraph, PentestState]:
    """构造横向场景: session A → host A → cred → host B。"""
    state = _make_state()
    g = state.attack_graph
    wm = WorldModelWriter(state)

    host_a = attach_host_to_graph(state, "10.0.0.1", discovered_by="recon")
    host_b = wm.upsert_node("host", "host:10.0.0.2", label="10.0.0.2")

    sid = wm.add_session("10.0.0.1", "root", "bash")

    cid = wm.add_credential({
        "service": "ssh", "source": "10.0.0.1",
        "user": "admin", "password": "secret123",
        "validated": True,
    })
    g.add_edge(host_a, cid, relation="yields")
    g.add_edge(cid, host_b, relation="pivots_to")

    return g, state


def _no_lateral_scenario() -> tuple[AttackGraph, PentestState]:
    """无横向链: 有 session 但无凭据连接到新 host。"""
    state = _make_state()
    g = state.attack_graph
    wm = WorldModelWriter(state)

    host_a = attach_host_to_graph(state, "10.0.0.1", discovered_by="recon")
    wm.add_session("10.0.0.1", "user", "bash")
    cid = wm.add_credential({
        "service": "ssh", "source": "10.0.0.1",
        "user": "user", "password": "x",
        "validated": False,
    })
    g.add_edge(host_a, cid, relation="yields")

    return g, state


class TestChainsEnhanced:
    """chains() 增强评分测试。"""

    def test_chains_with_validated_credential_scores_higher(self):
        state = _make_state()
        g = state.attack_graph
        wm = WorldModelWriter(state)
        attach_host_to_graph(state, "10.0.0.1", discovered_by="recon")

        f = VulnFinding(vuln_id="CVE-X", name="SQLi", severity="high",
                         cve="CVE-2024-0001", port=80,
                         target="http://10.0.0.1", exploitable=True)
        attach_finding_to_graph(state, f)

        cid_a = wm.add_credential({"service": "mysql", "source": "10.0.0.1",
                                    "user": "root", "password": "pass1",
                                    "validated": True})
        g.add_edge("finding:CVE-X", cid_a, relation="yields")
        sid = wm.add_session("10.0.0.1", "root", "bash")
        g.add_edge(cid_a, sid, relation="yields")

        wm_q = WorldModelQuery(g, state)
        chains = wm_q.chains()
        assert len(chains) == 1
        assert chains[0].score > 10.0  # high(7) + CVE(5) + validated(6) = 18+

    def test_empty_graph_returns_empty_chains(self):
        state = _make_state()
        wm_q = WorldModelQuery(state.attack_graph, state)
        assert wm_q.chains() == []


class TestLateralChains:
    """lateral_chains() 横向链推理测试。"""

    def test_lateral_chain_found(self):
        g, state = _lateral_scenario()
        wm_q = WorldModelQuery(g, state)
        lc = wm_q.lateral_chains()
        assert len(lc) >= 1
        top = lc[0]
        assert top.score > 0
        assert "10.0.0.2" in top.target or top.target.endswith("10.0.0.2")

    def test_validated_credential_scores_highest(self):
        g, state = _lateral_scenario()
        wm_q = WorldModelQuery(g, state)
        lc = wm_q.lateral_chains()
        # validated credential → hostB 应是最高分
        assert lc[0].score > 5.0

    def test_no_lateral_chain_when_no_pivot(self):
        g, state = _no_lateral_scenario()
        wm_q = WorldModelQuery(g, state)
        lc = wm_q.lateral_chains()
        # credential 没有 pivots_to 边 → 无横向链
        assert len(lc) == 0

    def test_lateral_chains_sorted_by_score_descending(self):
        g, state = _lateral_scenario()
        # 加第二个凭据(低分)
        wm = WorldModelWriter(state)
        cid2 = wm.add_credential({
            "service": "smb", "source": "10.0.0.1",
            "user": "guest", "password": "",
            "validated": False,
        })
        host_c = wm.upsert_node("host", "host:10.0.0.3", label="10.0.0.3")
        g.add_edge("host:10.0.0.1", cid2, relation="yields")
        g.add_edge(cid2, host_c, relation="pivots_to")

        wm_q = WorldModelQuery(g, state)
        lc = wm_q.lateral_chains()
        assert len(lc) == 2
        assert lc[0].score > lc[1].score  # validated 的排前面

    def test_no_pivot_to_self(self):
        """不应产生指向自己的横向链。"""
        state = _make_state()
        g = state.attack_graph
        wm = WorldModelWriter(state)
        host_a = attach_host_to_graph(state, "10.0.0.1", discovered_by="recon")
        wm.add_session("10.0.0.1", "root", "bash")
        cid = wm.add_credential({
            "service": "ssh", "source": "10.0.0.1",
            "user": "admin", "password": "x",
            "validated": True,
        })
        g.add_edge(host_a, cid, relation="yields")
        g.add_edge(cid, host_a, relation="pivots_to")  # 指向自己

        wm_q = WorldModelQuery(g, state)
        lc = wm_q.lateral_chains()
        assert len(lc) == 0


class TestChainScoringHelpers:
    """链评分辅助方法测试。"""

    def test_chain_score_with_objective_target(self):
        state = _make_state()
        g = state.attack_graph
        wm = WorldModelWriter(state)

        f = VulnFinding(vuln_id="CVE-T", name="RCE", severity="critical",
                         cve="CVE-2024-T", port=80,
                         target="http://10.0.0.1", exploitable=True)
        attach_finding_to_graph(state, f)
        cid = wm.add_credential({"service": "ssh", "source": "10.0.0.1",
                                  "user": "root", "password": "x",
                                  "validated": True})
        g.add_edge("finding:CVE-T", cid, relation="yields")
        oid = wm.upsert_node("objective", "objective:flag", label="flag.txt")
        g.add_edge(cid, oid, relation="enables")

        wm_q = WorldModelQuery(g, state)
        chains = wm_q.chains()
        assert len(chains) == 1
        # critical(10) + CVE(5) + validated(6) + objective(10) = 31+
        assert chains[0].score > 25.0
