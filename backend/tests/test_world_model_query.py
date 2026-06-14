"""WorldModelQuery 查询 API 单元测试 (W1-T1).

覆盖: exploitable_frontier / unreached_high_value / pivot_candidates /
usable_credentials / paths_to_objective / chains / rank_frontier /
空图 / 向后兼容 (旧 facts 字段)。
"""

from __future__ import annotations

import json

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
    _ag_credential_id,
)
from backend.agents.world_model import WorldModelQuery, WMNode, WMPath, WMChain


def _make_state() -> PentestState:
    return PentestState(target="http://test.local")


def _populated_graph() -> tuple[AttackGraph, PentestState]:
    """构造含 host/service/finding/credential/session/objective 的图。"""
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
        severity="medium",
        cve="",
        port=80,
        target="http://10.0.0.1",
        exploitable=True,
    )
    attach_finding_to_graph(state, f2, discovered_by="vuln_scan")

    f3 = VulnFinding(
        vuln_id="INFO-LEAK-01",
        name="Info Leak",
        severity="low",
        cve="",
        port=22,
        target="http://10.0.0.1",
        exploitable=False,
    )
    attach_finding_to_graph(state, f3, discovered_by="recon")

    attach_credential_to_graph(state, {
        "user": "admin",
        "password": "secret",
        "source": "ssh",
        "validated": True,
    }, discovered_by="exploit_agent")
    admin_cred_id = _ag_credential_id({
        "user": "admin", "password": "secret", "source": "ssh",
    })

    attach_credential_to_graph(state, {
        "user": "user",
        "source": "http",
        "validated": False,
    }, discovered_by="recon")

    sid = "session:10.0.0.1:root"
    g.upsert_node(sid, type="session", label="root@10.0.0.1",
                   attrs={"host": "10.0.0.1", "privilege": "root", "shell_type": "bash"})
    g.add_edge("finding:CVE-2023-0001", admin_cred_id, relation="yields",
               attrs={"via": "exploit"})
    g.add_edge(admin_cred_id, sid, relation="yields",
               attrs={"via": "ssh_login"})
    g.add_edge(sid, host_id, relation="runs_on")

    obj_id = "objective:flag"
    g.upsert_node(obj_id, type="objective", label="Flag /root/flag.txt",
                   attrs={"path": "/root/flag.txt"})
    g.add_edge(sid, obj_id, relation="leads_to",
               attrs={"confidence": 0.9})

    return g, state


# ── exploitable_frontier ─────────────────────────────────────

def test_exploitable_frontier():
    g, state = _populated_graph()
    wm = WorldModelQuery(g, state)
    frontier = wm.exploitable_frontier()
    ids = {n.id for n in frontier}
    assert "finding:CVE-2023-0001" in ids
    assert "finding:CVE-2023-0002" in ids
    assert "finding:INFO-LEAK-01" not in ids


def test_exploitable_frontier_empty():
    state = _make_state()
    wm = WorldModelQuery(state.attack_graph, state)
    assert wm.exploitable_frontier() == []


# ── unreached_high_value ─────────────────────────────────────

def test_unreached_high_value():
    g, state = _populated_graph()
    wm = WorldModelQuery(g, state)
    uv = wm.unreached_high_value()
    ids = {n.id for n in uv}
    assert "cred:" not in ids  # attached credentials have incoming edges if connected


def test_unreached_high_value_empty():
    state = _make_state()
    wm = WorldModelQuery(state.attack_graph, state)
    assert wm.unreached_high_value() == []


# ── pivot_candidates ─────────────────────────────────────────

def test_pivot_candidates():
    g, state = _populated_graph()
    wm = WorldModelQuery(g, state)
    pivots = wm.pivot_candidates()
    ids = {n.id for n in pivots}
    assert "host:10.0.0.1" in ids


def test_pivot_candidates_empty():
    state = _make_state()
    wm = WorldModelQuery(state.attack_graph, state)
    assert wm.pivot_candidates() == []


# ── usable_credentials ───────────────────────────────────────

def test_usable_credentials():
    g, state = _populated_graph()
    wm = WorldModelQuery(g, state)
    creds = wm.usable_credentials()
    assert len(creds) >= 1
    validated = [c for c in creds if c.attrs.get("validated")]
    assert len(validated) >= 1


def test_usable_credentials_empty():
    state = _make_state()
    wm = WorldModelQuery(state.attack_graph, state)
    assert wm.usable_credentials() == []


# ── paths_to_objective ───────────────────────────────────────

def test_paths_to_objective():
    g, state = _populated_graph()
    wm = WorldModelQuery(g, state)
    paths = wm.paths_to_objective()
    assert len(paths) >= 1
    found = False
    for p in paths:
        if "objective:flag" in p.nodes:
            found = True
            break
    assert found


def test_paths_to_objective_empty():
    state = _make_state()
    wm = WorldModelQuery(state.attack_graph, state)
    assert wm.paths_to_objective() == []


# ── chains ───────────────────────────────────────────────────

def test_chains():
    g, state = _populated_graph()
    wm = WorldModelQuery(g, state)
    chains = wm.chains()
    assert len(chains) >= 1
    found = False
    for c in chains:
        if "CVE-2023-0001" in c.start:
            found = True
            break
    assert found


def test_chains_empty():
    state = _make_state()
    wm = WorldModelQuery(state.attack_graph, state)
    assert wm.chains() == []


# ── rank_frontier ────────────────────────────────────────────

def test_rank_frontier():
    g, state = _populated_graph()
    wm = WorldModelQuery(g, state)
    ranked = wm.rank_frontier()
    assert len(ranked) >= 2
    scores = [s for _, s in ranked]
    assert scores == sorted(scores, reverse=True)
    top = ranked[0][0]
    assert top.attrs.get("severity") == "critical"


def test_rank_frontier_empty():
    state = _make_state()
    wm = WorldModelQuery(state.attack_graph, state)
    assert wm.rank_frontier() == []


# ── 向后兼容: 旧 facts 字段（无 attrs）仍可查询 ──────────────────

def test_backward_compat_facts_only():
    """旧 state_json 只有 facts 无 attrs 时查询不报错且正确工作。"""
    g = AttackGraph()
    n = AttackGraphNode(
        id="finding:OLD-001",
        type="finding",
        label="Old Vuln",
        facts={"severity": "high", "cve": "CVE-2020-0001", "exploitable": True},
    )
    g.nodes.append(n)
    state = _make_state()
    state.attack_graph = g
    wm = WorldModelQuery(g, state)
    frontier = wm.exploitable_frontier()
    assert len(frontier) == 1
    assert frontier[0].id == "finding:OLD-001"
    assert frontier[0].attrs.get("exploitable") is True
    assert frontier[0].attrs.get("severity") == "high"


def test_serialization_roundtrip():
    """确保 AttackGraphNode 序列化/反序列化不丢失 attrs。"""
    n = AttackGraphNode(
        id="host:1.2.3.4",
        type="host",
        label="1.2.3.4",
        attrs={"ip": "1.2.3.4", "os": "linux"},
    )
    e = AttackGraphEdge(
        src="host:1.2.3.4",
        dst="svc:1.2.3.4:80",
        relation="exposes",
        attrs={"protocol": "tcp"},
    )
    g = AttackGraph(nodes=[n], edges=[e])
    payload = g.to_payload()
    json_str = json.dumps(payload, default=str)
    loaded = json.loads(json_str)
    assert loaded["nodes"][0]["attrs"]["ip"] == "1.2.3.4"
    assert loaded["edges"][0]["attrs"]["protocol"] == "tcp"


def test_world_model_state_method():
    """PentestState.world_model() 惰性构造 WorldModelQuery。"""
    state = _make_state()
    attach_host_to_graph(state, "10.0.0.5")
    wm = state.world_model()
    assert isinstance(wm, WorldModelQuery)
    assert wm.exploitable_frontier() == []
