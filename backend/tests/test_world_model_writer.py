"""WorldModelWriter 统一写入入口单元测试 (WS1.5 R2)."""

from __future__ import annotations

from backend.agents.models import PentestState, VulnFinding
from backend.agents.world_model import WorldModelWriter


def _make_state() -> PentestState:
    return PentestState(target="http://test.local")


def test_writer_upsert_node_idempotent():
    state = _make_state()
    w = WorldModelWriter(state)
    nid1 = w.upsert_node("host", "host:1.2.3.4", attrs={"ip": "1.2.3.4"})
    nid2 = w.upsert_node("host", "host:1.2.3.4", attrs={"os": "linux"})
    assert nid1 == nid2 == "host:1.2.3.4"
    node = state.attack_graph.nodes[0]
    assert node.type == "host"
    merged = {**node.attrs, **node.facts}
    assert merged.get("ip") == "1.2.3.4"
    assert merged.get("os") == "linux"


def test_writer_add_edge():
    state = _make_state()
    w = WorldModelWriter(state)
    w.upsert_node("host", "host:1.2.3.4")
    w.upsert_node("service", "svc:1.2.3.4:80", attrs={"port": 80, "service": "http"})
    w.add_edge("host:1.2.3.4", "svc:1.2.3.4:80", "exposes", attrs={"protocol": "tcp"})
    assert len(state.attack_graph.edges) == 1
    e = state.attack_graph.edges[0]
    assert e.src == "host:1.2.3.4"
    assert e.dst == "svc:1.2.3.4:80"
    assert e.relation == "exposes"
    assert e.attrs.get("protocol") == "tcp"


def test_writer_add_finding():
    state = _make_state()
    w = WorldModelWriter(state)
    f = VulnFinding(
        vuln_id="CVE-2024-0001",
        name="Test RCE",
        severity="high",
        cve="CVE-2024-0001",
        port=80,
        target="http://10.0.0.1",
        exploitable=True,
    )
    fid = w.add_finding(f)
    assert fid == "finding:CVE-2024-0001"
    node = state.attack_graph.nodes[0]
    assert node.type == "finding"
    assert node.attrs.get("cve") == "CVE-2024-0001"
    assert node.attrs.get("severity") == "high"
    assert node.attrs.get("exploitable") is True
    assert node.attrs.get("exploited") is False


def test_writer_add_credential():
    state = _make_state()
    w = WorldModelWriter(state)
    cred = {"user": "admin", "password": "secret", "source": "ssh", "validated": True}
    cid = w.add_credential(cred)
    assert cid.startswith("cred:")
    node = state.attack_graph.nodes[0]
    assert node.type == "credential"
    assert node.attrs.get("username") == "admin"
    assert node.attrs.get("validated") is True
    assert node.attrs.get("has_secret") is True


def test_writer_add_session():
    state = _make_state()
    w = WorldModelWriter(state)
    sid = w.add_session("10.0.0.5", "root", "bash")
    assert sid == "session:10.0.0.5:root"
    node = state.attack_graph.nodes[0]
    assert node.type == "session"
    assert node.attrs.get("host") == "10.0.0.5"
    assert node.attrs.get("privilege") == "root"
    assert node.attrs.get("shell_type") == "bash"
    assert len(state.attack_graph.edges) >= 1


def test_writer_equivalent_to_attach_functions():
    """WorldModelWriter 的 add_finding 与 attach_finding_to_graph 语义等价。"""
    from backend.agents.fact_hooks import attach_finding_to_graph
    f = VulnFinding(
        vuln_id="EQUIV-001",
        name="Equiv Test",
        severity="critical",
        cve="CVE-2025-0001",
        exploitable=True,
    )
    state1 = _make_state()
    attach_finding_to_graph(state1, f)
    state2 = _make_state()
    w2 = WorldModelWriter(state2)
    w2.add_finding(f)
    assert len(state1.attack_graph.nodes) == len(state2.attack_graph.nodes)
    n1 = state1.attack_graph.nodes[0]
    n2 = state2.attack_graph.nodes[0]
    assert n1.type == n2.type
    assert n1.attrs.get("cve") == n2.attrs.get("cve")
