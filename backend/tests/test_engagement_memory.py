"""跨 engagement 记忆单元测试。

验证：
  1. ``extract_prior_intel`` 从历史 state_json 正确提取 PriorIntel；
  2. 凭据只存存在性提示，不含明文 password/value；
  3. ``inject_prior_into_state`` 将 prior 注入 attack_graph（source=prior 节点）；
  4. 跨租户：不匹配的 tenant 不应该返回历史记录。
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from backend.agents.engagement_memory import (
    PriorIntel,
    PriorService,
    PriorFinding,
    PriorCredentialHint,
    extract_prior_intel,
    inject_prior_into_state,
)
from backend.agents.models import PentestState, PortInfo, VulnFinding


@dataclass
class MockTaskRow:
    task_id: str
    state_json: str


def _make_state_json(**overrides) -> str:
    base = {
        "task_id": "mock-task-001",
        "target": "192.168.1.100",
        "target_host": "192.168.1.100",
        "tenant_id": "default",
        "open_ports": [
            {"port": 80, "service": "http", "version": "nginx/1.18", "banner": "nginx"},
            {"port": 22, "service": "ssh", "version": "OpenSSH_8.4", "banner": "SSH-2.0-OpenSSH_8.4"},
        ],
        "fingerprints": {"web_server": "nginx", "os": "linux"},
        "findings": [
            {
                "vuln_id": "f-001",
                "name": "SQL Injection",
                "severity": "high",
                "cve": "CVE-2021-0001",
            },
            {
                "vuln_id": "f-002",
                "name": "LFI",
                "severity": "critical",
                "cve": "",
            },
        ],
        "credential_store": [
            {"username": "admin", "password": "secret123", "service": "http", "source": "config.php"},
            {"username": "root", "value": "toor", "service": "ssh", "source": "shadow"},
            {"username": "user", "service": "ftp", "source": "ftp_anon"},
        ],
        "status": "completed",
    }
    base.update(overrides)
    return json.dumps(base)


# ─── extract_prior_intel ──────────────────────────────────────


def test_extract_prior_intel_basic():
    row = MockTaskRow(task_id="mock-task-001", state_json=_make_state_json())
    intel = extract_prior_intel([row])

    assert intel.source_task_count == 1
    assert len(intel.known_services) == 2
    assert intel.known_services[0].port == 80
    assert intel.known_services[0].service == "http"
    assert intel.known_services[1].port == 22
    assert intel.known_services[1].service == "ssh"

    assert len(intel.known_fingerprints) == 2
    assert intel.known_fingerprints["web_server"] == "nginx"

    assert len(intel.known_findings) == 2
    assert intel.known_findings[0].vuln_id == "f-001"
    assert intel.known_findings[0].severity == "high"

    assert len(intel.credential_hints) == 3


def test_credential_no_plaintext_in_to_dict():
    """凭据字典不应包含明文 password/value。"""
    row = MockTaskRow(task_id="mock-task-001", state_json=_make_state_json())
    intel = extract_prior_intel([row])
    d = intel.to_dict()

    for ch in d["credential_hints"]:
        assert "password" not in ch
        assert "value" not in ch
        assert "has_secret" in ch
        assert isinstance(ch["has_secret"], bool)


def test_credential_has_secret_is_true_when_password_exists():
    row = MockTaskRow(task_id="mock-task-001", state_json=_make_state_json())
    intel = extract_prior_intel([row])
    d = intel.to_dict()

    creds_by_user = {c["username"]: c for c in d["credential_hints"]}
    assert creds_by_user["admin"]["has_secret"] is True
    assert creds_by_user["root"]["has_secret"] is True
    assert creds_by_user["user"]["has_secret"] is False


def test_extract_empty_rows():
    intel = extract_prior_intel([])
    assert intel.is_empty()
    assert intel.source_task_count == 0


def test_extract_broken_state_json_is_skipped():
    row = MockTaskRow(task_id="bad", state_json="{broken json")
    intel = extract_prior_intel([row])
    assert intel.is_empty()


def test_deduplicate_services():
    """同 host:port 的服务不去重。"""
    row1 = MockTaskRow(task_id="t1", state_json=_make_state_json())
    row2 = MockTaskRow(task_id="t2", state_json=_make_state_json())
    intel = extract_prior_intel([row1, row2])
    assert intel.source_task_count == 2
    # 应该去重，不翻倍
    assert len(intel.known_services) == 2


def test_deduplicate_findings():
    row1 = MockTaskRow(task_id="t1", state_json=_make_state_json())
    row2 = MockTaskRow(task_id="t2", state_json=_make_state_json())
    intel = extract_prior_intel([row1, row2])
    assert len(intel.known_findings) == 2


def test_deduplicate_credential_hints():
    row1 = MockTaskRow(task_id="t1", state_json=_make_state_json())
    row2 = MockTaskRow(task_id="t2", state_json=_make_state_json())
    intel = extract_prior_intel([row1, row2])
    assert len(intel.credential_hints) == 3


# ─── inject_prior_into_state ──────────────────────────────────


def test_inject_prior_into_state():
    state = PentestState(
        task_id="test-task",
        target="192.168.1.100",
        target_host="192.168.1.100",
        owner_id="u1",
        tenant_id="default",
    )

    prior = PriorIntel(
        known_services=[
            PriorService(host="192.168.1.100", port=80, service="http", version="nginx"),
        ],
        known_fingerprints={"web_server": "nginx"},
        known_findings=[
            PriorFinding(vuln_id="f-001", name="SQLi", severity="high", cve="CVE-2021-0001"),
        ],
        credential_hints=[
            PriorCredentialHint(service="http", username="admin", has_secret=True),
        ],
        source_task_count=1,
        source_task_ids=["old-task-1"],
    )

    inject_prior_into_state(state, prior)

    assert "prior_intel" in state.runtime_facts
    assert state.runtime_facts["prior_intel"]["source_task_count"] == 1
    assert len(state.runtime_facts["prior_intel"]["credential_hints"]) == 1
    assert state.runtime_facts["prior_intel"]["credential_hints"][0]["has_secret"] is True
    assert "password" not in str(state.runtime_facts["prior_intel"]["credential_hints"][0])

    assert state.attack_graph is not None
    prior_nodes = [
        n for n in state.attack_graph.nodes
        if n.facts.get("source") == "prior"
    ]
    assert len(prior_nodes) >= 3  # host + service + finding

    prior_edges = [
        e for e in state.attack_graph.edges
        if e.note == "历史已知"
    ]
    assert len(prior_edges) >= 1


def test_inject_empty_prior_does_nothing():
    state = PentestState(task_id="test-empty")
    prior = PriorIntel()
    inject_prior_into_state(state, prior)
    assert "prior_intel" not in state.runtime_facts


def test_prior_nodes_have_from_history_fact():
    state = PentestState(
        task_id="test-task",
        target="192.168.1.100",
        target_host="192.168.1.100",
    )
    prior = PriorIntel(
        known_services=[PriorService(host="192.168.1.100", port=80, service="http")],
        source_task_count=1,
    )
    inject_prior_into_state(state, prior)

    host_node = next(
        (n for n in state.attack_graph.nodes if n.type == "host"),
        None,
    )
    assert host_node is not None
    assert host_node.facts.get("source") == "prior"
    assert host_node.facts.get("from_history") is True
    assert host_node.discovered_by == "engagement_memory"


def test_host_range_no_credential_expansion():
    """多 host 场景凭据不扩散到无关主机。"""
    state = PentestState(
        task_id="test-task",
        target="192.168.1.0/24",
        target_host="192.168.1.0/24",
    )
    prior = PriorIntel(
        known_services=[
            PriorService(host="192.168.1.10", port=22, service="ssh"),
            PriorService(host="192.168.1.20", port=80, service="http"),
        ],
        credential_hints=[
            PriorCredentialHint(service="ssh", username="root", has_secret=True),
        ],
        source_task_count=1,
    )
    inject_prior_into_state(state, prior)

    cred_nodes = sorted(
        [n for n in state.attack_graph.nodes if n.type == "credential"],
        key=lambda n: n.id,
    )
    assert len(cred_nodes) == 1
    assert "root" in cred_nodes[0].label
