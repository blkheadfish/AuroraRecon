"""Linear 模式回归冒烟测试。

验证项：
  - ``ATTACK_CHAIN_MODE=linear``（或未设置）时， build_graph 编译成功；
  - 老 edge 函数（``edge_after_foothold`` 等）行为未变；
  - ``Orchestrator._make_run_config`` 在 linear 模式下使用默认 recursion_limit；
  - linear 图上不存在反馈回流分支（vuln_scan ← post_foothold_enum 等）。
"""
from __future__ import annotations

import os
from contextlib import contextmanager

import pytest

from backend.agents.models import PentestState, TaskStatus, VulnFinding
from backend.agents.orchestrator import (
    Orchestrator,
    _build_graph_linear,
    _current_chain_mode,
    build_graph,
    edge_after_foothold,
    edge_after_privesc,
    edge_after_secondary,
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


# ─── 模式分发 ───────────────────────────────────────────────

def test_default_mode_is_linear():
    with _attack_mode(None):
        assert _current_chain_mode() == "linear"


def test_invalid_mode_falls_back_to_linear():
    with _attack_mode("garbage_mode"):
        assert _current_chain_mode() == "linear"


def test_build_graph_linear_compiles():
    with _attack_mode("linear"):
        compiled = build_graph(checkpointer=None)
        assert compiled is not None


def test_direct_linear_builder_compiles():
    """直接调用 _build_graph_linear，绕过环境变量。"""
    compiled = _build_graph_linear(checkpointer=None)
    assert compiled is not None


# ─── linear 模式 recursion_limit 较低 ──────────────────────

def test_linear_run_config_has_low_recursion():
    with _attack_mode("linear"):
        cfg = Orchestrator._make_run_config("task-1")
        assert cfg["recursion_limit"] <= 50
        assert cfg["configurable"]["thread_id"] == "task-1"


# ─── 老 edge 函数行为：linear 模式下完全保持原有逻辑 ──────

def test_edge_after_foothold_with_shell_goes_to_post():
    state = PentestState(target="x")
    state.got_shell = True
    assert edge_after_foothold(state) == "post_foothold_enum"


def test_edge_after_foothold_failed_goes_to_report():
    state = PentestState(target="x")
    state.status = TaskStatus.FAILED
    assert edge_after_foothold(state) == "report"


def test_edge_after_foothold_secondary_when_exploitable():
    state = PentestState(target="x")
    state.findings = [
        VulnFinding(name="x", severity="high", target="x", port=80, exploitable=True),
    ]
    assert edge_after_foothold(state) == "secondary_attack"


def test_edge_after_foothold_file_read_promotes_secondary():
    state = PentestState(target="x")
    state.foothold_status = "file_read"
    state.secondary_attack_done = False
    assert edge_after_foothold(state) == "secondary_attack"


def test_edge_after_secondary_shell_goes_post():
    state = PentestState(target="x")
    state.got_shell = True
    assert edge_after_secondary(state) == "post_foothold_enum"


def test_edge_after_secondary_no_shell_goes_report():
    state = PentestState(target="x")
    state.got_shell = False
    assert edge_after_secondary(state) == "report"


def test_edge_after_privesc_root_goes_objective():
    state = PentestState(target="x")
    state.privilege_level = "root"
    assert edge_after_privesc(state) == "objective_collect"


def test_edge_after_privesc_loops_when_under_cap():
    state = PentestState(target="x")
    state.privilege_level = "user"
    state.privesc_attempt_count = 1
    state.max_privesc_rounds = 3
    assert edge_after_privesc(state) == "privesc_again"


def test_edge_after_privesc_stops_when_cap_reached():
    state = PentestState(target="x")
    state.privilege_level = "user"
    state.privesc_attempt_count = 5
    state.max_privesc_rounds = 3
    assert edge_after_privesc(state) == "objective_collect"


# ─── linear 模式下 graph 不应包含反馈回流目标 ──────────────

def test_linear_graph_topology_excludes_replan_targets():
    """linear 模式编译后的图结构里，secondary_attack 不应路由到 vuln_scan。"""
    compiled = _build_graph_linear(checkpointer=None)
    # langgraph compiled graph 暴露 .get_graph()，其 edges/branches 反映拓扑
    drawn = compiled.get_graph()
    edge_pairs = {(e.source, e.target) for e in drawn.edges}
    # 老边: secondary_attack -> post_foothold_enum / report (经条件边/分支)
    # 反馈边 secondary_attack -> vuln_scan / surface_enum 必须不存在
    assert ("secondary_attack", "vuln_scan") not in edge_pairs
    assert ("secondary_attack", "surface_enum") not in edge_pairs
    assert ("post_foothold_enum", "vuln_scan") not in edge_pairs
    assert ("post_foothold_enum", "recon") not in edge_pairs
    assert ("post_foothold_enum", "surface_enum") not in edge_pairs
