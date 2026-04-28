"""Regression tests for phase idempotency helpers in fact_hooks.

阶段 B（幂等增量）的核心断言：

  - compute_phase_signature 对相同输入产出稳定 sha1；
  - should_skip_phase 在 (visit>0 且 prior_sig == sig) 时返回 (True, "duplicate_input_signature")；
  - mark_phase_visited 正确累加 phase_visit_count 与 phase_signature；
  - consume_pending_seeds / push_pending_seed 与桶解耦、去重；
  - 当 phase_visit_count 触达 max_phase_visits[phase] 时强制返回 (True, cap-reached)。
"""
from __future__ import annotations

from backend.agents.fact_hooks import (
    compute_phase_signature,
    consume_pending_seeds,
    mark_phase_visited,
    push_pending_seed,
    should_skip_phase,
)
from backend.agents.models import PentestState


# ─── 基础签名 ────────────────────────────────────────────────

def test_compute_phase_signature_stable_for_same_payload():
    a = compute_phase_signature({"hosts": ["1.1.1.1", "2.2.2.2"]})
    b = compute_phase_signature({"hosts": ["1.1.1.1", "2.2.2.2"]})
    assert a == b
    assert len(a) == 40  # sha1 hex


def test_compute_phase_signature_invariant_to_dict_order():
    # 两个 dict 的键序不同, signature 应一致(sort_keys=True)
    a = compute_phase_signature({"a": 1, "b": 2})
    b = compute_phase_signature({"b": 2, "a": 1})
    assert a == b


def test_compute_phase_signature_changes_with_payload():
    a = compute_phase_signature({"hosts": ["1.1.1.1"]})
    b = compute_phase_signature({"hosts": ["1.1.1.1", "2.2.2.2"]})
    assert a != b


# ─── 跳过逻辑 ────────────────────────────────────────────────

def test_should_skip_phase_first_visit_never_skips():
    state = PentestState(target="http://x")
    sig = compute_phase_signature({"any": 1})
    skip, reason = should_skip_phase(state, "recon", sig)
    assert skip is False
    assert reason == ""


def test_should_skip_phase_duplicate_signature_skips():
    state = PentestState(target="http://x")
    sig = compute_phase_signature({"hosts": ["1.1.1.1"]})
    mark_phase_visited(state, "recon", sig)

    # 同样的 signature 第二次进入 → 应直接跳过
    skip, reason = should_skip_phase(state, "recon", sig)
    assert skip is True
    assert "duplicate" in reason


def test_should_skip_phase_new_signature_does_not_skip():
    state = PentestState(target="http://x")
    sig1 = compute_phase_signature({"hosts": ["1.1.1.1"]})
    mark_phase_visited(state, "recon", sig1)

    # 新主机加入后 signature 变化 → 不应跳过
    sig2 = compute_phase_signature({"hosts": ["1.1.1.1", "2.2.2.2"]})
    skip, reason = should_skip_phase(state, "recon", sig2)
    assert skip is False


def test_should_skip_phase_cap_reached_forces_skip():
    state = PentestState(target="http://x")
    state.max_phase_visits["recon"] = 2
    sig_a = compute_phase_signature({"i": 1})
    sig_b = compute_phase_signature({"i": 2})
    mark_phase_visited(state, "recon", sig_a)
    mark_phase_visited(state, "recon", sig_b)

    sig_c = compute_phase_signature({"i": 3})
    skip, reason = should_skip_phase(state, "recon", sig_c)
    assert skip is True
    assert "cap_reached" in reason


def test_mark_phase_visited_increments_counter():
    state = PentestState(target="http://x")
    mark_phase_visited(state, "vuln_scan", "sig-1")
    assert state.phase_visit_count["vuln_scan"] == 1
    assert state.phase_signature["vuln_scan"] == "sig-1"

    mark_phase_visited(state, "vuln_scan", "sig-2")
    assert state.phase_visit_count["vuln_scan"] == 2
    assert state.phase_signature["vuln_scan"] == "sig-2"


# ─── pending_seeds 增量 ──────────────────────────────────────

def test_consume_pending_seeds_returns_and_clears_bucket():
    state = PentestState(target="http://x")
    state.pending_seeds["hosts"].extend(["10.0.0.1", "10.0.0.2"])
    seeds = consume_pending_seeds(state, "hosts")
    assert seeds == ["10.0.0.1", "10.0.0.2"]
    # 第二次调用应该是空的
    assert consume_pending_seeds(state, "hosts") == []


def test_consume_pending_seeds_unknown_bucket_returns_empty():
    state = PentestState(target="http://x")
    assert consume_pending_seeds(state, "bogus_bucket") == []


def test_push_pending_seed_dedupes():
    state = PentestState(target="http://x")
    push_pending_seed(state, "credentials", {"user": "root", "value": "toor"})
    push_pending_seed(state, "credentials", {"user": "root", "value": "toor"})
    push_pending_seed(state, "credentials", {"user": "admin", "value": "admin"})
    assert len(state.pending_seeds["credentials"]) == 2


def test_push_pending_seed_handles_missing_pending_seeds():
    state = PentestState(target="http://x")
    state.pending_seeds = {}  # 模拟旧 checkpoint 反序列化场景
    push_pending_seed(state, "web_paths", "/admin/login")
    assert "web_paths" in state.pending_seeds
    assert state.pending_seeds["web_paths"] == ["/admin/login"]


# ─── 综合：增量驱动重入应触发重跑（不跳过） ─────────────────

def test_idempotency_with_seed_drives_reentry():
    """在第一轮固化签名后，加入新种子使签名变化，确保第二轮不会跳过。"""
    state = PentestState(target="http://x")
    state.target_host = "1.1.1.1"

    # 第一轮 recon
    targets_round1 = [state.target_host]
    sig1 = compute_phase_signature({"targets": targets_round1})
    skip, _ = should_skip_phase(state, "recon", sig1)
    assert skip is False
    mark_phase_visited(state, "recon", sig1)

    # 同样输入第二次进入 → 跳过
    skip, reason = should_skip_phase(state, "recon", sig1)
    assert skip is True

    # 注入新种子主机 → signature 变化, 不应跳过
    push_pending_seed(state, "hosts", "2.2.2.2")
    seeds = consume_pending_seeds(state, "hosts")
    targets_round2 = [state.target_host] + seeds
    sig2 = compute_phase_signature({"targets": targets_round2})
    assert sig2 != sig1
    skip, _ = should_skip_phase(state, "recon", sig2)
    assert skip is False
