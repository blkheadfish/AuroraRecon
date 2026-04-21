"""Unit tests for A1/A2: _should_consult_llm threshold + _find_deep_scan_candidates scoring.

All tests are pure-Python, no docker/LLM required.
"""
from __future__ import annotations

import pytest

from backend.tools.dir_scan_orchestrator import DirScanOrchestrator


class _FakePlanner:
    def __init__(self, remaining_budget: float = 600.0) -> None:
        self.remaining_budget = remaining_budget


def _make_orchestrator(budget: float = 600.0) -> DirScanOrchestrator:
    orch = DirScanOrchestrator.__new__(DirScanOrchestrator)
    from backend.tools.parsers.path_aggregator import PathAggregator
    orch.aggregator = PathAggregator()
    orch.planner = _FakePlanner(budget)
    orch._round = 0
    orch._recent_new_hints = set()
    orch._deep_scan_queue = []
    return orch


# ───────────────────── A1 ─────────────────────
def test_should_consult_llm_high_value_hint_short_circuits():
    orch = _make_orchestrator()
    orch._round = 0
    orch._recent_new_hints = {"admin"}
    assert orch._should_consult_llm(new_paths=1, tool_name="ferox", elapsed=10.0) is True


def test_should_consult_llm_round_zero_without_hint_skips():
    orch = _make_orchestrator()
    orch._round = 0
    orch._recent_new_hints = set()
    assert orch._should_consult_llm(new_paths=50, tool_name="ferox", elapsed=10.0) is False


def test_should_consult_llm_lower_new_paths_threshold():
    orch = _make_orchestrator()
    orch._round = 1
    orch._recent_new_hints = set()
    # 9 new paths should now trigger (old threshold was >15)
    assert orch._should_consult_llm(new_paths=9, tool_name="ferox", elapsed=10.0) is True
    assert orch._should_consult_llm(new_paths=8, tool_name="ferox", elapsed=10.0) is False


def test_should_consult_llm_budget_gate_with_empty_round():
    orch = _make_orchestrator(budget=100.0)  # < 180s left
    orch._round = 2
    orch._recent_new_hints = set()
    assert orch._should_consult_llm(new_paths=0, tool_name="ferox", elapsed=10.0) is True


def test_track_recent_hints_only_new_paths():
    orch = _make_orchestrator()
    # Seed aggregator (paths get normalized to leading / no trailing slash)
    orch.aggregator.add_paths(["/old/foo"], source="seed", status=200)
    orch.aggregator.add_paths(["/admin", "/login.php"], source="ferox", status=200)
    new = ["/admin", "/login.php"]
    orch._track_recent_hints(new)
    assert "admin" in orch._recent_new_hints
    assert "login" in orch._recent_new_hints


def test_track_recent_hints_ignores_unknown_paths():
    """New paths that weren't in the aggregator shouldn't contribute hints or crash."""
    orch = _make_orchestrator()
    orch.aggregator.add_paths(["/admin"], source="ferox", status=200)
    orch._track_recent_hints(["/ghost", "/admin"])
    assert "admin" in orch._recent_new_hints


# ───────────────────── A2 ─────────────────────
def test_find_deep_scan_candidates_scores_keyword_only_dir():
    orch = _make_orchestrator()
    paths = ["admin/", "backup", "random.html", "image.png"]
    orch.aggregator.add_paths(paths, source="ferox", status=200)
    out = orch._find_deep_scan_candidates(paths, already_scanned=set())
    assert "admin/" in out
    assert "backup" in out
    assert "random.html" not in out
    assert "image.png" not in out


def test_find_deep_scan_candidates_respects_already_scanned():
    orch = _make_orchestrator()
    orch.aggregator.add_paths(["admin/", "api/"], source="ferox", status=200)
    out = orch._find_deep_scan_candidates(["admin/", "api/"], already_scanned={"admin/"})
    assert "admin/" not in out
    assert "api/" in out


def test_find_deep_scan_candidates_cap_is_ten():
    orch = _make_orchestrator()
    paths = [f"admin{i}/" for i in range(20)]
    orch.aggregator.add_paths(paths, source="ferox", status=200)
    out = orch._find_deep_scan_candidates(paths, already_scanned=set())
    assert len(out) == 10


def test_find_deep_scan_candidates_non_dir_with_keyword_still_picks_up():
    orch = _make_orchestrator()
    orch.aggregator.add_paths(["config.bak"], source="ferox", status=200)
    out = orch._find_deep_scan_candidates(["config.bak"], already_scanned=set())
    # keyword 'backup' (+3) alone is enough; plus high-value hint 'backup' (+2) = 5
    assert "config.bak" in out
