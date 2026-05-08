"""Unit tests for A3/A4: DeepScanCoordinator + pick_followups +回流 semantics.

All tests are pure-Python, no docker / LLM required. The ReconAgent drain
path is covered by a lightweight integration test that stubs the executor
so that feroxbuster is never actually invoked.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from backend.tools.deep_scan_coordinator import (
    DeepScanCoordinator,
    DeepScanTarget,
    pick_followups,
)
from backend.tools.parsers.path_aggregator import PathAggregator



def test_coordinator_dedupe_normalised_path():
    coord = DeepScanCoordinator()
    assert coord.enqueue(DeepScanTarget(path="/admin", reason="r1")) is True
    assert coord.enqueue(DeepScanTarget(path="admin", reason="r2")) is False
    assert coord.enqueue(DeepScanTarget(path="/admin/", reason="r3")) is False
    assert coord.pending_count() == 1


def test_coordinator_priority_upgrade_keeps_single_entry():
    coord = DeepScanCoordinator()
    coord.enqueue(DeepScanTarget(path="/api", reason="low", priority=10))
    coord.enqueue(DeepScanTarget(path="/api", reason="high", priority=80))
    batch = coord.pop_batch(5)
    assert len(batch) == 1
    assert batch[0].priority == 80
    assert batch[0].reason == "high"


def test_coordinator_pop_batch_respects_priority_order():
    coord = DeepScanCoordinator()
    coord.enqueue(DeepScanTarget(path="/a", priority=10))
    coord.enqueue(DeepScanTarget(path="/b", priority=90))
    coord.enqueue(DeepScanTarget(path="/c", priority=50))
    batch = coord.pop_batch(3)
    assert [t.path for t in batch] == ["/b", "/c", "/a"]


def test_coordinator_scanned_blocks_re_enqueue():
    coord = DeepScanCoordinator()
    coord.enqueue(DeepScanTarget(path="/foo"))
    coord.mark_scanned("/foo", elapsed_s=12.5)
    assert coord.enqueue(DeepScanTarget(path="/foo")) is False
    assert coord.has_been_scanned("foo") is True
    assert coord.scanned_count() == 1
    assert coord.stats().elapsed_s == pytest.approx(12.5)


def test_coordinator_budget_exhaustion():
    coord = DeepScanCoordinator(max_total_scans=2)
    coord.enqueue(DeepScanTarget(path="/a"))
    coord.enqueue(DeepScanTarget(path="/b"))
    coord.enqueue(DeepScanTarget(path="/c"))
    coord.mark_scanned("/a")
    coord.mark_scanned("/b")
    assert coord.pop_batch(5) == []
    assert coord.can_scan() is False


def test_coordinator_wall_time_budget():
    coord = DeepScanCoordinator(max_total_scans=10, budget_seconds=30.0)
    coord.enqueue(DeepScanTarget(path="/x"))
    coord.mark_scanned("/x", elapsed_s=35.0)
    assert coord.can_scan() is False



def test_pick_followups_matches_orchestrator_scoring():
    agg = PathAggregator()
    agg.add_paths(
        ["/admin/", "/backup", "/random.html", "/image.png", "/dashboard/"],
        source="ferox", status=200,
    )
    out = pick_followups(
        ["/admin/", "/backup", "/random.html", "/image.png", "/dashboard/"],
        agg,
        scanned=set(),
    )
    assert "/admin/" in out
    assert "/backup" in out
    assert "/dashboard/" in out
    assert "/random.html" not in out
    assert "/image.png" not in out


def test_pick_followups_respects_scanned_normalized():
    agg = PathAggregator()
    agg.add_paths(["/admin/", "/api"], source="ferox", status=200)
    out = pick_followups(
        ["/admin/", "/api"], agg, scanned={"/admin"},
    )
    assert "/admin/" not in out
    assert "/api" in out


def test_pick_followups_cap():
    agg = PathAggregator()
    paths = [f"/admin{i}/" for i in range(20)]
    agg.add_paths(paths, source="ferox", status=200)
    out = pick_followups(paths, agg, scanned=set())
    assert len(out) == 10



class _StubExecResult:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.exit_code = 0
        self.success = True
        self.elapsed = 0.01


class _StubExecutor:
    """Records every script invocation; returns canned ferox output."""

    def __init__(self) -> None:
        self.runs: list[str] = []
        self.scripted_outputs: dict[str, str] = {}
        self.default_output = ""

    async def run_script(self, script_content: str, **kwargs) -> _StubExecResult:
        self.runs.append(script_content)
        for needle, stdout in self.scripted_outputs.items():
            if needle in script_content:
                return _StubExecResult(stdout)
        return _StubExecResult(self.default_output)


@pytest.mark.asyncio
async def test_drain_queue_executes_in_priority_order_and_feeds_back():
    """When coordinator has targets queued from both Phase 2 and Phase 3,
    drain should pop them priority-desc, run ferox once per target, and
    feed dir-like discoveries back into the queue automatically."""
    from backend.agents.recon_agent import ReconAgent

    agent = ReconAgent.__new__(ReconAgent)
    stub = _StubExecutor()
    stub.scripted_outputs["/admin"] = (
        "200      GET     1l        4w      100c http://t/admin/users/\n"
        "200      GET     1l        4w      100c http://t/admin/config/\n"
    )
    stub.scripted_outputs["/api"] = (
        "200      GET     1l        4w      50c http://t/api/status.json\n"
    )
    agent.executor = stub

    coord = DeepScanCoordinator(max_total_scans=10, budget_seconds=120.0)
    coord.enqueue(DeepScanTarget(path="/admin", reason="phase2", priority=40))
    coord.enqueue(DeepScanTarget(path="/api", reason="phase3-llm", priority=60))

    aggregator = PathAggregator()

    await agent._drain_deep_scan_queue(
        base_url="http://t",
        aggregator=aggregator,
        coord=coord,
        task_id=None,
        max_rounds=3,
        batch_size=5,
    )

    assert coord.has_been_scanned("/admin")
    assert coord.has_been_scanned("/api")
    assert "/api" in stub.runs[0]
    assert "/admin" in stub.runs[1]
    scanned_paths = [p for p in coord._scanned]
    assert "/admin/users" in scanned_paths
    assert "/admin/config" in scanned_paths
