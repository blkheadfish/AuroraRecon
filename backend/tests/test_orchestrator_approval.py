"""
Regression tests for the refactored approval flow in the orchestrator.

Covers:
  - edge_should_exploit routes to `foothold_attempt` when auto_approve=True and
    there are exploitable findings, bypassing the human_approval interrupt.
  - edge_should_exploit routes to `report` when the task already failed or
    there is nothing exploitable, regardless of auto_approve.
  - node_human_approval auto-sets approved=True when auto_approve is on,
    and keeps exploitable findings intact.
  - node_human_approval keeps approved=False (and disables exploitable) when
    auto_approve is off and no explicit approval was granted.
"""
from __future__ import annotations

import asyncio

import pytest

from backend.agents.models import PentestState, TaskStatus, VulnFinding
from backend.agents.orchestrator import edge_should_exploit, node_human_approval


def _make_state(
    *,
    auto_approve: bool,
    status: TaskStatus = TaskStatus.PENDING,
    exploitable: bool = True,
) -> PentestState:
    state = PentestState(task_id="t-edge", target="http://x")
    state.auto_approve = auto_approve
    state.status = status
    if exploitable:
        state.findings.append(
            VulnFinding(
                name="Test Vuln",
                target="http://x",
                exploitable=True,
            )
        )
    return state


class TestEdgeShouldExploit:
    def test_failed_goes_to_report(self):
        state = _make_state(auto_approve=True, status=TaskStatus.FAILED)
        assert edge_should_exploit(state) == "report"

    def test_no_exploitable_goes_to_report(self):
        state = _make_state(auto_approve=False, exploitable=False)
        assert edge_should_exploit(state) == "report"

    def test_auto_approve_bypasses_human_approval(self):
        state = _make_state(auto_approve=True)
        assert edge_should_exploit(state) == "foothold_attempt"

    def test_manual_flow_routes_to_human_approval(self):
        state = _make_state(auto_approve=False)
        assert edge_should_exploit(state) == "human_approval"


class TestNodeHumanApproval:
    @pytest.mark.asyncio
    async def test_auto_approve_sets_approved_and_keeps_findings(self):
        state = _make_state(auto_approve=True)
        result = await node_human_approval(state)
        assert result.approved is True
        assert result.current_phase == "awaiting_approval"
        assert all(f.exploitable for f in result.findings)

    @pytest.mark.asyncio
    async def test_manual_pending_keeps_approved_false(self):
        state = _make_state(auto_approve=False)
        result = await node_human_approval(state)
        assert result.approved is False
        assert all(not f.exploitable for f in result.findings)

    @pytest.mark.asyncio
    async def test_manual_approved_by_router_keeps_exploitable(self):
        state = _make_state(auto_approve=False)
        state.approved = True
        result = await node_human_approval(state)
        assert result.approved is True
        assert any(f.exploitable for f in result.findings)
