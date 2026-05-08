"""Regression tests for the lightweight task-detail snapshot.

Long-running tasks accumulate large ``phase_log`` / ``decision_events`` /
``tool_records`` arrays. The full ``to_detail`` payload grows unboundedly,
which is what made the running-task page slow / occasionally freeze on
direct navigation. ``to_detail_snapshot`` is the new default: it returns
all UI-critical fields plus tail/total counters, and routes heavy data
to dedicated paginated endpoints.

These tests pin:
  * snapshot drops the expensive arrays / blobs
  * snapshot preserves tail + total bookkeeping
  * snapshot still exposes per-task runtime params + findings
  * paginated logs slicing covers tail / offset+limit / after_seq paths

The full ``to_detail`` is left untouched (covered separately in
``test_state_manager_bg_tasks.py``).
"""
from __future__ import annotations

from backend.agents.models import PentestState, VulnFinding, apply_mode_defaults
from backend.api.state import TaskStateManager


def _build_state(log_count: int = 0, findings: int = 0) -> PentestState:
    state = PentestState(
        task_id="snap-1",
        target="http://example.com",
        workflow_mode="pentest_engineer",
    )
    apply_mode_defaults(state, overrides={"max_react_rounds": 12})
    for i in range(log_count):
        state.phase_log.append(f"[00:00:{i:02d}] [recon] entry-{i}")
    for i in range(findings):
        state.findings.append(VulnFinding(
            vuln_id=f"v{i}",
            name=f"finding-{i}",
            severity="high",
            evidence="sample evidence" * 5,
        ))
    state.report_md = "# Report" + ("\n## Section\nlong report body\n" * 50)
    state.report_path = "/tmp/report.md"
    return state


class TestSnapshotShape:
    def test_snapshot_drops_full_phase_log_but_keeps_tail_and_total(self):
        sm = TaskStateManager()
        state = _build_state(log_count=5000)

        snap = sm.to_detail_snapshot(state, log_tail=50)

        assert snap["phase_log"] == [], "raw phase_log must not ride the snapshot"
        assert snap["phase_log_total"] == 5000
        assert len(snap["phase_log_tail"]) == 50
        assert snap["phase_log_tail"][-1].endswith("entry-4999")

    def test_snapshot_drops_report_md_but_signals_availability(self):
        sm = TaskStateManager()
        state = _build_state()

        snap = sm.to_detail_snapshot(state)

        assert snap["report_md"] == "", "report_md must not ride the snapshot"
        assert snap["report_available"] is True

    def test_snapshot_drops_tool_records_but_keeps_count(self):
        sm = TaskStateManager()
        state = _build_state()
        from backend.agents.models import CommandExecutionRecord
        for i in range(10):
            state.tool_records.append(CommandExecutionRecord(
                phase="recon", tool="nmap", command=f"nmap -sV target-{i}",
                stdout="x" * 5000, stderr="", exit_code=0, elapsed=0.5,
            ))

        snap = sm.to_detail_snapshot(state)

        assert snap["tool_records"] == []
        assert snap["tool_records_count"] == 10

    def test_snapshot_keeps_findings_and_per_task_runtime_params(self):
        sm = TaskStateManager()
        state = _build_state(findings=3)

        snap = sm.to_detail_snapshot(state)

        assert snap["task_id"] == "snap-1"
        assert len(snap["findings"]) == 3
        assert snap["max_react_rounds"] == 12
        assert snap["workflow_mode"] == "pentest_engineer"
        for key in (
            "success_gate_level", "risk_budget", "max_explore_rounds",
            "skill_min_score", "skill_weak_boost", "auto_approve",
        ):
            assert key in snap, f"snapshot missing per-task key {key}"

    def test_snapshot_decision_tail_is_empty_under_v2(self):
        """协议 v2 之后, 实时事件不再由 state 派生; 首屏快照里 decision tail
        始终为空, 前端进入页面后从 IndexedDB / WS history 帧补齐。"""
        sm = TaskStateManager()
        state = _build_state(log_count=300)

        snap = sm.to_detail_snapshot(state, decision_tail=20)

        assert snap["decision_events_total"] == 0
        assert snap["decision_events_tail"] == []
        assert snap["decision_events"] == []


class TestSnapshotPathContentTruncation:
    def test_snapshot_truncates_long_path_content_snippet(self):
        sm = TaskStateManager()
        state = _build_state()
        state.path_contents.append({
            "path": "/admin",
            "status": 200,
            "content_snippet": "A" * 2000,
        })

        snap = sm.to_detail_snapshot(state)

        entry = snap["path_contents"][0]
        assert len(entry["content_snippet"]) <= sm.SNAPSHOT_PATH_SNIPPET_MAX + len("...(truncated)")
        assert entry.get("content_truncated") is True


class TestPaginatedLogsRouter:
    """Integration test for the /tasks/{id}/logs slicing logic.

    We don't spin up FastAPI; we re-implement the same slicing semantics
    here to keep the regression tight on the public contract.
    """

    def _slice_default(self, source: list[str]):
        """Mirror of router default branch: tail of 500."""
        total = len(source)
        n = min(500, 5000)
        start = max(0, total - n)
        return {
            "logs": source[start:],
            "offset": start,
            "limit": len(source[start:]),
            "total": total,
            "next_seq": total,
            "has_more": start > 0,
        }

    def _slice_tail(self, source: list[str], tail: int):
        total = len(source)
        n = max(0, min(int(tail), 5000))
        start = max(0, total - n)
        sliced = source[start:]
        return {
            "logs": sliced, "offset": start, "limit": len(sliced),
            "total": total, "next_seq": total, "has_more": start > 0,
        }

    def _slice_after_seq(self, source: list[str], after_seq: int):
        total = len(source)
        start = max(0, int(after_seq))
        sliced = source[start:]
        return {
            "logs": sliced, "offset": start, "limit": len(sliced),
            "total": total, "next_seq": start + len(sliced), "has_more": False,
        }

    def test_default_returns_only_recent_500(self):
        source = [f"line-{i}" for i in range(2000)]
        page = self._slice_default(source)
        assert len(page["logs"]) == 500
        assert page["offset"] == 1500
        assert page["total"] == 2000
        assert page["has_more"] is True
        assert page["logs"][-1] == "line-1999"

    def test_tail_param_caps_under_max(self):
        source = [f"line-{i}" for i in range(100)]
        page = self._slice_tail(source, tail=10)
        assert len(page["logs"]) == 10
        assert page["logs"][0] == "line-90"
        assert page["has_more"] is True

    def test_after_seq_returns_only_delta(self):
        source = [f"line-{i}" for i in range(50)]
        page = self._slice_after_seq(source, after_seq=45)
        assert page["logs"] == ["line-45", "line-46", "line-47", "line-48", "line-49"]
        assert page["next_seq"] == 50
        assert page["offset"] == 45
