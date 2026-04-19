"""
Regression tests for the refactored CreateTaskRequest + TaskSummary schemas.

Covers:
  - workflow_mode accepts both supported values and rejects invalid ones.
  - All per-task override fields default to None (so the router can tell the
    difference between "not provided" and an explicit override).
  - TaskSummary carries workflow_mode and auto_approve with safe defaults.
  - End-to-end parity: PentestState constructed from CreateTaskRequest +
    apply_mode_defaults mirrors the values the router would persist.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.agents.models import PentestState, apply_mode_defaults
from backend.api.schemas import CreateTaskRequest, TaskSummary


class TestCreateTaskRequest:
    def test_minimal_payload_uses_pentest_engineer_defaults(self):
        req = CreateTaskRequest(target="http://10.0.0.1")
        assert req.workflow_mode == "pentest_engineer"
        # per-task overrides should default to None so router can detect
        # "not provided" vs explicit override.
        assert req.auto_approve is None
        assert req.success_gate_level is None
        assert req.risk_budget is None
        assert req.max_react_rounds is None
        assert req.max_explore_rounds is None
        assert req.skill_min_score is None
        assert req.skill_weak_boost is None

    def test_workflow_mode_accepts_ctf_expert(self):
        req = CreateTaskRequest(target="10.0.0.1", workflow_mode="ctf_expert")
        assert req.workflow_mode == "ctf_expert"

    def test_invalid_workflow_mode_is_rejected(self):
        with pytest.raises(ValidationError):
            CreateTaskRequest(target="10.0.0.1", workflow_mode="redteam_lord")

    def test_invalid_success_gate_level_is_rejected(self):
        with pytest.raises(ValidationError):
            CreateTaskRequest(
                target="10.0.0.1",
                success_gate_level="extreme",
            )

    def test_target_shell_metachars_rejected(self):
        with pytest.raises(ValidationError):
            CreateTaskRequest(target="10.0.0.1; rm -rf /")

    def test_explicit_overrides_propagate_via_apply_mode_defaults(self):
        req = CreateTaskRequest(
            target="http://example.com",
            workflow_mode="ctf_expert",
            auto_approve=False,           # override CTF default (True)
            max_react_rounds=7,
            skill_min_score=33,
        )
        state = PentestState(
            task_id="tid",
            target=req.target,
            workflow_mode=req.workflow_mode,
        )
        apply_mode_defaults(
            state,
            overrides={
                "auto_approve": req.auto_approve,
                "success_gate_level": req.success_gate_level,
                "risk_budget": req.risk_budget,
                "max_react_rounds": req.max_react_rounds,
                "max_explore_rounds": req.max_explore_rounds,
                "skill_min_score": req.skill_min_score,
                "skill_weak_boost": req.skill_weak_boost,
            },
        )
        assert state.workflow_mode == "ctf_expert"
        assert state.auto_approve is False
        assert state.max_react_rounds == 7
        assert state.skill_min_score == 33
        # Un-overridden field still inherits ctf_expert default.
        assert state.success_gate_level == "lenient"
        assert state.skill_weak_boost == 10


class TestTaskSummary:
    def test_defaults_include_workflow_mode_and_auto_approve(self):
        # All required fields present, everything else default-able.
        summary = TaskSummary(
            task_id="t1",
            target="http://x",
            status="pending",
            current_phase="init",
            findings_count=0,
            got_shell=False,
            report_path="",
        )
        assert summary.workflow_mode == "pentest_engineer"
        assert summary.auto_approve is False

    def test_roundtrip_from_db_row_like_dict(self):
        """Simulate the "DB row → TaskSummary" path used by list_tasks when
        the row was written before the refactor (no workflow_mode column)."""
        legacy_row = {
            "task_id": "tid-legacy",
            "target": "10.0.0.1",
            "status": "completed",
            "current_phase": "done",
            "findings_count": 3,
            "got_shell": True,
            "report_path": "reports/a.md",
            "privilege_level": "user",
            "created_at": "",
            "updated_at": "",
        }
        summary = TaskSummary(**legacy_row).model_dump()
        assert summary["workflow_mode"] == "pentest_engineer"
        assert summary["auto_approve"] is False
