"""
Regression tests for workflow_mode defaults matrix.

Covers:
  - `_MODE_DEFAULTS` exposes both supported modes with all per-task keys.
  - `mode_defaults()` returns safe defaults for unknown modes.
  - `apply_mode_defaults()` writes defaults into state and respects
    explicit per-task overrides.
"""
from __future__ import annotations

import pytest

from backend.agents.models import (
    PentestState,
    _MODE_DEFAULTS,
    apply_mode_defaults,
    mode_defaults,
)


_REQUIRED_KEYS = {
    "auto_approve",
    "success_gate_level",
    "risk_budget",
    "max_react_rounds",
    "max_explore_rounds",
    "skill_min_score",
    "skill_weak_boost",
}


class TestModeDefaultsMatrix:
    def test_contains_both_modes(self):
        assert "pentest_engineer" in _MODE_DEFAULTS
        assert "ctf_expert" in _MODE_DEFAULTS

    def test_all_modes_expose_required_keys(self):
        for mode, cfg in _MODE_DEFAULTS.items():
            missing = _REQUIRED_KEYS - set(cfg.keys())
            assert not missing, f"{mode} missing keys: {missing}"

    def test_pentest_engineer_is_safe_default(self):
        cfg = _MODE_DEFAULTS["pentest_engineer"]
        assert cfg["auto_approve"] is False, "Engineer must require approval"
        assert cfg["success_gate_level"] == "strict"
        assert cfg["skill_min_score"] >= 15
        assert cfg["skill_weak_boost"] == 0

    def test_ctf_expert_is_permissive(self):
        cfg = _MODE_DEFAULTS["ctf_expert"]
        assert cfg["auto_approve"] is True, "CTF should auto-approve"
        assert cfg["success_gate_level"] != "strict"
        assert cfg["skill_min_score"] <= 10
        assert cfg["skill_weak_boost"] > 0

    def test_mode_defaults_helper_returns_copy(self):
        a = mode_defaults("pentest_engineer")
        b = mode_defaults("pentest_engineer")
        a["auto_approve"] = "mutated"
        assert b["auto_approve"] is False, "mode_defaults must return a fresh dict"

    def test_unknown_mode_falls_back_to_engineer(self):
        cfg = mode_defaults("ctf_goat")
        assert cfg == _MODE_DEFAULTS["pentest_engineer"]


class TestApplyModeDefaults:
    def test_engineer_defaults_are_written_to_state(self):
        state = PentestState(workflow_mode="pentest_engineer")
        apply_mode_defaults(state)
        cfg = _MODE_DEFAULTS["pentest_engineer"]
        assert state.auto_approve == cfg["auto_approve"]
        assert state.success_gate_level == cfg["success_gate_level"]
        assert state.risk_budget == cfg["risk_budget"]
        assert state.max_react_rounds == cfg["max_react_rounds"]
        assert state.max_explore_rounds == cfg["max_explore_rounds"]
        assert state.skill_min_score == cfg["skill_min_score"]
        assert state.skill_weak_boost == cfg["skill_weak_boost"]

    def test_ctf_defaults_are_written_to_state(self):
        state = PentestState(workflow_mode="ctf_expert")
        apply_mode_defaults(state)
        cfg = _MODE_DEFAULTS["ctf_expert"]
        assert state.auto_approve == cfg["auto_approve"]
        assert state.success_gate_level == cfg["success_gate_level"]
        assert state.max_react_rounds == cfg["max_react_rounds"]

    def test_overrides_take_precedence(self):
        state = PentestState(workflow_mode="ctf_expert")
        apply_mode_defaults(
            state,
            overrides={
                "auto_approve": False,
                "max_react_rounds": 7,
                "skill_min_score": 42,
            },
        )
        assert state.auto_approve is False
        assert state.max_react_rounds == 7
        assert state.skill_min_score == 42
        assert state.success_gate_level == _MODE_DEFAULTS["ctf_expert"]["success_gate_level"]
        assert state.skill_weak_boost == _MODE_DEFAULTS["ctf_expert"]["skill_weak_boost"]

    def test_none_overrides_are_ignored(self):
        state = PentestState(workflow_mode="pentest_engineer")
        apply_mode_defaults(
            state,
            overrides={"auto_approve": None, "max_react_rounds": None},
        )
        cfg = _MODE_DEFAULTS["pentest_engineer"]
        assert state.auto_approve == cfg["auto_approve"]
        assert state.max_react_rounds == cfg["max_react_rounds"]

    def test_unknown_mode_still_applies_engineer_defaults(self):
        state = PentestState()
        object.__setattr__(state, "workflow_mode", "shadow")
        apply_mode_defaults(state)
        cfg = _MODE_DEFAULTS["pentest_engineer"]
        assert state.auto_approve == cfg["auto_approve"]
        assert state.skill_min_score == cfg["skill_min_score"]
