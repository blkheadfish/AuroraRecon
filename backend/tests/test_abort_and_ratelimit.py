"""Tests for abort registry and rate limiting (W0-T4)."""
from __future__ import annotations

import pytest

from backend.agents.abort_registry import (
    check_abort,
    clear_abort,
    request_abort,
    reset_all,
    snapshot,
)
from backend.agents.models import PentestState, TaskStatus


class TestAbortRegistry:
    def teardown_method(self):
        reset_all()

    def test_request_and_check(self):
        request_abort("task-1", "manual")
        assert check_abort("task-1") is True
        assert check_abort("task-2") is False

    def test_clear_abort(self):
        request_abort("task-1")
        assert check_abort("task-1") is True
        cleared = clear_abort("task-1")
        assert cleared is True
        assert check_abort("task-1") is False

    def test_clear_nonexistent(self):
        assert clear_abort("no-such") is False

    def test_request_multiple_times(self):
        request_abort("t1", "first")
        request_abort("t1", "second")
        assert check_abort("t1") is True

    def test_snapshot(self):
        request_abort("a", "r1")
        request_abort("b", "r2")
        snap = snapshot()
        assert "a" in snap
        assert "b" in snap
        assert snap["a"]["reason"] == "r1"

    def test_reset_all(self):
        request_abort("a")
        request_abort("b")
        reset_all()
        assert check_abort("a") is False
        assert check_abort("b") is False


class TestAbortInState:
    def test_state_aborted_status(self):
        state = PentestState()
        state.status = TaskStatus.ABORTED
        assert state.status == TaskStatus.ABORTED
        assert state.status.value == "aborted"

    def test_abort_status_in_enum(self):
        assert TaskStatus.ABORTED.value == "aborted"
