"""Tests for autonomous mode and irreversible gate (W0-T5)."""
from __future__ import annotations

import pytest

from backend.agents.irreversible_gate import (
    is_irreversible,
    is_reversible,
)
from backend.agents.models import PentestState


class TestIrreversibleGate:
    def test_persistence_phase_is_irreversible(self):
        irrev, reason = is_irreversible(phase="persistence")
        assert irrev is True

    def test_lateral_movement_phase_is_irreversible(self):
        irrev, reason = is_irreversible(phase="lateral_movement")
        assert irrev is True

    def test_recon_phase_is_reversible(self):
        irrev, reason = is_irreversible(phase="recon")
        assert irrev is False

    def test_exploit_phase_is_reversible(self):
        irrev, reason = is_irreversible(phase="foothold_attempt")
        assert irrev is False

    def test_useradd_command_is_irreversible(self):
        irrev, reason = is_irreversible(cmd="useradd -m backdoor")
        assert irrev is True

    def test_crontab_command_is_irreversible(self):
        irrev, reason = is_irreversible(cmd="echo '* * * * * /tmp/backdoor' | crontab -")
        assert irrev is True

    def test_reg_add_is_irreversible(self):
        irrev, reason = is_irreversible(cmd="reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d C:\\backdoor.exe")
        assert irrev is True

    def test_systemctl_enable_is_irreversible(self):
        irrev, reason = is_irreversible(cmd="systemctl enable backdoor")
        assert irrev is True

    def test_systemctl_status_is_reversible(self):
        irrev, reason = is_irreversible(cmd="systemctl status sshd")
        assert irrev is False

    def test_curl_is_reversible(self):
        irrev, reason = is_irreversible(cmd="curl http://10.0.0.5/admin")
        assert irrev is False

    def test_whoami_is_reversible(self):
        irrev, reason = is_irreversible(cmd="whoami && id")
        assert irrev is False

    def test_empty_action_and_cmd(self):
        irrev, reason = is_irreversible()
        assert irrev is False

    def test_rm_rf_is_irreversible(self):
        irrev, reason = is_irreversible(cmd="rm -rf /etc/important")
        assert irrev is True

    def test_is_reversible_helper(self):
        assert is_reversible(cmd="whoami") is True
        assert is_reversible(phase="persistence") is False

    def test_create_user_action_is_irreversible(self):
        irrev, reason = is_irreversible(action="create_user")
        assert irrev is True

    def test_scope_expansion_action_is_irreversible(self):
        irrev, reason = is_irreversible(action="scope_expansion")
        assert irrev is True


class TestAutonomyLevel:
    def test_state_defaults_to_manual(self):
        state = PentestState()
        assert state.autonomy_level == "manual"

    def test_state_can_be_autonomous(self):
        state = PentestState(autonomy_level="autonomous")
        assert state.autonomy_level == "autonomous"

    def test_state_can_be_supervised(self):
        state = PentestState(autonomy_level="supervised")
        assert state.autonomy_level == "supervised"
