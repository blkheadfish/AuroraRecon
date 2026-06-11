"""Tests for tightened safety invariants (W0-T3)."""
from __future__ import annotations

import pytest

from backend.agents.models import ParsedIntent, SafetyCheckResult
from backend.agents.safety_gate import PentestSafetyGate


def _make_intent(
    targets: list[str],
    scope_hint: str = "",
    raw_prompt: str = "",
    **kwargs,
) -> ParsedIntent:
    return ParsedIntent(
        targets=targets,
        scope_hint=scope_hint,
        raw_prompt=raw_prompt,
        **kwargs,
    )


def _gate() -> PentestSafetyGate:
    return PentestSafetyGate()


class TestTokenStillEnforcesBlocklist:
    def test_token_blocks_cloud_metadata(self):
        gate = _gate()
        intent = _make_intent(targets=["169.254.169.254"])
        result = gate.check(intent, authorization_token="secret-abc123")
        assert result.passed is False
        assert result.risk_level == "blocked"

    def test_token_blocks_large_cidr(self):
        gate = _gate()
        intent = _make_intent(targets=["0.0.0.0/0"])
        result = gate.check(intent, authorization_token="secret-abc123")
        assert result.passed is False
        assert result.risk_level == "blocked"

    def test_token_blocks_unauthorized_keyword(self):
        gate = _gate()
        intent = _make_intent(
            targets=["10.0.0.5"],
            raw_prompt="入侵某公司内网",
        )
        result = gate.check(intent, authorization_token="secret-abc123")
        assert result.passed is False
        assert result.risk_level == "blocked"

    def test_token_allows_private_target(self):
        gate = _gate()
        intent = _make_intent(targets=["10.0.0.5"])
        result = gate.check(intent, authorization_token="secret-abc123")
        assert result.passed is True
        assert "blocklist_still_enforced=yes" not in str(result.warnings)


class TestCtfLabOnlyPrivate:
    def test_ctf_lab_with_private_ips_allowed(self):
        gate = _gate()
        intent = _make_intent(
            targets=["192.168.1.5", "10.0.0.1"],
            scope_hint="ctf_lab",
        )
        result = gate.check(intent)
        assert result.passed is True
        assert result.risk_level != "blocked"

    def test_ctf_lab_with_public_ip_not_auto_approved(self):
        gate = _gate()
        intent = _make_intent(
            targets=["8.8.8.8"],
            scope_hint="ctf_lab",
        )
        result = gate.check(intent)
        assert result.passed is True
        assert result.risk_level == "warning"

    def test_ctf_lab_with_mixed_targets_warns(self):
        gate = _gate()
        intent = _make_intent(
            targets=["10.0.0.1", "8.8.8.8"],
            scope_hint="ctf_lab",
        )
        result = gate.check(intent)
        assert result.passed is True

    def test_ctf_lab_without_targets_fallback(self):
        gate = _gate()
        intent = _make_intent(
            targets=[],
            scope_hint="ctf_lab",
        )
        result = gate.check(intent)
        assert result.passed is True

    def test_no_ctf_no_auto(self):
        gate = _gate()
        intent = _make_intent(targets=["8.8.8.8"])
        result = gate.check(intent)
        assert result.passed is True
        assert result.risk_level == "warning"


class TestSafetyNoToken:
    def test_blocklist_no_token(self):
        gate = _gate()
        intent = _make_intent(targets=["169.254.169.254"])
        result = gate.check(intent)
        assert result.passed is False
        assert result.risk_level == "blocked"

    def test_private_target_no_token_passes(self):
        gate = _gate()
        intent = _make_intent(targets=["10.0.0.5"])
        result = gate.check(intent)
        assert result.passed is True
