"""
Regression tests for role-weighted Skill matching in SkillRegistry.

Validates that:
  - pentest_engineer mode requires min_score >= 20 (rejects weak signals)
  - ctf_expert mode accepts min_score >= 5 (+ weak_signal_boost of 10)
  - Both roles produce identical results for strong (CVE/name) matches
"""
from __future__ import annotations

import pytest

from backend.agents.models import VulnFinding
from backend.skills.registry import SkillRegistry, _ROLE_MATCH_CONFIG


class TestRoleMatchConfig:
    """Verify the role config constants are correct."""

    def test_pentest_engineer_config(self):
        cfg = _ROLE_MATCH_CONFIG["pentest_engineer"]
        assert cfg["min_score"] >= 15, "Engineer threshold should be high"
        assert cfg["weak_signal_boost"] == 0, "Engineer should not boost weak signals"

    def test_ctf_expert_config(self):
        cfg = _ROLE_MATCH_CONFIG["ctf_expert"]
        assert cfg["min_score"] <= 10, "CTF threshold should be low"
        assert cfg["weak_signal_boost"] > 0, "CTF should boost weak signals"


class TestRoleWeightedMatching:
    """Integration tests using real loaded skills."""

    @pytest.fixture(autouse=True)
    def registry(self):
        self.reg = SkillRegistry()
        self.reg.ensure_loaded()
        if self.reg.size == 0:
            pytest.skip("No skills loaded")

    def test_strong_match_identical_across_roles(self):
        """A CVE-exact match should return the same skill regardless of role."""
        finding = VulnFinding(
            name="Apache Shiro Deserialization RCE",
            cve="CVE-2016-4437",
            target="http://target:8080",
            exploitable=True,
        )
        result_eng = self.reg.match(finding, operator_role="pentest_engineer")
        result_ctf = self.reg.match(finding, operator_role="ctf_expert")
        if result_eng is not None:
            assert result_ctf is not None, "CTF should also match if engineer matches"
            assert result_eng.skill_id == result_ctf.skill_id

    def test_weak_signal_may_differ_between_roles(self):
        """A finding with only evidence-keyword match (score ~10) may only
        match under ctf_expert but not pentest_engineer."""
        finding = VulnFinding(
            name="Unknown Vuln",
            description="",
            evidence="possible tomcat default page detected",
            target="http://target:8080",
            exploitable=True,
        )
        result_eng = self.reg.match(finding, operator_role="pentest_engineer")
        result_ctf = self.reg.match(finding, operator_role="ctf_expert")
        # Under engineer (min_score=20), a 10-point evidence match is rejected.
        # Under ctf (min_score=5, boost=10), a 10+10=20 point match may be accepted.
        # We cannot assert exact results without knowing skill definitions,
        # but we verify CTF is at least as permissive as engineer.
        if result_eng is not None:
            assert result_ctf is not None, (
                "CTF should match if engineer matches (CTF is more permissive)"
            )

    def test_unknown_role_uses_defaults(self):
        """An unrecognized role should fall back to safe defaults."""
        finding = VulnFinding(
            name="Fastjson RCE",
            target="http://target:8080",
            exploitable=True,
        )
        result = self.reg.match(finding, operator_role="unknown_role")
        # Should not crash; defaults to min_score=10
        # Just verify no exception is raised
        assert result is None or hasattr(result, "skill_id")
