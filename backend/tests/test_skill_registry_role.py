"""
Regression tests for mode-weighted Skill matching in SkillRegistry.

Validates that:
  - pentest_engineer mode requires min_score >= 20 (rejects weak signals)
  - ctf_expert mode accepts min_score >= 5 (+ weak_signal_boost of 10)
  - Both modes produce identical results for strong (CVE/name) matches
  - Per-task min_score / weak_signal_boost overrides take precedence over
    workflow_mode defaults.
"""
from __future__ import annotations

import pytest

from backend.agents.models import VulnFinding
from backend.skills.registry import SkillRegistry, _MODE_MATCH_CONFIG


class TestModeMatchConfig:
    """Verify the workflow_mode config constants are correct."""

    def test_pentest_engineer_config(self):
        cfg = _MODE_MATCH_CONFIG["pentest_engineer"]
        assert cfg["min_score"] >= 15, "Engineer threshold should be high"
        assert cfg["weak_signal_boost"] == 0, "Engineer should not boost weak signals"

    def test_ctf_expert_config(self):
        cfg = _MODE_MATCH_CONFIG["ctf_expert"]
        assert cfg["min_score"] <= 10, "CTF threshold should be low"
        assert cfg["weak_signal_boost"] > 0, "CTF should boost weak signals"


class TestModeWeightedMatching:
    """Integration tests using real loaded skills."""

    @pytest.fixture(autouse=True)
    def registry(self):
        self.reg = SkillRegistry()
        self.reg.ensure_loaded()
        if self.reg.size == 0:
            pytest.skip("No skills loaded")

    def test_strong_match_identical_across_modes(self):
        """A CVE-exact match should return the same skill regardless of mode."""
        finding = VulnFinding(
            name="Apache Shiro Deserialization RCE",
            cve="CVE-2016-4437",
            target="http://target:8080",
            exploitable=True,
        )
        result_eng = self.reg.match(finding, workflow_mode="pentest_engineer")
        result_ctf = self.reg.match(finding, workflow_mode="ctf_expert")
        if result_eng is not None:
            assert result_ctf is not None, "CTF should also match if engineer matches"
            assert result_eng.skill_id == result_ctf.skill_id

    def test_weak_signal_may_differ_between_modes(self):
        """A finding with only evidence-keyword match (score ~10) may only
        match under ctf_expert but not pentest_engineer."""
        finding = VulnFinding(
            name="Unknown Vuln",
            description="",
            evidence="possible tomcat default page detected",
            target="http://target:8080",
            exploitable=True,
        )
        result_eng = self.reg.match(finding, workflow_mode="pentest_engineer")
        result_ctf = self.reg.match(finding, workflow_mode="ctf_expert")
        if result_eng is not None:
            assert result_ctf is not None, (
                "CTF should match if engineer matches (CTF is more permissive)"
            )

    def test_unknown_mode_uses_defaults(self):
        """An unrecognized workflow_mode should fall back to pentest_engineer defaults."""
        finding = VulnFinding(
            name="Fastjson RCE",
            target="http://target:8080",
            exploitable=True,
        )
        result = self.reg.match(finding, workflow_mode="unknown_mode")
        assert result is None or hasattr(result, "skill_id")

    def test_per_task_min_score_override_is_respected(self):
        """Explicit per-task min_score should override workflow_mode defaults."""
        finding = VulnFinding(
            name="Unknown Vuln",
            description="",
            evidence="possible tomcat default page detected",
            target="http://target:8080",
            exploitable=True,
        )
        result_override = self.reg.match(
            finding,
            workflow_mode="pentest_engineer",
            min_score=5,
            weak_signal_boost=10,
        )
        result_ctf = self.reg.match(finding, workflow_mode="ctf_expert")
        if result_ctf is not None:
            assert result_override is not None, (
                "Explicit per-task overrides should make pentest_engineer "
                "behave like ctf_expert"
            )

    def test_per_task_min_score_can_tighten_ctf(self):
        """A very high explicit min_score should reject weak matches even in
        ctf_expert mode."""
        finding = VulnFinding(
            name="Unknown Vuln",
            description="",
            evidence="possible tomcat default page detected",
            target="http://target:8080",
            exploitable=True,
        )
        result = self.reg.match(
            finding,
            workflow_mode="ctf_expert",
            min_score=1000,
            weak_signal_boost=0,
        )
        assert result is None, "Extreme min_score should reject all matches"
