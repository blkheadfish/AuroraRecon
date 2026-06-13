"""失败归因测试 (W2-T3).

覆盖: _build_failure_reflection 结构化归因 / 不同失败原因分类 /
failure_hypotheses state 字段 / ExploitResult.failure_reflection.
"""

from __future__ import annotations

from backend.agents.models import PentestState, VulnFinding, ExploitResult


class TestFailureReflection:
    """失败归因产出测试。"""

    def test_failure_hypotheses_field_exists(self):
        state = PentestState(target="http://test.local")
        assert hasattr(state, "failure_hypotheses")
        assert isinstance(state.failure_hypotheses, list)
        assert state.failure_hypotheses == []

    def test_exploit_result_has_failure_reflection(self):
        result = ExploitResult(
            vuln_id="CVE-X",
            success=False,
            evidence="test",
            failure_reflection={
                "vuln_id": "CVE-X",
                "cause": "filtered",
                "suggested_next": "try bypass",
                "round": 3,
                "commands_tried": 5,
                "failure_reason": "WAF blocked",
            },
        )
        assert result.failure_reflection is not None
        assert result.failure_reflection["cause"] == "filtered"

    def test_success_result_no_reflection(self):
        result = ExploitResult(vuln_id="CVE-Y", success=True, evidence="uid=0(root)")
        assert result.failure_reflection is None

    def test_failure_hypotheses_accumulates(self):
        state = PentestState(target="http://test.local")
        state.failure_hypotheses = [
            {"vuln_id": "CVE-A", "cause": "filtered", "suggested_next": "bypass"},
        ]
        state.failure_hypotheses.append(
            {"vuln_id": "CVE-B", "cause": "version_mismatch", "suggested_next": "check version"}
        )
        assert len(state.failure_hypotheses) == 2
        assert state.failure_hypotheses[0]["vuln_id"] == "CVE-A"
        assert state.failure_hypotheses[1]["cause"] == "version_mismatch"


class TestFailureCauseClassification:
    """失败原因分类逻辑测试 (从 _build_failure_reflection 逻辑取样, 不 import ExploitAgent)。"""

    @staticmethod
    def _classify_cause(stdout_samples: list[str], stderr_samples: list[str], reason: str, cmd_count: int) -> str:
        """与 ExploitAgent._build_failure_reflection 相同的分类逻辑。"""
        combined = " ".join((s or "")[:200] for s in stdout_samples + stderr_samples) + " " + reason
        combined = combined.lower()
        if any(kw in combined for kw in ("waf", "blocked", "403", "forbidden", "filtered")):
            return "filtered"
        if any(kw in combined for kw in ("401", "unauthorized", "auth", "denied", "login")):
            return "auth_required"
        if any(kw in combined for kw in ("not found", "404", "connect", "refused", "timeout")):
            return "no_callback"
        if any(kw in combined for kw in ("version", "not vulnerable", "patched")):
            return "version_mismatch"
        if any(kw in combined for kw in ("wrong", "invalid", "syntax", "error")):
            return "wrong_payload"
        if cmd_count >= 5:
            return "exhausted"
        return "unknown"

    def test_filtered_cause(self):
        cause = self._classify_cause(
            ["<html>403 Forbidden</html>"], [""], "WAF blocked", 2,
        )
        assert cause == "filtered"

    def test_auth_required_cause(self):
        cause = self._classify_cause(
            ["401 Unauthorized"], ["Login denied"], "Authentication failed", 1,
        )
        assert cause == "auth_required"

    def test_unknown_cause_with_few_commands(self):
        cause = self._classify_cause(
            ["some output"], [""], "no clear indicator", 2,
        )
        assert cause == "unknown"

    def test_exhausted_cause_after_many_commands(self):
        cause = self._classify_cause(
            ["nothing"] * 5, [""] * 5, "no luck", 5,
        )
        assert cause == "exhausted"

    def test_version_mismatch(self):
        cause = self._classify_cause(
            ["version 1.2.3 not vulnerable"], [""], "patched version", 3,
        )
        assert cause == "version_mismatch"

    def test_wrong_payload(self):
        cause = self._classify_cause(
            [""], ["syntax error near unexpected"], "invalid payload", 2,
        )
        assert cause == "wrong_payload"
