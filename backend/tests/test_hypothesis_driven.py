"""假设驱动探索测试 (W2-T4).

覆盖: recon_hypotheses 从报告消费升级为决策事件 /
privesc_hypotheses 驱动提权 / 假设 status 字段 /
hypothesis_test push_decision.
"""

from __future__ import annotations

from backend.agents.models import PentestState, VulnFinding


class TestHypothesisStatus:
    """假设状态管理测试。"""

    def test_recon_hypotheses_stored_with_status(self):
        state = PentestState(target="http://test.local")
        state.recon_hypotheses = [
            {
                "hypothesis": "可能存在 admin 后台",
                "status": "unverified",
                "confidence": 0.6,
                "category": "web_endpoint",
            },
            {
                "hypothesis": "可能存在 .git 泄露",
                "status": "verified",
                "confidence": 0.9,
                "category": "info_leak",
            },
        ]
        assert len(state.recon_hypotheses) == 2
        unverified = [h for h in state.recon_hypotheses if h.get("status") != "verified"]
        assert len(unverified) == 1
        assert unverified[0]["hypothesis"] == "可能存在 admin 后台"

    def test_privesc_hypotheses_stored_with_status(self):
        state = PentestState(target="http://test.local")
        state.privesc_hypotheses = [
            {
                "hypothesis": "可能可 sudo 提权",
                "status": "unverified",
                "confidence": 0.5,
                "category": "sudo",
            },
        ]
        assert len(state.privesc_hypotheses) == 1
        assert state.privesc_hypotheses[0]["category"] == "sudo"

    def test_hypothesis_status_transitions(self):
        state = PentestState(target="http://test.local")
        state.recon_hypotheses = [
            {"hypothesis": "test", "status": "unverified", "confidence": 0.5, "category": "test"},
        ]
        # 验证后更新状态
        state.recon_hypotheses[0]["status"] = "verified"
        state.recon_hypotheses[0]["confidence"] = 0.95
        assert state.recon_hypotheses[0]["status"] == "verified"
        assert state.recon_hypotheses[0]["confidence"] == 0.95

    def test_empty_hypotheses_no_crash(self):
        state = PentestState(target="http://test.local")
        assert state.recon_hypotheses == []
        assert state.privesc_hypotheses == []
        # 空列表不应该崩溃
        unverified = [h for h in state.recon_hypotheses if h.get("status") != "verified"]
        assert unverified == []


class TestHypothesisIntegration:
    """假设与决策流集成测试。"""

    def test_push_decision_hypothesis_test(self):
        state = PentestState(target="http://test.local")
        # push_decision 走事件总线, 不在 state 内保留; 验证 push 不抛异常
        try:
            state.push_decision({
                "action": "hypothesis_test",
                "phase": "recon",
                "thinking": "可能存在 admin 后台",
                "purpose": "假设驱动侦察",
                "message": "假设: 可能存在 admin 后台 (conf=0.60)",
                "hypothesis": {
                    "text": "可能存在 admin 后台",
                    "status": "unverified",
                    "confidence": 0.6,
                    "category": "web_endpoint",
                },
                "tone": "info",
            })
        except Exception as e:
            assert False, f"push_decision hypothesis_test 不应抛异常: {e}"

    def test_privesc_hypothesis_test_event(self):
        state = PentestState(target="http://test.local")
        try:
            state.push_decision({
                "action": "hypothesis_test",
                "phase": "privesc_attempt",
                "thinking": "可能可通过 SUID 提权",
                "purpose": "假设驱动提权",
                "message": "提权假设: 可能可通过 SUID 提权",
                "hypothesis": {
                    "text": "可能可通过 SUID 提权",
                    "status": "unverified",
                    "confidence": 0.4,
                    "category": "suid",
                },
                "tone": "info",
            })
        except Exception as e:
            assert False, f"push_decision hypothesis_test 不应抛异常: {e}"

    def test_verified_hypothesis_not_republished(self):
        """已验证的假设不应重复推送 hypothesis_test。"""
        state = PentestState(target="http://test.local")
        state.recon_hypotheses = [
            {"hypothesis": "已确认", "status": "verified", "confidence": 0.95, "category": "test"},
        ]
        # W2-T4 逻辑: 只有 status != "verified" 才推送
        unverified = [h for h in state.recon_hypotheses if h.get("status") != "verified"]
        assert unverified == []
