"""
Regression tests for FindingVerifier.

Covers the two false-positive cases from the project screenshots:
  1. Nmap 'Script execution failed' → should be rejected
  2. ActiveMQ KB detection on non-ActiveMQ target → should be rejected

Also covers true-positive confirmation:
  3. uid=0(root) in evidence → should be confirmed, confidence >= 85
  4. Hydra cracked credentials → confirmed
"""
from __future__ import annotations

import pytest

from backend.agents.finding_verifier import FindingVerifier
from backend.agents.models import VulnFinding, CONFIDENCE_THRESHOLD_EXPLOIT


@pytest.fixture
def verifier():
    return FindingVerifier()



class TestNmapScriptFailedRejection:
    """Nmap reports 'VULNERABLE' but output only contains 'Script execution failed'."""

    def test_script_execution_failed_rejected(self, verifier):
        finding = VulnFinding(
            name="http-vuln-cve2017-5638",
            severity="high",
            evidence="ERROR: Script execution failed (use -d to debug)",
            exploitable=True,
            tool="nmap-vuln-script",
        )
        result = verifier.verify(finding)
        assert result.verification_status == "rejected"
        assert result.confidence <= 20
        assert result.exploitable is False
        assert any("failure marker" in r for r in result.verification_reasons)

    def test_connection_timed_out_rejected(self, verifier):
        finding = VulnFinding(
            name="http-vuln-cve2021-41773",
            severity="critical",
            evidence="connection timed out\nno response received",
            exploitable=True,
            tool="nmap-vuln-script",
        )
        result = verifier.verify(finding)
        assert result.verification_status == "rejected"
        assert result.confidence <= 20
        assert result.exploitable is False

    def test_nmap_real_vulnerable_not_rejected(self, verifier):
        finding = VulnFinding(
            name="http-vuln-cve2017-5638",
            severity="high",
            evidence="State: VULNERABLE\nStruts2 is vulnerable to CVE-2017-5638",
            exploitable=True,
            tool="nmap-vuln-script",
        )
        result = verifier.verify(finding)
        assert result.verification_status != "rejected"
        assert result.confidence > 20



class TestActiveMQFalsePositive:
    """KB detection returns HTTP 200 on nginx but description claims ActiveMQ."""

    def test_activemq_on_nginx_rejected(self, verifier):
        finding = VulnFinding(
            name="ActiveMQ 默认弱口令",
            severity="high",
            description="检测 ActiveMQ 管理后台默认密码 admin/admin，如果返回200包含ActiveMQ内容则确认",
            evidence="HTTP/1.1 200 OK\nServer: nginx/1.18.0\n<html>Welcome to nginx</html>",
            exploitable=True,
            tool="kb-detection",
        )
        fp = {"summary": "nginx/1.18.0 static site"}
        result = verifier.verify(finding, fingerprint=fp)
        assert result.verification_status == "rejected"
        assert result.confidence <= 20
        assert result.exploitable is False

    def test_activemq_real_confirmed_not_rejected(self, verifier):
        finding = VulnFinding(
            name="ActiveMQ 默认弱口令",
            severity="high",
            description="ActiveMQ admin default password",
            evidence="HTTP/1.1 200 OK\nServer: Jetty(9.4.39)\nActiveMQ admin console\namq-broker",
            exploitable=True,
            tool="kb-detection",
        )
        fp = {"summary": "activemq jetty java"}
        result = verifier.verify(finding, fingerprint=fp)
        assert result.verification_status != "rejected"
        assert result.confidence > 20



class TestTruePositivePasswd:
    PASSWD_EVIDENCE = (
        "uid=0(root) gid=0(root) groups=0(root)\n"
        "root:x:0:0:root:/root:/bin/bash"
    )

    def test_uid_confirmed(self, verifier):
        finding = VulnFinding(
            name="Remote Code Execution via Struts2",
            severity="critical",
            evidence=self.PASSWD_EVIDENCE,
            exploitable=True,
            tool="kb-detection",
        )
        result = verifier.verify(finding)
        assert result.verification_status == "confirmed"
        assert result.confidence >= 85
        assert result.exploitable is True

    def test_passwd_lines_confirmed(self, verifier):
        finding = VulnFinding(
            name="LFI /etc/passwd read",
            severity="high",
            evidence="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            exploitable=False,
            tool="llm-discovery",
        )
        result = verifier.verify(finding)
        assert result.verification_status == "confirmed"
        assert result.confidence >= 85



class TestHydraConfirmed:
    def test_hydra_login_confirmed(self, verifier):
        finding = VulnFinding(
            name="SSH Weak Credentials",
            severity="high",
            evidence="[22][ssh] host: 10.0.0.1   login: admin   password: admin123",
            exploitable=True,
            tool="hydra",
        )
        result = verifier.verify(finding)
        assert result.verification_status == "confirmed"
        assert result.confidence >= 85



class TestServiceFindingLowConfidence:
    def test_service_enum_stays_low(self, verifier):
        finding = VulnFinding(
            name="SSH Server Detected",
            severity="info",
            confidence=40,
            evidence="nmap: 22/ssh OpenSSH 8.2p1",
            exploitable=False,
            tool="service-enum",
        )
        result = verifier.verify(finding)
        assert result.confidence <= 40
        assert result.exploitable is False
        assert result.verification_status in ("suspected",)



class TestConfidenceGate:
    def test_low_confidence_blocks_exploitable(self, verifier):
        finding = VulnFinding(
            name="Possible XSS",
            severity="medium",
            evidence="<script>alert(1)</script> reflected",
            exploitable=True,
            confidence=45,
            tool="nuclei",
        )
        result = verifier.verify(finding)
        assert result.confidence < CONFIDENCE_THRESHOLD_EXPLOIT
        assert result.exploitable is False
