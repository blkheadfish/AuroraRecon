"""
Regression tests for EvidenceVerifier across role-based gate policies.

Covers scenarios from the plan:
  - fastjson/shiro RCE markers
  - LFI file-read evidence (absolute, relative, long-output, HTML false-hit)
  - SSH key detection
  - Role-policy gating (strict vs medium vs lenient)
"""
from __future__ import annotations

import pytest

from backend.agents.evidence_verifier import (
    EvidenceLevel,
    EvidenceVerifier,
    GatePolicy,
    VerifyResult,
)



@pytest.fixture(params=[GatePolicy.STRICT, GatePolicy.MEDIUM, GatePolicy.LENIENT])
def verifier(request) -> EvidenceVerifier:
    return EvidenceVerifier(policy=request.param)


def _v(policy: GatePolicy) -> EvidenceVerifier:
    return EvidenceVerifier(policy=policy)



class TestConfirmedRCE:
    UID_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)"
    JNDI_OUTPUT = "JNDI_RCE_SUCCESS\nCommand output: id"
    SHIRO_OUTPUT = "SHIRO_RCE_CONFIRMED deserialization payload delivered"

    @pytest.mark.parametrize("stdout", [UID_OUTPUT, JNDI_OUTPUT, SHIRO_OUTPUT])
    def test_confirmed_rce_passes_all_policies(self, stdout):
        for policy in GatePolicy:
            vr = _v(policy).verify(stdout=stdout)
            assert vr.level == EvidenceLevel.CONFIRMED_RCE
            assert vr.passed is True, f"Should pass under {policy.value}"

    def test_uid_in_prior_round(self):
        records = [
            {"round": 1, "stdout": "scanning..."},
            {"round": 2, "stdout": "uid=33(www-data) gid=33(www-data)"},
        ]
        vr = _v(GatePolicy.STRICT).verify(stdout="done", all_records=records)
        assert vr.level == EvidenceLevel.CONFIRMED_RCE
        assert vr.passed is True



class TestProbableRCE:
    def test_response_code_200_passes_medium(self):
        vr = _v(GatePolicy.MEDIUM).verify(stdout="Response Code: 200")
        assert vr.level == EvidenceLevel.PROBABLE_RCE
        assert vr.passed is True

    def test_response_code_200_blocked_by_strict(self):
        vr = _v(GatePolicy.STRICT).verify(stdout="Response Code: 200")
        assert vr.level == EvidenceLevel.PROBABLE_RCE
        assert vr.passed is False

    def test_negative_keywords_downgrade(self):
        """IllegalAccessError should prevent probable_rce classification."""
        vr = _v(GatePolicy.MEDIUM).verify(
            stdout="Response Code: 200\nIllegalAccessError: access denied"
        )
        assert vr.level != EvidenceLevel.PROBABLE_RCE



class TestFileReadLFI:
    PASSWD_CONTENT = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
    )
    SHADOW_CONTENT = "root:$6$rounds=656000$salt$hash:18000:0:99999:7:::"
    SSH_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ..."

    def test_passwd_absolute_path(self):
        """LFI via absolute path /etc/passwd."""
        vr = _v(GatePolicy.LENIENT).verify(stdout=self.PASSWD_CONTENT)
        assert vr.level == EvidenceLevel.FILE_READ_ONLY
        assert vr.passed is True

    def test_passwd_embedded_in_html_block(self):
        """Real-world LFI output may wrap passwd lines in HTML/pre tags."""
        html_wrapped = (
            "<html><body><h1>dump</h1><pre>"
            "root:x:0:0:root:/root:/bin/bash\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
            "</pre></body></html>"
        )
        vr = _v(GatePolicy.LENIENT).verify(stdout=html_wrapped)
        assert vr.level == EvidenceLevel.FILE_READ_ONLY
        assert vr.passed is True

    def test_passwd_plain_no_tags(self):
        """No HTML/pre wrappers at all — raw passwd echoed straight from LFI."""
        raw = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        )
        vr = _v(GatePolicy.LENIENT).verify(stdout=raw)
        assert vr.level == EvidenceLevel.FILE_READ_ONLY
        assert vr.passed is True

    def test_passwd_with_separator_prefix(self):
        """Body prefixed with a separator line: '=== /etc/passwd ===' then content."""
        out = (
            "=== /etc/passwd ===\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "mysql:x:101:101:MySQL:/nonexistent:/bin/false\n"
        )
        vr = _v(GatePolicy.LENIENT).verify(stdout=out)
        assert vr.level == EvidenceLevel.FILE_READ_ONLY

    def test_passwd_inlined_in_meta_tag(self):
        """passwd line embedded in an HTML attribute without preceding newline."""
        html = (
            '<meta name="dump" '
            'content="root:x:0:0:root:/root:/bin/bash">'
        )
        vr = _v(GatePolicy.LENIENT).verify(stdout=html)
        assert vr.level == EvidenceLevel.FILE_READ_ONLY

    def test_log_line_without_shell_not_detected(self):
        """Log line containing colons must not trigger passwd detection."""
        log = "2024-01-01 12:00:00 INFO: session:user:1:2:foo:/foo:/bar"
        vr = _v(GatePolicy.LENIENT).verify(stdout=log)
        assert vr.level == EvidenceLevel.FAILED

    def test_passwd_blocked_by_strict(self):
        vr = _v(GatePolicy.STRICT).verify(stdout=self.PASSWD_CONTENT)
        assert vr.level == EvidenceLevel.FILE_READ_ONLY
        assert vr.passed is False

    def test_passwd_blocked_by_medium(self):
        vr = _v(GatePolicy.MEDIUM).verify(stdout=self.PASSWD_CONTENT)
        assert vr.level == EvidenceLevel.FILE_READ_ONLY
        assert vr.passed is False

    def test_shadow_detected(self):
        vr = _v(GatePolicy.LENIENT).verify(stdout=self.SHADOW_CONTENT)
        assert vr.level == EvidenceLevel.FILE_READ_ONLY

    def test_ssh_key_detected(self):
        vr = _v(GatePolicy.LENIENT).verify(stdout=self.SSH_KEY)
        assert vr.level == EvidenceLevel.FILE_READ_ONLY
        assert vr.passed is True

    def test_html_false_hit_no_evidence(self):
        """HTML page that looks similar but has no real passwd content."""
        html = (
            "<html><head><title>404</title></head><body>"
            "The page /etc/passwd was not found."
            "</body></html>"
        )
        vr = _v(GatePolicy.LENIENT).verify(stdout=html)
        assert vr.level == EvidenceLevel.FAILED

    def test_truncated_output_prior_round_recovery(self):
        """Evidence in earlier round should still be found even if latest is truncated."""
        records = [
            {"round": 1, "stdout": self.PASSWD_CONTENT},
            {"round": 2, "stdout": "...(truncated)"},
        ]
        vr = _v(GatePolicy.LENIENT).verify(
            stdout="...(truncated)", all_records=records
        )
        assert vr.level == EvidenceLevel.FILE_READ_ONLY
        assert vr.passed is True



class TestFailed:
    def test_empty_output(self):
        vr = _v(GatePolicy.LENIENT).verify(stdout="", stderr="")
        assert vr.level == EvidenceLevel.FAILED
        assert vr.passed is False

    def test_generic_error(self):
        vr = _v(GatePolicy.LENIENT).verify(
            stdout="Connection refused", stderr="curl: (7) Failed to connect"
        )
        assert vr.level == EvidenceLevel.FAILED

    def test_html_error_page(self):
        vr = _v(GatePolicy.MEDIUM).verify(
            stdout="<html><body><h1>500 Internal Server Error</h1></body></html>"
        )
        assert vr.level == EvidenceLevel.FAILED



_SCENARIOS = [
    ("confirmed_rce_uid", "uid=0(root) gid=0(root)", EvidenceLevel.CONFIRMED_RCE),
    ("probable_rce_200", "Response Code: 200", EvidenceLevel.PROBABLE_RCE),
    ("file_read_passwd", "root:x:0:0:root:/root:/bin/bash", EvidenceLevel.FILE_READ_ONLY),
    ("failed_empty", "", EvidenceLevel.FAILED),
]

_EXPECTED_PASS = {
    GatePolicy.STRICT: {EvidenceLevel.CONFIRMED_RCE},
    GatePolicy.MEDIUM: {EvidenceLevel.CONFIRMED_RCE, EvidenceLevel.PROBABLE_RCE},
    GatePolicy.LENIENT: {
        EvidenceLevel.CONFIRMED_RCE,
        EvidenceLevel.PROBABLE_RCE,
        EvidenceLevel.FILE_READ_ONLY,
    },
}


@pytest.mark.parametrize("name,stdout,expected_level", _SCENARIOS, ids=[s[0] for s in _SCENARIOS])
@pytest.mark.parametrize("policy", list(GatePolicy), ids=[p.value for p in GatePolicy])
def test_role_policy_matrix(name, stdout, expected_level, policy):
    """Cross-product: every scenario x every policy → deterministic pass/fail."""
    vr = _v(policy).verify(stdout=stdout)
    assert vr.level == expected_level, f"{name}: expected {expected_level}, got {vr.level}"
    should_pass = expected_level in _EXPECTED_PASS[policy]
    assert vr.passed is should_pass, (
        f"{name} under {policy.value}: expected passed={should_pass}, got {vr.passed}"
    )
