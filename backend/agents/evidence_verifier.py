"""
evidence_verifier.py
统一证据验证门控

所有 conclude_success 必须经过此模块才能落地为 ExploitResult.success=True。

验证等级:
  confirmed_rce   — 有硬证据（uid=, whoami 返回用户名, JNDI_RCE_SUCCESS）
  probable_rce    — 有较强间接证据（Response Code: 200 + 无 IllegalAccessError 等）
  file_read_only  — 仅文件读取（/etc/passwd 内容可读但无命令执行）
  failed          — 无有效证据

门控策略:
  strict  (pentest_engineer): 仅 confirmed_rce 算成功
  medium  (ctf_expert):       confirmed_rce + probable_rce 算成功
  lenient (调试):             confirmed_rce + probable_rce + file_read_only 算成功
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class EvidenceLevel(str, Enum):
    CONFIRMED_RCE = "confirmed_rce"
    PROBABLE_RCE = "probable_rce"
    FILE_READ_ONLY = "file_read_only"
    FAILED = "failed"


class GatePolicy(str, Enum):
    STRICT = "strict"
    MEDIUM = "medium"
    LENIENT = "lenient"


_GATE_PASS: dict[GatePolicy, set[EvidenceLevel]] = {
    GatePolicy.STRICT: {EvidenceLevel.CONFIRMED_RCE},
    GatePolicy.MEDIUM: {EvidenceLevel.CONFIRMED_RCE, EvidenceLevel.PROBABLE_RCE},
    GatePolicy.LENIENT: {
        EvidenceLevel.CONFIRMED_RCE,
        EvidenceLevel.PROBABLE_RCE,
        EvidenceLevel.FILE_READ_ONLY,
    },
}

# ── Hard-evidence patterns ────────────────────────────────

_UID_RE = re.compile(r"uid=\d+\([a-z0-9_.-]+\)\s+gid=\d+\([a-z0-9_.-]+\)", re.IGNORECASE)
_WHOAMI_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$", re.MULTILINE)
_PASSWD_LINE_RE = re.compile(
    r"[a-z_][\w.-]*:[^:\s]{0,2}:\d+:\d+:[^:\n]{0,64}:/[^\n]{1,200}",
    re.IGNORECASE | re.MULTILINE,
)
_SHADOW_LINE_RE = re.compile(
    r"[a-z_][\w.-]*:[\$!\*][^\s:]{6,}",
    re.IGNORECASE | re.MULTILINE,
)
_KNOWN_SYSTEM_ACCOUNTS = frozenset([
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
    "nobody", "systemd-network", "syslog", "messagebus", "landscape",
    "pollinate", "sshd", "ftp", "postfix", "dovecot", "mysql", "postgres",
    "apache", "nginx", "operator", "adm",
])
_KNOWN_SHELLS = frozenset([
    "/bin/bash", "/bin/sh", "/usr/sbin/nologin", "/bin/false",
    "/usr/bin/false", "/bin/sync", "/usr/sbin/login",
])


def _passwd_content_detected(text: str) -> bool:
    """Return True when text contains plausible /etc/passwd content.

    Uses structural uniqueness of passwd lines (7 colon-separated fields) plus
    a sanity gate: at least one known system account OR a recognised shell path
    must appear among the matched lines.  This avoids false positives from
    log lines or gecos text that happens to contain colons.
    """
    matches = _PASSWD_LINE_RE.findall(text)
    if not matches:
        return False
    for m in matches:
        username = m.split(":")[0].lower()
        if username in _KNOWN_SYSTEM_ACCOUNTS:
            return True
        for shell in _KNOWN_SHELLS:
            if shell in m:
                return True
    return False
_SSH_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"
)

_RCE_CONFIRMED_KEYWORDS = [
    "JNDI_RCE_SUCCESS",
    "SHIRO_RCE_CONFIRMED",
]

_RCE_PROBABLE_KEYWORDS = [
    "Response Code: 200",
]

_RCE_NEGATIVE_KEYWORDS = [
    "IllegalAccessError",
    "ClassNotFoundException",
    "NoClassDefFoundError",
]


@dataclass
class VerifyResult:
    level: EvidenceLevel
    reason: str
    passed: bool
    evidence_snippets: list[str]


class EvidenceVerifier:
    """Stateless verifier: classify evidence and apply gate policy."""

    def __init__(self, policy: GatePolicy = GatePolicy.STRICT):
        self.policy = policy

    def verify(
        self,
        stdout: str = "",
        stderr: str = "",
        shell_type: str = "",
        *,
        all_records: list[dict] | None = None,
    ) -> VerifyResult:
        """
        Classify the evidence level and decide pass/fail.

        Args:
            stdout/stderr: output from the most recent command
            shell_type: declared by LLM (rce, file_read, etc.)
            all_records: full command history for cross-reference
        """
        level, reason, snippets = self._classify(stdout, stderr, shell_type, all_records)
        passed = level in _GATE_PASS[self.policy]

        if not passed:
            logger.info(
                f"[EvidenceVerifier] BLOCKED: level={level.value}, "
                f"policy={self.policy.value}, reason={reason}"
            )
        else:
            logger.info(
                f"[EvidenceVerifier] PASSED: level={level.value}, "
                f"policy={self.policy.value}, reason={reason}"
            )

        return VerifyResult(
            level=level,
            reason=reason,
            passed=passed,
            evidence_snippets=snippets,
        )

    def _classify(
        self,
        stdout: str,
        stderr: str,
        shell_type: str,
        all_records: list[dict] | None,
    ) -> tuple[EvidenceLevel, str, list[str]]:
        combined = f"{stdout}\n{stderr}"
        snippets: list[str] = []

        # ── Check confirmed RCE ──────────────────────────
        m = _UID_RE.search(combined)
        if m:
            snippets.append(m.group(0))
            return EvidenceLevel.CONFIRMED_RCE, f"uid= pattern matched: {m.group(0)}", snippets

        for kw in _RCE_CONFIRMED_KEYWORDS:
            if kw in combined:
                snippets.append(kw)
                return EvidenceLevel.CONFIRMED_RCE, f"RCE keyword matched: {kw}", snippets

        # Also scan historical records for uid= that might be in prior rounds
        if all_records:
            for rec in all_records:
                rec_out = str(rec.get("stdout", ""))
                m2 = _UID_RE.search(rec_out)
                if m2:
                    snippets.append(f"[round {rec.get('round', '?')}] {m2.group(0)}")
                    return (
                        EvidenceLevel.CONFIRMED_RCE,
                        f"uid= found in prior round {rec.get('round', '?')}",
                        snippets,
                    )

        # ── Check probable RCE ───────────────────────────
        for kw in _RCE_PROBABLE_KEYWORDS:
            if kw in combined:
                has_negative = any(neg in combined for neg in _RCE_NEGATIVE_KEYWORDS)
                if not has_negative:
                    snippets.append(kw)
                    return EvidenceLevel.PROBABLE_RCE, f"probable RCE keyword: {kw}", snippets

        # ── Check file read ──────────────────────────────
        if _passwd_content_detected(combined):
            snippets.append("/etc/passwd content detected")
            return EvidenceLevel.FILE_READ_ONLY, "passwd file content readable", snippets

        if _SHADOW_LINE_RE.search(combined):
            snippets.append("/etc/shadow content detected")
            return EvidenceLevel.FILE_READ_ONLY, "shadow file content readable", snippets

        if _SSH_KEY_RE.search(combined):
            snippets.append("SSH private key detected")
            return EvidenceLevel.FILE_READ_ONLY, "SSH private key readable", snippets

        if all_records:
            for rec in all_records:
                rec_out = str(rec.get("stdout", ""))
                if _passwd_content_detected(rec_out):
                    snippets.append(f"[round {rec.get('round', '?')}] /etc/passwd readable")
                    return EvidenceLevel.FILE_READ_ONLY, "file read in prior round", snippets

        # ── shell_type hint ──────────────────────────────
        if shell_type and "file_read" in shell_type.lower():
            return EvidenceLevel.FILE_READ_ONLY, f"shell_type={shell_type}", snippets

        return EvidenceLevel.FAILED, "no hard evidence found", snippets


# ── Module-level default instance ─────────────────────────

_default_verifier: EvidenceVerifier | None = None


def get_verifier(policy: str | GatePolicy = GatePolicy.STRICT) -> EvidenceVerifier:
    global _default_verifier
    if isinstance(policy, str):
        try:
            policy = GatePolicy(policy)
        except ValueError:
            policy = GatePolicy.STRICT
    if _default_verifier is None or _default_verifier.policy != policy:
        _default_verifier = EvidenceVerifier(policy=policy)
    return _default_verifier
