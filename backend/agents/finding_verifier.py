"""
finding_verifier.py
统一漏洞 Finding 复核层

所有 VulnFinding 在写入 state.findings 前必须经过本模块复核。
复核逻辑按优先级分三档：
  强否定 → rejected,  confidence ≤ 20
  强正向 → confirmed,  confidence ≥ 85
  疑似   → suspected,  confidence 30-50
  默认   → likely,     confidence = 50

设计原则：
  - 纯规则匹配，不调用 LLM（确定性 + 零延迟）
  - 与现有 EvidenceVerifier 互补：EvidenceVerifier 校验 RCE 证据，
    本模块校验 Finding 级别的 description↔evidence 一致性
"""
from __future__ import annotations

import re
import logging
from typing import Optional

from backend.agents.models import VulnFinding, CONFIDENCE_THRESHOLD_EXPLOIT

logger = logging.getLogger(__name__)

# ── 强否定标记 ────────────────────────────────────────────
_HARD_NEGATIVE_MARKERS = (
    "script execution failed",
    "error: script execution failed",
    "caused no output",
    "no script results",
    "connection refused",
    "connection timed out",
    "timed out",
    "name or service not known",
)

_HTTP_ERROR_STATUS_RE = re.compile(
    r"\b(404 Not Found|502 Bad Gateway|503 Service Unavailable)\b",
    re.IGNORECASE,
)

# ── 强正向标记 ────────────────────────────────────────────
_UID_RE = re.compile(
    r"uid=\d+\([a-z0-9_.-]+\)\s+gid=\d+\([a-z0-9_.-]+\)",
    re.IGNORECASE,
)
_PASSWD_LINE_RE = re.compile(
    r"[a-z_][\w.-]*:[^:\s]{0,2}:\d+:\d+:[^:\n]{0,64}:/[^\n]{1,200}",
    re.IGNORECASE | re.MULTILINE,
)
_RCE_CONFIRMED_KEYWORDS = (
    "JNDI_RCE_SUCCESS",
    "SHIRO_RCE_CONFIRMED",
    "uid=0(root)",
)

# description 里常见的指纹要求关键词 → evidence 里需要出现
_FINGERPRINT_REQUIREMENTS: dict[str, list[str]] = {
    "activemq": ["activemq", "amq-"],
    "tomcat":   ["tomcat", "catalina", "coyote"],
    "struts":   ["struts", "opensymphony", "xwork", "ognl"],
    "shiro":    ["shiro", "rememberme", "deleteme"],
    "weblogic": ["weblogic", "wls", "bea"],
    "jenkins":  ["jenkins"],
    "spring":   ["spring", "springframework"],
    "fastjson": ["fastjson", "alibaba"],
    "geoserver": ["geoserver"],
    "thinkphp": ["thinkphp"],
    "wordpress": ["wordpress", "wp-"],
    "redis":    ["redis"],
    "jboss":    ["jboss"],
}


class FindingVerifier:
    """Stateless verifier: classify each Finding and assign confidence."""

    def verify(
        self,
        finding: VulnFinding,
        *,
        fingerprint: Optional[dict] = None,
        raw_output: str = "",
    ) -> VulnFinding:
        """Mutate finding in-place: set confidence / verification_status / reasons."""
        reasons: list[str] = []
        evidence_lower = (finding.evidence or "").lower()
        desc_lower = (finding.description or "").lower()
        name_lower = (finding.name or "").lower()
        fp_summary = (fingerprint or {}).get("summary", "").lower() if fingerprint else ""

        # ── Pass 1: 强否定 ──────────────────────────────────
        rejected = self._check_hard_negative(
            finding, evidence_lower, desc_lower, name_lower, fp_summary, reasons,
        )
        if rejected:
            finding.confidence = min(finding.confidence, 20)
            finding.verification_status = "rejected"
            finding.exploitable = False
            finding.verification_reasons = reasons
            logger.info(
                "[FindingVerifier] REJECTED: %s (confidence=%d, reasons=%s)",
                finding.name, finding.confidence, reasons,
            )
            return finding

        # ── Pass 2: 强正向 ──────────────────────────────────
        confirmed = self._check_hard_positive(
            finding, evidence_lower, reasons,
        )
        if confirmed:
            finding.confidence = max(finding.confidence, 85)
            finding.verification_status = "confirmed"
            finding.verification_reasons = reasons
            logger.info(
                "[FindingVerifier] CONFIRMED: %s (confidence=%d)",
                finding.name, finding.confidence,
            )
            return finding

        # ── Pass 3: 工具/来源加权 ───────────────────────────
        self._apply_tool_weight(finding, evidence_lower, reasons)

        # ── Pass 4: exploitable 门控 ────────────────────────
        if finding.exploitable and finding.confidence < CONFIDENCE_THRESHOLD_EXPLOIT:
            finding.exploitable = False
            reasons.append(
                f"confidence {finding.confidence} < threshold {CONFIDENCE_THRESHOLD_EXPLOIT}, exploitable downgraded"
            )

        if finding.verification_status == "unverified":
            if finding.confidence >= 70:
                finding.verification_status = "likely"
            elif finding.confidence >= 40:
                finding.verification_status = "suspected"
            else:
                finding.verification_status = "suspected"

        finding.verification_reasons = reasons
        return finding

    # ── 强否定逻辑 ────────────────────────────────────────

    @staticmethod
    def _check_hard_negative(
        finding: VulnFinding,
        evidence_lower: str,
        desc_lower: str,
        name_lower: str,
        fp_summary: str,
        reasons: list[str],
    ) -> bool:
        # Rule N1: evidence 含明确的执行失败/连接失败标记
        for marker in _HARD_NEGATIVE_MARKERS:
            if marker in evidence_lower:
                reasons.append(f"evidence contains failure marker: '{marker}'")
                return True

        # Rule N2: evidence 含 HTTP 错误状态且 description 要求 200
        if "200" in desc_lower or "返回200" in desc_lower or "如果返回" in desc_lower:
            m = _HTTP_ERROR_STATUS_RE.search(finding.evidence or "")
            if m:
                reasons.append(
                    f"description expects HTTP 200 but evidence has {m.group(0)}"
                )
                return True

        # Rule N3: description/name 声称需要特定技术栈，但同端口指纹完全不匹配
        if fp_summary and fp_summary != "unknown":
            for tech, keywords in _FINGERPRINT_REQUIREMENTS.items():
                tech_in_claim = tech in name_lower or tech in desc_lower
                if not tech_in_claim:
                    continue
                tech_in_evidence = any(kw in evidence_lower for kw in keywords)
                tech_in_fingerprint = any(kw in fp_summary for kw in keywords)
                if not tech_in_evidence and not tech_in_fingerprint:
                    # description claims ActiveMQ but neither evidence nor fingerprint shows it
                    reasons.append(
                        f"description claims '{tech}' but neither evidence "
                        f"nor fingerprint ('{fp_summary[:80]}') confirms it"
                    )
                    return True

        # Rule N4: description 要求 "200 + 特定关键词" 但 evidence 只有 200，
        # 缺少那个关键词
        if "如果" in desc_lower and "包含" in desc_lower:
            import re as _re
            m = _re.search(r"包含(.{2,20}?)(?:内容|字符|关键)", desc_lower)
            if m:
                required_keyword = m.group(1).strip().lower()
                if required_keyword and required_keyword not in evidence_lower:
                    if "200 ok" in evidence_lower or "http/1.1 200" in evidence_lower:
                        reasons.append(
                            f"description requires content containing "
                            f"'{required_keyword}' but evidence only has HTTP 200"
                        )
                        return True

        return False

    # ── 强正向逻辑 ────────────────────────────────────────

    @staticmethod
    def _check_hard_positive(
        finding: VulnFinding,
        evidence_lower: str,
        reasons: list[str],
    ) -> bool:
        if _UID_RE.search(finding.evidence or ""):
            reasons.append("uid= pattern matched in evidence")
            return True

        if _PASSWD_LINE_RE.search(finding.evidence or ""):
            reasons.append("/etc/passwd content detected in evidence")
            return True

        for kw in _RCE_CONFIRMED_KEYWORDS:
            if kw.lower() in evidence_lower:
                reasons.append(f"RCE keyword matched: {kw}")
                return True

        return False

    # ── 工具/来源加权 ─────────────────────────────────────

    @staticmethod
    def _apply_tool_weight(
        finding: VulnFinding,
        evidence_lower: str,
        reasons: list[str],
    ) -> None:
        tool = (finding.tool or "").lower()

        if tool == "nuclei":
            if finding.severity in ("critical", "high"):
                finding.confidence = max(finding.confidence, 65)
                reasons.append("nuclei critical/high template → confidence ≥ 65")
            elif finding.severity == "medium":
                finding.confidence = max(finding.confidence, 45)
                reasons.append("nuclei medium template → confidence ≥ 45")
            else:
                finding.confidence = max(finding.confidence, 30)

        elif tool == "nmap-vuln-script":
            has_vuln_keyword = "vulnerable" in evidence_lower
            if has_vuln_keyword:
                finding.confidence = max(finding.confidence, 55)
                reasons.append("nmap script output contains 'VULNERABLE'")
            else:
                finding.confidence = min(finding.confidence, 35)
                reasons.append("nmap script: no VULNERABLE keyword in output")

        elif tool == "kb-detection":
            if finding.exploitable:
                finding.confidence = max(finding.confidence, 70)
                reasons.append("kb-detection with exploitable=True → confidence ≥ 70")
            else:
                finding.confidence = max(finding.confidence, 50)

        elif tool == "llm-discovery":
            if finding.exploitable:
                finding.confidence = max(finding.confidence, 60)
                reasons.append("llm-discovery exploitable → confidence ≥ 60")
            else:
                finding.confidence = max(finding.confidence, 40)
                reasons.append("llm-discovery non-exploitable → confidence ≥ 40")

        elif tool == "hydra":
            if finding.exploitable and "login:" in evidence_lower:
                finding.confidence = max(finding.confidence, 90)
                finding.verification_status = "confirmed"
                reasons.append("hydra cracked credential → confirmed")

        elif tool == "service-enum":
            finding.confidence = min(finding.confidence, 40)
            finding.verification_status = "suspected"
            reasons.append("service-enum: port-open only, no vuln verification")

        elif tool == "cve-direct-check":
            if finding.exploitable:
                finding.confidence = max(finding.confidence, 75)
                reasons.append("cve-direct-check confirmed → confidence ≥ 75")
            else:
                finding.confidence = max(finding.confidence, 45)

        elif tool == "phuip-probe":
            if finding.exploitable:
                finding.confidence = max(finding.confidence, 80)
                reasons.append("phuip strong positive → confidence ≥ 80")
