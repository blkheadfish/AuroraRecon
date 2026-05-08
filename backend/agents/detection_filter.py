"""
detection_filter.py
纯探测类 Finding 过滤器

将所有 VulnFinding 按确定性规则分类：
- 真实漏洞 → 保留在 findings 列表
- 纯服务探测/组件识别 → 降级为侦察结果（不进漏洞列表）

规则全部来自 ``backend/config/detection_filter.yaml``，不依赖 LLM。
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import yaml

from backend.agents.models import VulnFinding

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "detection_filter.yaml"


def _load_config() -> dict:
    """加载过滤配置。加载失败返回空规则（不做过滤）。"""
    try:
        raw = _CONFIG_PATH.read_text(encoding="utf-8")
        return yaml.safe_load(raw) or {}
    except Exception as exc:
        logger.warning(f"[DetectionFilter] 配置加载失败: {exc}，使用空规则集")
        return {}


def _get_rules() -> dict:
    """提取 detection_filter 规则块，做一次小写归一化。"""
    cfg = _load_config()
    df = cfg.get("detection_filter", {}) or {}
    return {
        "name_keywords": [s.strip().lower() for s in df.get("name_keywords", []) if s and isinstance(s, str)],
        "description_keywords": [s.strip().lower() for s in df.get("description_keywords", []) if s and isinstance(s, str)],
        "template_id_patterns": [s.strip().lower() for s in df.get("template_id_patterns", []) if s and isinstance(s, str)],
        "keep_always_patterns": [s.strip().lower() for s in df.get("keep_always_patterns", []) if s and isinstance(s, str)],
        "exclude_info_severity": df.get("exclude_info_severity", True),
    }


def _should_keep(finding: VulnFinding, rules: dict) -> bool:
    """判断一个 finding 是否应保留在漏洞列表中。

    返回 True 表示保留（是真实漏洞），False 表示过滤（纯探测结果）。

    过滤策略：
    - 只过滤命中检测关键词的 nuclei/nikto 结果，不干扰 service-enum 等工具产出的 findings
    - 若 finding 已被标记为 exploitable=True，无条件保留
    - 若 finding 的 name/description 匹配 keep_always 白名单，无条件保留
    """
    name_lower = (finding.name or "").lower()
    desc_lower = (finding.description or "").lower()
    evidence_lower = (finding.evidence or "").lower()

    keep_patterns = rules["keep_always_patterns"]

    if finding.exploitable:
        return True

    combined = f"{name_lower} {desc_lower}"
    if any(kp in combined for kp in keep_patterns):
        return True

    detection_hits = 0

    name_keywords = rules["name_keywords"]
    if any(kw in name_lower for kw in name_keywords):
        detection_hits += 2

    desc_keywords = rules["description_keywords"]
    if any(kw in desc_lower for kw in desc_keywords):
        detection_hits += 1

    tid_patterns = rules["template_id_patterns"]
    tid = (getattr(finding, "template_id", "") or "").lower()
    if tid and any(pat in tid for pat in tid_patterns):
        detection_hits += 1

    if '"template-id"' in evidence_lower or '"template_id"' in evidence_lower:
        import re
        m = re.search(r'"template[-_]id"\s*:\s*"([^"]+)"', evidence_lower)
        if m:
            ev_tid = m.group(1).lower()
            if any(pat in ev_tid for pat in tid_patterns):
                detection_hits += 1

    severity_lower = (finding.severity or "info").lower()
    if detection_hits > 0 and severity_lower == "info":
        return False

    if detection_hits >= 2 and finding.confidence < 60:
        return False

    tool_lower = (finding.tool or "").lower()
    if severity_lower == "info" and tool_lower == "nikto":
        return False

    return True


def filter_findings(
    findings: list[VulnFinding],
    *,
    rules: Optional[dict] = None,
) -> tuple[list[VulnFinding], list[VulnFinding]]:
    """将 findings 拆分为「漏洞列表」和「侦察结果」。

    Args:
        findings: 原始 VulnFinding 列表
        rules: 可选的自定义规则 dict（为 None 时从 YAML 加载）

    Returns:
        (vuln_findings, recon_findings):
        - vuln_findings: 应保留在漏洞列表中的 Finding
        - recon_findings: 降级为侦察结果的 Finding（不进漏洞列表）
    """
    if rules is None:
        rules = _get_rules()

    if not rules.get("name_keywords") and not rules.get("description_keywords"):
        return findings, []

    vuln_findings: list[VulnFinding] = []
    recon_findings: list[VulnFinding] = []

    for f in findings:
        if _should_keep(f, rules):
            vuln_findings.append(f)
        else:
            recon_findings.append(f)

    if recon_findings:
        logger.info(
            f"[DetectionFilter] 过滤 {len(recon_findings)} 个纯探测结果: "
            + ", ".join(f.name[:60] for f in recon_findings[:10])
            + (f" ... +{len(recon_findings) - 10}" if len(recon_findings) > 10 else "")
        )

    return vuln_findings, recon_findings


def get_detection_rules() -> dict:
    """供外部查看当前生效的规则（调试/API 用）。"""
    return _get_rules()
