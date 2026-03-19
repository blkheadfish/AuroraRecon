"""nikto_parser.py —— 解析 Nikto JSON 输出（过滤噪音）"""
from __future__ import annotations
import json
import logging
from backend.agents.models import VulnFinding

logger = logging.getLogger(__name__)

# 这些关键词开头/包含的 Nikto 输出是纯信息噪音，不算漏洞
NOISE_KEYWORDS = [
    "target ip:",
    "target hostname:",
    "target port:",
    "start time:",
    "end time:",
    "host(s) tested",
    "0 error(s)",
    "items checked:",
    "items reported",
    "scan terminated",
    "server:",
    "platform:",
    "retrieved x-powered-by",
    "no cgi directories",
    "suggested security header missing",
    "junk http methods",
    "appears to be outdated",
    "allowed http methods",
    "options: allowed",
]


class NiktoParser:
    def parse(self, output: str, target: str) -> list[VulnFinding]:
        findings: list[VulnFinding] = []
        try:
            data = json.loads(output)
            vulnerabilities = data.get("vulnerabilities", [])
            for v in vulnerabilities:
                msg = v.get("msg", "").strip()
                if _is_noise(msg):
                    continue
                findings.append(VulnFinding(
                    name=msg[:80] or "Nikto 发现",
                    severity="info",
                    target=target,
                    description=msg,
                    evidence=v.get("url", ""),
                    exploitable=False,
                    tool="nikto",
                ))
        except (json.JSONDecodeError, KeyError):
            for line in output.splitlines():
                if "+ " in line and len(line) > 10:
                    msg = line.strip().lstrip("+ ")
                    if _is_noise(msg):
                        continue
                    findings.append(VulnFinding(
                        name=msg[:80] or "Nikto 发现",
                        severity="info",
                        target=target,
                        description=msg,
                        exploitable=False,
                        tool="nikto",
                    ))
        return findings


def _is_noise(msg: str) -> bool:
    """判断是否是无意义的元信息/低价值发现"""
    if len(msg) < 5:
        return True
    lower = msg.lower()
    return any(kw in lower for kw in NOISE_KEYWORDS)