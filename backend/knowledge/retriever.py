"""
knowledge/retriever.py
知识检索器 —— 从 ExploitKB 检索并格式化利用知识供 LLM 消费

核心职责:
  1. 根据漏洞信息检索匹配的知识条目
  2. 根据环境约束（NAT/公网）标注不可用的方案
  3. 格式化为 LLM 可理解的文本
  4. 将 {TARGET} 占位符替换为实际目标地址
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import Optional

from backend.knowledge.exploit_kb import ExploitEntry, ExploitKB

logger = logging.getLogger(__name__)


_SCHEME_BEFORE_TARGET_RE = re.compile(r"https?://\{TARGET\}", re.IGNORECASE)


def _substitute_target(template: str, target_placeholder: str) -> str:
    """智能替换 ``{TARGET}`` 占位符，避免 scheme 重复拼接。

    KB / Skill YAML 里历史上有两种写法：
      ① ``curl http://{TARGET}/x``  ← 模板自带 scheme，{TARGET} 应当只是 host:port
      ② ``curl {TARGET}/x``          ← 模板没 scheme，{TARGET} 应当是完整 URL

    实际传进来的 ``target_placeholder`` 多数情况已经带 scheme（例如
    ``http://10.0.0.5:8080``），如果遇到 ① 就会被拼成 ``http://http://10.0.0.5:8080/x``。
    这里做一次正则探测：模板里有 ``http(s)?://{TARGET}`` 时，把 placeholder
    的 scheme 剥掉再替换；其他情况按字面替换。
    """
    if not template or "{TARGET}" not in template:
        return template

    bare = target_placeholder
    m_scheme = re.match(r"^(https?://)(.*)$", target_placeholder, re.IGNORECASE)
    if m_scheme:
        bare = m_scheme.group(2)

    if _SCHEME_BEFORE_TARGET_RE.search(template):
        result = template.replace("{TARGET}", bare)
    else:
        result = template.replace("{TARGET}", target_placeholder)

    return result


def check_can_reverse(lhost: str) -> bool:
    """Determine if the target can connect back to LHOST.

    Returns False for empty, loopback, RFC1918 private, and link-local addresses.
    """
    if not lhost:
        return False
    if lhost in ("127.0.0.1", "0.0.0.0", "localhost"):
        return False
    try:
        addr = ipaddress.ip_address(lhost)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False
    except ValueError:
        pass
    return True


class EnvironmentProfile:
    """运行环境特征，影响可用的利用方案"""

    def __init__(self):
        self.lhost: str = os.getenv("LHOST", "")
        self.can_reverse: bool = check_can_reverse(self.lhost)

    def format_constraints(self) -> str:
        lines = []
        if self.can_reverse:
            lines.append(f"- 攻击机IP: {self.lhost}，目标可回连此地址")
            lines.append("- 可使用反弹shell、JNDI回连等方案")
        else:
            reason = "LHOST未配置" if not self.lhost else f"LHOST={self.lhost}(NAT/本地地址)"
            lines.append(f"- 攻击机处于NAT环境（{reason}），目标无法回连攻击机")
            lines.append("- 禁止使用: JNDI注入、反弹shell、DNS OOB等需要目标主动连接攻击机的方案")
            lines.append("- 只能使用: 直接回显型exploit（发HTTP请求，在响应中获得命令执行结果）")
        return "\n".join(lines)


class KnowledgeRetriever:
    """
    知识检索器。

    用法:
        retriever = KnowledgeRetriever()
        text = retriever.retrieve_for_exploit(
            vuln_name="Fastjson 反序列化",
            cve="CVE-2017-18349",
            target_url="http://192.168.1.100:8090",
        )
    """

    def __init__(self, kb: Optional[ExploitKB] = None):
        self.kb = kb or ExploitKB()
        self.env = EnvironmentProfile()

    def retrieve_for_exploit(
        self,
        vuln_name: str = "",
        cve: str = "",
        fingerprint: str = "",
        target_url: str = "",
        evidence: str = "",
        max_entries: int = 3,
    ) -> str:
        """
        检索并格式化利用知识（同步，关键词检索）。
        """
        entries = self.kb.search(
            vuln_name=vuln_name,
            cve=cve,
            fingerprint=fingerprint,
        )

        if not entries:
            logger.info(f"[Retriever] 未找到匹配知识: name={vuln_name}, cve={cve}")
            return self._fallback(vuln_name, cve)

        entries = entries[:max_entries]
        logger.info(
            f"[Retriever] 找到 {len(entries)} 条匹配知识: "
            f"{[e.vuln_id for e in entries]}"
        )

        sections = []
        for entry in entries:
            sections.append(self._format_entry(entry, target_url))
        return "\n\n".join(sections)

    async def retrieve_for_exploit_async(
        self,
        vuln_name: str = "",
        cve: str = "",
        fingerprint: str = "",
        target_url: str = "",
        evidence: str = "",
        max_entries: int = 3,
    ) -> str:
        """
        检索并格式化利用知识（异步，混合检索）。
        优先向量检索，不可用时降级为关键词。
        """
        query = f"{vuln_name} {cve} {fingerprint} {evidence[:200]}"
        entries = await self.kb.search_async(
            query=query,
            vuln_name=vuln_name,
            cve=cve,
            fingerprint=fingerprint,
            top_k=max_entries,
        )

        if not entries:
            entries = self.kb.search(
                vuln_name=vuln_name,
                cve=cve,
                fingerprint=fingerprint,
            )

        if not entries:
            logger.info(f"[Retriever] 未找到匹配知识: name={vuln_name}, cve={cve}")
            return self._fallback(vuln_name, cve)

        entries = entries[:max_entries]
        mode = "向量+关键词" if self.kb.vector_ready else "关键词"
        logger.info(
            f"[Retriever] [{mode}] 找到 {len(entries)} 条: "
            f"{[e.vuln_id for e in entries]}"
        )

        entries = entries[:max_entries]
        logger.info(
            f"[Retriever] 找到 {len(entries)} 条匹配知识: "
            f"{[e.vuln_id for e in entries]}"
        )

        return "\n\n".join(self._format_entry(e, target_url) for e in entries)

    async def retrieve_hybrid(
        self,
        vuln_name: str = "",
        cve: str = "",
        fingerprint: str = "",
        evidence: str = "",
        target_url: str = "",
        max_entries: int = 3,
    ) -> str:
        """
        混合检索（异步，关键词 + 向量语义）。

        如果 embedding 不可用，自动 fallback 到纯关键词。
        """
        query = " ".join(filter(None, [vuln_name, cve, fingerprint, evidence[:200]]))

        entries = await self.kb.search_hybrid(
            query=query,
            vuln_name=vuln_name,
            cve=cve,
            fingerprint=fingerprint,
            top_k=max_entries,
        )

        if not entries:
            logger.info(f"[Retriever] 混合检索未找到: {query[:100]}")
            return self._fallback(vuln_name, cve)

        logger.info(
            f"[Retriever] 混合检索命中 {len(entries)} 条: "
            f"{[e.vuln_id for e in entries]}"
        )

        return "\n\n".join(self._format_entry(e, target_url) for e in entries)

        entries = entries[:max_entries]
        logger.info(
            f"[Retriever] 找到 {len(entries)} 条匹配知识: "
            f"{[e.vuln_id for e in entries]}"
        )

        sections = []
        for entry in entries:
            sections.append(self._format_entry(entry, target_url))

        return "\n\n".join(sections)

    def _format_entry(self, entry: ExploitEntry, target_url: str = "") -> str:
        """将知识条目格式化为 LLM 可读文本"""
        target_placeholder = target_url or "http://TARGET"

        lines = [
            f"### {entry.description}",
            f"分类: {entry.category}",
            f"CVE: {', '.join(entry.match_cves) or 'N/A'}",
            f"受影响版本: {entry.affected_versions}",
        ]

        if entry.common_endpoints:
            lines.append(f"常见触发路径: {', '.join(entry.common_endpoints)}")

        if entry.default_port:
            lines.append(f"默认端口: {entry.default_port}")

        if entry.requires_callback:
            if self.env.can_reverse:
                lines.append(f"⚠️ 此漏洞需要目标回连攻击机。攻击机IP: {self.env.lhost}")
            else:
                lines.append(
                    f"🚫 此漏洞原本需要目标回连攻击机，但当前处于NAT环境无法回连。"
                )
                if entry.callback_note:
                    lines.append(f"   替代方案: {entry.callback_note}")

        if entry.detection_method:
            lines.append(f"\n**漏洞检测方法:**")
            lines.append(f"  {entry.detection_method}")

        if entry.dispatch_skill:
            lines.append(
                f"\n**利用方法**: 已由 Skill `{entry.dispatch_skill}` 接管，"
                f"KB 仅提供原理与回连约束，请勿依赖 KB 文本去拼命令。"
            )

        skip_exploit_steps = bool(entry.dispatch_skill or entry.exploit_steps_deprecated)
        if entry.exploit_steps and not skip_exploit_steps:
            lines.append(f"\n**利用步骤 ({len(entry.exploit_steps)} 步):**")
            for step in entry.exploit_steps:
                lines.append(f"\n  步骤{step.step}: {step.description}")
                if step.command:
                    cmd = _substitute_target(step.command, target_placeholder)
                    lines.append(f"  命令: {cmd}")
                if step.expected_result:
                    lines.append(f"  预期结果: {step.expected_result}")
                if step.notes:
                    lines.append(f"  注意: {step.notes}")

        if entry.verification_command:
            cmd = _substitute_target(entry.verification_command, target_placeholder)
            lines.append(f"\n**RCE验证命令:** {cmd}")
        if entry.verification_success_sign:
            lines.append(f"**成功标志:** {entry.verification_success_sign}")

        raw = entry.raw_json or {}
        pt = raw.get("path_templates") or []
        if pt:
            lines.append("\n**主机攻链模板（按阶段推进，勿停在单点）:**")
            for i, t in enumerate(pt[:15], 1):
                if not isinstance(t, dict):
                    continue
                st = t.get("stage", "")
                pre = t.get("precondition", "")
                act = _substitute_target(t.get("action", "") or "", target_placeholder)
                sig = t.get("success_sign", "")
                nx = t.get("next_stage", "")
                lines.append(f"\n  {i}. [{st}] {act}")
                if pre:
                    lines.append(f"      前置: {pre}")
                if sig:
                    lines.append(f"      成功迹象: {sig}")
                if nx:
                    lines.append(f"      下一阶段: {nx}")
        fb = raw.get("fallbacks") or []
        if fb:
            lines.append("\n**阶段失败备选:**")
            for t in fb[:12]:
                if isinstance(t, dict):
                    lines.append(f"  - [{t.get('stage', '')}] {t.get('action', '')}")
        on = raw.get("opsec_notes") or []
        if on:
            lines.append("\n**OpSec / 稳定性:**")
            for note in on:
                lines.append(f"  - {note}")

        return "\n".join(lines)

    def _fallback(self, vuln_name: str, cve: str) -> str:
        return (
            f"知识库中未找到 {vuln_name or cve} 的专项利用知识。\n"
            f"请根据你的安全知识和扫描证据自行推理利用方案:\n"
            f"- 仔细分析证据中的版本号、框架名、错误信息\n"
            f"- 优先尝试直接回显型exploit（curl/wget发请求看响应）\n"
            f"- 如果是Web应用，尝试常见路径和默认凭据\n"
        )

    def get_environment_constraints(self) -> str:
        return self.env.format_constraints()