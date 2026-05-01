"""
intent_parser.py —— 自然语言任务意图解析器

设计原则：
1. 正则优先：IP/CIDR/域名提取是确定性逻辑，不依赖 LLM
2. 关键词映射：漏洞类型/渗透阶段/范围提示用关键词匹配，同样不依赖 LLM
3. LLM 辅助：仅在正则和关键词无法得出明确结论时，才调用 LLM 做语义补充

安全注意：
- 所有正则只做提取不做执行，无命令注入风险
- LLM 输出会经过 _coerce_intent_payload() 安全规整
- ambiguity_level 判断逻辑纯确定，不会被 LLM 输出覆盖
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from backend.agents.models import ParsedIntent, TargetType, AmbiguityLevel

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════
# 正则集合——确定性提取，不依赖 LLM
# ══════════════════════════════════════════════════════════════

# CIDR 格式: x.x.x.x/N
_CIDR_RE = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b"
)

# IPv4 地址（非 CIDR）
_IP_RE = re.compile(
    r"\b(?<!/)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?\b"
)

# URL 格式
_URL_RE = re.compile(
    r"https?://[^\s,;'\"，。、）)]+", re.IGNORECASE
)

# 域名（含端口）
_DOMAIN_RE = re.compile(
    r"(?<![./@\w])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}(?::\d{1,5})?(?![\w./])"
)

# ══════════════════════════════════════════════════════════════
# 关键词映射表——同样不依赖 LLM
# ══════════════════════════════════════════════════════════════

# 范围提示词 → scope_hint
_SCOPE_HINT_KEYWORDS: dict[str, str] = {
    "内网": "intranet",
    "局域网": "intranet",
    "子网": "subnet",
    "C段": "c_segment",
    "C 段": "c_segment",
    "DMZ": "dmz",
    "隔离区": "dmz",
    "公司网络": "corporate_network",
    "靶场": "ctf_lab",
    "靶机": "ctf_lab",
    "vulnhub": "ctf_lab",
    "hackthebox": "ctf_lab",
    "tryhackme": "ctf_lab",
}

# 漏洞类型关键词 → priority_vulns 标签
_VULN_KEYWORDS: dict[str, list[str]] = {
    # Web 框架漏洞
    "shiro": ["shiro", "deserialization"],
    "fastjson": ["fastjson", "deserialization"],
    "log4j": ["log4j", "rce"],
    "log4shell": ["log4j", "rce"],
    "struts": ["struts2", "rce"],
    "struts2": ["struts2", "rce"],
    "thinkphp": ["thinkphp", "rce"],
    "weblogic": ["weblogic", "deserialization"],
    "jboss": ["jboss", "deserialization"],
    "tomcat": ["tomcat", "default_creds"],
    # 通用漏洞类型
    "弱口令": ["weak_password"],
    "弱密码": ["weak_password"],
    "默认口令": ["default_creds"],
    "默认密码": ["default_creds"],
    "sql注入": ["sqli"],
    "sql 注入": ["sqli"],
    "xss": ["xss"],
    "文件上传": ["file_upload"],
    "上传漏洞": ["file_upload"],
    "文件包含": ["lfi"],
    "lfi": ["lfi"],
    "命令注入": ["cmdi"],
    "命令执行": ["rce"],
    "rce": ["rce"],
    "反序列化": ["deserialization"],
    "ssrf": ["ssrf"],
    "未授权访问": ["auth_bypass"],
    "信息泄露": ["info_leak"],
    "敏感信息": ["info_leak"],
}

# 渗透阶段关键词
_PHASE_KEYWORDS: dict[str, list[str]] = {
    "recon": ["扫一扫", "扫描", "探测", "侦察", "发现", "收集信息", "信息收集",
               "看看", "看一下", "检查一下", "有哪些", "存活"],
    "exploit": ["打一下", "利用", "拿下", "getshell", "get shell",
                 "漏洞利用", "攻击"],
    "post_exploit": ["横向移动", "提权", "内网渗透", "后渗透", "持久化"],
    "full_chain": ["完整测试", "完整渗透", "渗透测试", "红队", "攻防"],
}

# 主机发现触发关键词
_DISCOVERY_KEYWORDS = [
    "有哪些主机", "存活主机", "发现主机", "资产发现", "存活扫描",
    "内网里有哪些", "网段里有哪些", "C段里有哪些",
    "扫描网段", "内网扫描", "资产探测",
]

# Web 相关焦点关键词
_WEB_FOCUS_KEYWORDS = ["web", "网站", "网页", "http", "https", "Web",
                         "Web 服务", "web服务", "web 应用"]

_DB_FOCUS_KEYWORDS = ["数据库", "mysql", "redis", "mongodb", "postgres",
                        "oracle", "mssql", "sql server"]


def _is_valid_ip(ip: str) -> bool:
    """校验是否为合法 IPv4 地址（含 octet 范围检查）。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _is_private_ip(ip: str) -> bool:
    """判断 IP 是否属于私有地址范围。

    用于 SafetyGate 判断——但不在此模块做阻断决策，仅标记。
    """
    if not _is_valid_ip(ip):
        return False
    parts = [int(p) for p in ip.split(".")]
    first, second = parts[0], parts[1]
    # 10.0.0.0/8
    if first == 10:
        return True
    # 172.16.0.0/12
    if first == 172 and 16 <= second <= 31:
        return True
    # 192.168.0.0/16
    if first == 192 and second == 168:
        return True
    return False


def _extract_targets_by_regex(prompt: str) -> tuple[list[str], TargetType]:
    """正则优先提取：CIDR → IP → URL → 域名。

    返回 (targets, target_type)。
    """
    targets: list[str] = []
    target_type: TargetType = "unknown"

    # 1. 优先匹配 CIDR
    cidr_matches = _CIDR_RE.findall(prompt)
    if cidr_matches:
        for m in cidr_matches:
            candidate = m.strip()
            if candidate not in targets:
                targets.append(candidate)
        target_type = "cidr"
        # CIDR 内可能也包含单个 IP，继续提取供参考
        # （例如 "192.168.1.0/24 里重点看 .50"）

    # 2. 提取独立 IP（排除已在 CIDR 中的）
    ip_matches = _IP_RE.findall(prompt)
    if ip_matches:
        for m in ip_matches:
            candidate = m.strip()
            if candidate in targets:
                continue
            # 检查这个 IP 是否已在某个 CIDR 范围内
            in_cidr = False
            for cidr in targets:
                try:
                    cidr_ip, prefix = cidr.split("/")
                    if _ip_in_cidr(candidate, cidr_ip, int(prefix)):
                        in_cidr = True
                        break
                except (ValueError, IndexError):
                    pass
            if not in_cidr and _is_valid_ip(candidate):
                targets.append(candidate)
        if not targets or target_type == "unknown":
            target_type = "ip" if targets else target_type
        # 如果 CIDR 和 IP 共存，保持 target_type=cidr（更宏观的视角）

    # 3. 提取 URL
    url_matches = _URL_RE.findall(prompt)
    for m in url_matches:
        candidate = m.strip().rstrip(".,;'\"，。、)）")
        if candidate not in targets:
            targets.append(candidate)
        if target_type == "unknown":
            target_type = "domain"

    # 4. 提取纯域名（排除 IP 和 URL）
    domain_matches = _DOMAIN_RE.findall(prompt)
    for m in domain_matches:
        candidate = m.strip().rstrip(".,;'\"，。、)）")
        # 排除 IP 格式
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?$", candidate):
            continue
        if candidate not in targets:
            targets.append(candidate)
        if target_type == "unknown":
            target_type = "domain"

    return targets, target_type


def _ip_in_cidr(ip: str, network: str, prefix: int) -> bool:
    """判断 IP 是否在给定 CIDR 范围内（纯位运算，无网络依赖）。"""
    try:
        ip_int = _ip_to_int(ip)
        net_int = _ip_to_int(network)
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return (ip_int & mask) == (net_int & mask)
    except (ValueError, AttributeError):
        return False


def _ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid IP: {ip}")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
           (int(parts[2]) << 8) + int(parts[3])


def _extract_scope_hint(prompt: str) -> Optional[str]:
    """从 prompt 中提取范围提示词。"""
    for keyword, hint in _SCOPE_HINT_KEYWORDS.items():
        if keyword.lower() in prompt.lower():
            return hint
    return None


def _extract_vuln_keywords(prompt: str) -> list[str]:
    """从 prompt 中提取漏洞类型关键词，映射到 priority_vulns 标签。"""
    result: list[str] = []
    prompt_lower = prompt.lower()
    for keyword, tags in _VULN_KEYWORDS.items():
        if keyword.lower() in prompt_lower:
            for tag in tags:
                if tag not in result:
                    result.append(tag)
    return result


def _extract_phases(prompt: str) -> list[str]:
    """从 prompt 中提取期望的渗透阶段。"""
    phases: list[str] = []
    prompt_lower = prompt.lower()
    for phase, keywords in _PHASE_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in prompt_lower:
                if phase not in phases:
                    phases.append(phase)
                break
    return phases if phases else ["recon"]  # 默认至少做侦察


def _check_requires_discovery(prompt: str, targets: list[str],
                               target_type: TargetType) -> bool:
    """判断是否需要先做主机发现。

    触发条件：
    1. prompt 包含发现类关键词
    2. CIDR 目标且没有额外指定具体 IP
    """
    prompt_lower = prompt.lower()
    # 关键词匹配
    for kw in _DISCOVERY_KEYWORDS:
        if kw.lower() in prompt_lower:
            return True
    # CIDR 目标天然需要发现
    if target_type == "cidr":
        return True
    return False


def _extract_task_focus(prompt: str) -> list[str]:
    """从 prompt 中提取任务关注的服务类型。"""
    focus: list[str] = []
    prompt_lower = prompt.lower()
    for kw in _WEB_FOCUS_KEYWORDS:
        if kw.lower() in prompt_lower:
            focus.append("web")
            break
    for kw in _DB_FOCUS_KEYWORDS:
        if kw.lower() in prompt_lower:
            focus.append("database")
            break
    return focus


def _compute_ambiguity(targets: list[str], target_type: TargetType,
                        scope_hint: Optional[str]) -> AmbiguityLevel:
    """根据目标明确程度计算 ambiguity_level。

    纯确定性逻辑，不依赖 LLM。
    """
    if targets and target_type in ("ip", "cidr", "domain"):
        return "clear"
    if scope_hint:
        return "partial"
    return "vague"


def _generate_clarification_needed(targets: list[str],
                                    target_type: TargetType,
                                    scope_hint: Optional[str],
                                    requires_discovery: bool) -> list[str]:
    """生成需要用户补充的问题列表。"""
    questions: list[str] = []
    if not targets:
        questions.append("请提供目标 IP 地址、网段(CIDR)或域名")
    if requires_discovery and not targets:
        questions.append("请指定需要扫描的网段范围(如 10.0.0.0/24)")
    if scope_hint and not targets:
        questions.append(f"检测到您关注 '{scope_hint}' 范围，请提供具体网段")
    return questions


# ══════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════


def parse_intent_deterministic(raw_prompt: str) -> ParsedIntent:
    """纯确定性解析——不依赖 LLM，快速且可审计。

    这是主入口。LLM 辅助解析见 parse_intent_with_llm()。
    """
    targets, target_type = _extract_targets_by_regex(raw_prompt)
    scope_hint = _extract_scope_hint(raw_prompt)
    priority_vulns = _extract_vuln_keywords(raw_prompt)
    phases = _extract_phases(raw_prompt)
    requires_discovery = _check_requires_discovery(raw_prompt, targets, target_type)
    task_focus = _extract_task_focus(raw_prompt)
    ambiguity = _compute_ambiguity(targets, target_type, scope_hint)
    clarifications = _generate_clarification_needed(
        targets, target_type, scope_hint, requires_discovery
    )

    return ParsedIntent(
        target_type=target_type,
        targets=targets,
        scope_hint=scope_hint,
        task_focus=task_focus,
        pentest_phase=phases,
        priority_vulns=priority_vulns,
        requires_discovery=requires_discovery,
        ambiguity_level=ambiguity,
        clarification_needed=clarifications,
        raw_prompt=raw_prompt,
    )


def parse_intent_with_llm(raw_prompt: str) -> ParsedIntent:
    """LLM 辅助解析——在确定性解析基础上，用 LLM 补充语义字段。

    安全注意：
    - 基础解析（targets/target_type/ambiguity_level）由确定性逻辑完成，
      LLM 不参与这些关键判断，避免 prompt injection 绕过。
    - LLM 仅补充 scope_hint/task_focus/pentest_phase 等语义字段。
    - LLM 输出会经过严格校验，不会覆盖确定性结果。
    """
    # 先做确定性解析
    base = parse_intent_deterministic(raw_prompt)

    # 仅在没有 scope_hint 或没有 task_focus 时调用 LLM
    needs_llm = not base.scope_hint or not base.task_focus or not base.priority_vulns
    if not needs_llm:
        return base

    try:
        llm_result = _call_llm_for_intent(raw_prompt)
        if llm_result:
            base = _merge_llm_result(base, llm_result)
    except Exception as e:
        logger.info(f"[intent_parser] LLM 辅助解析失败，回退确定性结果: {e}")

    return base


def _call_llm_for_intent(raw_prompt: str) -> Optional[dict]:
    """调用 LLM 做语义补充。

    使用独立调用，不依赖 LangGraph state，避免耦合。
    超时 5s，失败静默回退。
    """
    import asyncio

    async def _invoke():
        from backend.llm.router import LLMRouter
        from backend.llm.prompts.templates import INTENT_PARSE_PROMPT
        llm = LLMRouter()
        raw = await llm.chat(
            INTENT_PARSE_PROMPT.format(raw_prompt=raw_prompt),
            response_format="json",
            temperature=0.1,
            max_tokens=512,
        )
        return raw

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # 在已有事件循环中，使用同步方式（用 run_coroutine_threadsafe 投递）
            import concurrent.futures
            future = asyncio.run_coroutine_threadsafe(_invoke(), loop)
            raw = future.result(timeout=5.0)
        else:
            raw = asyncio.run(_invoke())
    except Exception as e:
        logger.info(f"[intent_parser] LLM 调用失败: {e}")
        return None

    if not raw:
        return None

    # 安全反序列化
    try:
        data = json.loads(raw if isinstance(raw, str) else str(raw))
        if not isinstance(data, dict):
            return None
        return data
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _merge_llm_result(base: ParsedIntent,
                       llm_data: dict) -> ParsedIntent:
    """将 LLM 补充的语义字段安全合并到确定性结果。

    核心原则：LLM 不覆盖确定性字段（targets/target_type/ambiguity_level）。
    """
    # scope_hint: 仅在确定性结果为空时采纳 LLM
    if not base.scope_hint:
        llm_scope = str(llm_data.get("scope_hint") or "").strip()[:64]
        if llm_scope:
            base.scope_hint = llm_scope

    # task_focus: 合并去重
    llm_focus = llm_data.get("task_focus")
    if isinstance(llm_focus, list):
        for f in llm_focus:
            if isinstance(f, str) and f.strip().lower() not in base.task_focus:
                base.task_focus.append(f.strip().lower())

    # pentest_phase: 仅在确定性结果为空时采纳
    if not base.pentest_phase or base.pentest_phase == ["recon"]:
        llm_phases = llm_data.get("pentest_phases") or llm_data.get("pentest_phase")
        if isinstance(llm_phases, list):
            phases = [p.lower().strip() for p in llm_phases if isinstance(p, str)]
            if phases:
                base.pentest_phase = phases

    # priority_vulns: 合并去重（LLM 可能识别出关键词未命中的 CVE）
    llm_vulns = llm_data.get("priority_vulns")
    if isinstance(llm_vulns, list):
        for v in llm_vulns:
            if isinstance(v, str) and v.strip().lower() not in base.priority_vulns:
                base.priority_vulns.append(v.strip().lower())

    return base


# ── 便捷函数：外部模块调用入口 ──────────────────────────


def parse_target_from_prompt(prompt: str) -> str:
    """从自然语言中提取第一个可用的目标地址。

    用于兼容旧接口：当 target 字段为空时，从 raw_prompt 提取。
    """
    intent = parse_intent_deterministic(prompt)
    return intent.targets[0] if intent.targets else ""
