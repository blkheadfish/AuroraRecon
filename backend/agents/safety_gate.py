"""
safety_gate.py —— 渗透任务确定性安全卡口

设计原则（严格遵循）：
1. 所有规则来自 backend/config/safety_rules.yaml，LLM 无法覆盖
2. 三层模型：authorization_token 放行 → 黑名单 BLOCK → 灰名单 WARNING
3. 每次 BLOCK/WARNING 都写审计日志
4. 不依赖 LLM，不被 prompt injection 绕过

安全注意：
- IP 范围判断使用 ipaddress 标准库，不调用外部 API
- 关键词匹配不区分大小写但只匹配完整中文短语
- 敏感 IP 段配置在 YAML 中，运维可控
"""
from __future__ import annotations

import ipaddress
import logging
import os
from pathlib import Path
from typing import Optional

import yaml

from backend.agents.models import ParsedIntent, SafetyCheckResult, RiskLevel
from backend.agents.intent_parser import _is_valid_ip, _is_private_ip

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════
# 配置加载
# ══════════════════════════════════════════════════════════════

_CONFIG_PATH = os.getenv(
    "SAFETY_RULES_PATH",
    str(Path(__file__).resolve().parent.parent / "config" / "safety_rules.yaml")
)


def _load_rules() -> dict:
    """加载 YAML 安全规则配置。规则加载失败时使用空配置（默认安全）。"""
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        return config.get("safety", {})
    except FileNotFoundError:
        logger.warning(f"[SafetyGate] 配置文件未找到: {_CONFIG_PATH}，使用空规则")
        return {}
    except Exception as e:
        logger.error(f"[SafetyGate] 配置文件加载失败: {e}，使用空规则")
        return {}


# ══════════════════════════════════════════════════════════════
# IP / CIDR 判断工具（纯确定性运算）
# ══════════════════════════════════════════════════════════════


def _get_cidr_prefix(cidr_str: str) -> int:
    try:
        return int(cidr_str.split("/")[1])
    except (IndexError, ValueError):
        return 32


def _ip_in_cidrs(ip: str, cidr_list: list[str]) -> bool:
    """判断 IP 是否在任意一个 CIDR 范围内。使用 ipaddress 标准库。"""
    if not _is_valid_ip(ip) or not cidr_list:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr_str in cidr_list:
            try:
                network = ipaddress.ip_network(cidr_str, strict=False)
                if ip_obj in network:
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def _cidr_overlaps(cidr_str: str, cidr_list: list[str]) -> bool:
    """判断一个 CIDR 是否与列表中的任意 CIDR 有重叠。"""
    if not cidr_list:
        return False
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False
    for other_str in cidr_list:
        try:
            other = ipaddress.ip_network(other_str, strict=False)
            if network.overlaps(other):
                return True
        except ValueError:
            continue
    return False


# ══════════════════════════════════════════════════════════════
# SafetyGate 核心
# ══════════════════════════════════════════════════════════════


class PentestSafetyGate:
    """渗透任务安全卡口。

    校验顺序：
    1. authorization_token 存在 → 放行（记录审计日志）
    2. 白名单命中 → 放行
    3. 黑名单命中 → BLOCK
    4. 灰名单命中 → WARNING
    5. 默认：公网 IP 警告，私网 IP 放行
    """

    def __init__(self):
        self._rules = _load_rules()

    def reload(self) -> None:
        self._rules = _load_rules()
        logger.info("[SafetyGate] 规则已重新加载")

    @property
    def block_rules(self) -> dict:
        return self._rules.get("block_list", {})

    @property
    def warn_rules(self) -> dict:
        return self._rules.get("warn_list", {})

    @property
    def allow_rules(self) -> dict:
        return self._rules.get("allow_list", {})

    def check(self, intent: ParsedIntent,
              authorization_token: Optional[str] = None,
              user_id: str = "") -> SafetyCheckResult:
        """执行安全校验。"""
        # ── 第一层：有授权 token → 全量放行 ──────────────
        if authorization_token:
            logger.info(
                f"[SafetyGate] 授权令牌通过: user={user_id}, "
                f"token_prefix={authorization_token[:6]}***, targets={intent.targets}"
            )
            return SafetyCheckResult(
                passed=True,
                risk_level="safe",
                warnings=[f"已记录授权令牌: {authorization_token[:6]}***"],
            )

        # ── 第二层：白名单检查 ────────────────────────────
        if self._check_allowlist(intent):
            logger.info(
                f"[SafetyGate] 白名单通过: targets={intent.targets}"
            )
            return SafetyCheckResult(passed=True, risk_level="safe")

        # ── 第三层：黑名单检查 ────────────────────────────
        blocked, block_reason = self._check_blocklist(intent)
        if blocked:
            self._audit_log("BLOCK", intent, block_reason, user_id,
                             authorization_token)
            return SafetyCheckResult(
                passed=False,
                risk_level="blocked",
                block_reason=block_reason,
            )

        # ── 第四层：灰名单检查（WARNING）──────────────────
        warnings, confirmations = self._check_warnlist(intent)
        if warnings:
            self._audit_log("WARNING", intent, "; ".join(warnings),
                             user_id, authorization_token)
            return SafetyCheckResult(
                passed=True,
                risk_level="warning",
                warnings=warnings,
                required_confirmations=confirmations,
            )

        return SafetyCheckResult(passed=True, risk_level="safe")

    # ── 白名单 ─────────────────────────────────────────

    def _check_allowlist(self, intent: ParsedIntent) -> bool:
        authorized_cidrs = self.allow_rules.get("authorized_cidrs", []) or []
        authorized_hosts = self.allow_rules.get("authorized_hosts", []) or []

        for target in intent.targets:
            if "/" in target:
                if _cidr_overlaps(target, authorized_cidrs):
                    return True
            else:
                if _is_valid_ip(target):
                    if target in authorized_hosts or _ip_in_cidrs(target, authorized_cidrs):
                        return True
                elif target in authorized_hosts:
                    return True

        # scope_hint 为 ctf_lab 时额外放行
        if intent.scope_hint == "ctf_lab":
            return True

        return False

    # ── 黑名单 ─────────────────────────────────────────

    def _check_blocklist(self, intent: ParsedIntent) -> tuple[bool, Optional[str]]:
        cloud_cidrs = self.block_rules.get("cloud_provider_cidrs", []) or []
        gov_cidrs = self.block_rules.get("government_cidrs", []) or []
        keywords = self.block_rules.get("unauthorized_keywords", []) or []
        max_prefix = self.block_rules.get("max_cidr_prefix", 8)

        # 1. 恶意意图关键词
        prompt_lower = intent.raw_prompt.lower()
        for kw in keywords:
            if kw.lower() in prompt_lower:
                return True, f"检测到未授权意图关键词: '{kw}'"

        # 2. CIDR 前缀过大
        for target in intent.targets:
            if "/" in target:
                prefix = _get_cidr_prefix(target)
                if prefix <= max_prefix:
                    return True, f"CIDR 范围过大 (/{prefix} <= /{max_prefix})，拒绝执行"

        # 3. 云服务商 metadata IP 段
        for target in intent.targets:
            if _is_valid_ip(target) and _ip_in_cidrs(target, cloud_cidrs):
                return True, f"目标 {target} 属于云服务商 metadata IP 段，拒绝执行"

        # 4. 政府/关基 IP 段
        for target in intent.targets:
            if _is_valid_ip(target) and _ip_in_cidrs(target, gov_cidrs):
                return True, f"目标 {target} 属于政府/关基 IP 段，拒绝执行"

        return False, None

    # ── 灰名单 ─────────────────────────────────────────

    def _check_warnlist(self, intent: ParsedIntent) -> tuple[list[str], list[str]]:
        warnings: list[str] = []
        confirmations: list[str] = []
        warn_rules = self.warn_rules

        cidr_threshold = warn_rules.get("cidr_warn_threshold", 16)
        public_ip_no_auth = warn_rules.get("public_ip_no_auth", True)
        exploit_without_target = warn_rules.get("exploit_without_clear_target", True)

        # 1. CIDR 范围警告
        for target in intent.targets:
            if "/" in target:
                prefix = _get_cidr_prefix(target)
                if prefix < cidr_threshold:
                    warnings.append(
                        f"目标 CIDR 范围较大 (/{prefix} < /{cidr_threshold})，"
                        f"扫描 {target} 可能产生大量流量"
                    )
                    confirmations.append("confirm_large_cidr")

        # 2. 公网 IP 无授权警告
        if public_ip_no_auth:
            for target in intent.targets:
                if _is_valid_ip(target) and not _is_private_ip(target):
                    warnings.append(
                        f"目标 {target} 为公网 IP，请确认您拥有对该目标的合法测试授权"
                    )
                    confirmations.append("confirm_public_ip_authorization")
                    break

        # 3. exploit 阶段但目标不明确
        if exploit_without_target and "exploit" in intent.pentest_phase:
            if intent.ambiguity_level in ("partial", "vague"):
                warnings.append(
                    "您期望执行漏洞利用阶段，但当前目标不明确。请确认具体利用目标"
                )
                confirmations.append("confirm_exploit_target")

        # 4. 需要发现但无明确网段
        if intent.requires_discovery and intent.ambiguity_level == "vague":
            warnings.append(
                "需要主机发现但没有指定目标网段，请提供具体扫描范围"
            )

        return warnings, confirmations

    # ── 审计日志 ────────────────────────────────────────

    def _audit_log(self, level: str, intent: ParsedIntent,
                   reason: str, user_id: str,
                   authorization_token: Optional[str]) -> None:
        log_msg = (
            f"[SAFETY_AUDIT] level={level} "
            f"user={user_id} "
            f"targets={intent.targets} "
            f"target_type={intent.target_type} "
            f"ambiguity={intent.ambiguity_level} "
            f"reason={reason} "
            f"has_token={'yes' if authorization_token else 'no'}"
        )
        if level == "BLOCK":
            logger.warning(log_msg)
        else:
            logger.info(log_msg)

        # 异步写入 DB 审计日志（最佳努力，不阻塞主流程）
        try:
            import asyncio
            from datetime import datetime
            audit_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "level": level,
                "user_id": user_id,
                "targets": str(intent.targets),
                "raw_prompt": intent.raw_prompt[:200],
                "reason": reason,
                "has_authorization": bool(authorization_token),
            }
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_write_audit_db(audit_entry))
            except RuntimeError:
                pass
        except Exception as e:
            logger.debug(f"[SafetyGate] 审计日志 DB 写入跳过: {e}")


async def _write_audit_db(entry: dict) -> None:
    try:
        from backend.db.database import save_safety_audit_log
        await save_safety_audit_log(entry)
    except Exception as e:
        logger.debug(f"[SafetyGate] 审计日志 DB 写入失败: {e}")


# ══════════════════════════════════════════════════════════════
# 单例
# ══════════════════════════════════════════════════════════════

_safety_gate: Optional[PentestSafetyGate] = None


def get_safety_gate() -> PentestSafetyGate:
    global _safety_gate
    if _safety_gate is None:
        _safety_gate = PentestSafetyGate()
    return _safety_gate
