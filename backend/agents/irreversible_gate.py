"""irreversible_gate.py — 不可逆动作分类器。

在 autonomous 模式下，可逆动作自动放行，不可逆动作仍触发 checkpoint 暂停。
不可逆分类宁可保守（多卡人）；绝对禁止项（危险命令黑名单）不因 autonomous 放行。
"""
from __future__ import annotations

import re
from typing import Optional

IRREVERSIBLE_PHASES = frozenset({
    "persistence",
    "lateral_movement",
})

IRREVERSIBLE_ACTIONS = frozenset({
    "scope_expansion",
    "create_user",
    "delete_data",
    "write_to_system",
    "registry_write",
    "scheduled_task",
    "wmi_persistence",
})

_IRREVERSIBLE_CMD_PATTERNS = (
    re.compile(r"useradd|adduser"),
    re.compile(r"net\s+user\s+\S+\s+/add"),
    re.compile(r"schtasks\s+/create"),
    re.compile(r"reg\s+add"),
    re.compile(r"New-Service|New-LocalUser"),
    re.compile(r"crontab\s+-"),
    re.compile(r"systemctl\s+(enable|start)\b(?!.*status)"),
    re.compile(r">>\s*/etc/(passwd|shadow|sudoers)"),
    re.compile(r">>\s*/root/"),
    re.compile(r"mkfifo\s"),
    re.compile(r"netcat\s+-[lL]"),
    re.compile(r"nc\s+-[lL]"),
    re.compile(r"ssh-copy-id"),
    re.compile(r"wget.*\|\s*(ba)?sh\b"),
    re.compile(r"curl.*\|\s*(ba)?sh\b"),
    re.compile(r"rm\s+-[rf]{2,}\s"),
    re.compile(r"del\s+/[fsq]"),
    re.compile(r"drop\s+(table|database)"),
    re.compile(r"iptables\s+-[AI]"),
    re.compile(r"netsh\s+firewall"),
    re.compile(r"Set-ItemProperty\s+.*\\(Windows\s+NT|SYSTEM|SOFTWARE)"),
)

SCOPE_EXPANSION_PATTERNS = (
    re.compile(r"nmap\s+(-sn\s+)?(?!.*("
               r"127\.0\.0\.[0-9]+|"
               r"10\.\d+\.\d+\.\d+|"
               r"172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|"
               r"192\.168\.\d+\.\d+"
               r"))\d+\.\d+\.\d+\.\d+"),
    re.compile(r"for\s+host\s+in"),
)


def _is_irreversible_command(cmd: str) -> tuple[bool, str]:
    if not cmd:
        return (False, "")
    for pattern in _IRREVERSIBLE_CMD_PATTERNS:
        if pattern.search(cmd):
            return (True, f"命令模式命中不可逆规则: {pattern.pattern[:60]}")
    return (False, "")


def _is_scope_expansion(cmd: str) -> tuple[bool, str]:
    if not cmd:
        return (False, "")
    for pattern in SCOPE_EXPANSION_PATTERNS:
        if pattern.search(cmd):
            return (True, "命令可能发现新主机，scope 可能扩张")
    return (False, "")


def is_irreversible(
    action: str = "",
    cmd: str = "",
    phase: str = "",
) -> tuple[bool, str]:
    """判定一个动作是否不可逆。

    Args:
        action: 决策事件 action (如 "persistence", "lateral_movement")
        cmd: shell 命令字符串
        phase: 当前阶段名

    Returns:
        (is_irreversible, reason) — 宁可保守，宁可多卡。
    """
    if phase in IRREVERSIBLE_PHASES:
        return (True, f"阶段 '{phase}' 归类为不可逆")

    if action in IRREVERSIBLE_ACTIONS:
        return (True, f"动作 '{action}' 归类为不可逆")

    if cmd:
        is_irrev, reason = _is_irreversible_command(cmd)
        if is_irrev:
            return (True, reason)

        is_expand, reason = _is_scope_expansion(cmd)
        if is_expand:
            return (True, reason)

    return (False, "")


def is_reversible(action: str = "", cmd: str = "", phase: str = "") -> bool:
    irrev, _ = is_irreversible(action=action, cmd=cmd, phase=phase)
    return not irrev
