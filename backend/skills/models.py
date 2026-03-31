"""
skills/models.py
Skill 数据模型

设计原则：
  - 所有字段都有合理默认值，YAML 只需写必要部分
  - 条件判断用简单的 key-value 字典，不搞 DSL
  - parse_rules 用声明式规则，不写代码
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ─────────────────────────────────────────────────────────
# 基础类型
# ─────────────────────────────────────────────────────────

class StepOutcome(str, Enum):
    """步骤执行后的跳转指令"""
    NEXT_STEP = "next_step"           # 继续当前路径的下一步
    NEXT_PATH = "next_path"           # 放弃当前路径，尝试下一条
    CONCLUDE_SUCCESS = "conclude_success"  # 利用成功
    CONCLUDE_FAIL = "conclude_fail"    # 利用失败（不再尝试）


@dataclass
class ParseRule:
    """
    探测结果解析规则。

    声明式：根据命令输出的内容，设置上下文变量。
    每条规则互不排斥，按顺序全部评估。
    """
    # 触发条件（满足 ANY 一个即触发）
    if_contains: list[str] = field(default_factory=list)
    if_not_contains: list[str] = field(default_factory=list)
    if_status_code: list[int] = field(default_factory=list)
    if_regex: str = ""  # 正则匹配

    # 附加条件
    and_body_not_empty: bool = False

    # 触发后设置的上下文变量
    set: dict[str, Any] = field(default_factory=dict)

    def evaluate(self, stdout: str, stderr: str, status_code: int) -> dict[str, Any]:
        """评估规则，返回要设置的变量（空 dict = 未触发）"""
        combined = f"{stdout} {stderr}".lower()

        triggered = False

        if self.if_contains:
            if any(kw.lower() in combined for kw in self.if_contains):
                triggered = True

        if self.if_not_contains:
            if all(kw.lower() not in combined for kw in self.if_not_contains):
                triggered = True

        if self.if_status_code:
            if status_code in self.if_status_code:
                triggered = True

        if self.if_regex:
            if re.search(self.if_regex, stdout, re.IGNORECASE):
                triggered = True

        # 无任何触发条件 = 不触发
        if not (self.if_contains or self.if_not_contains
                or self.if_status_code or self.if_regex):
            return {}

        if not triggered:
            return {}

        # 附加条件检查
        if self.and_body_not_empty and not stdout.strip():
            return {}

        return dict(self.set)


@dataclass
class SuccessCriteria:
    """步骤成功判定条件"""
    stdout_contains_any: list[str] = field(default_factory=list)
    stdout_contains_all: list[str] = field(default_factory=list)
    stdout_not_empty: bool = False
    stdout_regex: str = ""
    exit_code: Optional[int] = None

    def evaluate(self, stdout: str, stderr: str, exit_code: int) -> bool:
        combined = f"{stdout} {stderr}"

        if self.stdout_contains_any:
            if not any(kw.lower() in combined.lower() for kw in self.stdout_contains_any):
                return False

        if self.stdout_contains_all:
            if not all(kw.lower() in combined.lower() for kw in self.stdout_contains_all):
                return False

        if self.stdout_not_empty:
            # 去除空白和常见无意义输出
            clean = stdout.strip()
            if not clean or clean in ("null", "None", "{}", "[]"):
                return False

        if self.stdout_regex:
            if not re.search(self.stdout_regex, stdout, re.IGNORECASE):
                return False

        if self.exit_code is not None:
            if exit_code != self.exit_code:
                return False

        return True


# ─────────────────────────────────────────────────────────
# 探测阶段
# ─────────────────────────────────────────────────────────

@dataclass
class ProbeStep:
    """探测子步骤（一个 Probe 可包含多个 step）"""
    command: str
    parse_rules: list[ParseRule] = field(default_factory=list)
    timeout: int = 15


@dataclass
class Probe:
    """
    探测定义。

    利用前的精准信息收集：确认漏洞、推断版本、检测环境约束。
    探测结果设置到 SkillContext 中，供决策树使用。
    """
    id: str
    description: str = ""

    # 单命令探测（简单场景）
    command: str = ""
    parse_rules: list[ParseRule] = field(default_factory=list)
    timeout: int = 15

    # 多步骤探测（复杂场景，如需要多个 payload 对比）
    steps: list[ProbeStep] = field(default_factory=list)

    # 前置条件：上下文变量满足才执行
    depends_on: dict[str, Any] = field(default_factory=dict)

    # 环境要求：如 env.can_reverse = true
    requires: dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────
# 利用步骤和路径
# ─────────────────────────────────────────────────────────

@dataclass
class ExploitStep:
    """利用路径中的单个步骤"""
    id: str
    description: str = ""
    command: str = ""
    timeout: int = 30

    # 端口映射（用于反连回调）
    publish_ports: list[int] = field(default_factory=list)

    # 成功判定
    success_criteria: SuccessCriteria = field(default_factory=SuccessCriteria)

    # 跳转控制
    on_success: str = "next_step"       # step_id 或 StepOutcome
    on_fail: str = "next_path"          # step_id 或 StepOutcome

    # 成功时的证据提取
    evidence_capture: dict[str, str] = field(default_factory=dict)
    # 如 {"current_user": "stdout", "shell_type": "rce_bcel"}
    # "stdout" = 从命令输出中提取，其他值为字面量


@dataclass
class ExploitPath:
    """
    一条利用路径。

    每个 Skill 包含多条路径，按 priority 排序。
    引擎选择第一个满足条件的路径执行。
    """
    path_id: str
    name: str = ""
    priority: int = 10
    principle: str = ""   # 原理说明（给 LLM 参考）

    # 前置条件（全部满足才选择此路径）
    conditions: dict[str, Any] = field(default_factory=dict)

    # 排除条件（满足任一则跳过）
    skip_if: dict[str, Any] = field(default_factory=dict)

    # 利用步骤
    steps: list[ExploitStep] = field(default_factory=list)

    # 特殊模式：LLM 自由推理
    mode: str = ""  # "" = 正常步骤执行, "react_freeform" = LLM 自由推理
    max_rounds: int = 5


# ─────────────────────────────────────────────────────────
# 匹配规则
# ─────────────────────────────────────────────────────────

@dataclass
class MatchRule:
    """单条匹配规则"""
    fingerprint_contains: list[str] = field(default_factory=list)
    cve_matches: list[str] = field(default_factory=list)
    evidence_contains: list[str] = field(default_factory=list)
    json_probe_result: str = ""
    service_is: str = ""       # nmap service 字段
    port_is: list[int] = field(default_factory=list)

    def matches(
        self,
        fingerprint: str = "",
        cve: str = "",
        evidence: str = "",
        json_probe: str = "",
        service: str = "",
        port: Optional[int] = None,
    ) -> bool:
        """检查是否匹配。所有非空字段必须全部满足。"""
        fp_lower = fingerprint.lower()
        ev_lower = evidence.lower()

        checks = []

        if self.fingerprint_contains:
            checks.append(
                any(kw.lower() in fp_lower for kw in self.fingerprint_contains)
            )

        if self.cve_matches:
            checks.append(
                any(c.lower() == cve.lower() for c in self.cve_matches)
            )

        if self.evidence_contains:
            checks.append(
                any(kw.lower() in ev_lower for kw in self.evidence_contains)
            )

        if self.json_probe_result:
            checks.append(
                self.json_probe_result.lower() in json_probe.lower()
            )

        if self.service_is:
            checks.append(
                self.service_is.lower() == service.lower()
            )

        if self.port_is:
            checks.append(
                port in self.port_is if port else False
            )

        # 无条件 = 不匹配
        if not checks:
            return False

        return all(checks)


@dataclass
class MatchConfig:
    """匹配配置"""
    rules: list[MatchRule] = field(default_factory=list)   # 满足 ANY 即匹配
    exclude: list[MatchRule] = field(default_factory=list)  # 满足 ANY 即排除


# ─────────────────────────────────────────────────────────
# 顶层 Skill 定义
# ─────────────────────────────────────────────────────────

@dataclass
class Skill:
    """
    完整的 Exploit Skill 定义。

    一个 Skill 对应一类漏洞的完整利用方法论：
      - 原理说明
      - 匹配规则
      - 探测阶段
      - 多条利用路径（按优先级排列）
      - 修复建议
    """
    skill_id: str
    name: str
    category: str = ""
    version: str = "1.0"
    principle: str = ""   # 漏洞原理（给 LLM 兜底时参考）

    match: MatchConfig = field(default_factory=MatchConfig)
    probes: list[Probe] = field(default_factory=list)
    exploit_paths: list[ExploitPath] = field(default_factory=list)

    remediation: str = ""

    # 加载元信息
    source_file: str = ""  # YAML 文件路径


# ─────────────────────────────────────────────────────────
# 运行时上下文
# ─────────────────────────────────────────────────────────

@dataclass
class SkillContext:
    """
    Skill 执行过程中的运行时上下文。

    存储：
    - 目标信息（从 VulnAgent 传入）
    - 环境信息（攻击机 IP、是否可回连）
    - 探测阶段设置的变量
    - 步骤执行记录
    """
    # 目标信息
    endpoint: str = ""          # 实际的 JSON/Web 接口 URL
    target_ip: str = ""
    target_port: int = 0
    target_os: str = "unknown"

    # 环境信息
    lhost: str = ""
    can_reverse: bool = False
    task_id: Optional[str] = None  # 任务 ID，用于持久容器执行

    # 动态变量（探测阶段设置，决策树使用）
    variables: dict[str, Any] = field(default_factory=dict)

    # 执行记录
    probe_records: list[dict] = field(default_factory=list)
    step_records: list[dict] = field(default_factory=list)
    commands_run: list[str] = field(default_factory=list)

    # 当前成功的利用命令模板（用于验证阶段复用）
    exploit_cmd_template: str = ""

    def set_var(self, key: str, value: Any) -> None:
        self.variables[key] = value

    def get_var(self, key: str, default: Any = None) -> Any:
        return self.variables.get(key, default)

    def check(self, conditions: dict[str, Any]) -> bool:
        """
        检查条件是否满足。

        支持的 key 格式：
          - "fastjson_confirmed": true        → 检查 variables
          - "env.can_reverse": true            → 检查环境属性
          - "fastjson_version_range": ">=1.2.68" → 不做精确比较，检查变量值
        """
        for key, expected in conditions.items():
            if key.startswith("env."):
                attr = key[4:]
                actual = getattr(self, attr, None)
            else:
                actual = self.variables.get(key)

            if actual is None:
                return False

            # 布尔比较
            if isinstance(expected, bool):
                if bool(actual) != expected:
                    return False
            # 字符串比较（含版本范围等，简单做精确匹配）
            elif isinstance(expected, str):
                if str(actual) != expected:
                    return False
            # 其他类型
            else:
                if actual != expected:
                    return False

        return True

    def substitute(self, template: str) -> str:
        """
        替换模板中的变量占位符。

        {ENDPOINT}    → 目标接口 URL
        {TARGET_IP}   → 目标 IP
        {TARGET_PORT} → 目标端口
        {LHOST}       → 攻击机 IP
        {EXPLOIT_CMD} → 当前成功的利用命令
        {var_name}    → 上下文变量
        """
        result = template

        # 固定变量
        replacements = {
            "{ENDPOINT}": self.endpoint,
            "{TARGET_IP}": self.target_ip,
            "{TARGET_PORT}": str(self.target_port),
            "{LHOST}": self.lhost,
            "{EXPLOIT_CMD}": self.exploit_cmd_template,
        }

        for placeholder, value in replacements.items():
            result = result.replace(placeholder, value)

        # 动态变量
        for key, value in self.variables.items():
            result = result.replace(f"{{{key}}}", str(value))

        return result