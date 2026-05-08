"""
skills/models.py
Skill 数据模型

设计原则：
  - 所有字段都有合理默认值，YAML 只需写必要部分
  - 条件判断用简单的 key-value 字典，不搞 DSL
  - parse_rules 用声明式规则，不写代码
"""
from __future__ import annotations

import asyncio
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


def _parse_version_tuple(v: str) -> tuple[int, ...]:
    """Parse '1.2.68' into (1, 2, 68) for comparison."""
    parts: list[int] = []
    for seg in re.split(r'[.\-_]', v.strip()):
        m = re.match(r'(\d+)', seg)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts) if parts else (0,)


def _compare_version(actual: str, expression: str) -> bool:
    """Evaluate version range expressions like '>= 1.2.68', '< 2.0'."""
    expression = expression.strip()
    m = re.match(r'^([><!]=?)\s*(.+)$', expression)
    if not m:
        return str(actual) == expression
    op, ver_str = m.group(1), m.group(2)
    try:
        a = _parse_version_tuple(actual)
        b = _parse_version_tuple(ver_str)
    except Exception:
        return False
    ops = {
        '>=': a >= b, '<=': a <= b,
        '>': a > b, '<': a < b,
        '!=': a != b, '==': a == b,
    }
    return ops.get(op, False)


_PLAIN_VERSION_RE = re.compile(r'^\d+(\.\d+)*$')


def _is_plain_version(value: str) -> bool:
    """Return True if value looks like a plain version number (e.g. '1.2.47')."""
    return bool(_PLAIN_VERSION_RE.match(value.strip()))


_SHELL_SAFE_RE = re.compile(r'^[A-Za-z0-9._/:\-=+@,]+$')


def _needs_shell_quoting(value: str) -> bool:
    """Return True if the value contains shell metacharacters that need quoting."""
    if not value:
        return True
    return not _SHELL_SAFE_RE.match(value)


def _is_inside_quotes(template: str, placeholder: str) -> bool:
    """Check if the placeholder is already inside single or double quotes."""
    idx = template.find(placeholder)
    if idx < 0:
        return False
    before = template[:idx]
    single_count = before.count("'") - before.count("\\'")
    if single_count % 2 == 1:
        return True
    double_count = before.count('"') - before.count('\\"')
    if double_count % 2 == 1:
        return True
    return False


def _safe_substitute(template: str, placeholder: str, value: str) -> str:
    """Apply shlex.quote() unless the placeholder is already inside quotes."""
    if not _needs_shell_quoting(value):
        return value
    if _is_inside_quotes(template, placeholder):
        return value
    return shlex.quote(value)



class StepOutcome(str, Enum):
    """步骤执行后的跳转指令"""
    NEXT_STEP = "next_step"
    NEXT_PATH = "next_path"
    CONCLUDE_SUCCESS = "conclude_success"
    CONCLUDE_FAIL = "conclude_fail"


@dataclass
class ParseRule:
    """
    探测结果解析规则。

    声明式：根据命令输出的内容，设置上下文变量。
    每条规则互不排斥，按顺序全部评估。
    """
    if_contains: list[str] = field(default_factory=list)
    if_not_contains: list[str] = field(default_factory=list)
    if_status_code: list[int] = field(default_factory=list)
    if_regex: str = ""

    and_body_not_empty: bool = False

    set: dict[str, Any] = field(default_factory=dict)

    def evaluate(self, stdout: str, stderr: str, status_code: int) -> dict[str, Any]:
        """评估规则，返回要设置的变量（空 dict = 未触发）。

        支持 if_regex 捕获组: set 值中的 ``$1``, ``$2`` … 会被替换为
        对应的正则匹配组内容，从而把探测结果动态传递给下游步骤。
        """
        combined = f"{stdout} {stderr}".lower()

        checks: list[bool] = []
        regex_groups: tuple[str, ...] = ()

        if self.if_contains:
            checks.append(
                any(kw.lower() in combined for kw in self.if_contains)
            )

        if self.if_not_contains:
            checks.append(
                all(kw.lower() not in combined for kw in self.if_not_contains)
            )

        if self.if_status_code:
            checks.append(status_code in self.if_status_code)

        if self.if_regex:
            combined_for_regex = stdout + "\n" + stderr
            m = re.search(self.if_regex, combined_for_regex, re.IGNORECASE)
            checks.append(bool(m))
            if m:
                regex_groups = m.groups()

        if not checks:
            return {}

        if not all(checks):
            return {}

        if self.and_body_not_empty and not stdout.strip():
            return {}

        result = dict(self.set)
        if regex_groups:
            for k, v in result.items():
                if isinstance(v, str):
                    for i, g in enumerate(regex_groups, 1):
                        v = v.replace(f"${i}", g or "")
                    result[k] = v
        return result


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

    command: str = ""
    parse_rules: list[ParseRule] = field(default_factory=list)
    timeout: int = 15

    steps: list[ProbeStep] = field(default_factory=list)

    depends_on: dict[str, Any] = field(default_factory=dict)

    requires: dict[str, Any] = field(default_factory=dict)

    skip_if: dict[str, Any] = field(default_factory=dict)



@dataclass
class ExploitStep:
    """利用路径中的单个步骤"""
    id: str
    description: str = ""
    command: str = ""
    timeout: int = 30

    publish_ports: list[int] = field(default_factory=list)

    success_criteria: SuccessCriteria = field(default_factory=SuccessCriteria)

    on_success: str = "next_step"
    on_fail: str = "next_path"

    evidence_capture: dict[str, str] = field(default_factory=dict)


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
    principle: str = ""

    conditions: dict[str, Any] = field(default_factory=dict)

    conditions_any: list[dict[str, Any]] = field(default_factory=list)

    skip_if: dict[str, Any] = field(default_factory=dict)

    steps: list[ExploitStep] = field(default_factory=list)

    mode: str = ""
    max_rounds: int = 5



@dataclass
class MatchRule:
    """单条匹配规则"""
    fingerprint_contains: list[str] = field(default_factory=list)
    cve_matches: list[str] = field(default_factory=list)
    evidence_contains: list[str] = field(default_factory=list)
    json_probe_result: str = ""
    service_is: str = ""
    port_is: list[int] = field(default_factory=list)
    tool_is: str = ""
    variable_present: list[str] = field(default_factory=list)

    def matches(
        self,
        fingerprint: str = "",
        cve: str = "",
        evidence: str = "",
        json_probe: str = "",
        service: str = "",
        port: Optional[int] = None,
        tool: str = "",
        variables: Optional[dict[str, Any]] = None,
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

        if self.tool_is:
            checks.append(
                self.tool_is.lower() == (tool or "").lower()
            )

        if self.variable_present:
            variables = variables or {}
            checks.append(
                any(
                    bool(variables.get(var_name))
                    for var_name in self.variable_present
                )
            )

        if not checks:
            return False

        return all(checks)


@dataclass
class MatchConfig:
    """匹配配置"""
    rules: list[MatchRule] = field(default_factory=list)
    exclude: list[MatchRule] = field(default_factory=list)



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
    phase: str = "foothold"
    version: str = "1.0"
    principle: str = ""

    match: MatchConfig = field(default_factory=MatchConfig)
    probes: list[Probe] = field(default_factory=list)
    exploit_paths: list[ExploitPath] = field(default_factory=list)

    remediation: str = ""

    source_file: str = ""

    # AI 引导文档（从 SKILL.md 加载，可选）
    doc: Any = field(default=None, repr=False)



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
    endpoint: str = ""
    target_ip: str = ""
    target_port: int = 0
    target_os: str = "unknown"

    lhost: str = ""
    can_reverse: bool = False
    task_id: Optional[str] = None
    log_callback: Any = None
    skill_dir: str = ""  # Skill 脚本所在目录（Docker 内为 /opt/skills/xxx）

    variables: dict[str, Any] = field(default_factory=dict)

    php_runtime: dict[str, Any] = field(default_factory=dict)
    runtime_facts: dict[str, dict[str, Any]] = field(default_factory=dict)
    confirmed_facts: dict[str, Any] = field(default_factory=dict)

    probe_records: list[dict] = field(default_factory=list)
    step_records: list[dict] = field(default_factory=list)
    commands_run: list[str] = field(default_factory=list)

    exploit_cmd_template: str = ""

    _var_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    async def set_var_async(self, key: str, value: Any) -> None:
        """Concurrency-safe variable write for use inside ``asyncio.gather``."""
        async with self._var_lock:
            self.variables[key] = value

    async def append_record_async(self, target: str, record: dict) -> None:
        """Concurrency-safe append to probe_records / step_records."""
        async with self._var_lock:
            getattr(self, target).append(record)

    def set_var(self, key: str, value: Any) -> None:
        self.variables[key] = value

    def get_var(self, key: str, default: Any = None) -> Any:
        return self.variables.get(key, default)

    def check(self, conditions: dict[str, Any]) -> bool:
        """
        检查条件是否满足。

        支持的 key 格式：
          - "fastjson_confirmed": true              → 布尔比较
          - "env.can_reverse": true                  → 检查环境属性
          - "version_tier": "lte_1.2.47"            → 字符串等值比较（推荐）
          - "fastjson_version": ">= 1.2.68"         → 版本比较（actual 必须是纯版本号）
        """
        for key, expected in conditions.items():
            if key == "variable_present":
                name = str(expected)
                if name in self.variables and self.variables.get(name) not in (None, ""):
                    continue
                return False
            if key.startswith("env.php."):
                attr = key[len("env.php."):]
                actual = (self.php_runtime or {}).get(attr)
            elif key.startswith("env.") and key[4:].split(".", 1)[0] in (
                "apache", "nginx", "tomcat", "spring", "env_file"
            ):
                kind, _, rest = key[4:].partition(".")
                bucket = (self.runtime_facts or {}).get(kind) or {}
                cur: Any = bucket
                for part in (rest.split(".") if rest else []):
                    if isinstance(cur, dict) and part in cur:
                        cur = cur[part]
                    else:
                        cur = None
                        break
                actual = cur
            elif key.startswith("env.surface."):
                rest = key[len("env.surface."):]
                kind, _, attr = rest.partition(".")
                bucket = (self.runtime_facts or {}).get(kind) or {}
                surface = bucket.get("_attack_surface") or {}
                actual = surface.get(attr)
            elif key.startswith("env."):
                attr = key[4:]
                actual = getattr(self, attr, None)
            elif key.startswith("confirmed."):
                path = key[len("confirmed."):].split(".")
                cur: Any = self.confirmed_facts or {}
                for part in path:
                    if isinstance(cur, dict) and part in cur:
                        cur = cur[part]
                    else:
                        cur = None
                        break
                actual = cur
            else:
                actual = self.variables.get(key)

            if actual is None:
                return False

            if isinstance(expected, bool):
                if bool(actual) != expected:
                    return False
            elif isinstance(expected, str):
                exp_stripped = expected.strip()
                is_version_expr = (
                    exp_stripped
                    and exp_stripped[0] in ('>', '<', '!', '=')
                    and re.match(r'^[><!]=?\s*[\d.]', exp_stripped)
                )
                if is_version_expr:
                    actual_str = str(actual)
                    if not _is_plain_version(actual_str):
                        return False
                    if not _compare_version(actual_str, exp_stripped):
                        return False
                elif str(actual) != expected:
                    return False
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

        replacements = {
            "{ENDPOINT}": self.endpoint,
            "{TARGET_IP}": self.target_ip,
            "{TARGET_PORT}": str(self.target_port),
            "{LHOST}": self.lhost,
            "{EXPLOIT_CMD}": self.exploit_cmd_template,
            "{skill_dir}": self.skill_dir,
        }

        for placeholder, value in replacements.items():
            if placeholder in result:
                safe_val = _safe_substitute(result, placeholder, value)
                result = result.replace(placeholder, safe_val)

        for key, value in self.variables.items():
            placeholder = f"{{{key}}}"
            if placeholder in result:
                str_val = str(value)
                safe_val = _safe_substitute(result, placeholder, str_val)
                result = result.replace(placeholder, safe_val)

        return result