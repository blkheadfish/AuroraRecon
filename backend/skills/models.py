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
import time
import uuid
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
class SkillEvent:
    """
    跨 Skill 消息传递事件。

    一个 Skill 执行成功后发布事件，下游 Skill 消费事件。
    支持发布-订阅模式，实现 Skill 间组合链。
    """
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    event_type: str = ""           # "file_extracted", "credential_found", "service_discovered"
    source_skill_id: str = ""
    target_skill_ids: list[str] = field(default_factory=list)  # 推荐的后续 skill
    payload: dict[str, Any] = field(default_factory=dict)
    priority: int = 5
    timestamp: float = field(default_factory=time.time)
    consumed: bool = False

    def to_context_variables(self) -> dict[str, Any]:
        """将事件载荷转换为可注入 ctx.variables 的平面字典。"""
        result: dict[str, Any] = {}
        for k, v in self.payload.items():
            safe_key = f"event_{self.event_type}_{k}"
            result[safe_key] = v
            result[k] = v  # also set short form (may be overridden)
        result["_source_event_type"] = self.event_type
        result["_source_skill_id"] = self.source_skill_id
        return result


# ============================================================
# 结构化探测结果（替代字符串正则 IPC）
# ============================================================

@dataclass
class LFIProbeResult:
    """LFI 探测的结构化结果"""
    confirmed: bool = False
    params: list[str] = field(default_factory=list)       # 多个可注入参数
    depths: dict[str, int] = field(default_factory=dict)  # param → depth 映射
    styles: list[str] = field(default_factory=list)        # absolute/relative/php_filter
    readable_files: list[str] = field(default_factory=list)  # 已确认可读的文件列表
    wrappers_available: list[str] = field(default_factory=list)  # data://, php://input, expect://
    waf_detected: bool = False
    blind: bool = False  # blind LFI (no direct output, only side-channel)

    def __post_init__(self):
        """Normalize single-value fields from scripts that use singular keys."""
        pass  # normalization handled in to_variables()

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "LFIProbeResult":
        """Construct from a payload dict with flexible key handling."""
        kwargs: dict[str, Any] = {}
        # Handle singular 'param' → 'params'
        if "param" in payload and "params" not in payload:
            kwargs["params"] = [payload["param"]]
        # Handle singular 'depth' → 'depths'
        if "depth" in payload and "depths" not in payload:
            param_name = payload.get("param", "unknown")
            kwargs["depths"] = {param_name: int(payload["depth"])}
        # Handle singular 'style' → 'styles'
        if "style" in payload and "styles" not in payload:
            kwargs["styles"] = [payload["style"]]
        # Handle 'files' → 'readable_files'
        if "files" in payload and "readable_files" not in payload:
            kwargs["readable_files"] = payload["files"]
        # Handle 'wrapper' → 'wrappers_available'
        if "wrapper" in payload and "wrappers_available" not in payload:
            kwargs["wrappers_available"] = [payload["wrapper"]]
        # Copy all known fields
        for field_name in cls.__dataclass_fields__:
            if field_name in payload and field_name not in kwargs:
                kwargs[field_name] = payload[field_name]
        return cls(**kwargs)

    def to_variables(self) -> dict[str, Any]:
        result: dict[str, Any] = {"lfi_confirmed": self.confirmed}
        if self.params:
            result["lfi_param"] = self.params[0]
            result["lfi_params"] = self.params
        if self.depths:
            first_param = self.params[0] if self.params else "unknown"
            result["lfi_depth"] = str(self.depths.get(first_param, 0))
            result["lfi_depths"] = self.depths
        if self.styles:
            result["lfi_style"] = self.styles[0]
            result["lfi_styles"] = self.styles
        if self.readable_files:
            result["readable_files_list"] = self.readable_files
            result["readable_files_count"] = len(self.readable_files)
        if self.wrappers_available:
            result["wrappers_available"] = self.wrappers_available
            result["data_wrapper_available"] = "data" in self.wrappers_available
            result["input_wrapper_available"] = "input" in self.wrappers_available
            result["expect_wrapper_available"] = "expect" in self.wrappers_available
        result["waf_detected"] = self.waf_detected
        result["lfi_blind"] = self.blind
        return result


@dataclass
class CredentialProbeResult:
    """凭据探测的结构化结果"""
    found: bool = False
    usernames: list[str] = field(default_factory=list)
    passwords: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    hashes_base64: list[str] = field(default_factory=list)  # B64-encoded hash content
    ssh_keys: list[str] = field(default_factory=list)
    service: str = ""

    def to_variables(self) -> dict[str, Any]:
        result: dict[str, Any] = {"credential_found": self.found}
        if self.usernames:
            result["found_usernames"] = self.usernames
            result["known_users_b64"] = "\n".join(self.usernames[:30])
            result["known_users_preview"] = ", ".join(self.usernames[:5])
        if self.passwords:
            result["found_passwords"] = self.passwords
            result["known_passwords_count"] = len(self.passwords)
        if self.hashes:
            result["found_hashes"] = self.hashes
            result["hashes_count"] = len(self.hashes)
        if self.ssh_keys:
            result["ssh_key_found"] = True
            result["ssh_keys_list"] = self.ssh_keys
        if self.hashes or self.passwords:
            result["has_known_creds"] = True
        return result


@dataclass
class RCEProbeResult:
    """RCE 探测的结构化结果"""
    confirmed: bool = False
    shell_type: str = ""  # rce_data_wrapper, rce_input_wrapper, rce_log_poison, etc.
    current_user: str = ""
    command_outputs: list[str] = field(default_factory=list)
    reverse_callback_received: bool = False
    webshell_url: str = ""

    def to_variables(self) -> dict[str, Any]:
        result: dict[str, Any] = {"rce_confirmed": self.confirmed}
        if self.shell_type:
            result["shell_type"] = self.shell_type
        if self.current_user:
            result["current_user"] = self.current_user
        if self.command_outputs:
            result["command_outputs"] = self.command_outputs
        result["reverse_callback_received"] = self.reverse_callback_received
        if self.webshell_url:
            result["webshell_url"] = self.webshell_url
        return result


# Map event type → structured result parser
_STRUCTURED_RESULT_PARSERS: dict[str, type] = {}


def register_structured_parser(event_type: str, parser_cls: type) -> None:
    """注册结构化结果解析器"""
    _STRUCTURED_RESULT_PARSERS[event_type] = parser_cls


def _parse_structured_json_line(
    line: str,
) -> tuple[str, dict[str, Any]] | None:
    """
    解析单行 NDJSON 格式的结构化输出。
    返回 (event_type, payload) 或 None。
    """
    try:
        import json as _json
        obj = _json.loads(line.strip())
        if not isinstance(obj, dict):
            return None
        event = obj.get("event", "")
        if not event:
            return None
        payload = obj.get("payload") or obj.get("data") or {}
        if not isinstance(payload, dict):
            return None
        return (event, payload)
    except Exception:
        return None


# 预注册内置结构化类型
register_structured_parser("lfi_param_found", LFIProbeResult)
register_structured_parser("lfi_files_readable", LFIProbeResult)
register_structured_parser("lfi_probe_result", LFIProbeResult)
register_structured_parser("credential_found", CredentialProbeResult)
register_structured_parser("credentials_found", CredentialProbeResult)
register_structured_parser("rce_probe_result", RCEProbeResult)


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

    # 路径成功后触发的事件（发布-订阅模式）
    on_success: dict[str, Any] = field(default_factory=dict)



@dataclass
class MatchRule:
    """单条匹配规则"""
    fingerprint_contains: list[str] = field(default_factory=list)
    cve_matches: list[str] = field(default_factory=list)
    evidence_contains: list[str] = field(default_factory=list)
    evidence_regex: list[str] = field(default_factory=list)
    evidence_keywords: list[str] = field(default_factory=list)
    json_probe_result: str = ""
    service_is: str = ""
    port_is: list[int] = field(default_factory=list)
    tool_is: str = ""
    variable_present: list[str] = field(default_factory=list)

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        import re as _re
        return set(_re.findall(r'[a-z0-9]{2,}', text.lower()))

    @staticmethod
    def _tokens_match(evidence_tokens: set[str], keyword_tokens: set[str]) -> bool:
        if not keyword_tokens:
            return False
        return bool(evidence_tokens & keyword_tokens)

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

    # 自适应决策树：根据探测结果动态选择路径，替代 priority 瀑布
    # 格式: { "if": [{"condition": {...}, "then_path": "id"}...], "default": "id" }
    selector: Optional[dict] = None

    # AI 引导文档（从 SKILL.md 加载，可选）
    doc: Any = field(default=None, repr=False)

    # References 文件内容（按需加载，filename → content）
    references: dict[str, str] = field(default_factory=dict, repr=False)


@dataclass
class SkillMeta:
    """
    轻量 Skill 元数据 — 启动时加载（~50 tokens/skill）。

    只包含匹配和路由所需的最小信息，完整 Skill 在执行时按需加载。
    """
    skill_id: str
    name: str
    description: str = ""
    category: str = ""
    phase: str = "foothold"
    match: MatchConfig = field(default_factory=MatchConfig)
    source_file: str = ""



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

    # 跨 Skill 事件队列（发布-订阅模式）
    event_queue: list[SkillEvent] = field(default_factory=list)

    # 结构化探测结果（替代字符串正则 IPC）
    structured_results: dict[str, Any] = field(default_factory=dict)

    # 当前 finding 的原始 evidence 文本（供 match_any_keyword 条件使用）
    _finding_evidence: str = ""

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

    def publish_event(
        self,
        event_type: str,
        source_skill_id: str,
        target_skill_ids: list[str],
        payload: dict[str, Any],
        priority: int = 5,
    ) -> SkillEvent:
        """发布一个跨 Skill 事件到事件队列。"""
        event = SkillEvent(
            event_type=event_type,
            source_skill_id=source_skill_id,
            target_skill_ids=target_skill_ids,
            payload=payload,
            priority=priority,
        )
        self.event_queue.append(event)
        return event

    def consume_events(self) -> list[SkillEvent]:
        """消费所有未处理事件，注入变量并标记为已消费。"""
        consumed: list[SkillEvent] = []
        for event in self.event_queue:
            if event.consumed:
                continue
            for k, v in event.to_context_variables().items():
                if v is not None and k not in self.variables:
                    self.variables[k] = v
            event.consumed = True
            consumed.append(event)
        return consumed

    def has_pending_events(self) -> bool:
        """检查是否有未消费事件。"""
        return any(not e.consumed for e in self.event_queue)

    def merge_structured_output(self, stdout: str) -> int:
        """
        解析 stdout 中的 NDJSON 行，合并到 structured_results 和 variables。

        返回解析到的结构化行数。
        """
        count = 0
        for line in stdout.splitlines():
            line = line.strip()
            parsed = _parse_structured_json_line(line)
            if parsed is None:
                continue
            event_type, payload = parsed
            self.structured_results.setdefault(event_type, []).append(payload)

            # 尝试通过注册的解析器转换为结构化对象
            parser_cls = _STRUCTURED_RESULT_PARSERS.get(event_type)
            if parser_cls is None:
                # 尝试前缀匹配
                for registered_key, cls in _STRUCTURED_RESULT_PARSERS.items():
                    if event_type.startswith(registered_key):
                        parser_cls = cls
                        break

            if parser_cls is not None:
                try:
                    if hasattr(parser_cls, "from_payload"):
                        obj = parser_cls.from_payload(payload)
                    else:
                        obj = parser_cls(**{k: v for k, v in payload.items()
                                           if k in parser_cls.__dataclass_fields__})
                    if hasattr(obj, "to_variables"):
                        for k, v in obj.to_variables().items():
                            self.set_var(k, v)
                    self.structured_results.setdefault("_objects", []).append(obj)
                except Exception:
                    pass

            # 无论是否有解析器，都将 payload 扁平化到 variables
            for k, v in payload.items():
                safe_key = f"json_{event_type}_{k}"
                self.set_var(safe_key, v)
                if k not in self.variables:
                    self.set_var(k, v)

            count += 1
        return count

    def check(self, conditions: dict[str, Any]) -> bool:
        """
        检查条件是否满足。

        支持的 key 格式：
          - "any_of": [{...}, {...}]               → OR 逻辑：至少一个分组全通过
          - "all_of": [{...}, {...}]               → AND 逻辑：所有分组必须全通过
          - "variable_present": "key"              → 检查变量存在且非空
          - "variable_not_empty": "key"            → 检查变量存在且非空（同 variable_present）
          - "variable_greater_than": {key: n}      → 检查变量值 > n（数值比较）
          - "variable_in_list": {key: [v1, v2]}     → 检查变量值在列表中
          - "match_any_keyword": {source: s, keywords: [...]}  → 模糊关键词匹配
          - "env.can_reverse": true                → 检查环境属性
          - "env.php.<attr>": ...                  → PHP 运行时属性
          - "env.<kind>.<attr>": ...               → runtime_facts 属性
          - "confirmed.<path>": ...                → confirmed_facts 属性
          - "version_tier": "lte_1.2.47"          → 字符串等值比较
          - "fastjson_version": ">= 1.2.68"       → 版本比较
        """

        # ---- NEW: nested any_of / all_of ----
        if "any_of" in conditions:
            if not conditions["any_of"]:
                return False
            return any(self.check(sub) for sub in conditions["any_of"])

        if "all_of" in conditions:
            if not conditions["all_of"]:
                return True
            return all(self.check(sub) for sub in conditions["all_of"])

        # ---- NEW: variable_not_empty ----
        if "variable_not_empty" in conditions:
            name = str(conditions["variable_not_empty"])
            if name in self.variables and self.variables.get(name) not in (None, ""):
                pass
            else:
                return False

        # ---- NEW: variable_greater_than (supports >, >=, <, <=, ==) ----
        if "variable_greater_than" in conditions:
            vgt = conditions["variable_greater_than"]
            if isinstance(vgt, dict):
                for var_name, threshold in vgt.items():
                    actual_val = self.variables.get(var_name)
                    if actual_val is None:
                        return False
                    try:
                        if not (float(actual_val) > float(threshold)):
                            return False
                    except (ValueError, TypeError):
                        return False
            else:
                return False

        # ---- NEW: variable_in_list ----
        if "variable_in_list" in conditions:
            vil = conditions["variable_in_list"]
            if isinstance(vil, dict):
                for var_name, expected_list in vil.items():
                    actual_val = self.variables.get(var_name)
                    if actual_val is None:
                        return False
                    if isinstance(expected_list, list):
                        if actual_val not in expected_list and str(actual_val) not in expected_list:
                            return False
                    else:
                        return False
            else:
                return False

        # ---- NEW: match_any_keyword ----
        if "match_any_keyword" in conditions:
            mak = conditions["match_any_keyword"]
            if isinstance(mak, dict):
                source = mak.get("source", "")
                keywords = mak.get("keywords", [])
                if not keywords:
                    return False
                source_text = ""
                if source == "finding_evidence":
                    source_text = getattr(self, "_finding_evidence", "")
                elif source in self.variables:
                    source_text = str(self.variables.get(source, ""))
                else:
                    source_text = source
                source_lower = source_text.lower()
                if not any(kw.lower() in source_lower for kw in keywords):
                    return False
            else:
                return False

        # ---- existing flat-condition logic ----
        for key, expected in conditions.items():
            # skip new nesting keys that were already handled
            if key in (
                "any_of", "all_of",
                "variable_not_empty", "variable_greater_than",
                "variable_in_list", "match_any_keyword",
            ):
                continue

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