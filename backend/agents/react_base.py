"""
agents/react_base.py
ReAct 通用基础组件

把 ``ExploitAgent._exploit_react`` 与 ``SkillEngine._react_freeform`` 之间
重复的逻辑提取为可复用的小工具，避免双份维护：

  - ``parse_react_decision``    解析 LLM JSON 回复
  - ``check_command_safety``    Guard + dangerous_command + dedup 三连
  - ``verify_conclude_success`` 包装 EvidenceVerifier
  - ``build_exec_record``       统一命令执行记录结构
  - ``DEFAULT_REACT_ACTIONS``   合法 action 集合

设计原则：
  - 只提取**纯函数和数据结构**，不做继承式抽象（继承会让两个 ReAct 路径
    被强行拉到同一形态，反而难维护）
  - 调用方仍然各自控制循环、对话历史、prompt，最大保留灵活性
  - 任何"应该共用但还没用"的子能力先在这里用 TODO 标注，谁先动谁迁移
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from backend.agents.evidence_verifier import (
    EvidenceVerifier,
    GatePolicy,
    VerifyResult,
    get_verifier,
)

logger = logging.getLogger(__name__)


DEFAULT_REACT_ACTIONS = frozenset({
    "execute", "conclude_success", "conclude_fail",
})



@dataclass
class ParsedDecision:
    """LLM 决策的解析结果。"""
    ok: bool
    decision: dict[str, Any]
    raw: str

    @property
    def action(self) -> str:
        return str(self.decision.get("action") or "")

    @property
    def thinking(self) -> str:
        return str(self.decision.get("thinking") or "")

    @property
    def purpose(self) -> str:
        return str(self.decision.get("purpose") or "")

    @property
    def command(self) -> str:
        return str(self.decision.get("command") or "").strip()

    @property
    def reason(self) -> str:
        return str(self.decision.get("reason") or "")


def parse_react_decision(response_raw: str) -> ParsedDecision:
    """
    把 LLM 返回的 JSON 字符串解析成 ``ParsedDecision``。

    宽容度：
      - 标准 ``json.loads`` 失败时再尝试单引号修正（少数 LLM 输出会用 '）
      - 仍失败 → ``ok=False`` + 空 dict
    """
    if not response_raw or not isinstance(response_raw, str):
        return ParsedDecision(ok=False, decision={}, raw="")

    raw_preview = response_raw[:1000]
    try:
        parsed = json.loads(response_raw)
        if isinstance(parsed, dict):
            return ParsedDecision(ok=True, decision=parsed, raw=raw_preview)
    except json.JSONDecodeError:
        try:
            parsed = json.loads(response_raw.replace("'", '"'))
            if isinstance(parsed, dict):
                return ParsedDecision(ok=True, decision=parsed, raw=raw_preview)
        except Exception:
            pass
    return ParsedDecision(ok=False, decision={}, raw=raw_preview)



@dataclass
class CommandSafetyResult:
    """命令进入执行器之前所有前置检查的结果。"""
    allowed: bool
    code: str = ""
    reason: str = ""

    @classmethod
    def ok(cls) -> "CommandSafetyResult":
        return cls(allowed=True)


_DANGEROUS_PATTERNS = (
    "rm -rf /",
    "rm -rf /*",
    "mkfs.",
    "dd if=/dev/zero",
    ":(){:|:&};:",
    "> /dev/sda",
    "chmod -R 777 /",
    "shutdown",
    "reboot",
    "init 0",
    "init 6",
    "iptables -F",
)
_RM_RF_RE = re.compile(r"rm\s+-[rf]{2,}\s+[/$~]")
_OVERWRITE_ETC_RE = re.compile(r">\s*/etc/")


def is_dangerous_command(cmd: str) -> bool:
    """判定一条 shell 命令是否包含破坏性动作。"""
    if not cmd:
        return False
    low = cmd.lower().strip()
    if any(p in low for p in _DANGEROUS_PATTERNS):
        return True
    if _RM_RF_RE.search(low):
        return True
    if _OVERWRITE_ETC_RE.search(low):
        return True
    return False


def check_command_safety(
    cmd: str,
    *,
    seen_commands: set[str],
    guard: Any = None,
    confirmed_facts: Optional[dict] = None,
    failed_commands: Optional[list[str]] = None,
) -> CommandSafetyResult:
    """
    统一的执行前置检查链：

      1. ``Guard.evaluate()`` —— 基于已确认事实/已失败命令拦截
      2. ``is_dangerous_command()`` —— 兜底硬规则
      3. 重复命令去重（按归一化空白后的串）

    ``seen_commands`` 由调用方维护并在每轮 success 后 add；本函数仅查询
    （命中即视为重复并拒绝）。
    """
    if not cmd:
        return CommandSafetyResult(
            allowed=False, code="empty",
            reason="你返回了 execute 但 command 为空。请生成一条具体的命令。",
        )

    if guard is not None:
        try:
            decision = guard.evaluate(
                cmd,
                confirmed_facts=confirmed_facts or {},
                failed_commands=failed_commands or [],
            )
        except Exception:
            decision = None
        if decision is not None and not getattr(decision, "allowed", True):
            code = getattr(decision, "code", "guard")
            reason = getattr(decision, "reason", "")
            return CommandSafetyResult(
                allowed=False,
                code=f"guard:{code}",
                reason=(
                    f"命令被 Guard 拒绝({code}): {reason}。"
                    "请基于已确认事实重规划，不要重复已失败或已确认无需重探的动作。"
                ),
            )

    if is_dangerous_command(cmd):
        return CommandSafetyResult(
            allowed=False,
            code="dangerous",
            reason=(
                "该命令被安全策略阻止（包含破坏性操作）。"
                "请生成仅用于验证漏洞的无害命令。"
            ),
        )

    cmd_normalized = " ".join(cmd.split())
    if cmd_normalized in seen_commands:
        return CommandSafetyResult(
            allowed=False,
            code="duplicate",
            reason=(
                "这条命令你之前已经执行过了。请调整参数后重试"
                "（如更换路径深度、文件名、端口、参数名等），"
                "或在确认当前向量已彻底无法利用后再切换方法。"
            ),
        )

    return CommandSafetyResult.ok()


def normalize_command(cmd: str) -> str:
    """归一化空白用于去重比较。"""
    return " ".join((cmd or "").split())



@dataclass
class ConclusionVerification:
    """conclude_success 验证结果。"""
    passed: bool
    level: str = ""
    reason: str = ""
    snippets: list[str] = field(default_factory=list)


def verify_conclude_success(
    *,
    decision: ParsedDecision,
    last_records: list[dict],
    gate_policy: Optional[GatePolicy] = None,
) -> ConclusionVerification:
    """
    包装 ``EvidenceVerifier.verify`` 的常见调用方式。

    从 ``last_records`` 末尾取 stdout/stderr，结合 ``decision.shell_type``
    走 verifier。
    """
    last_stdout = ""
    last_stderr = ""
    if last_records:
        last_stdout = str(last_records[-1].get("stdout") or "")
        last_stderr = str(last_records[-1].get("stderr") or "")

    shell_type = str(decision.decision.get("shell_type") or "rce")

    verifier: EvidenceVerifier = get_verifier(gate_policy) if gate_policy else get_verifier()
    vr: VerifyResult = verifier.verify(
        stdout=last_stdout,
        stderr=last_stderr,
        shell_type=shell_type,
        all_records=last_records,
    )

    return ConclusionVerification(
        passed=bool(vr.passed),
        level=getattr(vr.level, "value", str(vr.level)),
        reason=str(vr.reason or ""),
        snippets=list(getattr(vr, "evidence_snippets", []) or []),
    )



def build_exec_record(
    *,
    command: str,
    stdout: str,
    stderr: str,
    exit_code: int,
    elapsed: float,
    purpose: str = "",
    round_no: Optional[int] = None,
    extra: Optional[dict] = None,
) -> dict:
    """
    构造 ``ctx.step_records`` / ``all_records`` 的单条执行记录。

    保持与现有 ``ExploitAgent`` / ``SkillEngine`` 字段一致，方便后续把两边
    的 record 一起喂给 EvidenceVerifier 或落库。
    """
    record = {
        "round": round_no,
        "timestamp": datetime.utcnow().isoformat(),
        "command": command,
        "purpose": purpose,
        "stdout": stdout or "",
        "stderr": stderr or "",
        "exit_code": int(exit_code),
        "elapsed": round(float(elapsed or 0.0), 1),
    }
    if extra:
        record.update(extra)
    return record



def feedback_for_invalid_action(action: str) -> str:
    """LLM 返回未知 action 时给的 user 反馈。"""
    return (
        f"无法识别 action='{action}'。"
        "请返回 execute / conclude_success / conclude_fail 之一。"
    )


def feedback_for_invalid_json() -> str:
    """LLM 输出非 JSON 时的 user 反馈。"""
    return (
        "你的输出不是合法 JSON，请严格按照要求的 JSON 格式重新回答："
        '{"action": "execute|conclude_success|conclude_fail", ...}'
    )
