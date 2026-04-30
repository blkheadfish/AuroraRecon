"""
agents/function_calling.py
工具调用 Schema 转换层

职责：
  1. 让 LLM 通过 OpenAI Function Calling 协议返回 tool_calls；
  2. 把 tool_calls 翻译成可直接被 ToolExecutor.run_script() 执行的 shell 脚本；
  3. 提供 ReAct 循环的"软启用"开关 —— 默认仍走 JSON 模式（向后兼容），
     设置 ``EXPLOIT_FUNCTION_CALLING=true`` 后切到 tools 模式。

为什么不上 MCP？
  MCP 设计为 LSP 风格的"动态工具发现"，对独立 Agent + 已知工具集的渗透
  系统是反向优化（额外的 IPC 跳数、JSON-RPC 序列化、stdio 流复用、子进程
  生命周期）。Function Calling 与现有 LLMRouter 直接同进程同步，零额外延迟。
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
from dataclasses import dataclass
from typing import Any, Optional

from backend.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


# ── 开关 ───────────────────────────────────────────────────

def function_calling_enabled() -> bool:
    """ReAct 是否启用 Function Calling 模式。"""
    val = os.getenv("EXPLOIT_FUNCTION_CALLING", "").strip().lower()
    return val in ("1", "true", "yes", "on")


# ── 翻译结果 ───────────────────────────────────────────────

@dataclass
class ResolvedToolCall:
    """tool_call → 可执行 shell 脚本 的中间表示。"""
    tool_name: str           # YAML 里登记的 name（或 'run_shell' / 'http_request'）
    script: str              # 给 executor.run_script 的 script_content
    purpose: str             # 给 record_purpose
    timeout: int             # 覆盖超时（0=用默认）
    raw_args: dict           # LLM 原始 arguments，供日志/审计

    @property
    def display(self) -> str:
        """日志友好的命令展示串。"""
        cmd = self.script.strip().splitlines()[0] if self.script else ""
        return cmd[:300]


# ── 主入口 ─────────────────────────────────────────────────

def build_react_tools_schema(
    registry: Optional[ToolRegistry] = None,
    *,
    categories: Optional[list[str]] = None,
    max_tools: int = 48,
) -> list[dict]:
    """
    给 ReAct 循环准备 OpenAI tools schema。

    默认导出 exploit / recon / vuln_scan / general 类别 + 通用 meta 工具
    （run_shell / http_request），保证 LLM 既有专用工具又有兜底。
    """
    reg = registry or ToolRegistry()
    cats = categories or ["exploit", "vuln_scan", "post_exploit", "general", "recon"]
    return reg.to_openai_tools(
        categories=cats, include_meta=True, max_tools=max_tools,
    )


def resolve_tool_call(
    tool_call: Any,
    registry: Optional[ToolRegistry] = None,
) -> Optional[ResolvedToolCall]:
    """
    把 OpenAI ChatCompletion tool_call 翻译成 ResolvedToolCall。

    支持两种入参：
      - openai SDK 的 ChatCompletionMessageToolCall 对象
      - 已经 dict 化的 ``{"function": {"name", "arguments"}, "id"}``

    对于未注册的 tool_name 返回 None（让上层进 fallback）。
    """
    name, raw_args = _extract_call_fields(tool_call)
    if not name:
        return None

    args = _parse_arguments(raw_args)
    purpose = str(args.get("purpose") or "")[:200]
    timeout = _coerce_int(args.get("timeout"))

    # 1. meta 工具：run_shell
    if name == "run_shell":
        script = str(args.get("script") or "").strip()
        if not script:
            return None
        return ResolvedToolCall(
            tool_name="run_shell",
            script=script,
            purpose=purpose or "react_shell",
            timeout=timeout or 0,
            raw_args=args,
        )

    # 2. meta 工具：http_request
    if name == "http_request":
        script = _http_request_to_curl(args)
        if not script:
            return None
        return ResolvedToolCall(
            tool_name="http_request",
            script=script,
            purpose=purpose or f"http_{(args.get('method') or 'get').lower()}",
            timeout=timeout or _coerce_int(args.get("timeout")) or 0,
            raw_args=args,
        )

    # 3. 注册表里的具体工具
    reg = registry or ToolRegistry()
    tool_def = reg.get(name) or reg.get(name.replace("_", "-"))
    if not tool_def:
        # OpenAI 把 - 替换为 _，反向尝试
        for candidate in reg.list_all():
            sanitized = re.sub(r"[^A-Za-z0-9_\-]", "_", candidate.name)
            if sanitized == name:
                tool_def = candidate
                break

    if not tool_def:
        logger.warning(f"[FunctionCalling] 未注册工具: {name}")
        return None

    cmd_args = str(args.get("args") or "").strip()
    cmd_str = (tool_def.command or tool_def.name).strip()
    if cmd_args:
        cmd_str = f"{cmd_str} {cmd_args}"

    return ResolvedToolCall(
        tool_name=tool_def.name,
        script=cmd_str,
        purpose=purpose or f"tool:{tool_def.name}",
        timeout=timeout or 0,
        raw_args=args,
    )


# ── 内部工具 ───────────────────────────────────────────────

def _extract_call_fields(tool_call: Any) -> tuple[str, str]:
    """从 SDK 对象/dict 里抽出 (function_name, arguments_json_string)。"""
    if tool_call is None:
        return "", ""

    # dict path
    if isinstance(tool_call, dict):
        fn = tool_call.get("function") or {}
        return str(fn.get("name") or ""), str(fn.get("arguments") or "{}")

    # openai SDK object
    fn = getattr(tool_call, "function", None)
    if fn is None:
        return "", ""
    return str(getattr(fn, "name", "") or ""), str(getattr(fn, "arguments", "") or "{}")


def _parse_arguments(raw: str) -> dict:
    """LLM 给的 arguments 字段是 JSON 字符串，解析失败返回空 dict。"""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        # 兜底：偶尔 LLM 输出非严格 JSON，尝试单引号修正
        try:
            return json.loads(raw.replace("'", '"'))
        except Exception:
            logger.debug(f"[FunctionCalling] arguments 解析失败: {raw[:200]}")
            return {}


def _coerce_int(val: Any) -> int:
    try:
        return max(0, int(val))
    except (TypeError, ValueError):
        return 0


def _http_request_to_curl(args: dict) -> str:
    """把 http_request 参数翻成 curl 命令。"""
    url = str(args.get("url") or "").strip()
    if not url:
        return ""

    method = (args.get("method") or "GET").upper()
    headers = args.get("headers") or {}
    body = args.get("body") or ""
    follow = bool(args.get("follow_redirects"))
    timeout = _coerce_int(args.get("timeout")) or 15

    parts: list[str] = ["curl", "-sS", "-i"]
    if follow:
        parts.append("-L")
    parts.extend(["--max-time", str(timeout)])
    parts.extend(["-X", method])

    if isinstance(headers, dict):
        for k, v in headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])

    if body and method in ("POST", "PUT", "PATCH"):
        parts.extend(["--data-binary", shlex.quote(str(body))])

    parts.append(shlex.quote(url))
    return " ".join(parts)


# ── ReAct system prompt 增量 ───────────────────────────────

REACT_TOOLS_SYSTEM_ADDENDUM = """
你现在使用 OpenAI Function Calling 协议，请直接返回 tool_calls，
而不是文本里嵌 JSON。
- 一次只调一个工具；
- 优先使用具体工具（如 nmap/curl/sqlmap/hydra）而非 run_shell；
- 当需要复合命令、变量替换、循环、管道时再回落到 run_shell；
- 简单 HTTP 探测请用 http_request，比手写 curl 更稳；
- 完成判定请通过 conclude_success / conclude_fail 两个特殊工具调用，
  或者在没有调用工具时在 content 里输出 JSON: {"action": "conclude_success/fail", ...}。
"""
