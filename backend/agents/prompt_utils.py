"""prompt_utils.py — 共享的 prompt 拼装工具。

唯一的职责: 把"操作员实时指令"以最高优先级注入到任意一个 LLM prompt 里。
来源:
  - ``state.pending_user_prompt``     ← /chat 接口和 /checkpoint/respond 都会写入
  - ``state.user_messages``           ← 决策视图聊天的时间线(取最近若干条)

注入策略:
  - 双重注入: prompt 最开头 (LLM 对系统级权威性敏感) + 末尾 (LLM 对 recency
    敏感), 两个位置都贴一份带显著标记的 OPERATOR INSTRUCTION 块。
  - 标记里写明"OVERRIDES ALL DEFAULTS BELOW/ABOVE", 并用中英双语避免被
    弱模型忽略。
  - 安全护栏(审批 / risk_budget / success_gate_level)由代码侧控制, prompt
    里不会因为用户说"跳过审批"就真的跳过—— supervisor 路由白名单兜底。
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.agents.models import PentestState


_HEADER = (
    "【操作员实时指令 - 最高优先级 / OPERATOR INSTRUCTION - HIGHEST PRIORITY】\n"
    "以下来自任务对话视图的实时输入, 优先级高于本 prompt 中其它默认设定。"
    "在不违反安全护栏(人工审批 / 风险预算 / 证据门槛)的前提下, 你必须优先"
    "采纳这些指令的方向与策略。\n"
    "(Live operator input from the task chat view. These take precedence "
    "over any other defaults in this prompt; you must follow them as long "
    "as the safety guardrails — human approval, risk budget, evidence gate — "
    "remain satisfied.)\n"
)
_FOOTER_NOTE = "【操作员指令结束 / END OPERATOR INSTRUCTION】"


def operator_guidance_block(
    state: "PentestState",
    *,
    max_messages: int = 12,
    per_message_chars: int = 800,
) -> str:
    """Return a self-contained text block with the operator's latest guidance.

    Empty string when neither ``pending_user_prompt`` nor recent
    ``user_messages`` carry anything actionable. Caller can therefore safely
    treat the empty result as "no-op".
    """
    pending = (getattr(state, "pending_user_prompt", "") or "").strip()
    msgs = list(getattr(state, "user_messages", None) or [])

    bullets: list[str] = []
    for m in msgs[-max_messages:]:
        text = (m.get("text") or "").strip()
        if not text:
            continue
        if len(text) > per_message_chars:
            text = text[: per_message_chars] + "…"
        bullets.append(text)

    if not pending and not bullets:
        return ""

    parts: list[str] = [_HEADER]
    if pending:
        snippet = pending if len(pending) <= 2000 else pending[:2000] + "…"
        parts.append(f"持续指令 (sticky):\n{snippet}\n")
    if bullets:
        parts.append("最近的对话补充 (chronological):")
        parts.extend(f"- {b}" for b in bullets)
    parts.append(_FOOTER_NOTE)
    return "\n".join(parts).strip() + "\n"


def attach_operator_guidance(prompt: str, state: "PentestState") -> str:
    """Wrap *prompt* so the operator guidance appears at both ends.

    No-op when there is no guidance, so existing call sites can adopt this
    helper unconditionally without changing behaviour for branches that
    never receive operator input.
    """
    block = operator_guidance_block(state)
    if not block:
        return prompt
    body = prompt or ""
    return f"{block}\n{body}\n\n{block}"
