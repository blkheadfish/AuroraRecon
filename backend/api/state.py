"""
state.py —— 全局状态管理器

将散落的全局变量封装为 TaskStateManager 类，
所有 Router / Service 通过依赖注入获取同一实例。
"""
from __future__ import annotations

import asyncio
import re
import logging
import threading
from datetime import datetime
from typing import Optional

from backend.agents.models import PentestState, TaskStatus

logger = logging.getLogger(__name__)

# 模块级编译正则（避免循环内重复 compile）
TOOL_START_RE = re.compile(r"执行\s+([^\s]+)\s+\[([^\]]+)\]")
TOOL_DONE_RE = re.compile(r"(?:✅|❌)\s+([^\s]+)\s+完成:\s+exit=([-]?\d+),.*?耗时=([\d.]+)s")
THOUGHT_RE = re.compile(
    r"LLM|分析|决策|策略|推理|建议|主动发现|KB|知识库|扫描策略|优先级|"
    r"Skill 引擎|ReAct|模型",
    re.IGNORECASE,
)


_SHELL_NAMES = {"/bin/bash", "/bin/sh", "bash", "sh", "/bin/zsh", "zsh"}
_SKIP_PREFIX_RE = re.compile(
    r"^(set\s|export\s|cd\s|echo\s|#|if\s|then\b|else\b|fi\b|do\b|done\b|while\s|for\s|\[)"
)
_VAR_ASSIGN_RE = re.compile(r"^\w+=")


def _infer_tool_from_command(cmd: str) -> str:
    """Extract the primary tool name from a shell command/script string."""
    if not cmd:
        return "script"
    for segment in re.split(r"[;\n|]|&&|\|\|", cmd):
        segment = segment.strip()
        if not segment:
            continue
        if _SKIP_PREFIX_RE.match(segment):
            continue
        if _VAR_ASSIGN_RE.match(segment):
            continue
        first_token = segment.split()[0]
        name = first_token.rsplit("/", 1)[-1]
        if name and name not in _SHELL_NAMES:
            return name
    return "script"


def _command_preview(command: str, max_len: int = 280) -> str:
    """Compress command while retaining suspicious fragments for debugging."""
    normalized = " ".join((command or "").split())
    if not normalized:
        return ""
    if len(normalized) <= max_len:
        return normalized

    markers = (
        "<?php",
        "system($_GET",
        "sshpass -p",
        "auth.log",
        "User-Agent:",
    )
    marker_pos = -1
    for marker in markers:
        marker_pos = normalized.find(marker)
        if marker_pos >= 0:
            break

    if marker_pos >= 0:
        head_len = min(90, max_len // 3)
        tail_len = min(90, max_len // 3)
        window_len = max_len - head_len - tail_len - len(" ...  ... ")
        start = max(0, marker_pos - window_len // 3)
        mid = normalized[start:start + window_len]
        return f"{normalized[:head_len]} ... {mid} ... {normalized[-tail_len:]}"

    keep = max_len // 2
    return f"{normalized[:keep]} ... {normalized[-keep:]}"


class TaskStateManager:
    """进程内任务状态容器（单例）"""

    def __init__(self):
        self._tasks: dict[str, PentestState] = {}
        self._running_tasks: set[str] = set()
        self._approval_inflight: dict[str, float] = {}
        self.APPROVAL_INFLIGHT_TIMEOUT = 600

        self.db_available = False
        self.redis_available = False
        self.msf_available = False

        self._tool_registry_cache = None

        # 增量 decision_events 缓存
        self._decision_cache: dict[str, list[dict]] = {}
        self._decision_cursor: dict[str, tuple[int, int, int]] = {}

        # 后台任务句柄注册表(run_task / resume_task 的 asyncio.Task)
        # cancel / delete 时可以精确取消对应协程,避免 zombie 残留。
        self._bg_tasks: dict[str, asyncio.Task] = {}

        # ── task 级单调 log seq counter ────────────────────
        # ``PentestState.log()`` 把 ``len(phase_log)-1`` 当作 seq 给 WS 用,
        # 但 fork 出新分支时 child 的 phase_log 是父分支的拷贝, 之后两条
        # 分支各自向前追加, seq 在 task 维度上不再单调; WS 重连按 seq 增量
        # 补丁的逻辑会乱。改用进程内 task 级 counter, 配合
        # ``PentestState.phase_log_seqs`` 持久化每条日志的真实 seq, WS
        # 重连用 bisect 定位 start_idx, 跨分支也能严格单调对齐。
        # counter 可能在 worker 线程被 ``state.log`` 间接读到, 加锁保证原子。
        self._log_seq_counter: dict[str, int] = {}
        self._log_seq_lock = threading.Lock()

    # ── 任务 CRUD ─────────────────────────────────────────

    def get(self, task_id: str) -> Optional[PentestState]:
        return self._tasks.get(task_id)

    def set(self, task_id: str, state: PentestState):
        self._tasks[task_id] = state

    def pop(self, task_id: str) -> Optional[PentestState]:
        # 任务彻底退出时一并清理 task-scoped 缓存, 避免 task_id 复用
        # (rare, 测试 / 重启场景) 时把旧的 decision_cache / log seq
        # 当成新任务的初始值。
        self._decision_cache.pop(task_id, None)
        self._decision_cursor.pop(task_id, None)
        self.reset_log_seq(task_id)
        return self._tasks.pop(task_id, None)

    def all_states(self) -> list[PentestState]:
        return list(self._tasks.values())

    def items(self):
        return self._tasks.items()

    # ── 运行中任务集合 ────────────────────────────────────

    def mark_running(self, task_id: str):
        self._running_tasks.add(task_id)

    def mark_stopped(self, task_id: str):
        self._running_tasks.discard(task_id)

    @property
    def running_count(self) -> int:
        return len(self._running_tasks)

    def is_running(self, task_id: str) -> bool:
        return task_id in self._running_tasks

    # ── 审批锁 ────────────────────────────────────────────

    def set_approval_inflight(self, task_id: str, ts: float):
        self._approval_inflight[task_id] = ts

    def get_approval_inflight(self, task_id: str) -> Optional[float]:
        return self._approval_inflight.get(task_id)

    def clear_approval_inflight(self, task_id: str):
        self._approval_inflight.pop(task_id, None)

    # ── 后台任务注册表 ────────────────────────────────────

    def register_bg_task(self, task_id: str, task: asyncio.Task) -> None:
        """注册一个后台协程(若已有旧句柄则先取消,避免泄漏)。"""
        old = self._bg_tasks.get(task_id)
        if old and not old.done():
            old.cancel()
        self._bg_tasks[task_id] = task

    def unregister_bg_task(self, task_id: str) -> None:
        self._bg_tasks.pop(task_id, None)

    # ── 任务级 log seq ────────────────────────────────────

    def next_log_seq(self, task_id: str, *, anchor: int | None = None) -> int:
        """返回 ``task_id`` 维度下一条日志的单调 seq。

        - 跨分支(fork 后两条分支各自向 phase_log 追加)仍能单调推进;
        - WS 重连 ``after_log_seq`` 用这条 seq 走 bisect, 不会再漏补;
        - ``anchor`` 给 hydrate / resume 路径用: 进程重启后第一次 log 时
          从 ``state.phase_log_seqs[-1]`` 同步起点, 避免 counter 退回 0
          以致前端重连 ``after_log_seq=K`` 时被错误地当作"全部要补"。

        线程安全: ``threading.Lock`` 保证 worker 线程 ``state.log()`` 间接
        调用时 counter 不会与主协程互相吞掉自增。
        """
        with self._log_seq_lock:
            cur = self._log_seq_counter.get(task_id, -1)
            if anchor is not None and anchor > cur:
                cur = int(anchor)
            cur += 1
            self._log_seq_counter[task_id] = cur
            return cur

    def reset_log_seq(self, task_id: str) -> None:
        with self._log_seq_lock:
            self._log_seq_counter.pop(task_id, None)

    def peek_log_seq(self, task_id: str) -> int:
        with self._log_seq_lock:
            return self._log_seq_counter.get(task_id, -1)

    def cancel_bg_task(self, task_id: str) -> bool:
        """主动取消 run_task/resume_task 协程。返回是否发起了取消。

        语义说明:
            ``run_task`` / ``resume_task`` / ``_resume_branch_bg`` 内部都用
            ``sm._bg_tasks.get(task_id) is my_task`` 判断自己是不是当前
            owner——是 owner 才走 ``stop container`` / ``publish('done')`` /
            ``clear_*_sink`` 的收尾。如果这里直接 ``pop``,``cancel`` 唤醒
            后的 finally 会把自己误判成"被分支接管",于是整个用户主动 cancel
            的语义就被吞掉了 (容器不关、done 不发、sink 不清)。所以
            ``cancel_bg_task`` 只发取消信号,真正的 unregister 由协程自己
            在 finally 里完成。
        """
        task = self._bg_tasks.get(task_id)
        if not task or task.done():
            return False
        task.cancel()
        return True

    # ── 工具注册表缓存 ────────────────────────────────────

    def get_tool_registry(self):
        if self._tool_registry_cache is None:
            from backend.tools.tool_registry import ToolRegistry
            self._tool_registry_cache = ToolRegistry()
        return self._tool_registry_cache

    # ── 辅助转换函数 ──────────────────────────────────────

    def to_summary(self, state: PentestState) -> dict:
        from backend.api.schemas import TaskSummary
        return TaskSummary(
            task_id=state.task_id,
            target=state.target,
            status=state.status.value,
            current_phase=state.current_phase,
            findings_count=len(state.findings),
            got_shell=state.got_shell,
            report_path=state.report_path,
            privilege_level=state.privilege_level,
            created_at=state.created_at,
            updated_at=datetime.utcnow().isoformat(),
            workflow_mode=state.workflow_mode,
            auto_approve=state.auto_approve,
        ).model_dump()

    def to_detail(self, state: PentestState) -> dict:
        base = self.to_summary(state)
        base.update({
            "target_os": state.target_os,
            "scope_note": state.scope_note,
            "extra_hint": state.extra_hint,
            "user_prompt": state.user_prompt,
            "error_msg": state.error_msg,
            "open_ports": [p.model_dump() for p in state.open_ports],
            "os_info": state.os_info,
            "web_paths": state.web_paths,
            "path_contents": state.path_contents,
            "subdomains": state.subdomains,
            "findings": [f.model_dump() for f in state.findings],
            "exploit_results": [r.model_dump() for r in state.exploit_results],
            "tool_records": [r.model_dump() for r in state.tool_records],
            "decision_events": self.build_decision_events(state) + list(state.live_decision_events),
            "post_findings": state.post_findings,
            "report_md": state.report_md,
            "phase_log": state.phase_log,
            "fingerprints": state.fingerprints,
            "foothold_status": state.foothold_status,
            "credential_store": state.credential_store,
            "loot_store": state.loot_store,
            "privesc_hypotheses": state.privesc_hypotheses,
            "objective_status": state.objective_status,
            "attack_next_steps": state.attack_next_steps,
            "privesc_attempt_count": state.privesc_attempt_count,
            "max_privesc_rounds": state.max_privesc_rounds,
            "chain_summary": state.chain_summary,
            "chain_visited": state.chain_visited,
            "secondary_elided": state.secondary_elided,
            "secondary_attack_count": state.secondary_attack_count,
            "max_secondary_attacks": state.max_secondary_attacks,
            # per-task 运行时参数(workflow_mode/auto_approve 已在 summary 里)
            "success_gate_level": state.success_gate_level,
            "risk_budget": state.risk_budget,
            "max_react_rounds": state.max_react_rounds,
            "max_explore_rounds": state.max_explore_rounds,
            "skill_min_score": state.skill_min_score,
            "skill_weak_boost": state.skill_weak_boost,
            # 通用 Plan 模式 checkpoint(刷新页面后用于回填确认卡片)
            "pending_checkpoint": state.pending_checkpoint,
            "checkpoint_history": list(state.checkpoint_history or []),
            "pending_user_prompt": state.pending_user_prompt,
            # 攻击链反馈循环 / Supervisor 模式可视化字段
            "attack_graph": state.attack_graph.to_payload() if state.attack_graph else {"nodes": [], "edges": []},
            "phase_visit_count": dict(state.phase_visit_count or {}),
            "replan_signals": dict(state.replan_signals or {}),
            "replan_count": state.replan_count,
            "max_replan": state.max_replan,
            "supervisor_round": state.supervisor_round,
            "supervisor_history": list(state.supervisor_history or []),
        })
        # stdout/stderr 截断（避免 MB 级响应）+ 标注 truncated_reason
        for rec in base.get("tool_records", []):
            for field in ("stdout", "stderr"):
                val = rec.get(field, "")
                if len(val) > 2000:
                    original_len = len(val)
                    rec[field] = val[:2000] + "\n...(truncated)"
                    rec["truncated"] = True
                    rec.setdefault(
                        "truncated_reason",
                        f"API 层截断: {field} {original_len}→2000 字符",
                    )
        return base

    # 任务详情接口默认返回的轻量快照大小阈值。运行时间长的任务 phase_log /
    # decision_events 会增长到 5k+,直接整体下发会让前端首屏卡顿,所以默认
    # 只回最近 N 条,完整数据通过 /tasks/{id}/logs 与 ?full=true 走分页/按需。
    DEFAULT_SNAPSHOT_LOG_TAIL = 60
    DEFAULT_SNAPSHOT_DECISION_TAIL = 120
    SNAPSHOT_PATH_SNIPPET_MAX = 400
    SNAPSHOT_EXPLOIT_OUTPUT_MAX = 1000

    def to_detail_snapshot(
        self,
        state: PentestState,
        log_tail: int = DEFAULT_SNAPSHOT_LOG_TAIL,
        decision_tail: int = DEFAULT_SNAPSHOT_DECISION_TAIL,
    ) -> dict:
        """Lightweight detail used by the running-task page首屏。

        与 ``to_detail`` 的差异:
          * ``phase_log`` 被替换为 ``phase_log_tail`` (最近 N 条) +
            ``phase_log_total`` (总数),完整日志走 ``/tasks/{id}/logs``
            的分页接口。
          * ``decision_events`` 同样仅返回 ``decision_events_tail`` +
            ``decision_events_total``。
          * ``tool_records`` 直接丢弃(前端 view 实际未消费),仅保留
            ``tool_records_count`` 用于摘要展示。
          * ``report_md`` 不再随首屏返回,前端打开「报告」Tab 时再走
            ``/tasks/{id}/report``。
          * ``exploit_results`` 内每条 stdout/stderr 截断到 1KB,
            ``path_contents`` 的 ``content_snippet`` 截断到 400 字符。

        ``decision_events`` 字段名保持向后兼容(等同于 tail),老前端
        即便没有更新仍能拿到最近的事件渲染。
        """
        base = self.to_summary(state)

        log_tail = max(0, min(log_tail, 500))
        decision_tail = max(0, min(decision_tail, 500))

        log_total = len(state.phase_log or [])
        phase_log_tail = (
            list(state.phase_log[-log_tail:]) if (log_tail and log_total) else []
        )

        all_events = self.build_decision_events(state) + list(state.live_decision_events)
        decision_total = len(all_events)
        decision_tail_slice = (
            all_events[-decision_tail:] if decision_tail and decision_total else []
        )

        path_contents_snapshot: list[dict] = []
        for c in (state.path_contents or []):
            if not isinstance(c, dict):
                continue
            entry = dict(c)
            snippet = entry.get("content_snippet") or ""
            if isinstance(snippet, str) and len(snippet) > self.SNAPSHOT_PATH_SNIPPET_MAX:
                entry["content_snippet"] = (
                    snippet[: self.SNAPSHOT_PATH_SNIPPET_MAX] + "...(truncated)"
                )
                entry["content_truncated"] = True
            path_contents_snapshot.append(entry)

        exploit_results_snapshot: list[dict] = []
        for r in state.exploit_results:
            payload = r.model_dump() if hasattr(r, "model_dump") else dict(r or {})
            for field_name in ("command_results", "command_records"):
                records = payload.get(field_name) or []
                trimmed = []
                for rec in records:
                    if not isinstance(rec, dict):
                        trimmed.append(rec)
                        continue
                    rec_copy = dict(rec)
                    for io in ("stdout", "stderr"):
                        val = rec_copy.get(io, "")
                        if isinstance(val, str) and len(val) > self.SNAPSHOT_EXPLOIT_OUTPUT_MAX:
                            rec_copy[io] = (
                                val[: self.SNAPSHOT_EXPLOIT_OUTPUT_MAX] + "\n...(truncated)"
                            )
                            rec_copy["truncated"] = True
                    trimmed.append(rec_copy)
                payload[field_name] = trimmed
            exploit_results_snapshot.append(payload)

        base.update({
            "target_os": state.target_os,
            "scope_note": state.scope_note,
            "extra_hint": state.extra_hint,
            "user_prompt": state.user_prompt,
            "error_msg": state.error_msg,
            "open_ports": [p.model_dump() for p in state.open_ports],
            "os_info": state.os_info,
            "web_paths": state.web_paths,
            "path_contents": path_contents_snapshot,
            "subdomains": state.subdomains,
            "findings": [f.model_dump() for f in state.findings],
            "exploit_results": exploit_results_snapshot,
            # 显式置空,避免老前端再去渲染整张大表;计数/快照足够支撑 UI。
            "tool_records": [],
            "tool_records_count": len(state.tool_records or []),
            # 兼容字段:旧前端 read decision_events,等价于 tail
            "decision_events": decision_tail_slice,
            "decision_events_tail": decision_tail_slice,
            "decision_events_total": decision_total,
            "post_findings": state.post_findings,
            # report_md 单独走 /tasks/{id}/report,首屏不再随车
            "report_md": "",
            "report_available": bool(state.report_md or state.report_path),
            # phase_log 改为 tail + total,前端分页走 /tasks/{id}/logs
            "phase_log": [],
            "phase_log_tail": phase_log_tail,
            "phase_log_total": log_total,
            "fingerprints": state.fingerprints,
            "foothold_status": state.foothold_status,
            "credential_store": state.credential_store,
            "loot_store": state.loot_store,
            "privesc_hypotheses": state.privesc_hypotheses,
            "objective_status": state.objective_status,
            "attack_next_steps": state.attack_next_steps,
            "privesc_attempt_count": state.privesc_attempt_count,
            "max_privesc_rounds": state.max_privesc_rounds,
            "chain_summary": state.chain_summary,
            "chain_visited": state.chain_visited,
            "secondary_elided": state.secondary_elided,
            "success_gate_level": state.success_gate_level,
            "risk_budget": state.risk_budget,
            "max_react_rounds": state.max_react_rounds,
            "max_explore_rounds": state.max_explore_rounds,
            "skill_min_score": state.skill_min_score,
            "skill_weak_boost": state.skill_weak_boost,
            # Plan 风格 checkpoint 数据,刷新后用于回填确认卡片
            "pending_checkpoint": state.pending_checkpoint,
            "checkpoint_history": list(state.checkpoint_history or [])[-10:],
            "pending_user_prompt": state.pending_user_prompt,
            # 攻击链反馈循环 / Supervisor 模式可视化字段（首屏精简版）
            "attack_graph": state.attack_graph.to_payload() if state.attack_graph else {"nodes": [], "edges": []},
            "phase_visit_count": dict(state.phase_visit_count or {}),
            "replan_signals": dict(state.replan_signals or {}),
            "replan_count": state.replan_count,
            "max_replan": state.max_replan,
            "supervisor_round": state.supervisor_round,
            "supervisor_history": list(state.supervisor_history or [])[-20:],
            "secondary_attack_count": state.secondary_attack_count,
            "max_secondary_attacks": state.max_secondary_attacks,
        })
        return base

    def ws_phase_payload(self, state: PentestState, log_tail: int = 5) -> dict:
        tail = max(1, min(log_tail, 50))
        log_total = len(state.phase_log or [])
        seqs = list(getattr(state, "phase_log_seqs", []) or [])
        last_seq = (
            int(seqs[-1])
            if (seqs and len(seqs) == log_total and log_total)
            else (log_total - 1 if log_total else -1)
        )
        return {
            "phase": state.current_phase,
            "status": state.status.value,
            "logs": state.phase_log[-tail:],
            # 把 phase_log 当前末尾的 task 级 seq 透出, 让前端 phase_update
            # 也能推进 ``lastLogSeq``, 与 history_logs / log 事件统一口径。
            "log_seq_last": last_seq,
            # 便于前端按 activeBranchId 过滤 phase_update 事件流。
            "branch_id": getattr(state, "active_branch_id", "") or "",
            "findings_count": len(state.findings),
            "got_shell": state.got_shell,
            "privilege_level": state.privilege_level,
            "foothold_status": state.foothold_status,
            "chain_visited": state.chain_visited,
            "secondary_elided": state.secondary_elided,
            "attack_next_steps": state.attack_next_steps,
            "privesc_attempt_count": state.privesc_attempt_count,
        }

    # ── 增量 decision_events 构建 ─────────────────────────

    @staticmethod
    def _extract_phase_log(log_entry: str) -> tuple[str, str, str]:
        match = re.match(r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<phase>[^\]]+)\]\s+(?P<msg>.*)$", log_entry or "")
        if not match:
            return "", "", log_entry or ""
        return match.group("ts"), match.group("phase"), match.group("msg")

    @staticmethod
    def _normalize_phase_log_ts(
        state_created_at: str, ts_short: str, prev_iso: str
    ) -> str:
        """把 phase_log 里的 ``[HH:MM:SS]`` 短时间戳标准化成 ISO-8601 串,
        与 ``push_decision`` 写入的 ``timestamp`` 对齐, 这样前端字典序 sort
        可以严格还原时间序, 不会再出现"HH:MM:SS 永远排在 YYYY-MM-DDTHH:MM
        前面"的错位。

        规则:
            - 输入已是 ISO (含 ``T``) → 直接透传
            - 否则用 ``prev_iso`` 的日期作为 anchor;
              若当前 HH:MM:SS 比 ``prev`` 的 HH:MM:SS 小, 视为跨午夜, 日期 +1
            - 没有 prev 时退到 ``state.created_at`` 的日期; 都没有就用 utcnow
            - ``ts_short`` 无法解析时返回空串 (调用方兜底)
        """
        if not ts_short:
            return ""
        if "T" in ts_short and len(ts_short) >= 10:
            return ts_short
        m = re.match(r"^(\d{2}):(\d{2}):(\d{2})", ts_short)
        if not m:
            return ""
        cur_hms = f"{m.group(1)}:{m.group(2)}:{m.group(3)}"

        base_date = ""
        base_hms = ""
        if prev_iso and len(prev_iso) >= 10 and prev_iso[4] == "-":
            base_date = prev_iso[:10]
            tm = re.search(r"T(\d{2}:\d{2}:\d{2})", prev_iso)
            if tm:
                base_hms = tm.group(1)
        if not base_date:
            if state_created_at and len(state_created_at) >= 10:
                base_date = state_created_at[:10]
            else:
                base_date = datetime.utcnow().strftime("%Y-%m-%d")

        if base_hms and cur_hms < base_hms:
            try:
                from datetime import date as _date, timedelta as _td
                base_date = (_date.fromisoformat(base_date) + _td(days=1)).isoformat()
            except Exception:
                pass

        return f"{base_date}T{cur_hms}"

    def build_decision_events(self, state: PentestState) -> list[dict]:
        """Build decision events with incremental caching."""
        tid = state.task_id

        cur_log = len(state.phase_log or [])
        cur_rec = len(state.tool_records or [])
        cur_exp = len(state.exploit_results or [])
        prev = self._decision_cursor.get(tid, (0, 0, 0))

        if prev == (cur_log, cur_rec, cur_exp) and tid in self._decision_cache:
            return list(self._decision_cache[tid])

        events = list(self._decision_cache.get(tid, []))
        seen_exec_keys: set[tuple[str, str, str]] = set()
        for ev in events:
            ts = ev.get("timestamp", "")
            phase = ev.get("phase", "")
            cmd = ev.get("command", "")
            if ev.get("action") == "command_exec":
                seen_exec_keys.add((ts, phase, cmd))

        # 增量构造 phase_log 派生事件时, 用上一次缓存里最末一条 ISO 时间戳作为
        # anchor, 跨调用维持 prev_iso, 让跨午夜推进逻辑稳定。
        prev_iso = ""
        for ev in reversed(events):
            ts = ev.get("timestamp", "")
            if ts and "T" in ts and len(ts) >= 10:
                prev_iso = ts
                break
        state_created_at = getattr(state, "created_at", "") or ""

        base_idx = prev[0] if tid in self._decision_cache else 0

        # 1) incremental phase_log
        for idx in range(base_idx, cur_log):
            entry = state.phase_log[idx]
            ts_short, phase, msg = self._extract_phase_log(entry)
            ts = self._normalize_phase_log_ts(state_created_at, ts_short, prev_iso) or ts_short
            if ts and "T" in ts:
                prev_iso = ts
            tone = "info"
            action = "log"
            tool = ""
            backend = ""
            exit_code = None
            elapsed_ms = None

            start_match = TOOL_START_RE.search(msg)
            if start_match:
                tool = start_match.group(1).strip()
                backend = start_match.group(2).strip()
                action = "tool_start"
                tone = "primary"

            done_match = TOOL_DONE_RE.search(msg)
            if done_match:
                tool = done_match.group(1).strip()
                exit_code = int(done_match.group(2))
                elapsed_ms = int(float(done_match.group(3)) * 1000.0)
                action = "tool_result"
                tone = "success" if exit_code == 0 else "danger"

            if "审批" in msg or "授权" in msg:
                action = "approval"
                tone = "warning"

            if action == "log" and THOUGHT_RE.search(msg):
                action = "thought"
                tone = "primary"

            # 历史日志里 tool 就是 TOOL_START_RE / TOOL_DONE_RE 抓到的字面;
            # executor 已经把 ``/bin/bash`` 替换成 display_tool, 但兼容残留
            # 老日志 / 直接被监督模式注入的旧文本: 命中 shell 名就退一步显示
            # ``script``,否则前端工具链还会出现 ``/bin/bash``。
            if tool and tool in _SHELL_NAMES:
                tool = "script"
            events.append({
                "id": f"log-{idx}",
                "timestamp": ts,
                "phase": phase,
                "action": action,
                "tool": tool,
                "display_tool": tool,
                "backend": backend,
                "poc_or_vuln": "",
                "command": "",
                "runtime_command": "",
                "stdout": "",
                "stderr": "",
                "exit_code": exit_code,
                "elapsed_ms": elapsed_ms,
                "purpose": "",
                "round": None,
                "truncated": False,
                "total_len": 0,
                "message": msg,
                "raw": entry,
                "tone": tone,
            })

        # 2) incremental tool_records
        rec_start = prev[1] if tid in self._decision_cache else 0
        for ridx in range(rec_start, cur_rec):
            record = state.tool_records[ridx]
            payload = record.model_dump() if hasattr(record, "model_dump") else dict(record or {})
            cmd = str(payload.get("command") or "")
            runtime_cmd = str(payload.get("runtime_command") or "")
            stdout = str(payload.get("stdout") or "")
            stderr = str(payload.get("stderr") or "")
            timestamp = str(payload.get("timestamp") or "")
            phase = str(payload.get("phase") or "")
            # display_tool 由 executor 直接落库,老记录没有时回退到 ``tool`` +
            # 命令推断,确保前端工具链不会再看到 ``/bin/bash``。
            display_tool = str(payload.get("display_tool") or "").strip()
            tool = str(payload.get("tool") or "shell")
            if not display_tool:
                if tool in _SHELL_NAMES:
                    display_tool = _infer_tool_from_command(cmd)
                else:
                    display_tool = tool
            tool = display_tool
            backend = str(payload.get("backend") or "")
            exit_code = payload.get("exit_code")
            elapsed = payload.get("elapsed")
            purpose = str(payload.get("purpose") or "")
            round_no = payload.get("round")
            truncated = bool(payload.get("truncated") or False)
            total_len = payload.get("total_len")
            if total_len is None:
                total_len = len(stdout) + len(stderr)
            try:
                total_len_val = int(total_len)
            except Exception:
                total_len_val = len(stdout) + len(stderr)

            dedupe_key = (timestamp, phase, cmd)
            if dedupe_key in seen_exec_keys:
                continue
            seen_exec_keys.add(dedupe_key)

            rec_id = str(payload.get("id") or f"tool-rec-{ridx}")
            events.append({
                "id": f"exec-{rec_id}",
                "timestamp": timestamp,
                "phase": phase or "unknown",
                "action": "command_exec",
                "tool": tool,
                "display_tool": display_tool,
                "backend": backend,
                "poc_or_vuln": "",
                "command": cmd,
                "runtime_command": runtime_cmd,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "elapsed_ms": int(float(elapsed) * 1000.0) if elapsed is not None else None,
                "purpose": purpose,
                "round": round_no,
                "truncated": truncated,
                "total_len": total_len_val,
                "message": f"命令执行: {tool} {_command_preview(cmd)}".strip(),
                "raw": "",
                "tone": "success" if exit_code == 0 else "danger",
            })

        # 3) incremental exploit_results
        exp_start = prev[2] if tid in self._decision_cache else 0
        for ridx in range(exp_start, cur_exp):
            result = state.exploit_results[ridx]
            result_payload = result.model_dump() if hasattr(result, "model_dump") else result
            vuln_id = result_payload.get("vuln_id", "")
            records = result_payload.get("command_records") or result_payload.get("command_results") or []
            for cidx, record in enumerate(records):
                cmd = str(record.get("command") or "")
                runtime_cmd = str(record.get("runtime_command") or "")
                stdout = str(record.get("stdout") or "")
                stderr = str(record.get("stderr") or "")
                exit_code = record.get("exit_code")
                elapsed = record.get("elapsed")
                timestamp = str(record.get("timestamp") or "")
                purpose = str(record.get("purpose") or "")
                round_no = record.get("round")
                truncated = bool(record.get("truncated") or False)
                total_len = record.get("total_len")
                if total_len is None:
                    total_len = len(stdout) + len(stderr)
                try:
                    total_len_val = int(total_len)
                except Exception:
                    total_len_val = len(stdout) + len(stderr)
                dedupe_key = (timestamp, "exploit", cmd)
                if dedupe_key in seen_exec_keys:
                    continue
                seen_exec_keys.add(dedupe_key)
                rec_display_tool = str(record.get("display_tool") or "").strip()
                rec_tool = str(record.get("tool") or "shell")
                if not rec_display_tool:
                    if rec_tool in _SHELL_NAMES:
                        rec_display_tool = _infer_tool_from_command(cmd)
                    else:
                        rec_display_tool = rec_tool
                rec_tool = rec_display_tool
                events.append({
                    "id": f"cmd-{ridx}-{cidx}",
                    "timestamp": timestamp,
                    "phase": str(record.get("phase") or "exploit"),
                    "action": "command_exec",
                    "tool": rec_tool,
                    "display_tool": rec_display_tool,
                    "backend": str(record.get("backend") or ""),
                    "poc_or_vuln": vuln_id,
                    "command": cmd,
                    "runtime_command": runtime_cmd,
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                    "elapsed_ms": int(float(elapsed) * 1000.0) if elapsed is not None else None,
                    "purpose": purpose,
                    "round": round_no,
                    "truncated": truncated,
                    "total_len": total_len_val,
                    "message": f"命令执行: {_command_preview(cmd)}",
                    "raw": "",
                    "tone": "success" if exit_code == 0 else "danger",
                })

        for event in events:
            event.setdefault("purpose", "")
            event.setdefault("round", None)
            event.setdefault("truncated", False)
            event.setdefault("total_len", 0)
            event.setdefault("runtime_command", "")
            # 前端 helper 优先读 display_tool 渲染节点,兜底到 tool。
            event.setdefault("display_tool", event.get("tool") or "")

        self._decision_cache[tid] = events
        self._decision_cursor[tid] = (cur_log, cur_rec, cur_exp)
        return events


# ── 模块级单例 ────────────────────────────────────────────
_state_manager = TaskStateManager()


def get_state_manager() -> TaskStateManager:
    return _state_manager
