"""
state.py —— 全局状态管理器

将散落的全局变量封装为 TaskStateManager 类，
所有 Router / Service 通过依赖注入获取同一实例。
"""
from __future__ import annotations

import re
import logging
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

    # ── 任务 CRUD ─────────────────────────────────────────

    def get(self, task_id: str) -> Optional[PentestState]:
        return self._tasks.get(task_id)

    def set(self, task_id: str, state: PentestState):
        self._tasks[task_id] = state

    def pop(self, task_id: str) -> Optional[PentestState]:
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
        ).model_dump()

    def to_detail(self, state: PentestState) -> dict:
        base = self.to_summary(state)
        base.update({
            "target_os": state.target_os,
            "scope_note": state.scope_note,
            "extra_hint": state.extra_hint,
            "user_prompt": state.user_prompt,
            "workflow_mode": state.workflow_mode,
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
            "operator_role": state.operator_role,
            "success_gate_level": state.success_gate_level,
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

    def ws_phase_payload(self, state: PentestState, log_tail: int = 5) -> dict:
        tail = max(1, min(log_tail, 50))
        return {
            "phase": state.current_phase,
            "status": state.status.value,
            "logs": state.phase_log[-tail:],
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

        base_idx = prev[0] if tid in self._decision_cache else 0

        # 1) incremental phase_log
        for idx in range(base_idx, cur_log):
            entry = state.phase_log[idx]
            ts, phase, msg = self._extract_phase_log(entry)
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

            events.append({
                "id": f"log-{idx}",
                "timestamp": ts,
                "phase": phase,
                "action": action,
                "tool": tool,
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
            tool = str(payload.get("tool") or "shell")
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
                events.append({
                    "id": f"cmd-{ridx}-{cidx}",
                    "timestamp": timestamp,
                    "phase": str(record.get("phase") or "exploit"),
                    "action": "command_exec",
                    "tool": str(record.get("tool") or "shell"),
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

        self._decision_cache[tid] = events
        self._decision_cursor[tid] = (cur_log, cur_rec, cur_exp)
        return events


# ── 模块级单例 ────────────────────────────────────────────
_state_manager = TaskStateManager()


def get_state_manager() -> TaskStateManager:
    return _state_manager
