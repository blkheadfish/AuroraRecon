"""
orchestrator.py  ── 改进版
主要改进：
  1. MemorySaver checkpointer   → 内置无需额外依赖，进程内断点续跑
  2. @retry_node 装饰器         → 工具调用失败自动重试（最多3次）
  3. human_approval 节点        → 利用前强制人工确认（竞赛演示亮点）
  4. interrupt_before=["human_approval"] → LangGraph 原生中断机制
  5. task_id 透传               → 所有 agent.run() 都传入 task_id
  6. parse_target 统一解析       → 创建 state 后立即解析，全链路使用 target_host/target_port

流程（主机攻链优先）：
  START → recon → vuln_scan → surface_enum → exploit_decision
        → human_approval（interrupt_before 暂停等待审批）
        → foothold_attempt → secondary_attack（可选）→ post_foothold_enum
        → privesc_attempt（可循环）→ objective_collect → report → END
        ↓（无可利用漏洞）
        report → END
"""
from __future__ import annotations

import asyncio
import functools
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Optional

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from backend.agents.models import (
    CommandExecutionRecord,
    ExploitResult,
    ParsedTarget,
    PentestState,
    PortInfo,
    TaskStatus,
    VulnFinding,
    parse_target,
)

logger = logging.getLogger(__name__)

# 与前端 TaskProgressMermaid 节点顺序一致（单调推进）
_CHAIN_PHASE_ORDER: list[str] = [
    "recon",
    "vuln_scan",
    "surface_enum",
    "exploit_decision",
    "awaiting_approval",
    "foothold_attempt",
    "secondary_attack",
    "post_foothold_enum",
    "privesc_attempt",
    "objective_collect",
    "report",
]


def _record_chain_visit(state: PentestState, phase_name: str) -> None:
    if phase_name not in state.chain_visited:
        state.chain_visited.append(phase_name)


# ───────────────────────────────────────────────────────
# 目标解析 → 写入 state
# ───────────────────────────────────────────────────────

def _apply_parsed_target(state: PentestState) -> None:
    """
    在任务创建后、recon 前，将用户原始 target 统一解析并写回 state。

    之后所有 agent 都通过 state.target_host / state.target_port 使用，
    不再各自解析 state.target，确保单一真相。
    """
    parsed: ParsedTarget = parse_target(state.target)
    state.target_host = parsed.host
    state.target_port = parsed.port
    state.target_scheme = parsed.scheme
    state.target_path = parsed.path
    state.target_raw = parsed.raw or state.target

    # 如果 target 本身含协议/端口/路径，把 target 归一化为纯 host
    # 以确保 nmap 等工具拿到的是干净的扫描目标
    # （state.target 保持不变，仍然是用户原始输入）
    if parsed.host:
        port_info = f":{parsed.port}" if parsed.port else ""
        scheme_info = f" (scheme={parsed.scheme})" if parsed.scheme else ""
        state.log(
            f"目标解析: host={parsed.host}{port_info}{scheme_info}"
        )
    else:
        state.log(f"⚠ 目标解析失败，原始输入: {state.target}")


def _append_tool_record(
    state: PentestState,
    record: dict,
    *,
    default_phase: str,
) -> None:
    """将执行器结构化记录写入 state.tool_records（去重）。"""
    payload = dict(record or {})
    payload.setdefault("phase", default_phase)
    payload.setdefault("timestamp", datetime.utcnow().isoformat())
    payload.setdefault("id", uuid.uuid4().hex[:16])
    payload.setdefault("truncated", False)
    if payload.get("total_len") is None:
        payload["total_len"] = len(str(payload.get("stdout") or "")) + len(str(payload.get("stderr") or ""))
    rec = CommandExecutionRecord(**payload)
    if rec.id and any(item.id == rec.id for item in state.tool_records):
        return
    state.tool_records.append(rec)


def _operator_chat_block(state: PentestState) -> str:
    """决策对话中最近若干条用户消息，注入 LLM 上下文（纯文本，避免结构注入）。"""
    lines: list[str] = []
    for m in state.user_messages[-12:]:
        t = (m.get("text") or "").strip()
        if t:
            if len(t) > 800:
                t = t[:800] + "…"
            lines.append(t)
    if not lines:
        return ""
    return "\n操作员实时补充（决策对话，请优先参考）：\n" + "\n".join(f"- {t}" for t in lines)


def _build_exploit_context(state: PentestState) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "ports_summary": ", ".join(
            f"{p.port}/{p.service}({p.version[:30]})" for p in state.open_ports[:20]
        ),
        "web_paths": ", ".join(state.web_paths[:20]) if state.web_paths else "无",
        "fingerprint": state.raw_recon.get("raw_nmap", "")[:500],
        "fingerprints": state.fingerprints,
        "extra_hint": state.extra_hint,
        "user_prompt": state.user_prompt,
        "workflow_mode": state.workflow_mode,
        "attack_chain_mode": True,
        "attack_chain_hint": (
            "主机攻链优先：以「立足点→枚举→提权→目标」为主线；"
            "单漏洞利用只是战术动作，需在链路上推进而非只追求命中一条 CVE。"
        ),
    }
    oc = _operator_chat_block(state)
    if oc:
        ctx["operator_chat"] = oc
    return ctx


def _sync_foothold_state(state: PentestState) -> None:
    """根据 exploit 结果同步 foothold_status（与 got_shell 一致）。"""
    if not state.got_shell:
        state.foothold_status = "none"
        return
    successes = [r for r in state.exploit_results if r.success]
    if not successes:
        state.foothold_status = "none"
        return
    first = successes[0]
    si = first.session_info or {}
    if si.get("session_id"):
        st = (first.shell_type or "").lower()
        state.foothold_status = "meterpreter" if "meterpreter" in st else "shell"
    elif (si.get("method") or "").lower() == "react":
        st = (first.shell_type or "").lower()
        if any(x in st for x in ("reverse", "bind", "tty")):
            state.foothold_status = "shell"
        else:
            state.foothold_status = "web_rce"
    else:
        state.foothold_status = "shell"


def _merge_attack_steps(state: PentestState, steps: list | None) -> None:
    existing = {(s.get("stage"), s.get("action")) for s in (state.attack_next_steps or [])}
    for s in steps or []:
        if not isinstance(s, dict):
            continue
        key = (s.get("stage"), s.get("action"))
        if key not in existing:
            state.attack_next_steps.append(s)
            existing.add(key)


def _flatten_post_findings_for_report(state: PentestState) -> None:
    """兼容报告模板对 post_findings['findings'] 的遍历。"""
    pf = dict(state.post_findings or {})
    flat: dict[str, Any] = {}
    if isinstance(pf.get("post_foothold"), dict):
        flat["post_foothold"] = pf["post_foothold"].get("findings", {})
    if isinstance(pf.get("privesc_latest"), dict):
        flat["privesc"] = pf["privesc_latest"].get("findings", {})
    if isinstance(pf.get("objective"), dict):
        flat["objective"] = pf["objective"].get("findings", {})
    pf["findings"] = flat
    state.post_findings = pf


# ───────────────────────────────────────────────────────
# retry 装饰器
# ───────────────────────────────────────────────────────

def retry_node(max_attempts: int = 3, delay: float = 2.0):
    def decorator(fn):
        @functools.wraps(fn)
        async def wrapper(state: PentestState) -> PentestState:
            last_exc: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await fn(state)
                except Exception as exc:
                    last_exc = exc
                    state.log(f"{fn.__name__} 第 {attempt}/{max_attempts} 次失败: {exc}")
                    if attempt < max_attempts:
                        await asyncio.sleep(delay * attempt)
            state.error_msg = f"{fn.__name__} 在 {max_attempts} 次重试后仍失败: {last_exc}"
            state.log(state.error_msg)
            return state
        return wrapper
    return decorator


# ───────────────────────────────────────────────────────
# 节点函数
# ───────────────────────────────────────────────────────

@retry_node(max_attempts=3, delay=2.0)
async def node_recon(state: PentestState) -> PentestState:
    from backend.agents.recon_agent import ReconAgent
    from backend.tools.executor import ToolExecutor
    state.current_phase = "recon"
    _record_chain_visit(state, "recon")
    state.status = TaskStatus.RUNNING

    # 为本次任务启动专属工具容器（多人并发时每个 task 独立隔离）
    try:
        _exec = ToolExecutor()
        await _exec.start_task_container(state.task_id)
        state.log(f"工具容器已就绪: pentest_task_{state.task_id[:12]}")
    except Exception as _ce:
        # 容器启动失败不阻断流程，降级为 docker run --rm 模式
        state.log(f"⚠ 工具容器启动失败，降级为临时容器模式: {_ce}")

    state.log(f"开始侦察目标: {state.target_host or state.target}")
    agent = ReconAgent()
    async def _on_tool_log(line: str):
        state.log(line)
    async def _on_exec_record(record: dict):
        _append_tool_record(state, record, default_phase="recon")
    result = await agent.run(
        target=state.target_host or state.target,
        target_port=state.target_port,
        task_id=state.task_id,
        log_callback=_on_tool_log,
        record_callback=_on_exec_record,
    )
    state.open_ports = result.get("ports", [])
    state.os_info = _stringify_dict_keys(result.get("os_info", {}))
    state.web_paths = result.get("web_paths", [])
    state.subdomains = result.get("subdomains", [])
    state.raw_recon = _stringify_dict_keys(result)
    state.target_os = _infer_os(state.open_ports, state.os_info)
    state.log(f"侦察完成: {len(state.open_ports)} 端口, OS={state.target_os}")
    return state


@retry_node(max_attempts=2, delay=3.0)
async def node_vuln_scan(state: PentestState) -> PentestState:
    from backend.agents.vuln_agent import VulnAgent
    state.current_phase = "vuln_scan"
    _record_chain_visit(state, "vuln_scan")
    state.log("开始漏洞扫描...")
    agent = VulnAgent()
    async def _on_tool_log(line: str):
        state.log(line)
    async def _on_exec_record(record: dict):
        _append_tool_record(state, record, default_phase="vuln_scan")
    result = await agent.run(
        target=state.target_host or state.target,
        ports=state.open_ports,
        web_paths=state.web_paths,
        target_os=state.target_os,
        target_port=state.target_port,
        target_scheme=state.target_scheme,
        task_id=state.task_id,
        log_callback=_on_tool_log,
        record_callback=_on_exec_record,
    )
    state.findings = result.get("findings", [])
    # msgpack (LangGraph checkpoint) 不允许 int 作 dict key
    # raw_vuln 和 fingerprints 都可能含 int key（端口号），必须递归转换
    state.raw_vuln = _stringify_dict_keys(result)
    state.fingerprints = _stringify_dict_keys(result.get("fingerprints", {}))
    exploitable = [f for f in state.findings if f.exploitable]
    state.log(f"漏洞扫描完成: {len(state.findings)} 发现, {len(exploitable)} 可利用")
    return state


async def node_surface_enum(state: PentestState) -> PentestState:
    """攻链：Web/服务表面枚举线索合并（轻量，避免重复重型扫描）。"""
    state.current_phase = "surface_enum"
    _record_chain_visit(state, "surface_enum")
    state.log("攻链: 表面枚举 — 合并 Web 路径与常见入口线索")
    seen: set[str] = set()
    merged: list[str] = []
    for p in state.web_paths or []:
        s = (p or "").strip()
        if s and s not in seen:
            seen.add(s)
            merged.append(s)
    webish = any(
        p.port in (80, 443, 8080, 8443, 8000, 8888)
        or "http" in (p.service or "").lower()
        for p in state.open_ports
    )
    if webish:
        for extra in ("/robots.txt", "/.git/HEAD", "/admin", "/antibot_image/", "/login"):
            if extra not in seen:
                seen.add(extra)
                merged.append(extra)
    state.web_paths = merged[:100]
    state.log(f"表面枚举完成: Web 线索 {len(state.web_paths)} 条")
    return state


async def node_exploit_decision(state: PentestState) -> PentestState:
    from backend.llm.router import LLMRouter
    state.current_phase = "exploit_decision"
    _record_chain_visit(state, "exploit_decision")
    exploitable = [f for f in state.findings if f.exploitable]
    if not exploitable:
        state.log("无可利用漏洞，跳过利用阶段")
        return state

    state.log(f"LLM 分析 {len(exploitable)} 个漏洞的利用优先级...")
    try:
        llm = LLMRouter()
        prompt = _build_exploit_decision_prompt(state)
        decision = await llm.chat(prompt, response_format="json")
        decision_data = json.loads(decision)

        priority_map: dict[str, dict] = {
            v["vuln_id"]: v for v in decision_data.get("targets", [])
        }
        for finding in state.findings:
            if finding.vuln_id in priority_map:
                rec = priority_map[finding.vuln_id]
                if not rec.get("should_exploit", True):
                    # 只允许 LLM 禁用 low/info 级别的漏洞
                    # high/critical 级别的漏洞必须保留，避免 LLM 误判
                    if finding.severity in ("low", "info"):
                        finding.exploitable = False
                        logger.info(
                            f"[ExploitDecision] 禁用低优先级: {finding.name} ({finding.severity})"
                        )
                    else:
                        logger.info(
                            f"[ExploitDecision] 保留 {finding.severity} 级别: {finding.name}"
                            f"（LLM 建议跳过但级别过高，强制保留）"
                        )

        remaining = sum(1 for f in state.findings if f.exploitable)
        state.log(f"LLM 决策完成，保留 {remaining} 个可利用漏洞")
    except Exception as e:
        state.log(f"LLM 决策异常（保留原始可利用标记）: {e}")
    return state


async def node_human_approval(state: PentestState) -> PentestState:
    """
    人工审批节点。
    流程：
      1. 图执行到此节点前，interrupt_before 暂停整个图
      2. 前端收到 current_phase=awaiting_approval 后显示审批按钮
      3. 用户点击「批准/拒绝」→ POST /tasks/{id}/approve
      4. API 调用 orchestrator.resume(task_id, approved=True/False)
      5. LangGraph 以更新后的 state 重新进入此节点执行
      6. 此时 state.approved 已被 resume 注入，节点根据结果决定后续
    """
    state.current_phase = "awaiting_approval"
    _record_chain_visit(state, "awaiting_approval")
    exploitable = [f for f in state.findings if f.exploitable]

    if not state.approved:
        # 首次进入（interrupt 前的 pre-check），记录等待日志
        # 实际上 interrupt_before 会在这行之前暂停，这里是 resume 后才运行
        state.log(f"⏸ 收到审批请求：{len(exploitable)} 个漏洞待利用")

    if state.approved:
        state.log("✅ 已获授权，继续利用阶段")
    else:
        state.log("⚠ 未获授权，跳过利用阶段")
        for f in state.findings:
            f.exploitable = False
    return state


async def node_foothold_attempt(state: PentestState) -> PentestState:
    from backend.agents.exploit_agent import ExploitAgent
    state.current_phase = "foothold_attempt"
    _record_chain_visit(state, "foothold_attempt")
    exploitable = [f for f in state.findings if f.exploitable]

    php_fpm = [
        f for f in state.findings
        if "11043" in (f.cve or "").lower() or "php-fpm" in (f.name or "").lower()
    ]
    if php_fpm:
        php_exploitable = [f for f in php_fpm if f.exploitable]
        logger.info(
            f"[Orchestrator] PHP-FPM findings: "
            f"total={len(php_fpm)}, exploitable={len(php_exploitable)}, "
            f"names={[f.name for f in php_fpm]}"
        )
        if not php_exploitable:
            state.log(
                f"PHP-FPM 发现 {len(php_fpm)} 个但均未确认可利用"
                f"（tool={php_fpm[0].tool}）"
            )

    state.log(f"攻链: 立足点尝试 — 利用 {len(exploitable)} 个漏洞条目（战术层）")
    try:
        agent = ExploitAgent()
        exploit_context = _build_exploit_context(state)
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="foothold_attempt")
        async def _on_decision(event: dict):
            state.push_decision(event)
        results = await agent.run(
            target=state.target_host or state.target,
            findings=exploitable,
            target_os=state.target_os,
            context=exploit_context,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
            decision_callback=_on_decision,
        )
        state.exploit_results = results
        successes = [r for r in results if r.success]
        state.got_shell = len(successes) > 0
        if state.got_shell:
            si = successes[0].session_info or {}
            state.privilege_level = si.get("privilege") or (
                "root" if "root" in str(si.get("current_user", "")).lower() else "user"
            )
            state.log(f"成功获取 shell，权限: {state.privilege_level}")
            state.secondary_elided = True
        else:
            state.log("所有利用尝试均未成功")
        _sync_foothold_state(state)
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"利用阶段异常: {e}")
    return state


async def node_secondary_attack(state: PentestState) -> PentestState:
    """首轮利用未拿到 shell 时，对失败项再跑一轮（结合操作员对话中的新提示）。"""
    from backend.agents.exploit_agent import ExploitAgent
    state.current_phase = "secondary_attack"
    _record_chain_visit(state, "secondary_attack")
    state.secondary_attack_done = True

    if state.got_shell:
        state.log("已有 shell，跳过二次攻击")
        return state

    exploitable = [f for f in state.findings if f.exploitable]
    if not exploitable:
        state.log("无可利用项，跳过二次攻击")
        return state

    failed_ids = {r.vuln_id for r in state.exploit_results if not r.success}
    if state.exploit_results and failed_ids:
        findings_retry = [f for f in exploitable if f.vuln_id in failed_ids]
    else:
        findings_retry = list(exploitable)

    if not findings_retry:
        state.log("二次攻击：没有需要重试的漏洞条目")
        return state

    state.log(f"二次攻击：对 {len(findings_retry)} 个漏洞再尝试一轮...")
    try:
        agent = ExploitAgent()
        exploit_context = _build_exploit_context(state)
        exploit_context["secondary_pass"] = True
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="secondary_attack")
        async def _on_decision(event: dict):
            state.push_decision(event)
        new_results = await agent.run(
            target=state.target_host or state.target,
            findings=findings_retry,
            target_os=state.target_os,
            context=exploit_context,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
            decision_callback=_on_decision,
        )
        by_id: dict[str, ExploitResult] = {r.vuln_id: r for r in state.exploit_results}
        for nr in new_results:
            prev = by_id.get(nr.vuln_id)
            if prev is None:
                by_id[nr.vuln_id] = nr
            elif nr.success:
                by_id[nr.vuln_id] = nr
            elif not prev.success:
                by_id[nr.vuln_id] = nr
        state.exploit_results = list(by_id.values())
        successes = [r for r in state.exploit_results if r.success]
        state.got_shell = len(successes) > 0
        if state.got_shell:
            si = successes[0].session_info or {}
            state.privilege_level = si.get("privilege") or (
                "root" if "root" in str(si.get("current_user", "")).lower() else "user"
            )
            state.log(f"二次攻击后成功获取 shell，权限: {state.privilege_level}")
        else:
            state.log("二次攻击仍未成功")
        _sync_foothold_state(state)
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"二次攻击异常: {e}")
    return state


async def node_post_foothold_enum(state: PentestState) -> PentestState:
    from backend.agents.post_agent import PostExploitAgent
    state.current_phase = "post_foothold_enum"
    _record_chain_visit(state, "post_foothold_enum")
    state.log("攻链: 立足后枚举")
    try:
        agent = PostExploitAgent()
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="post_foothold_enum")
        res = await agent.run_post_foothold_enum(
            exploit_results=state.exploit_results,
            target_os=state.target_os,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
        )
        base = dict(state.post_findings or {})
        base["post_foothold"] = res
        state.post_findings = base
        for c in res.get("new_credentials") or []:
            if isinstance(c, dict):
                state.credential_store.append(c)
        for h in res.get("privesc_hypotheses") or []:
            if isinstance(h, dict):
                state.privesc_hypotheses.append(h)
        for l in res.get("loot_hints") or []:
            if isinstance(l, dict):
                state.loot_store.append(l)
        _merge_attack_steps(state, res.get("next_steps"))
        fp = res.get("final_privilege")
        if fp and fp != "unknown":
            state.privilege_level = fp
        state.log("立足后枚举完成")
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"立足后枚举异常: {e}")
    return state


async def node_privesc_attempt(state: PentestState) -> PentestState:
    from backend.agents.post_agent import PostExploitAgent
    state.current_phase = "privesc_attempt"
    _record_chain_visit(state, "privesc_attempt")
    state.privesc_attempt_count += 1
    state.log(f"攻链: 提权尝试 第 {state.privesc_attempt_count}/{state.max_privesc_rounds} 轮")
    try:
        agent = PostExploitAgent()
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="privesc_attempt")
        res = await agent.run_privesc_phase(
            exploit_results=state.exploit_results,
            target_os=state.target_os,
            task_id=state.task_id,
            round_num=state.privesc_attempt_count,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
        )
        base = dict(state.post_findings or {})
        base["privesc_latest"] = res
        state.post_findings = base
        state.privilege_level = res.get("final_privilege", state.privilege_level)
        _merge_attack_steps(state, res.get("next_steps"))
        pl = (state.privilege_level or "").lower()
        if pl == "root":
            state.objective_status["root_reached"] = True
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"提权阶段异常: {e}")
    return state


async def node_objective_collect(state: PentestState) -> PentestState:
    from backend.agents.post_agent import PostExploitAgent
    state.current_phase = "objective_collect"
    _record_chain_visit(state, "objective_collect")
    state.log("攻链: 目标收集（flag / proof 线索）")
    try:
        agent = PostExploitAgent()
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="objective_collect")
        res = await agent.run_objective_collect(
            exploit_results=state.exploit_results,
            target_os=state.target_os,
            task_id=state.task_id,
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
        )
        base = dict(state.post_findings or {})
        base["objective"] = res
        state.post_findings = base
        findings = res.get("findings") or {}
        if findings.get("flag_hints"):
            state.objective_status["flag_hints"] = True
        if findings.get("root_context_hint"):
            state.objective_status["root_context_hint"] = True
        state.objective_status["report_ready"] = True
        _merge_attack_steps(state, res.get("next_steps"))
        state.chain_summary = (
            f"foothold={state.foothold_status}; privilege={state.privilege_level}; "
            f"privesc_rounds={state.privesc_attempt_count}"
        )
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"目标收集异常: {e}")
    return state


async def node_report(state: PentestState) -> PentestState:
    from backend.report.generator import ReportGenerator
    state.current_phase = "report"
    _record_chain_visit(state, "report")
    state.log("开始生成报告...")
    try:
        _flatten_post_findings_for_report(state)
        gen = ReportGenerator()
        report_md, report_path = await gen.generate(state)
        state.report_md = report_md
        state.report_path = report_path
        state.status = TaskStatus.COMPLETED
        state.log(f"报告生成完成: {report_path}")
    except Exception as e:
        state.error_msg = str(e)
        state.status = TaskStatus.FAILED
        state.log(f"报告生成异常: {e}")
    finally:
        # 任务结束，清理专属工具容器（无论成功失败都执行）
        try:
            from backend.tools.executor import ToolExecutor
            _exec = ToolExecutor()
            await _exec.stop_task_container(state.task_id)
            state.log("工具容器已清理")
        except Exception:
            pass
    return state


# ───────────────────────────────────────────────────────
# 条件边
# ───────────────────────────────────────────────────────

def edge_should_exploit(state: PentestState) -> str:
    return "human_approval" if any(f.exploitable for f in state.findings) else "report"


def edge_after_approval(state: PentestState) -> str:
    return "foothold_attempt" if any(f.exploitable for f in state.findings) else "report"


def edge_after_foothold(state: PentestState) -> str:
    if state.got_shell:
        return "post_foothold_enum"
    if not state.secondary_attack_done and any(f.exploitable for f in state.findings):
        return "secondary_attack"
    return "report"


def edge_after_secondary(state: PentestState) -> str:
    return "post_foothold_enum" if state.got_shell else "report"


def edge_after_privesc(state: PentestState) -> str:
    pl = (state.privilege_level or "").lower()
    if pl == "root":
        return "objective_collect"
    if state.privesc_attempt_count >= state.max_privesc_rounds:
        return "objective_collect"
    return "privesc_again"


# ───────────────────────────────────────────────────────
# 构建图
# ───────────────────────────────────────────────────────

def build_graph(checkpointer=None):
    graph = StateGraph(PentestState)

    graph.add_node("recon",               node_recon)
    graph.add_node("vuln_scan",           node_vuln_scan)
    graph.add_node("surface_enum",        node_surface_enum)
    graph.add_node("exploit_decision",    node_exploit_decision)
    graph.add_node("human_approval",      node_human_approval)
    graph.add_node("foothold_attempt",    node_foothold_attempt)
    graph.add_node("secondary_attack",    node_secondary_attack)
    graph.add_node("post_foothold_enum",  node_post_foothold_enum)
    graph.add_node("privesc_attempt",     node_privesc_attempt)
    graph.add_node("objective_collect",   node_objective_collect)
    graph.add_node("report",              node_report)

    graph.add_edge(START, "recon")
    graph.add_edge("recon", "vuln_scan")
    graph.add_edge("vuln_scan", "surface_enum")
    graph.add_edge("surface_enum", "exploit_decision")
    graph.add_conditional_edges(
        "exploit_decision", edge_should_exploit,
        {"human_approval": "human_approval", "report": "report"},
    )
    graph.add_conditional_edges(
        "human_approval", edge_after_approval,
        {"foothold_attempt": "foothold_attempt", "report": "report"},
    )
    graph.add_conditional_edges(
        "foothold_attempt", edge_after_foothold,
        {
            "post_foothold_enum": "post_foothold_enum",
            "secondary_attack": "secondary_attack",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "secondary_attack", edge_after_secondary,
        {"post_foothold_enum": "post_foothold_enum", "report": "report"},
    )
    graph.add_edge("post_foothold_enum", "privesc_attempt")
    graph.add_conditional_edges(
        "privesc_attempt", edge_after_privesc,
        {
            "objective_collect": "objective_collect",
            "privesc_again": "privesc_attempt",
        },
    )
    graph.add_edge("objective_collect", "report")
    graph.add_edge("report", END)

    return graph.compile(
        checkpointer=checkpointer,
        # 在 human_approval 节点前中断，等待前端调用 /approve 后 resume
        interrupt_before=["human_approval"],
    )


# ───────────────────────────────────────────────────────
# Orchestrator 对外接口
# ───────────────────────────────────────────────────────

class Orchestrator:
    def __init__(self):
        self._graph = None

    async def _ensure_graph(self):
        if self._graph is None:
            # MemorySaver 内置于 langgraph，无需额外依赖
            # 进程内断点续跑完全正常，重启后状态清空
            checkpointer = MemorySaver()
            self._graph = build_graph(checkpointer=checkpointer)

    def _prepare_state(
        self,
        target: str,
        scope_note: str,
        extra_hint: str,
        user_prompt: str,
        workflow_mode: str,
        task_id: Optional[str],
    ) -> PentestState:
        """创建并解析 PentestState，统一入口。"""
        state = PentestState(
            target=target,
            scope_note=scope_note,
            extra_hint=extra_hint,
            user_prompt=user_prompt,
            workflow_mode=workflow_mode,
            task_id=task_id or str(uuid.uuid4()),
        )
        # ── 关键：在 recon 之前统一解析目标 ──────────────
        _apply_parsed_target(state)
        return state

    async def run(
        self,
        target: str,
        scope_note: str = "CTF/授权靶场测试",
        extra_hint: str = "",
        user_prompt: str = "",
        workflow_mode: str = "standard",
        task_id: Optional[str] = None,
    ) -> PentestState:
        await self._ensure_graph()
        initial_state = self._prepare_state(
            target, scope_note, extra_hint, user_prompt, workflow_mode, task_id,
        )
        config = {"configurable": {"thread_id": initial_state.task_id}}
        initial_state.log(f"任务启动，目标: {target}")
        final_state: PentestState = await self._graph.ainvoke(initial_state, config=config)
        return final_state

    async def run_stream(
        self,
        target: str,
        scope_note: str = "CTF/授权靶场测试",
        extra_hint: str = "",
        user_prompt: str = "",
        workflow_mode: str = "standard",
        task_id: Optional[str] = None,
    ):
        await self._ensure_graph()
        initial_state = self._prepare_state(
            target, scope_note, extra_hint, user_prompt, workflow_mode, task_id,
        )
        config = {"configurable": {"thread_id": initial_state.task_id}}

        async for event in self._graph.astream(initial_state, config=config):
            for node_name, state in event.items():
                yield node_name, state

    async def resume(self, task_id: str, approved: bool = True) -> None:
        await self._ensure_graph()
        config = {"configurable": {"thread_id": task_id}}
        # 正确做法：先把 approved 注入现有 checkpoint，再从断点继续
        # ainvoke({"approved": ...}) 是错的——LangGraph 会把字典当新初始 state 从头跑
        await self._graph.aupdate_state(config, {"approved": approved})
        await self._graph.ainvoke(None, config=config)

    async def resume_stream(self, task_id: str, approved: bool = True):
        """
        流式恢复执行（审批后继续 exploit → post → report）。

        与 resume() 的区别：用 astream 代替 ainvoke，
        每个节点完成后 yield 状态更新，供 API 层实时推送。
        """
        await self._ensure_graph()
        config = {"configurable": {"thread_id": task_id}}
        await self._graph.aupdate_state(config, {"approved": approved})

        async for event in self._graph.astream(None, config=config):
            for node_name, state in event.items():
                yield node_name, state

    async def get_state(self, task_id: str) -> Optional[PentestState]:
        await self._ensure_graph()
        config = {"configurable": {"thread_id": task_id}}
        snapshot = await self._graph.aget_state(config)
        if snapshot and snapshot.values:
            try:
                return PentestState(**snapshot.values)
            except Exception:
                return None
        return None


# ───────────────────────────────────────────────────────
# 辅助函数
# ───────────────────────────────────────────────────────

def _stringify_dict_keys(obj: Any) -> Any:
    """
    递归将 dict 的所有 key 转为 str。

    LangGraph 的 MemorySaver 使用 msgpack 序列化 checkpoint，
    msgpack 默认 strict_map_key=True 不允许 int/float 作为 dict key。
    VulnAgent 的 fingerprints 用端口号(int)做 key，必须转换。
    """
    if isinstance(obj, dict):
        return {str(k): _stringify_dict_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_stringify_dict_keys(item) for item in obj]
    return obj


def _infer_os(ports: list[PortInfo], os_info: dict) -> str:
    port_nums = {p.port for p in ports}
    linux_signs = port_nums & {22, 111, 2049}
    windows_signs = port_nums & {135, 139, 445, 3389, 5985}

    port_guess = "unknown"
    if linux_signs and not windows_signs:
        port_guess = "linux"
    elif windows_signs and not linux_signs:
        port_guess = "windows"

    service_guess = "unknown"
    for p in ports:
        combined = f"{p.service} {p.version} {p.banner}".lower()
        if any(k in combined for k in ["apache", "nginx", "openssh", "ubuntu", "debian"]):
            service_guess = "linux"
            break
        if any(k in combined for k in ["microsoft", "iis", "windows"]):
            service_guess = "windows"
            break

    nmap_guess = "unknown"
    if os_info.get("os_type") and os_info["os_type"] != "unknown":
        if int(os_info.get("accuracy", 0)) >= 90:
            return os_info["os_type"].lower()
        nmap_guess = os_info["os_type"].lower()

    for guess in [service_guess, port_guess, nmap_guess]:
        if guess != "unknown":
            return guess
    return "unknown"


def _build_exploit_decision_prompt(state: PentestState) -> str:
    findings_json = json.dumps(
        [f.model_dump() for f in state.findings if f.exploitable],
        ensure_ascii=False, indent=2,
    )
    ports_json = json.dumps(
        [p.model_dump() for p in state.open_ports[:20]],
        ensure_ascii=False,
    )
    op_chat = _operator_chat_block(state)
    return f"""你是一名资深渗透测试工程师，正在合法授权的 CTF 靶场中进行安全测试。

目标信息:
- 地址: {state.target}
- 操作系统: {state.target_os}
- 开放端口: {ports_json}
- 任务模式: {state.workflow_mode}
- 用户附加提示: {state.extra_hint or '无'}
- 用户偏好 Prompt: {state.user_prompt or '无'}
{op_chat or ''}

发现的可利用漏洞:
{findings_json}

请分析漏洞，制定利用优先级，返回纯 JSON（不含 markdown 代码块）：
{{
  "analysis": "整体分析",
  "targets": [
    {{
      "vuln_id": "漏洞ID",
      "priority": 1,
      "should_exploit": true,
      "reason": "原因",
      "recommended_msf_module": "模块路径或null",
      "recommended_tool": "其他工具"
    }}
  ]
}}

按成功率从高到低排序，优先选择有成熟 MSF 模块或 PoC 的漏洞。"""