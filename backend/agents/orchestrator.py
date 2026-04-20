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
  START → recon → surface_enum → intel_harvest → vuln_scan → exploit_decision
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
import os
import re
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

TASK_TIMEOUT = int(os.getenv("TASK_TIMEOUT_SECONDS", "7200"))

# 与前端 TaskProgressMermaid 节点顺序一致（单调推进）
_CHAIN_PHASE_ORDER: list[str] = [
    "recon",
    "surface_enum",
    "intel_harvest",
    "vuln_scan",
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


def _build_dir_intel(state: PentestState) -> dict[str, Any]:
    """Build structured directory intelligence from web_paths_inventory and related state."""
    intel: dict[str, Any] = {
        "high_value_paths": [],
        "potential_entry_points": [],
        "exposed_files": [],
        "backup_files": [],
        "api_endpoints": [],
        "dir_listings": [],
        "git_exposed": False,
    }
    _hv_hints = {"admin", "login", "upload", "info_disclosure"}
    _api_hints = {"api"}
    _backup_hints = {"backup"}
    _config_hints = {"config", "leak"}

    for item in (state.web_paths_inventory or []):
        path = item.get("path", "")
        hints = set(item.get("hints", []))
        if not path:
            continue
        if hints & _hv_hints:
            intel["high_value_paths"].append(path)
        if hints & _api_hints:
            intel["api_endpoints"].append(path)
        if hints & _backup_hints:
            intel["backup_files"].append(path)
        if hints & _config_hints:
            intel["exposed_files"].append(path)
        if "?" in path or "=" in path:
            intel["potential_entry_points"].append(path)

    for p in (state.web_paths or []):
        lower = p.lower()
        if ".git" in lower:
            intel["git_exposed"] = True
        if any(lower.endswith(ext) for ext in (".bak", ".old", ".backup", ".swp", ".orig")):
            if p not in intel["backup_files"]:
                intel["backup_files"].append(p)

    if state.dirlist_tree:
        for dl_path in (state.dirlist_interesting_files or [])[:10]:
            if dl_path not in intel["dir_listings"]:
                intel["dir_listings"].append(dl_path)

    for key in intel:
        if isinstance(intel[key], list):
            intel[key] = intel[key][:20]

    return intel


def _build_exploit_context(state: PentestState) -> dict[str, Any]:
    _normalize_and_dedupe_state_facts(state, source_node="build_exploit_context")
    path_contents = state.path_contents or []
    path_content_summary = "无"
    if path_contents:
        summary_lines = []
        for item in path_contents[:12]:
            keywords = item.get("keywords", [])
            summary_lines.append(
                f"{item.get('path', '')} "
                f"(status={item.get('status', 0)}, "
                f"title={item.get('title', '')[:50]}, "
                f"tech={','.join(item.get('tech_clues', [])[:4])}"
                + (f", keywords={','.join(keywords[:4])}" if keywords else "")
                + ")"
            )
        path_content_summary = "\n".join(summary_lines)

    web_paths_str = ", ".join(state.web_paths[:30]) if state.web_paths else "无"

    # Include directory listing tree if available
    dirlist_info = ""
    if state.dirlist_tree:
        dirlist_info = f"\n目录列表文件树:\n{state.dirlist_tree}"
    if state.dirlist_interesting_files:
        dirlist_info += f"\n有价值文件: {', '.join(state.dirlist_interesting_files[:15])}"

    # Build structured directory intelligence for exploit decision
    dir_intel: dict[str, Any] = state.dir_intel or {}
    if not dir_intel:
        dir_intel = _build_dir_intel(state)

    ctx: dict[str, Any] = {
        "ports_summary": ", ".join(
            f"{p.port}/{p.service}({p.version[:30]})" for p in state.open_ports[:20]
        ),
        "web_paths": web_paths_str,
        "path_contents": path_content_summary,
        "dirlist_info": dirlist_info,
        "dir_intel": dir_intel,
        "fingerprint": state.raw_recon.get("raw_nmap", "")[:500],
        "fingerprints": state.fingerprints,
        "extra_hint": state.extra_hint,
        "user_prompt": state.user_prompt,
        "workflow_mode": state.workflow_mode,
        "auto_approve": state.auto_approve,
        "success_gate_level": state.success_gate_level,
        "risk_budget": state.risk_budget,
        "max_react_rounds": state.max_react_rounds,
        "max_explore_rounds": state.max_explore_rounds,
        "skill_min_score": state.skill_min_score,
        "skill_weak_boost": state.skill_weak_boost,
        "php_runtime": state.php_runtime or {},
        "runtime_facts": state.runtime_facts or {},
        "confirmed_facts": state.confirmed_facts or {},
        "prior_probe_variables": state.exploit_probe_variables or {},
        "prior_failed_commands": state.failed_commands_by_vuln or {},
        "attack_chain_mode": True,
        "attack_chain_hint": (
            "主机攻链优先：以「立足点→枚举→提权→目标」为主线；"
            "单漏洞利用只是战术动作，需在链路上推进而非只追求命中一条 CVE。"
        ),
    }

    if state.intel_files:
        intel_lines = []
        for f in state.intel_files[:10]:
            intel = f.get("intel", {})
            if intel.get("risk_level") in ("critical", "high"):
                intel_lines.append(f"{f['path']}: {intel.get('summary', '')}")
        if intel_lines:
            ctx["intel_harvest_summary"] = "\n".join(intel_lines)

    if state.page_params:
        param_lines = []
        for p in state.page_params:
            status = "已验证" if p.get("verified") else "待验证"
            param_lines.append(
                f"{p['url']} [{p['vuln_type']}] param={p['param_name']} ({status})"
            )
        ctx["discovered_params"] = "\n".join(param_lines)

    oc = _operator_chat_block(state)
    if oc:
        ctx["operator_chat"] = oc
    return ctx


def _sync_foothold_state(state: PentestState) -> None:
    """根据 exploit 结果同步 foothold_status（区分 RCE 与 file_read）。"""
    if not state.got_shell:
        file_read_results = [
            r for r in state.exploit_results
            if r.success and r.exploit_level == "file_read"
        ]
        if file_read_results:
            state.foothold_status = "file_read"
        else:
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
            state.status = TaskStatus.FAILED
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
    state.path_contents = _stringify_dict_keys(result.get("path_contents", []))
    state.subdomains = result.get("subdomains", [])
    state.raw_recon = _stringify_dict_keys(result)
    state.target_os = _infer_os(state.open_ports, state.os_info)
    state.dir_scan_strategy = _stringify_dict_keys(result.get("scan_strategy", {}))

    # Emit dir-discovery coverage report as a decision event
    dir_cov = result.get("dir_coverage")
    if dir_cov:
        state.push_decision({
            "action": "tool_coverage_report",
            "phase": "recon",
            "message": (
                f"目录发现覆盖率{'达标' if dir_cov.get('satisfied') else '未达标'}: "
                f"扫描 {dir_cov.get('total_paths', 0)} 路径, "
                f"工具: {dir_cov.get('category_counts', {})}"
            ),
            "tone": "info" if dir_cov.get("satisfied") else "warn",
            "raw": json.dumps(dir_cov, ensure_ascii=False),
        })
        # Emit per-tool events
        for t in dir_cov.get("tools", []):
            if t["status"] == "skipped":
                state.push_decision({
                    "action": "tool_skipped",
                    "phase": "recon",
                    "tool": t["name"],
                    "message": f"跳过 {t['name']}: {t.get('skip_reason', 'N/A')}",
                    "tone": "warn",
                })
            elif t["status"] in ("executed", "failed", "timeout"):
                state.push_decision({
                    "action": "tool_executed",
                    "phase": "recon",
                    "tool": t["name"],
                    "message": (
                        f"{t['name']}: {t['status']} "
                        f"(+{t.get('paths', 0)} 路径, {t.get('elapsed', 0):.1f}s)"
                    ),
                    "tone": "info" if t["status"] == "executed" else "warn",
                })

    # Emit LLM recon analysis hints if available
    llm_hints = result.get("llm_recon_hints") or {}
    if llm_hints:
        vectors = llm_hints.get("potential_attack_vectors", [])
        rec_tools = llm_hints.get("recommended_next_tools", [])
        state.push_decision({
            "action": "thought",
            "phase": "recon",
            "thinking": (
                f"LLM 侦察分析: OS推测={llm_hints.get('os_guess', 'N/A')}, "
                f"攻击向量: {'; '.join(vectors[:5]) if vectors else '无'}"
            ),
            "purpose": "LLM 侦察智能分析",
            "plan": [f"推荐工具: {', '.join(rec_tools[:5])}"] if rec_tools else [],
            "message": f"LLM 分析: {len(vectors)} 攻击向量, 推荐 {', '.join(rec_tools[:3]) if rec_tools else '无'}",
        })

    state.log(f"侦察完成: {len(state.open_ports)} 端口, OS={state.target_os}")

    # Emit recon summary thought event
    ports_summary = ", ".join(
        f"{p.port}/{p.service}" for p in state.open_ports[:15]
    )
    web_count = len(state.web_paths or [])
    sub_count = len(state.subdomains or [])
    state.push_decision({
        "action": "thought",
        "phase": "recon",
        "thinking": (
            f"侦察完成: 发现 {len(state.open_ports)} 个开放端口 ({ports_summary}), "
            f"OS推断={state.target_os}, 发现 {web_count} 条Web路径. "
            f"路径内容探测采集 {len(state.path_contents or [])} 条."
            + (f" 子域名: {sub_count} 个." if sub_count else "")
        ),
        "purpose": "侦察阶段总结",
        "plan": [
            f"开放端口: {len(state.open_ports)} 个",
            f"Web路径: {web_count} 条",
            *([ f"子域名: {sub_count} 个"] if sub_count else []),
            f"下一步: 漏洞扫描",
        ],
        "message": f"侦察完成: {len(state.open_ports)} 端口, {web_count} 路径, OS={state.target_os}",
    })
    return state


@retry_node(max_attempts=2, delay=3.0)
async def node_vuln_scan(state: PentestState) -> PentestState:
    from backend.agents.vuln_agent import VulnAgent
    state.current_phase = "vuln_scan"
    _record_chain_visit(state, "vuln_scan")

    # Consume paths discovered by intel_harvest and merge into attack surface
    if state.intel_discovered_paths:
        existing = set(state.web_paths or [])
        new_count = 0
        for p in state.intel_discovered_paths:
            if p not in existing:
                state.web_paths.append(p)
                existing.add(p)
                new_count += 1
        if new_count:
            state.log(f"情报回注: intel_harvest 新增 {new_count} 条路径到攻击面")

    state.log("开始漏洞扫描...")
    agent = VulnAgent()
    async def _on_tool_log(line: str):
        state.log(line)
    async def _on_exec_record(record: dict):
        _append_tool_record(state, record, default_phase="vuln_scan")
    async def _on_decision(event: dict):
        state.push_decision(event)
    nmap_vuln_hints = state.raw_recon.get("nmap_vuln_hints", [])
    result = await agent.run(
        target=state.target_host or state.target,
        ports=state.open_ports,
        web_paths=state.web_paths,
        path_contents=state.path_contents,
        target_os=state.target_os,
        target_port=state.target_port,
        target_scheme=state.target_scheme,
        task_id=state.task_id,
        log_callback=_on_tool_log,
        record_callback=_on_exec_record,
        decision_callback=_on_decision,
        nmap_vuln_hints=nmap_vuln_hints,
    )
    state.findings = result.get("findings", [])
    # msgpack (LangGraph checkpoint) 不允许 int 作 dict key
    # raw_vuln 和 fingerprints 都可能含 int key（端口号），必须递归转换
    state.raw_vuln = _stringify_dict_keys(result)
    state.fingerprints = _stringify_dict_keys(result.get("fingerprints", {}))
    exploitable = [f for f in state.findings if f.exploitable]
    state.log(f"漏洞扫描完成: {len(state.findings)} 发现, {len(exploitable)} 可利用")
    return state


# ── Tech-adaptive sensitive file probe list ──────────────────────
_TECH_SENSITIVE_MAP: dict[str, list[str]] = {
    "PHP": [
        "phpinfo.php", "config.php", "settings.php", "wp-config.php",
        "configuration.php", "local.php", "database.php",
    ],
    "WordPress": [
        "wp-config.php", "wp-login.php", "xmlrpc.php",
        "wp-content/debug.log", "wp-includes/version.php",
    ],
    "JSP": ["WEB-INF/web.xml", "WEB-INF/classes/", "status"],
    "Tomcat": [
        "manager/html", "host-manager/html", "WEB-INF/web.xml",
        "META-INF/context.xml", "status",
    ],
    "Spring": [
        "actuator", "actuator/env", "actuator/health", "actuator/info",
        "actuator/mappings", "actuator/configprops", "actuator/beans",
        "env", "trace", "heapdump",
    ],
    "Django": [
        "admin/", "settings.py", "__debug__/", "static/admin/",
    ],
    "Flask": [
        "console", "static/", "config.py",
    ],
    "IIS": [
        "web.config", "iisstart.htm", "aspnet_client/",
        "trace.axd", "elmah.axd",
    ],
    "ASP": [
        "web.config", "Global.asax", "App_Data/",
    ],
    "JBoss": [
        "jmx-console/", "web-console/", "invoker/JMXInvokerServlet",
        "status", "WEB-INF/web.xml",
    ],
    "WebLogic": [
        "console/", "wls-wsat/CoordinatorPortType",
        "bea_wls_internal/", "_async/AsyncResponseService",
    ],
    "Node": [
        "package.json", ".npmrc", "server.js", "app.js",
    ],
}

_BASE_SENSITIVE_PATHS = [
    ".env", "robots.txt", "sitemap.xml", ".htaccess", ".DS_Store",
    "server-status", "backup", "backup.sql", "dump", "dump.sql",
    "config", ".git/HEAD", ".git/config", ".svn/entries",
    "admin", "console",
]

_BACKUP_SUFFIXES = ["", ".bak", ".old", ".backup", ".swp", ".save", ".orig", "~", ".1"]


def _build_sensitive_paths(tech_hints: list[str]) -> list[str]:
    """Generate a de-duplicated sensitive path list tailored to detected tech stack."""
    hints_upper = {h.upper() for h in tech_hints if h}

    tech_specific: list[str] = []
    for tech_key, paths in _TECH_SENSITIVE_MAP.items():
        if tech_key.upper() in hints_upper or any(
            tech_key.upper() in h for h in hints_upper
        ):
            tech_specific.extend(paths)

    base_names = list(_BASE_SENSITIVE_PATHS) + tech_specific

    result: list[str] = []
    for b in base_names:
        for s in _BACKUP_SUFFIXES:
            result.append(f"/{b}{s}")

    seen: set[str] = set()
    deduped: list[str] = []
    for p in result:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped


async def node_surface_enum(state: PentestState) -> PentestState:
    """攻链：深度表面枚举 — planner-driven web probing + sensitive file detection."""
    import time as _time
    from backend.tools.executor import ToolExecutor
    from backend.tools.parsers.path_aggregator import PathAggregator
    from backend.tools.parsers.dirlist_crawler import crawl_directory_listings
    from backend.tools.tool_coverage_planner import ToolCoveragePlanner
    state.current_phase = "surface_enum"
    _record_chain_visit(state, "surface_enum")
    state.log("攻链: 表面枚举 — 多工具 Web 探测与敏感文件发现")

    aggregator = PathAggregator()
    aggregator.add_paths(state.web_paths or [], source="recon_phase")

    web_ports = [
        p for p in state.open_ports
        if p.port in (80, 443, 8080, 8443, 8000, 8888, 8081, 8090, 9000, 9090)
        or "http" in (p.service or "").lower()
    ]

    # Extract tech hints from recon phase for dynamic probe list generation
    _raw_recon = state.raw_recon or {}
    _recon_tech_hints: list[str] = []
    for _pi in state.open_ports:
        for tok in ((_pi.version or "") + " " + (_pi.banner or "")).split():
            if tok and len(tok) > 2:
                _recon_tech_hints.append(tok)
    _llm_hints = _raw_recon.get("llm_recon_hints") or {}
    for _hv in _llm_hints.get("high_value_ports", []):
        if isinstance(_hv, dict):
            if _hv.get("service"):
                _recon_tech_hints.append(_hv["service"])
            if _hv.get("attack_surface"):
                _recon_tech_hints.append(_hv["attack_surface"])

    if web_ports:
        executor = ToolExecutor()
        host = state.target_host or state.target

        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="surface_enum")

        for wp in web_ports[:3]:
            scheme = "https" if wp.port in (443, 8443) else "http"
            base_url = f"{scheme}://{host}:{wp.port}"

            sensitive_paths = _build_sensitive_paths(_recon_tech_hints)
            probe_cmds = []
            for sp in sensitive_paths:
                probe_cmds.append(
                    f'CODE=$(curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 "{base_url}{sp}"); '
                    f'[ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "{sp} $CODE"'
                )
            probe_script = " ; ".join(probe_cmds)
            try:
                probe_result = await executor.run_script(
                    script_content=probe_script,
                    timeout=60,
                    log_callback=_on_tool_log,
                    record_callback=_on_exec_record,
                    record_phase="surface_enum",
                    record_purpose="sensitive_file_probe",
                )
                if probe_result.stdout:
                    for line in probe_result.stdout.strip().splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            path, code = parts[0], parts[1]
                            if code in ("200", "301", "302", "403", "500"):
                                aggregator.add_paths(
                                    [path], source="curl_probe", status=int(code),
                                )
                                state.log(f"敏感文件发现: {path} (HTTP {code})")
            except Exception as e:
                logger.warning(f"[SurfaceEnum] 敏感文件探测异常: {e}")

            # ── Directory listing crawl (recursive) ──
            existing_paths = aggregator.get_actionable_paths()

            def _looks_like_directory(p: str) -> bool:
                basename = p.rstrip("/").rsplit("/", 1)[-1]
                if not basename:
                    return True
                return "." not in basename

            dir_candidates = [p for p in existing_paths if _looks_like_directory(p)]

            dirlist_seeds_from_content: list[str] = []
            for pc in (state.path_contents or []):
                title = (pc.get("title") or "").lower()
                snippet = (pc.get("content_snippet") or "").lower()
                if (
                    "index of" in title
                    or "parent directory" in snippet
                    or pc.get("dir_listing")
                ):
                    dirlist_seeds_from_content.append(pc["path"])

            dir_candidates = dirlist_seeds_from_content + dir_candidates
            dir_candidates.append("/")
            dir_candidates = list(dict.fromkeys(dir_candidates))[:30]
            try:
                dirlist_result = await crawl_directory_listings(
                    base_url=base_url,
                    seed_paths=dir_candidates,
                    executor=executor,
                    max_depth=3,
                    max_total_entries=200,
                    log_callback=_on_tool_log,
                    record_callback=_on_exec_record,
                )
                if dirlist_result.entries:
                    new_paths = [e.path for e in dirlist_result.entries]
                    aggregator.add_paths(new_paths, source="dirlist_crawl")
                    interesting = [e for e in dirlist_result.entries if e.interesting]
                    state.log(
                        f"[SurfaceEnum] 目录列表爬取: "
                        f"发现 {len(dirlist_result.entries)} 条目 "
                        f"({len(interesting)} 个有价值文件), "
                        f"{len(dirlist_result.dir_listing_paths)} 个目录列表页"
                    )
                    state.dirlist_tree = dirlist_result.file_tree_text
                    state.dirlist_interesting_files = [
                        e.path for e in dirlist_result.entries if e.interesting
                    ][:30]
            except Exception as e:
                logger.warning(f"[SurfaceEnum] 目录列表爬取异常: {e}")

            # ── Planner-driven web probe + fuzz tools ──
            planner = ToolCoveragePlanner(
                categories=["web_probe", "fuzz"],
                max_tools=4,
                max_stage_runtime=360,
            )
            plan = planner.build_plan(base_url, existing_paths_count=aggregator.count)

            for tool_spec in plan:
                should, skip_reason = planner.should_run(tool_spec)
                if not should:
                    planner.record_result(
                        tool_spec["name"], "skipped", skip_reason=skip_reason,
                    )
                    state.log(f"[SurfaceEnum] 跳过 {tool_spec['name']}: {skip_reason}")
                    continue

                tool_name = tool_spec["name"]
                state.log(f"[SurfaceEnum] Web 探测: 执行 {tool_name}")
                t0 = _time.monotonic()
                try:
                    tool_result = await executor.run_script(
                        script_content=tool_spec["script"],
                        timeout=tool_spec["timeout"],
                        log_callback=_on_tool_log,
                        record_callback=_on_exec_record,
                        record_phase="surface_enum",
                        record_purpose=f"{tool_name}_probe",
                    )
                    elapsed = _time.monotonic() - t0
                    stdout = tool_result.stdout or ""
                    new_count = aggregator.ingest(tool_name, stdout, base_url)
                    planner.record_result(
                        tool_name, "executed",
                        paths_found=new_count, raw_len=len(stdout),
                        elapsed=elapsed,
                    )
                    state.log(
                        f"[SurfaceEnum] {tool_name}: +{new_count} 路径 "
                        f"(累计 {aggregator.count}), {elapsed:.1f}s"
                    )
                except Exception as e:
                    elapsed = _time.monotonic() - t0
                    planner.record_result(
                        tool_name, "failed",
                        skip_reason=str(e)[:200], elapsed=elapsed,
                    )
                    logger.warning(f"[SurfaceEnum] {tool_name} 异常: {e}")

            # Emit coverage report
            report = planner.coverage_report()
            report_dict = report.to_log_dict()
            state.push_decision({
                "action": "tool_coverage_report",
                "phase": "surface_enum",
                "message": (
                    f"Web 探测覆盖率{'达标' if report.satisfied else '未达标'}: "
                    f"{report_dict['category_counts']}"
                ),
                "tone": "info" if report.satisfied else "warn",
                "raw": json.dumps(report_dict, ensure_ascii=False),
            })

    full_inventory = aggregator.get_inventory(min_confidence=0.4)
    state.web_paths_inventory = full_inventory[:200]
    state.web_paths = [
        item["path"] for item in full_inventory
        if item.get("status") in (200, 403, 0)
    ][:200]
    inv = aggregator.summary()
    state.log(
        f"表面枚举完成: {inv['total_paths']} 条路径 "
        f"(高价值 {inv['high_value']}), "
        f"来源工具: {', '.join(inv['source_tools'])}"
    )

    # Emit surface_enum summary thought
    high_value_paths = [
        p for p in state.web_paths[:30]
        if any(kw in p.lower() for kw in (
            "admin", "login", "config", "backup", ".git", ".env", "manager",
            "console", "upload", "api", "debug", "phpinfo",
        ))
    ]
    state.push_decision({
        "action": "thought",
        "phase": "surface_enum",
        "thinking": (
            f"表面枚举完成: 共发现 {inv['total_paths']} 条路径, "
            f"其中高价值 {inv['high_value']} 条. "
            f"来源工具: {', '.join(inv['source_tools'])}. "
            + (f"高价值路径: {', '.join(high_value_paths[:10])}" if high_value_paths else "未发现明显高价值路径.")
        ),
        "purpose": "表面枚举总结",
        "plan": [
            f"总路径: {inv['total_paths']}",
            f"高价值: {inv['high_value']}",
            f"下一步: 利用决策分析",
        ],
        "message": f"表面枚举完成: {inv['total_paths']} 路径, {inv['high_value']} 高价值",
    })
    return state


# ───────────────────────────────────────────────────────
# intel_harvest — 文件情报提取 + 页面源码审计
# ───────────────────────────────────────────────────────

_FILE_EXTS = {
    ".sql", ".conf", ".cfg", ".ini", ".xml", ".yaml", ".yml", ".json",
    ".properties", ".bak", ".old", ".backup", ".env", ".htpasswd",
    ".htaccess", ".log", ".txt", ".csv", ".key", ".pem",
}
_PAGE_EXTS = {".php", ".jsp", ".asp", ".aspx", ".py", ".cgi", ".do", ".action"}
_BINARY_EXTS = {".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".war", ".jar", ".class", ".exe", ".dll", ".so"}
_SENSITIVE_KEYWORDS = {"password", "passwd", "token", "secret", "credential", "key", "auth"}
_PAGE_KEYWORDS = {"login", "admin", "upload", "manager", "console"}
_MAX_FILE_TARGETS = 15
_MAX_PAGE_TARGETS = 15


def _classify_harvest_targets(state: PentestState) -> tuple[list[str], list[str]]:
    """Split discovered paths into file targets (Pipeline A) and page targets (Pipeline B)."""
    file_candidates: list[str] = []
    page_candidates: list[str] = []
    seen: set[str] = set()

    def _ext(p: str) -> str:
        lower = p.lower().rstrip("/")
        for ext in sorted(_FILE_EXTS | _PAGE_EXTS | _BINARY_EXTS, key=len, reverse=True):
            if lower.endswith(ext):
                return ext
        return ""

    for p in (state.dirlist_interesting_files or []):
        ext = _ext(p)
        if ext in _BINARY_EXTS or p in seen:
            continue
        seen.add(p)
        if ext in _FILE_EXTS:
            file_candidates.append(p)
        elif ext in _PAGE_EXTS:
            page_candidates.append(p)

    for p in (state.web_paths or []):
        if p in seen:
            continue
        ext = _ext(p)
        if ext in _BINARY_EXTS:
            continue
        seen.add(p)
        if ext in _FILE_EXTS:
            file_candidates.append(p)
        elif ext in _PAGE_EXTS:
            page_candidates.append(p)

    for pc in (state.path_contents or []):
        p = pc.get("path", "")
        if p in seen:
            continue
        kws = {k.lower() for k in (pc.get("keywords") or [])}
        tech = pc.get("tech_clues") or []
        if kws & _SENSITIVE_KEYWORDS:
            seen.add(p)
            file_candidates.append(p)
        elif tech or kws & _PAGE_KEYWORDS:
            seen.add(p)
            page_candidates.append(p)

    # LLM-confirmed high-value paths from intel analysis (via update_hints_from_intel)
    _intel_confirmed = {
        "high_risk_intel", "credential_confirmed", "secret_confirmed",
        "config_leak", "db_dump", "attack_lead",
    }
    for item in (state.web_paths_inventory or []):
        p = item.get("path", "")
        if p in seen:
            continue
        item_hints = set(item.get("hints", []))
        if item_hints & _intel_confirmed:
            seen.add(p)
            file_candidates.append(p)

    return file_candidates[:_MAX_FILE_TARGETS], page_candidates[:_MAX_PAGE_TARGETS]


def _build_harvest_script(base_url: str, file_targets: list[str], page_targets: list[str]) -> str:
    lines = [
        'set +e',
        f'BASE="{base_url}"',
        "while IFS='|' read -r TYPE HPATH; do",
        '  [ -z "$HPATH" ] && continue',
        '  LIMIT=$( [ "$TYPE" = "page" ] && echo 12288 || echo 8192 )',
        '  echo "__HARVEST_BEGIN__"',
        '  echo "TYPE:$TYPE"',
        '  echo "PATH:$HPATH"',
        '  TMP_H=$(mktemp); TMP_B=$(mktemp)',
        '  CODE=$(curl -sS -L --max-time 12 -D "$TMP_H" -o "$TMP_B" -w "%{http_code}" "$BASE$HPATH" 2>/dev/null || echo "000")',
        '  echo "CODE:$CODE"',
        '  HEADERS=$(head -c 1024 "$TMP_H" | tr \'\\r\' \' \')',
        '  echo "HEADERS:$HEADERS"',
        '  head -c $LIMIT "$TMP_B"',
        '  echo ""',
        '  echo "__HARVEST_END__"',
        '  rm -f "$TMP_H" "$TMP_B"',
        "done <<'EOF_TARGETS'",
    ]
    for p in file_targets:
        lines.append(f"file|{p}")
    for p in page_targets:
        lines.append(f"page|{p}")
    lines.append("EOF_TARGETS")
    return "\n".join(lines)


def _parse_harvest_output(raw: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    blocks = raw.split("__HARVEST_BEGIN__")
    for block in blocks[1:]:
        end_idx = block.find("__HARVEST_END__")
        if end_idx < 0:
            continue
        block = block[:end_idx]
        entry: dict[str, Any] = {"type": "", "path": "", "code": "000", "headers": "", "body": ""}
        body_lines: list[str] = []
        header_done = False
        for line in block.split("\n"):
            if not header_done:
                if line.startswith("TYPE:"):
                    entry["type"] = line[5:].strip()
                    continue
                elif line.startswith("PATH:"):
                    entry["path"] = line[5:].strip()
                    continue
                elif line.startswith("CODE:"):
                    entry["code"] = line[5:].strip()
                    continue
                elif line.startswith("HEADERS:"):
                    entry["headers"] = line[8:].strip()
                    header_done = True
                    continue
            body_lines.append(line)
        entry["body"] = "\n".join(body_lines).strip()
        if entry["path"]:
            results.append(entry)
    return results


_VULN_TYPE_NAMES = {
    "lfi": "文件包含漏洞 (LFI)",
    "sqli": "SQL 注入",
    "cmdi": "命令注入 (CMDi)",
    "ssti": "服务端模板注入 (SSTI)",
    "ssrf": "SSRF",
    "xss": "XSS",
    "rfi": "远程文件包含 (RFI)",
}


def _check_verify_result(stdout: str, vuln_type: str) -> bool:
    s = stdout.lower()
    if vuln_type == "lfi":
        return "root:x:0:0" in s or "/bin/bash" in s or "/bin/sh" in s
    if vuln_type == "sqli":
        sql_errors = ["sql syntax", "mysql", "sqlite", "postgresql", "ora-", "unclosed quotation"]
        return any(e in s for e in sql_errors)
    if vuln_type == "ssti":
        return "49" in stdout
    if vuln_type == "cmdi":
        return "uid=" in s
    return False


_INTEL_HINT_MAP = [
    ("credentials", "credential_confirmed"),
    ("secrets", "secret_confirmed"),
    ("config_intel", "config_leak"),
    ("attack_hints", "attack_lead"),
]


def _update_inventory_hints_from_intel(
    state: PentestState, path: str, intel: dict,
) -> None:
    """Reflect LLM file-analysis conclusions back into web_paths_inventory hints.

    Maps structured fields from FILE_INTEL_EXTRACT output to confirmed hint
    labels, only trusting items with confidence high/medium.
    """
    new_hints: list[str] = []
    risk = intel.get("risk_level", "none")
    if risk in ("critical", "high"):
        new_hints.append("high_risk_intel")
    for intel_key, hint_label in _INTEL_HINT_MAP:
        items = intel.get(intel_key) or []
        if any(
            isinstance(i, dict) and i.get("confidence") in ("high", "medium")
            for i in items
        ):
            new_hints.append(hint_label)
    if intel.get("file_type") == "sql_dump":
        new_hints.append("db_dump")
    if not new_hints:
        return
    for inv_item in (state.web_paths_inventory or []):
        if inv_item.get("path") == path:
            existing = set(inv_item.get("hints", []))
            inv_item["hints"] = list(existing | set(new_hints))
            break


from backend.agents.fact_hooks import (
    apply_service_info_extraction as _apply_service_info_extraction,
    make_fact_sink as _make_fact_sink,
    normalize_and_dedupe_state_facts as _normalize_and_dedupe_state_facts,
)


@retry_node()
async def node_intel_harvest(state: PentestState) -> PentestState:
    """Pipeline between surface_enum and vuln_scan: download files + audit page source."""
    from backend.llm.router import LLMRouter
    from backend.llm.prompts.templates import FILE_INTEL_EXTRACT, PAGE_SOURCE_AUDIT
    from backend.tools.executor import ToolExecutor

    state.current_phase = "intel_harvest"
    _record_chain_visit(state, "intel_harvest")
    state.log("情报采集: 文件情报提取 + 页面源码审计")

    file_targets, page_targets = _classify_harvest_targets(state)
    if not file_targets and not page_targets:
        state.log("情报采集: 无高价值目标，跳过")
        return state

    state.log(f"情报采集: 文件目标 {len(file_targets)} 个, 页面目标 {len(page_targets)} 个")

    host = state.target_host or state.target
    web_ports = [
        p for p in state.open_ports
        if p.port in (80, 443, 8080, 8443, 8000, 8888, 8081, 8090, 9000, 9090)
        or "http" in (p.service or "").lower()
    ]
    if not web_ports:
        state.log("情报采集: 未发现 Web 端口，跳过")
        return state

    wp = web_ports[0]
    scheme = "https" if wp.port in (443, 8443) else "http"
    base_url = f"{scheme}://{host}:{wp.port}"

    executor = ToolExecutor()

    async def _on_tool_log(line: str):
        state.log(line)

    async def _on_exec_record(record: dict):
        _append_tool_record(state, record, default_phase="intel_harvest")

    # ── Step B: batch download ──
    script = _build_harvest_script(base_url, file_targets, page_targets)
    try:
        dl_result = await executor.run_script(
            script_content=script,
            timeout=max(30, 15 * (len(file_targets) + len(page_targets))),
            log_callback=_on_tool_log,
            record_callback=_on_exec_record,
            record_phase="intel_harvest",
            record_purpose="batch_download",
        )
    except Exception as e:
        state.log(f"情报采集: 批量下载失败 — {e}")
        return state

    harvested = _parse_harvest_output(dl_result.stdout or "")
    if not harvested:
        state.log("情报采集: 下载结果为空，跳过 LLM 分析")
        return state

    state.log(f"情报采集: 下载完成, 共 {len(harvested)} 个目标")

    # ── Step C.0: deterministic service-info extraction (before LLM) ──
    # phpinfo / apache server-status / nginx stub_status / tomcat manager /
    # spring actuator / .env 一次性过完所有 parser，写入 state.runtime_facts
    _apply_service_info_extraction(state, harvested, base_url, wp.port)

    # ── Step C: LLM analysis (concurrent, semaphore=3) ──
    llm = LLMRouter()
    sem = asyncio.Semaphore(3)

    async def _analyze_file(entry: dict) -> dict[str, Any] | None:
        if not entry["body"] or entry["code"] in ("000", "404"):
            return None
        prompt = FILE_INTEL_EXTRACT.format(
            target=state.target,
            file_path=entry["path"],
            status_code=entry["code"],
            file_content=entry["body"][:8192],
        )
        async with sem:
            try:
                raw = await llm.chat(prompt, response_format="json", temperature=0.1, max_tokens=2048)
                return json.loads(raw)
            except Exception as exc:
                logger.warning(f"[IntelHarvest] LLM file analysis failed for {entry['path']}: {exc}")
                return None

    async def _analyze_page(entry: dict) -> dict[str, Any] | None:
        if not entry["body"] or entry["code"] in ("000", "404"):
            return None
        prompt = PAGE_SOURCE_AUDIT.format(
            target=state.target,
            page_url=f"{base_url}{entry['path']}",
            status_code=entry["code"],
            response_headers=entry["headers"][:512],
            page_source=entry["body"][:12288],
        )
        async with sem:
            try:
                raw = await llm.chat(prompt, response_format="json", temperature=0.1, max_tokens=2048)
                return json.loads(raw)
            except Exception as exc:
                logger.warning(f"[IntelHarvest] LLM page audit failed for {entry['path']}: {exc}")
                return None

    file_entries = [e for e in harvested if e["type"] == "file"]
    page_entries = [e for e in harvested if e["type"] == "page"]

    file_tasks = [_analyze_file(e) for e in file_entries]
    page_tasks = [_analyze_page(e) for e in page_entries]
    all_results = await asyncio.gather(*(file_tasks + page_tasks), return_exceptions=True)

    file_results = all_results[:len(file_tasks)]
    page_results = all_results[len(file_tasks):]

    # ── Step E (Pipeline A): inject file intel into state ──
    for entry, intel in zip(file_entries, file_results):
        if isinstance(intel, Exception) or intel is None:
            continue
        state.intel_files.append({
            "path": entry["path"],
            "content_snippet": entry["body"][:200],
            "intel": intel,
        })

        for cred in (intel.get("credentials") or []):
            if cred.get("confidence") != "low":
                state.credential_store.append(cred)

        for secret in (intel.get("secrets") or []):
            state.loot_store.append({"type": "secret", **secret})

        risk = intel.get("risk_level", "none")
        if risk in ("critical", "high"):
            state.findings.append(VulnFinding(
                name=f"信息泄露 - {entry['path']}",
                severity=risk,
                target=f"{base_url}{entry['path']}",
                port=wp.port,
                description=intel.get("summary", ""),
                evidence=entry["body"][:300],
                exploitable=True,
                tool="intel_harvest",
            ))

        for np in (intel.get("new_paths") or []):
            if np:
                if np not in state.web_paths:
                    state.web_paths.append(np)
                if np not in state.intel_discovered_paths:
                    state.intel_discovered_paths.append(np)

        # Reflect LLM analysis conclusions back into inventory hints
        _update_inventory_hints_from_intel(state, entry["path"], intel)

    # ── Step D + E (Pipeline B): verify params & inject findings ──
    for entry, audit in zip(page_entries, page_results):
        if isinstance(audit, Exception) or audit is None:
            continue

        page_url = f"{base_url}{entry['path']}"

        for hp in (audit.get("hidden_paths") or []):
            if hp:
                if hp not in state.web_paths:
                    state.web_paths.append(hp)
                if hp not in state.intel_discovered_paths:
                    state.intel_discovered_paths.append(hp)

        for leak in (audit.get("leaked_info") or []):
            state.loot_store.append({"source": entry["path"], **leak})

        for param in (audit.get("injectable_params") or []):
            param_url = param.get("url", "")
            if not param_url:
                continue

            # Step D: auto-verify high/medium confidence params
            verified = False
            verify_evidence = ""
            vtype = param.get("vuln_type", "unknown")
            conf = param.get("confidence", "low")

            if conf != "low":
                verify_cmd = None
                if vtype == "lfi":
                    verify_cmd = (
                        f'for d in 3 5 7; do '
                        f'TRAV=$(printf "../%.0s" $(seq 1 $d)); '
                        f'RESP=$(curl -sS --max-time 5 "{param_url}${{TRAV}}etc/passwd"); '
                        f'echo "DEPTH=$d"; echo "$RESP" | head -5; '
                        f'echo "---"; done'
                    )
                elif vtype == "sqli":
                    verify_cmd = f"curl -sS --max-time 5 \"{param_url}' OR '1'='1\""
                elif vtype == "ssti":
                    verify_cmd = f'curl -sS --max-time 5 "{param_url}{{{{7*7}}}}"'
                elif vtype == "cmdi":
                    verify_cmd = f'curl -sS --max-time 5 "{param_url}|id"'

                if verify_cmd:
                    try:
                        vr = await executor.run_script(
                            script_content=verify_cmd,
                            timeout=20,
                            log_callback=_on_tool_log,
                            record_callback=_on_exec_record,
                            record_phase="intel_harvest",
                            record_purpose=f"verify_{vtype}",
                        )
                        verify_evidence = (vr.stdout or "")[:500]
                        verified = _check_verify_result(vr.stdout or "", vtype)
                    except Exception as exc:
                        logger.debug(f"[IntelHarvest] verify failed for {param_url}: {exc}")

            param_record = {
                "url": param_url,
                "param_name": param.get("param_name", ""),
                "method": param.get("method", "GET"),
                "vuln_type": vtype,
                "confidence": conf,
                "source": param.get("source", ""),
                "evidence": param.get("evidence", ""),
                "verified": verified,
                "verify_evidence": verify_evidence,
            }
            state.page_params.append(param_record)

            if verified:
                vuln_label = _VULN_TYPE_NAMES.get(vtype, vtype.upper())
                state.findings.append(VulnFinding(
                    name=f"{vuln_label} - {param.get('param_name', '')}",
                    severity="high",
                    target=param_url,
                    port=wp.port,
                    description=f"页面 {page_url} 的 {param.get('param_name', '')} 参数存在{vuln_label}",
                    evidence=verify_evidence[:500],
                    exploitable=True,
                    tool="intel_harvest",
                ))
                state.log(f"情报采集: 已验证 {vuln_label} @ {param_url}")

    # Summary
    verified_count = sum(1 for p in state.page_params if p.get("verified"))
    state.log(
        f"情报采集完成: "
        f"文件情报 {len(state.intel_files)} 份, "
        f"发现参数 {len(state.page_params)} 个 "
        f"(已验证 {verified_count})"
    )
    state.push_decision({
        "action": "thought",
        "phase": "intel_harvest",
        "thinking": (
            f"情报采集完成: 分析了 {len(file_entries)} 个文件和 {len(page_entries)} 个页面. "
            f"提取文件情报 {len(state.intel_files)} 份, "
            f"发现注入参数 {len(state.page_params)} 个, "
            f"其中已验证 {verified_count} 个."
        ),
        "purpose": "情报采集总结",
        "message": (
            f"情报采集: {len(state.intel_files)} 文件情报, "
            f"{len(state.page_params)} 参数 ({verified_count} 已验证)"
        ),
    })
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

        # Emit exploit decision thought event
        analysis = decision_data.get("analysis", "")
        targets_info = decision_data.get("targets", [])
        plan_steps = []
        for t in targets_info[:6]:
            vuln_id = t.get("vuln_id", "?")
            reason = t.get("reason", "")
            should = t.get("should_exploit", True)
            plan_steps.append(
                f"{'[利用]' if should else '[跳过]'} {vuln_id}: {reason[:80]}"
            )
        state.push_decision({
            "action": "thought",
            "phase": "exploit_decision",
            "thinking": analysis or f"LLM 分析 {len(exploitable)} 个漏洞，保留 {remaining} 个可利用",
            "purpose": "利用优先级决策",
            "plan": plan_steps,
            "message": f"LLM 决策: {remaining}/{len(exploitable)} 个漏洞将被利用",
        })
    except Exception as e:
        state.log(f"LLM 决策异常（保留原始可利用标记）: {e}")
    return state


async def node_human_approval(state: PentestState) -> PentestState:
    """
    人工审批节点。

    - 当 state.auto_approve=True(例如 CTF 模式/用户显式勾选"自动通过")时,
      节点会直接把 approved 置为 True 并跳过人工等待。实际跳过发生在
      `build_graph` 的 `interrupt_before` 动态判定里,本节点只负责记录日志与
      推进状态。
    - 否则保持原行为:LangGraph 在本节点前中断,前端 /approve 设置 approved
      后再恢复执行。
    """
    state.current_phase = "awaiting_approval"
    _record_chain_visit(state, "awaiting_approval")
    exploitable = [f for f in state.findings if f.exploitable]

    if state.auto_approve and not state.approved:
        state.approved = True
        state.log(f"✅ auto_approve 生效,跳过人工审批({len(exploitable)} 个待利用漏洞)")
    elif not state.approved:
        state.log(f"⏸ 收到审批请求:{len(exploitable)} 个漏洞待利用")

    if state.approved:
        state.log("✅ 已获授权,继续利用阶段")
    else:
        state.log("⚠ 未获授权,跳过利用阶段")
        for f in state.findings:
            f.exploitable = False
    return state


async def node_foothold_attempt(state: PentestState) -> PentestState:
    from backend.agents.exploit_agent import ExploitAgent
    state.current_phase = "foothold_attempt"
    _record_chain_visit(state, "foothold_attempt")
    exploitable = [f for f in state.findings if f.exploitable]
    _normalize_and_dedupe_state_facts(state, source_node="foothold_attempt_pre")

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

    # Pre-sweep: synthesize service-level findings for open ports without
    # matching vulns, so ExploitAgent can match port-based Skills
    existing_ports = {f.port for f in state.findings if f.port}
    for p in state.open_ports:
        if p.port in existing_ports:
            continue
        if p.service and p.service.lower() not in ("unknown", "tcpwrapped"):
            synthetic = VulnFinding(
                name=f"{p.service.upper()} Service",
                severity="low",
                port=p.port,
                target=f"{state.target_host or state.target}:{p.port}",
                description=f"Service: {p.service} {p.version}",
                evidence=f"nmap: {p.port}/{p.protocol} {p.service} {p.version}",
                exploitable=True,
                tool="service-sweep",
            )
            state.findings.append(synthetic)
            existing_ports.add(p.port)

    exploitable = [f for f in state.findings if f.exploitable]
    state.log(f"攻链: 立足点尝试 — 利用 {len(exploitable)} 个漏洞条目（含服务级 finding）")
    try:
        agent = ExploitAgent()
        exploit_context = _build_exploit_context(state)
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="foothold_attempt")
        async def _on_decision(event: dict):
            if (event or {}).get("action") == "guard_block":
                code = (event or {}).get("guard_code") or "unknown"
                key = f"guard_block:{code}"
                state.guard_stats[key] = int(state.guard_stats.get(key, 0)) + 1
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
            fact_sink=_make_fact_sink(state),
        )
        state.exploit_results = results
        successes = [r for r in results if r.success]
        rce_successes = [r for r in successes if r.exploit_level in ("rce", "")]
        state.got_shell = len(rce_successes) > 0
        if state.got_shell:
            si = rce_successes[0].session_info or {}
            state.privilege_level = si.get("privilege") or (
                "root" if "root" in str(si.get("current_user", "")).lower() else "user"
            )
            state.log(f"成功获取 shell，权限: {state.privilege_level}")
            state.secondary_elided = True
        else:
            file_reads = [r for r in successes if r.exploit_level == "file_read"]
            if file_reads:
                state.log(
                    f"LFI 文件读取已确认 ({len(file_reads)} 条), "
                    f"但未获得 RCE，继续深入利用"
                )
                state.foothold_status = "file_read"
            else:
                state.log("所有利用尝试均未成功")
        _sync_foothold_state(state)
        _normalize_and_dedupe_state_facts(state, source_node="foothold_attempt_post")
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
    _normalize_and_dedupe_state_facts(state, source_node="secondary_attack_pre")

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
        if state.foothold_status == "file_read":
            exploit_context["lfi_escalation"] = True
            exploit_context["lfi_hint"] = (
                "前序利用已通过 LFI 确认文件读取能力，但未获得 RCE。"
                "请集中尝试: PHP Wrappers → 日志注入 → 已读取凭据的复用"
            )
            file_read_results = [
                r for r in state.exploit_results
                if r.success and r.exploit_level == "file_read"
            ]
            if file_read_results:
                exploit_context["prior_file_reads"] = file_read_results[0].evidence[:2000]
        async def _on_tool_log(line: str):
            state.log(line)
        async def _on_exec_record(record: dict):
            _append_tool_record(state, record, default_phase="secondary_attack")
        async def _on_decision(event: dict):
            if (event or {}).get("action") == "guard_block":
                code = (event or {}).get("guard_code") or "unknown"
                key = f"guard_block:{code}"
                state.guard_stats[key] = int(state.guard_stats.get(key, 0)) + 1
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
            fact_sink=_make_fact_sink(state),
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
        rce_successes = [r for r in successes if r.exploit_level in ("rce", "")]
        state.got_shell = len(rce_successes) > 0
        if state.got_shell:
            si = rce_successes[0].session_info or {}
            state.privilege_level = si.get("privilege") or (
                "root" if "root" in str(si.get("current_user", "")).lower() else "user"
            )
            state.log(f"二次攻击后成功获取 shell，权限: {state.privilege_level}")
        else:
            file_reads = [r for r in successes if r.exploit_level == "file_read"]
            if file_reads:
                state.log("二次攻击: LFI 文件读取确认，但仍未获得 RCE")
            else:
                state.log("二次攻击仍未成功")
        _sync_foothold_state(state)
        _normalize_and_dedupe_state_facts(state, source_node="secondary_attack_post")
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
    """
    决策阶段结束后的路由:
      - 任务已失败 → report
      - 无可利用 finding → report
      - 有可利用 finding 且 auto_approve=True → 直接进入 foothold_attempt,
        不经过 human_approval interrupt(避免 LangGraph 暂停等待)
      - 其余情况 → human_approval(会在 interrupt_before 处暂停)
    """
    if state.status == TaskStatus.FAILED:
        return "report"
    if not any(f.exploitable for f in state.findings):
        return "report"
    if state.auto_approve:
        return "foothold_attempt"
    return "human_approval"


def edge_after_approval(state: PentestState) -> str:
    if state.status == TaskStatus.FAILED:
        return "report"
    return "foothold_attempt" if any(f.exploitable for f in state.findings) else "report"


def edge_after_foothold(state: PentestState) -> str:
    if state.status == TaskStatus.FAILED:
        return "report"
    if state.got_shell:
        return "post_foothold_enum"
    # File-read foothold: escalate LFI → RCE via secondary attack
    if state.foothold_status == "file_read":
        if not state.secondary_attack_done:
            return "secondary_attack"
        return "report"
    if not state.secondary_attack_done and any(f.exploitable for f in state.findings):
        return "secondary_attack"
    return "report"


def edge_after_secondary(state: PentestState) -> str:
    if state.status == TaskStatus.FAILED:
        return "report"
    return "post_foothold_enum" if state.got_shell else "report"


def edge_after_privesc(state: PentestState) -> str:
    if state.status == TaskStatus.FAILED:
        return "objective_collect"
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
    graph.add_node("intel_harvest",       node_intel_harvest)
    graph.add_node("exploit_decision",    node_exploit_decision)
    graph.add_node("human_approval",      node_human_approval)
    graph.add_node("foothold_attempt",    node_foothold_attempt)
    graph.add_node("secondary_attack",    node_secondary_attack)
    graph.add_node("post_foothold_enum",  node_post_foothold_enum)
    graph.add_node("privesc_attempt",     node_privesc_attempt)
    graph.add_node("objective_collect",   node_objective_collect)
    graph.add_node("report",              node_report)

    graph.add_edge(START, "recon")
    graph.add_edge("recon", "surface_enum")
    graph.add_edge("surface_enum", "intel_harvest")
    graph.add_edge("intel_harvest", "vuln_scan")
    graph.add_edge("vuln_scan", "exploit_decision")
    graph.add_conditional_edges(
        "exploit_decision", edge_should_exploit,
        {
            "human_approval": "human_approval",
            "foothold_attempt": "foothold_attempt",  # auto_approve 直通
            "report": "report",
        },
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
        self._graph_lock = asyncio.Lock()

    async def _ensure_graph(self):
        if self._graph is not None:
            return
        async with self._graph_lock:
            if self._graph is None:
                checkpointer = MemorySaver()
                self._graph = build_graph(checkpointer=checkpointer)

    def _prepare_state(self, initial_state: PentestState) -> PentestState:
        """
        对 Router 已构造好的 initial_state 做最后一次统一预处理:
          - 确保 task_id 存在
          - 解析 target 结构化信息
          - 记录启动日志,回显 workflow_mode 与关键策略字段
        不再读取任何 OPERATOR_ROLE/SUCCESS_GATE/RISK_BUDGET 环境变量。
        """
        if not initial_state.task_id:
            initial_state.task_id = str(uuid.uuid4())
        _apply_parsed_target(initial_state)
        initial_state.log(
            f"workflow_mode={initial_state.workflow_mode}, "
            f"auto_approve={initial_state.auto_approve}, "
            f"gate={initial_state.success_gate_level}, "
            f"risk_budget={initial_state.risk_budget}, "
            f"react_rounds={initial_state.max_react_rounds}, "
            f"explore_rounds={initial_state.max_explore_rounds}"
        )
        return initial_state

    async def run(self, initial_state: PentestState) -> PentestState:
        await self._ensure_graph()
        initial_state = self._prepare_state(initial_state)
        config = {"configurable": {"thread_id": initial_state.task_id}}
        initial_state.log(f"任务启动,目标: {initial_state.target}")
        try:
            final_state: PentestState = await asyncio.wait_for(
                self._graph.ainvoke(initial_state, config=config),
                timeout=TASK_TIMEOUT,
            )
        except asyncio.TimeoutError:
            initial_state.status = TaskStatus.FAILED
            initial_state.error_msg = f"任务超时(>{TASK_TIMEOUT}s)"
            initial_state.log(initial_state.error_msg)
            try:
                from backend.tools.executor import TaskContainerManager
                await TaskContainerManager.stop(initial_state.task_id)
                initial_state.log("超时后容器已清理")
            except Exception:
                pass
            return initial_state
        return final_state

    async def run_stream(self, initial_state: PentestState):
        await self._ensure_graph()
        initial_state = self._prepare_state(initial_state)
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
    from backend.llm.prompts.templates import EXPLOIT_DECISION
    findings_json = json.dumps(
        [f.model_dump() for f in state.findings if f.exploitable],
        ensure_ascii=False, indent=2,
    )
    ports_json = json.dumps(
        [p.model_dump() for p in state.open_ports[:20]],
        ensure_ascii=False,
    )
    dir_intel = state.dir_intel or _build_dir_intel(state)
    dir_intel_json = json.dumps(dir_intel, ensure_ascii=False, indent=2)
    base_prompt = EXPLOIT_DECISION.format(
        target=state.target,
        target_os=state.target_os,
        ports_json=ports_json,
        findings_json=findings_json,
        dir_intel_json=dir_intel_json,
    )
    extras: list[str] = []
    if state.workflow_mode and state.workflow_mode != "standard":
        extras.append(f"任务模式: {state.workflow_mode}")
    if state.extra_hint:
        extras.append(f"用户附加提示: {state.extra_hint}")
    if state.user_prompt:
        extras.append(f"用户偏好: {state.user_prompt}")
    op_chat = _operator_chat_block(state)
    if op_chat:
        extras.append(op_chat)
    if extras:
        base_prompt += "\n\n【补充上下文】\n" + "\n".join(extras)
    return base_prompt