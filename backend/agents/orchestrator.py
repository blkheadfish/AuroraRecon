"""
orchestrator.py  ── 改进版
主要改进：
  1. MemorySaver checkpointer   → 内置无需额外依赖，进程内断点续跑
  2. @retry_node 装饰器         → 工具调用失败自动重试（最多3次）
  3. human_approval 节点        → 利用前强制人工确认（竞赛演示亮点）
  4. interrupt_before=["exploit"] → LangGraph 原生中断机制
  5. task_id 透传               → 所有 agent.run() 都传入 task_id

流程：
  START → recon → vuln_scan → exploit_decision
        → human_approval（interrupt_before 暂停等待审批）
        → exploit → post_exploit → report → END
                 ↓（无可利用漏洞）
               report → END
"""
from __future__ import annotations

import asyncio
import functools
import json
import logging
import uuid
from typing import Optional

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from backend.agents.models import ExploitResult, PentestState, PortInfo, TaskStatus, VulnFinding

logger = logging.getLogger(__name__)


# ───────────────────────────────────────────────────────────
# retry 装饰器
# ───────────────────────────────────────────────────────────

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


# ───────────────────────────────────────────────────────────
# 节点函数
# ───────────────────────────────────────────────────────────

@retry_node(max_attempts=3, delay=2.0)
async def node_recon(state: PentestState) -> PentestState:
    from backend.agents.recon_agent import ReconAgent
    from backend.tools.executor import ToolExecutor
    state.current_phase = "recon"
    state.status = TaskStatus.RUNNING

    # 为本次任务启动专属工具容器（多人并发时每个 task 独立隔离）
    try:
        _exec = ToolExecutor()
        await _exec.start_task_container(state.task_id)
        state.log(f"工具容器已就绪: pentest_task_{state.task_id[:12]}")
    except Exception as _ce:
        # 容器启动失败不阻断流程，降级为 docker run --rm 模式
        state.log(f"⚠ 工具容器启动失败，降级为临时容器模式: {_ce}")

    state.log(f"开始侦察目标: {state.target}")
    agent = ReconAgent()
    result = await agent.run(state.target, task_id=state.task_id)
    state.open_ports = result.get("ports", [])
    state.os_info = result.get("os_info", {})
    state.web_paths = result.get("web_paths", [])
    state.subdomains = result.get("subdomains", [])
    state.raw_recon = result
    state.target_os = _infer_os(state.open_ports, state.os_info)
    state.log(f"侦察完成: {len(state.open_ports)} 端口, OS={state.target_os}")
    return state


@retry_node(max_attempts=2, delay=3.0)
async def node_vuln_scan(state: PentestState) -> PentestState:
    from backend.agents.vuln_agent import VulnAgent
    state.current_phase = "vuln_scan"
    state.log("开始漏洞扫描...")
    agent = VulnAgent()
    result = await agent.run(
        target=state.target,
        ports=state.open_ports,
        web_paths=state.web_paths,
        target_os=state.target_os,
        task_id=state.task_id,
    )
    state.findings = result.get("findings", [])
    state.raw_vuln = result
    exploitable = [f for f in state.findings if f.exploitable]
    state.log(f"漏洞扫描完成: {len(state.findings)} 发现, {len(exploitable)} 可利用")
    return state


async def node_exploit_decision(state: PentestState) -> PentestState:
    from backend.llm.router import LLMRouter
    state.current_phase = "exploit_decision"
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
                    finding.exploitable = False

        state.log("LLM 决策完成")
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


async def node_exploit(state: PentestState) -> PentestState:
    from backend.agents.exploit_agent import ExploitAgent
    state.current_phase = "exploit"
    exploitable = [f for f in state.findings if f.exploitable]
    state.log(f"开始利用 {len(exploitable)} 个漏洞...")
    try:
        agent = ExploitAgent()
        exploit_context = {
            "ports_summary": ", ".join(
                f"{p.port}/{p.service}({p.version[:30]})" for p in state.open_ports[:20]
            ),
            "web_paths": ", ".join(state.web_paths[:20]) if state.web_paths else "无",
            "fingerprint": state.raw_recon.get("raw_nmap", "")[:500],
        }
        results = await agent.run(
            target=state.target,
            findings=exploitable,
            target_os=state.target_os,
            context=exploit_context,
            task_id=state.task_id,
        )
        state.exploit_results = results
        successes = [r for r in results if r.success]
        state.got_shell = len(successes) > 0
        if state.got_shell:
            state.privilege_level = successes[0].session_info.get("privilege", "user")
            state.log(f"成功获取 shell，权限: {state.privilege_level}")
        else:
            state.log("所有利用尝试均未成功")
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"利用阶段异常: {e}")
    return state


async def node_post_exploit(state: PentestState) -> PentestState:
    from backend.agents.post_agent import PostExploitAgent
    state.current_phase = "post_exploit"
    state.log("开始后渗透操作...")
    try:
        agent = PostExploitAgent()
        result = await agent.run(
            exploit_results=state.exploit_results,
            target_os=state.target_os,
            task_id=state.task_id,
        )
        state.post_findings = result
        state.privilege_level = result.get("final_privilege", state.privilege_level)
        state.log(f"后渗透完成，最终权限: {state.privilege_level}")
    except Exception as e:
        state.error_msg = str(e)
        state.log(f"后渗透阶段异常: {e}")
    return state


async def node_report(state: PentestState) -> PentestState:
    from backend.report.generator import ReportGenerator
    state.current_phase = "report"
    state.log("开始生成报告...")
    try:
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


# ───────────────────────────────────────────────────────────
# 条件边
# ───────────────────────────────────────────────────────────

def edge_should_exploit(state: PentestState) -> str:
    return "human_approval" if any(f.exploitable for f in state.findings) else "report"


def edge_after_approval(state: PentestState) -> str:
    return "exploit" if any(f.exploitable for f in state.findings) else "report"


def edge_should_post(state: PentestState) -> str:
    return "post_exploit" if state.got_shell else "report"


# ───────────────────────────────────────────────────────────
# 构建图
# ───────────────────────────────────────────────────────────

def build_graph(checkpointer=None):
    graph = StateGraph(PentestState)

    graph.add_node("recon",            node_recon)
    graph.add_node("vuln_scan",        node_vuln_scan)
    graph.add_node("exploit_decision", node_exploit_decision)
    graph.add_node("human_approval",   node_human_approval)
    graph.add_node("exploit",          node_exploit)
    graph.add_node("post_exploit",     node_post_exploit)
    graph.add_node("report",           node_report)

    graph.add_edge(START, "recon")
    graph.add_edge("recon", "vuln_scan")
    graph.add_edge("vuln_scan", "exploit_decision")
    graph.add_conditional_edges(
        "exploit_decision", edge_should_exploit,
        {"human_approval": "human_approval", "report": "report"},
    )
    graph.add_conditional_edges(
        "human_approval", edge_after_approval,
        {"exploit": "exploit", "report": "report"},
    )
    graph.add_conditional_edges(
        "exploit", edge_should_post,
        {"post_exploit": "post_exploit", "report": "report"},
    )
    graph.add_edge("post_exploit", "report")
    graph.add_edge("report", END)

    return graph.compile(
        checkpointer=checkpointer,
        # 在 human_approval 节点前中断，等待前端调用 /approve 后 resume
        interrupt_before=["human_approval"],
    )


# ───────────────────────────────────────────────────────────
# Orchestrator 对外接口
# ───────────────────────────────────────────────────────────

class Orchestrator:
    def __init__(self):
        self._graph = None

    async def _ensure_graph(self):
        if self._graph is None:
            # MemorySaver 内置于 langgraph，无需额外依赖
            # 进程内断点续跑完全正常，重启后状态清空
            checkpointer = MemorySaver()
            self._graph = build_graph(checkpointer=checkpointer)

    async def run(
        self,
        target: str,
        scope_note: str = "CTF/授权靶场测试",
        task_id: Optional[str] = None,
    ) -> PentestState:
        await self._ensure_graph()
        initial_state = PentestState(
            target=target,
            scope_note=scope_note,
            task_id=task_id or str(uuid.uuid4()),
        )
        config = {"configurable": {"thread_id": initial_state.task_id}}
        initial_state.log(f"任务启动，目标: {target}")
        final_state: PentestState = await self._graph.ainvoke(initial_state, config=config)
        return final_state

    async def run_stream(
        self,
        target: str,
        scope_note: str = "CTF/授权靶场测试",
        task_id: Optional[str] = None,
    ):
        await self._ensure_graph()
        task_id = task_id or str(uuid.uuid4())
        initial_state = PentestState(target=target, scope_note=scope_note, task_id=task_id)
        config = {"configurable": {"thread_id": task_id}}

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


# ───────────────────────────────────────────────────────────
# 辅助函数
# ───────────────────────────────────────────────────────────

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
    return f"""你是一名资深渗透测试工程师，正在合法授权的 CTF 靶场中进行安全测试。

目标信息:
- 地址: {state.target}
- 操作系统: {state.target_os}
- 开放端口: {ports_json}

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