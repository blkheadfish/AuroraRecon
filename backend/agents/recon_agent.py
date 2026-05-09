"""
recon_agent.py
侦察 Agent —— 端口扫描 / 服务识别 / 目录爆破 / 子域名枚举

改进：
  - target 参数现在是纯 host/IP（由 orchestrator 统一解析）
  - 新增 target_port 参数，用户显式指定端口时优先扫描该端口
  - 目录发现使用 ToolCoveragePlanner 驱动多工具链
"""
from __future__ import annotations

import asyncio
import ipaddress as _ipaddress
import json
import logging
import os
import re
import shlex
import time
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

from backend.agents.models import PortInfo
from backend.tools.executor import ToolExecutor, ExecuteResult, LogCallback, RecordCallback
from backend.tools.parsers.nmap_parser import NmapParser
from backend.tools.parsers.path_aggregator import PathAggregator
from backend.tools.tool_coverage_planner import ToolCoveragePlanner, CoverageReport

logger = logging.getLogger(__name__)


def _preview_path_list(paths: list[str], limit: int = 24) -> str:
	if not paths:
		return "(无)"
	head = paths[:limit]
	s = ", ".join(head)
	if len(paths) > limit:
		s += f" …(共 {len(paths)} 条)"
	return s


def _normalize_deep_scan_root(scan_sub: str) -> str:
	"""Normalize LLM-provided base path for prefix matching."""
	r = (scan_sub or "/").strip()
	if not r:
		r = "/"
	if not r.startswith("/"):
		r = "/" + r
	return r.rstrip("/") or "/"


def _paths_under_deep_root(scan_root: str, paths: list[str]) -> list[str]:
	"""Keep paths that live under scan_root (same path or descendant)."""
	root = _normalize_deep_scan_root(scan_root)
	out: list[str] = []
	for p in paths:
		pn = p if p.startswith("/") else "/" + p
		if root == "/":
			out.append(pn)
		elif pn == root or pn.startswith(root + "/"):
			out.append(pn)
	return sorted(set(out))


def _ferox_stdout_sample(stdout: str, max_lines: int = 22, max_chars: int = 3200) -> str:
	"""Short, readable sample of feroxbuster lines for logs."""
	lines = [ln.rstrip() for ln in (stdout or "").splitlines() if ln.strip()]
	if not lines:
		return "(ferox 无有效输出行)"
	buf: list[str] = []
	n = 0
	for ln in lines:
		if n >= max_lines:
			buf.append(f"…(另有 {len(lines) - max_lines} 行未展示)")
			break
		buf.append(ln[:220])
		n += 1
	text = "\n".join(buf)
	if len(text) > max_chars:
		text = text[:max_chars] + "…"
	return text


class ReconAgent:
	def __init__(self):
		self.executor = ToolExecutor()
		self.nmap_parser = NmapParser()
		self._operator_block: str = ""
		self._operator_plan: Any = None

	async def run(
		self,
		target: str,
		target_port: Optional[int] = None,
		task_id: Optional[str] = None,
		log_callback: LogCallback = None,
		record_callback: RecordCallback = None,
		decision_callback: Optional[Callable] = None,
		operator_block: str = "",
		operator_plan: Any = None,
		plan_tools: list[str] | None = None,
	) -> dict[str, Any]:
		"""
		执行侦察。

		Args:
		    target:      纯 host 或 IP（不含端口/协议，由 orchestrator 解析后传入）
		    target_port: 用户显式指定的端口（可选）。
		                 如果指定，会加入常用端口列表一起扫描，
		                 确保该端口一定被覆盖。
		    task_id:     任务 ID
		    log_callback: 日志回调
		    decision_callback: 实时决策事件回调（tool_start / tool_result / thought）
		    operator_block: 操作员指令块(由 node_recon 从 state 提取), 注入到所有
		                    LLM prompt 两端 — 不让 LLM 决策只看到"默认行为", 而是
		                    看到用户实时输入的方向(例如"看看80端口下有什么目录")。
		    operator_plan:  ``operator_replanner`` 产出的 ``OperatorPlan`` 结构化
		                    战术计划; 内部 ``_dir_scan`` 会把它透传给
		                    ``ToolCoveragePlanner.build_plan``, 让 ``preferred_tools``
		                    / ``avoided_tools`` / ``keyword_hints`` 直接影响目录爆破
		                    的工具序列与字典生成 (例如用户说要 gobuster 时, 让
		                    gobuster 真的被排到第一位且 must_run)。
		"""
		self._decision_callback = decision_callback
		self._operator_block = operator_block or ""
		self._operator_plan = operator_plan

		_DIR_SCAN_TOOLS = {"gobuster", "dirsearch", "feroxbuster", "ffuf", "dir-discovery", "dirb"}
		_run_dir_scan = not plan_tools or bool(set(plan_tools) & _DIR_SCAN_TOOLS)
		_run_nmap_vuln = not plan_tools or "nmap" in plan_tools
		_run_subdomain = not plan_tools or any(t in plan_tools for t in ("subfinder", "amass", "subdomain"))
		_fast_scan = plan_tools is not None and not _run_dir_scan
		_plan_steps = getattr(self, "_plan_steps", None) or []
		if plan_tools:
			logger.info(f"[ReconAgent] plan_tools={plan_tools}, dir_scan={_run_dir_scan}, "
			            f"nmap_vuln={_run_nmap_vuln}, subdomain={_run_subdomain}, fast={_fast_scan}")

		async def _tool_stream_cb(line: str) -> None:
			"""Forward tool stdout/stderr lines as tool_stream decision events."""
			if decision_callback:
				import uuid as _uuid
				await decision_callback({
					"action": "tool_stream",
					"phase": "recon",
					"stream_id": f"recon-{_uuid.uuid4().hex[:8]}",
					"line": line,
				})

		if log_callback or record_callback or decision_callback:
			origin_run = self.executor.run
			origin_run_script = self.executor.run_script

			async def _run_with_hooks(*args, **kwargs):
				if log_callback:
					kwargs.setdefault("log_callback", log_callback)
				if record_callback:
					kwargs.setdefault("record_callback", record_callback)
					kwargs.setdefault("record_phase", "recon")
				if decision_callback:
					kwargs.setdefault("stream_callback", _tool_stream_cb)
				return await origin_run(*args, **kwargs)

			async def _run_script_with_hooks(*args, **kwargs):
				if log_callback:
					kwargs.setdefault("log_callback", log_callback)
				if record_callback:
					kwargs.setdefault("record_callback", record_callback)
					kwargs.setdefault("record_phase", "recon")
				if decision_callback:
					kwargs.setdefault("stream_callback", _tool_stream_cb)
				return await origin_run_script(*args, **kwargs)

			self.executor.run = _run_with_hooks
			self.executor.run_script = _run_script_with_hooks

		logger.info(f"[ReconAgent] 开始侦察: {target}" +
		            (f" (用户指定端口: {target_port})" if target_port else ""))

		if decision_callback:
			await decision_callback({
				"action": "tool_start",
				"phase": "recon",
				"tool": "nmap",
				"message": f"开始 Nmap 端口扫描: {target}",
			})

		ports, os_info, raw_nmap = await self._nmap_scan(
			target, target_port, task_id, log_callback,
			fast=_fast_scan,
		)

		if decision_callback:
			ports_summary = ", ".join(f"{p.port}/{p.service}" for p in ports[:15])
			await decision_callback({
				"action": "tool_result",
				"phase": "recon",
				"tool": "nmap",
				"message": f"Nmap 扫描完成: 发现 {len(ports)} 个开放端口 ({ports_summary})",
			})

		nmap_vuln_hints: list = []
		llm_recon_hints: dict = {}
		if _run_nmap_vuln:
			if decision_callback:
				await decision_callback({
					"action": "tool_start",
					"phase": "recon",
					"tool": "nmap-vuln-scripts",
					"message": f"Nmap 漏洞脚本扫描: {len(ports)} 个端口",
				})

			nmap_vuln_hints = await self._nmap_vuln_scan(
				target, [p.port for p in ports], task_id, log_callback,
				ports_info=ports,
			)

			if decision_callback:
				await decision_callback({
					"action": "tool_result",
					"phase": "recon",
					"tool": "nmap-vuln-scripts",
					"message": f"Nmap 漏洞脚本完成: {len(nmap_vuln_hints)} 条线索",
				})

			llm_recon_hints = await self._llm_analyze_nmap(
				target, raw_nmap, ports, log_callback,
			)
		elif plan_tools and log_callback:
			await log_callback(f"[ReconAgent] [Plan] 跳过 nmap 漏洞脚本/LLM 分析 (plan_tools={plan_tools})")

		web_ports = [
			p for p in ports
			if _fast_scan
			or p.service in ("http", "https")
			or p.port in (80, 443, 8080, 8443, 8888, 8090, 9080, 9443, 7001, 8009)
		]

		if target_port:
			existing_port_nums = {p.port for p in web_ports}
			if target_port not in existing_port_nums:
				for p in ports:
					if p.port == target_port:
						web_ports.append(p)
						break

		web_paths: list[str] = []
		path_contents: list[dict[str, Any]] = []
		raw_gobuster = ""
		dir_coverage: dict = {}

		scan_strategy: dict = {}
		tech_hints: list[str] = []
		if web_ports:
			primary_scheme = "https" if web_ports[0].port in (443, 8443) else "http"
			primary_target = f"{primary_scheme}://{target}:{web_ports[0].port}"

			tech_hints = await self._quick_fingerprint(
				target, web_ports, task_id, log_callback,
			)

			if _run_dir_scan:
				if decision_callback:
					await decision_callback({
						"action": "tool_start",
						"phase": "recon",
						"tool": "dir-discovery",
						"message": f"开始目录发现: {len(web_ports)} 个 Web 端口",
					})

				has_waf = await self._detect_waf(
					primary_target, task_id, log_callback,
				)

				scan_strategy = await self._llm_plan_dir_strategy(
					primary_target, tech_hints, ports, has_waf, log_callback,
				)

				aggregator = PathAggregator()
				raw_outputs_all: list[str] = []
				coverage_reports: list[dict] = []

				from backend.tools.deep_scan_coordinator import DeepScanCoordinator
				deep_coord = DeepScanCoordinator(
					max_total_scans=30,
					budget_seconds=900.0,
				)

				for wp in web_ports[:4]:
					scheme = "https" if wp.port in (443, 8443) else "http"
					web_target = f"{scheme}://{target}:{wp.port}"
					if log_callback:
						await log_callback(
							f"[ReconAgent] 目录发现: 扫描 Web 端口 {wp.port} ({scheme})"
						)
					_, raw_out, coverage_rpt, port_aggregator = await self._dir_scan(
						web_target, task_id, log_callback,
						has_waf=has_waf, tech_hints=tech_hints,
						scan_strategy=scan_strategy,
						record_callback=record_callback,
						deep_coord=deep_coord,
					)
					raw_outputs_all.append(raw_out)
					coverage_reports.append(coverage_rpt.to_log_dict())
					for p_entry in port_aggregator._entries.values():
						if p_entry.path in aggregator._entries:
							aggregator._entries[p_entry.path].merge(p_entry)
						else:
							aggregator._entries[p_entry.path] = p_entry

				await self._llm_deep_dive(
					primary_target, tech_hints, aggregator,
					task_id, log_callback, record_callback,
					scan_strategy=scan_strategy,
					deep_coord=deep_coord,
				)

				await self._drain_deep_scan_queue(
					base_url=primary_target,
					aggregator=aggregator,
					coord=deep_coord,
					task_id=task_id,
					log_callback=log_callback,
					record_callback=record_callback,
				)

				path_contents = await self._probe_path_contents(
					web_target=primary_target,
					aggregator=aggregator,
					task_id=task_id,
					log_callback=log_callback,
				)
				web_paths = aggregator.get_actionable_paths()
				raw_gobuster = "\n".join(raw_outputs_all)
				dir_coverage = coverage_reports[0] if coverage_reports else {}

				if decision_callback:
					await decision_callback({
						"action": "tool_result",
						"phase": "recon",
						"tool": "dir-discovery",
						"message": f"目录发现完成: {len(web_paths)} 条路径",
					})
			elif log_callback:
				await log_callback(f"[ReconAgent] [Plan] 跳过目录爆破 (plan_tools={plan_tools})")

		subdomains: list = []
		if _run_subdomain:
			subdomains = await self._subdomain_enum(
				target, task_id, log_callback,
			)
		elif plan_tools and log_callback:
			await log_callback(f"[ReconAgent] [Plan] 跳过子域名枚举 (plan_tools={plan_tools})")

		return {
			"ports": ports,
			"os_info": os_info,
			"web_paths": web_paths,
			"path_contents": path_contents,
			"subdomains": subdomains,
			"raw_nmap": raw_nmap,
			"raw_gobuster": raw_gobuster,
			"nmap_vuln_hints": nmap_vuln_hints,
			"dir_coverage": dir_coverage,
			"llm_recon_hints": llm_recon_hints,
			"scan_strategy": scan_strategy,
		}

	async def _nmap_scan(
		self,
		target: str,
		target_port: Optional[int],
		task_id: Optional[str],
		log_callback: LogCallback = None,
		fast: bool = False,
	) -> tuple[list[PortInfo], dict, str]:
		if target_port:
			logger.info(
				f"[ReconAgent] 用户已指定端口 {target_port}，"
				f"跳过端口枚举，直接 nmap -sV/-A 精细扫描"
			)
			port_str = str(target_port)
			nmap_detail_args = [
				"-sS", "-A", "-Pn",
				"--reason", "--defeat-rst-ratelimit",
				"-p", port_str, "-oX", "-", target,
			]
			detail_result: ExecuteResult = await self.executor.run(
				tool="nmap",
				args=nmap_detail_args,
				timeout=300,
				task_id=task_id,
				log_callback=log_callback,
			)
			if not detail_result.success:
				logger.warning(
					f"[ReconAgent] 指定端口 {target_port} 精细扫描失败，返回空结果"
				)
				return [], {}, detail_result.stdout or ""
			ports, os_info = self.nmap_parser.parse_xml_full(detail_result.stdout)
			return ports, os_info, detail_result.stdout

		common_ports_list = [
			21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143, 443, 445, 993, 995,
			1433, 1521, 2049, 2181, 3000, 3306, 3389, 5432, 5900, 5985, 6379,
			7001, 7002, 8000, 8008, 8080, 8081, 8090, 8161, 8443, 8888, 9000,
			9001, 9090, 9200, 9443, 10000, 27017, 61616,
		]

		if target_port and target_port not in common_ports_list:
			common_ports_list.append(target_port)

		common_ports = ",".join(str(p) for p in sorted(common_ports_list))

		precise_result: ExecuteResult = await self.executor.run(
			tool="nmap",
			args=["-sS", "-T4", "-Pn", "--open", "--reason",
			      "--defeat-rst-ratelimit", "--max-retries", "3",
			      "-p", common_ports, "-oX", "-", target],
			timeout=120,
			task_id=task_id,
			log_callback=log_callback,
		)

		precise_ports: list[int] = []
		if precise_result.success:
			precise_ports, _ = self.nmap_parser.extract_open_ports(precise_result.stdout)


		if fast and precise_ports:
			fast_ports_result = self.nmap_parser.parse_xml(precise_result.stdout)
			logger.info(f"[ReconAgent] fast scan done: {len(fast_ports_result)} open ports (common ports hit)")
			return fast_ports_result, {}, precise_result.stdout or ""
		if fast and not precise_ports:
			logger.info("[ReconAgent] fast mode but no common ports open, falling back to full scan")
		fast_result: ExecuteResult = await self.executor.run(
			tool="nmap",
			args=["-sS", "-T4", "-Pn", "--open", "--reason",
			      "--defeat-rst-ratelimit", "--max-retries", "2",
			      "--min-rate", "2000", "-p-", "-oX", "-", target],
			timeout=600,
			task_id=task_id,
			log_callback=log_callback,
		)

		fast_open: list[int] = []
		fast_filtered: list[int] = []
		if fast_result.success:
			fast_open, fast_filtered = self.nmap_parser.extract_open_ports(fast_result.stdout)

		all_ports = list(set(precise_ports + fast_open))
		if not all_ports:
			logger.warning("两轮扫描均未发现开放端口")
			return [], {}, precise_result.stdout or ""

		port_str = ",".join(str(p) for p in sorted(all_ports)[:50])
		try:
			_is_private = _ipaddress.ip_address(target).is_private
		except ValueError:
			_is_private = False
		if _is_private:
			nmap_detail_args = ["-sS", "-A", "--osscan-guess", "-Pn",
			                    "--reason", "--defeat-rst-ratelimit",
			                    "-p", port_str, "-oX", "-", target]
		else:
			nmap_detail_args = ["-sS", "-sV", "--version-all", "-sC", "-Pn",
			                    "--reason", "--defeat-rst-ratelimit",
			                    "-p", port_str, "-oX", "-", target]
		detail_result: ExecuteResult = await self.executor.run(
			tool="nmap",
			args=nmap_detail_args,
			timeout=300,
			task_id=task_id,
			log_callback=log_callback,
		)

		if not detail_result.success:
			logger.warning("Nmap 精细扫描失败，使用快速扫描结果")
			return self.nmap_parser.parse_xml(precise_result.stdout or fast_result.stdout), {}, ""

		ports, os_info = self.nmap_parser.parse_xml_full(detail_result.stdout)

		verified_filtered = await self._tcp_verify_filtered_ports(
			target, fast_filtered, task_id, log_callback
		)
		ports.extend(verified_filtered)

		return ports, os_info, detail_result.stdout

	async def _tcp_verify_filtered_ports(
		self,
		target: str,
		filtered_ports: list[int],
		task_id: Optional[str],
		log_callback: LogCallback = None,
	) -> list[PortInfo]:
		"""TCP connect 二次验证 SYN 扫描标记为 filtered 的端口。

		filtered 可能是防火墙丢包、网络拥塞、或主机离线。
		用 -sT (TCP connect) 重新探测——三次握手能完成的才是真可达端口。
		"""
		if not filtered_ports:
			return []

		verify_ports = filtered_ports[:200]
		port_str = ",".join(str(p) for p in verify_ports)

		logger.info(
			f"[ReconAgent] TCP connect 验证 {len(verify_ports)} 个 filtered 端口: "
			f"{port_str[:120]}"
		)
		if log_callback:
			await log_callback(
				f"[ReconAgent] TCP connect 二次验证 {len(verify_ports)} 个 filtered 端口..."
			)

		try:
			result: ExecuteResult = await self.executor.run(
				tool="nmap",
				args=[
					"-sT", "-T4", "-Pn", "--open", "--reason",
					"--max-retries", "2",
					"-p", port_str, "-oX", "-", target,
				],
				timeout=min(300, 30 + 3 * len(verify_ports)),
				task_id=task_id,
				log_callback=log_callback,
			)
			if result.success and result.stdout:
				open_ports, _ = self.nmap_parser.extract_open_ports(result.stdout)
				if open_ports:
					verified = self.nmap_parser.parse_xml(result.stdout)
					logger.info(
						f"[ReconAgent] TCP 验证: {len(filtered_ports)} filtered → "
						f"{len(open_ports)} 确认开放"
					)
					return verified
		except Exception as e:
			logger.warning(f"[ReconAgent] TCP 验证 filtered 端口异常: {e}")

		return []

	async def _nmap_vuln_scan(
		self,
		target: str,
		open_ports: list[int],
		task_id: Optional[str],
		log_callback: LogCallback = None,
		ports_info: list[PortInfo] | None = None,
	) -> list[dict]:
		"""4th nmap pass: targeted per-service vuln scripts instead of blanket --script=vuln."""
		if not open_ports:
			return []

		script_timeout = int(os.getenv("NMAP_SCRIPT_TIMEOUT", "30"))

		_SERVICE_SCRIPTS: dict[str, tuple[set[int], str]] = {
			"http": (
				{80, 443, 8080, 8443, 8000, 8888, 8081, 8090, 9000, 9090, 3000, 7001, 7002, 8008, 8161, 9200, 9443, 10000},
				"http-vuln*,http-enum,http-shellshock,http-sql-injection",
			),
			"smb": ({445, 139}, "smb-vuln*,smb-enum-shares,smb-os-discovery"),
			"ftp": ({21}, "ftp-anon,ftp-vsftpd-backdoor,ftp-proftpd-backdoor"),
			"ssh": ({22}, "ssh2-enum-algos,ssh-auth-methods"),
			"mysql": ({3306}, "mysql-vuln-cve2012-2122,mysql-empty-password,mysql-enum"),
			"rdp": ({3389}, "rdp-vuln-ms12-020"),
			"smtp": ({25, 587}, "smtp-vuln-cve2010-4344,smtp-open-relay"),
			"snmp": ({161}, "snmp-info,snmp-sysdescr,snmp-brute"),
			"dns": ({53}, "dns-zone-transfer,dns-brute"),
			"nfs": ({2049}, "nfs-ls,nfs-statfs,nfs-showmount"),
			"mssql": ({1433}, "ms-sql-info,ms-sql-hasdbaccess,ms-sql-empty-password"),
		}

		svc_port_map: dict[str, list[int]] = {}
		_service_lookup: dict[int, str] = {}
		if ports_info:
			_service_lookup = {p.port: (p.service or "").lower() for p in ports_info}

		remaining: list[int] = []
		for port in sorted(open_ports):
			matched = False
			svc_name = _service_lookup.get(port, "")
			for group_name, (port_set, _scripts) in _SERVICE_SCRIPTS.items():
				if port in port_set or group_name in svc_name:
					svc_port_map.setdefault(group_name, []).append(port)
					matched = True
					break
			if not matched:
				remaining.append(port)

		all_hints: list[dict] = []

		for group_name, group_ports in svc_port_map.items():
			_, scripts = _SERVICE_SCRIPTS[group_name]
			port_str = ",".join(str(p) for p in group_ports[:10])
			timeout = 60 + 10 * len(group_ports)
			if log_callback:
				await log_callback(
					f"[ReconAgent] nmap vuln ({group_name}): ports={port_str}, timeout={timeout}s"
				)
			logger.info(f"[ReconAgent] Nmap vuln ({group_name}): {port_str}")
			try:
				result: ExecuteResult = await self.executor.run(
					tool="nmap",
					args=[
						"-sT", "-Pn", "--reason", "--defeat-rst-ratelimit",
						f"--script={scripts}",
						f"--script-timeout={script_timeout}",
						"-p", port_str, "-oX", "-", target,
					],
					timeout=timeout,
					task_id=task_id,
					log_callback=log_callback,
				)
				if result.success or result.stdout:
					hints = self.nmap_parser.parse_vuln_scripts(result.stdout or "")
					all_hints.extend(hints)
				else:
					logger.warning(
						f"[ReconAgent] Nmap vuln ({group_name}) 失败: "
						f"{(result.stderr or '')[:200]}"
					)
			except Exception as e:
				logger.warning(f"[ReconAgent] Nmap vuln ({group_name}) 异常: {e}")

		if remaining:
			fallback_ports = remaining[:5]
			port_str = ",".join(str(p) for p in fallback_ports)
			timeout = 90 + 15 * len(fallback_ports)
			if log_callback:
				await log_callback(
					f"[ReconAgent] nmap vuln (other): ports={port_str}, timeout={timeout}s"
				)
			logger.info(f"[ReconAgent] Nmap vuln (other): {port_str}")
			try:
				result = await self.executor.run(
					tool="nmap",
					args=[
						"-sT", "-Pn", "--reason", "--defeat-rst-ratelimit",
						"--script=vuln",
						f"--script-timeout={script_timeout}",
						"-p", port_str, "-oX", "-", target,
					],
					timeout=timeout,
					task_id=task_id,
					log_callback=log_callback,
				)
				if result.success or result.stdout:
					hints = self.nmap_parser.parse_vuln_scripts(result.stdout or "")
					all_hints.extend(hints)
			except Exception as e:
				logger.warning(f"[ReconAgent] Nmap vuln (other) 异常: {e}")

		if all_hints:
			logger.info(f"[ReconAgent] Nmap vuln scan 共发现 {len(all_hints)} 个漏洞提示")
		return all_hints

	async def _llm_analyze_nmap(
		self,
		target: str,
		raw_nmap: str,
		ports: list[PortInfo],
		log_callback: LogCallback = None,
	) -> dict:
		"""Use LLM to analyze nmap results and suggest next steps."""
		if not raw_nmap or not ports:
			return {}

		nmap_snippet = raw_nmap[:4000]
		try:
			from backend.llm.router import LLMRouter
			from backend.llm.prompts.templates import RECON_ANALYSIS
			from backend.agents.prompt_utils import wrap_prompt_with_block

			if log_callback:
				await log_callback("[ReconAgent] LLM 分析 Nmap 扫描结果...")

			llm = LLMRouter()
			prompt = RECON_ANALYSIS.format(
				target=target,
				raw_output=nmap_snippet,
			)
			prompt = wrap_prompt_with_block(prompt, self._operator_block)
			import json
			response = await llm.chat(prompt, response_format="json")
			hints = json.loads(response)
			if log_callback:
				vectors = hints.get("potential_attack_vectors", [])
				tools = hints.get("recommended_next_tools", [])
				await log_callback(
					f"[ReconAgent] LLM 分析完成: "
					f"攻击向量 {len(vectors)} 条, "
					f"推荐工具 {', '.join(tools[:5]) if tools else '无'}"
				)
			return hints
		except Exception as e:
			logger.debug(f"[ReconAgent] LLM 分析 Nmap 失败 (非致命): {e}")
			if log_callback:
				await log_callback(f"[ReconAgent] LLM 分析跳过: {e}")
			return {}

	@staticmethod
	def _is_ip_address(target: str) -> bool:
		try:
			_ipaddress.ip_address(target)
			return True
		except ValueError:
			return False

	async def _subdomain_enum(
		self,
		target: str,
		task_id: Optional[str],
		log_callback: LogCallback = None,
	) -> list[str]:
		"""Enumerate subdomains for domain targets using subfinder."""
		if self._is_ip_address(target):
			return []

		if "." not in target:
			return []

		if log_callback:
			await log_callback(f"[ReconAgent] 子域名枚举: {target}")

		subdomains: list[str] = []

		try:
			result: ExecuteResult = await self.executor.run(
				tool="subfinder",
				args=["-d", target, "-silent", "-t", "20"],
				timeout=60,
				task_id=task_id,
				log_callback=log_callback,
			)
			if result.success and result.stdout:
				for line in result.stdout.strip().splitlines():
					sub = line.strip().lower()
					if sub and sub not in subdomains and target in sub:
						subdomains.append(sub)
		except Exception as e:
			logger.debug(f"[ReconAgent] subfinder 失败: {e}")

		if not subdomains:
			try:
				result = await self.executor.run(
					tool="amass",
					args=["enum", "-passive", "-d", target, "-timeout", "2"],
					timeout=90,
					task_id=task_id,
					log_callback=log_callback,
				)
				if result.success and result.stdout:
					for line in result.stdout.strip().splitlines():
						sub = line.strip().lower()
						if sub and sub not in subdomains and target in sub:
							subdomains.append(sub)
			except Exception as e:
				logger.debug(f"[ReconAgent] amass 失败: {e}")

		if log_callback:
			await log_callback(
				f"[ReconAgent] 子域名枚举完成: 发现 {len(subdomains)} 个子域名"
			)
		return subdomains[:100]

	async def _detect_waf(
		self,
		web_target: str,
		task_id: Optional[str],
		log_callback: LogCallback = None,
	) -> bool:
		"""Run wafw00f to detect WAF presence. Returns True if WAF detected."""
		if log_callback:
			await log_callback("[ReconAgent] WAF 检测中...")
		try:
			result: ExecuteResult = await self.executor.run(
				tool="wafw00f",
				args=[web_target, "-o", "-"],
				timeout=30,
				task_id=task_id,
				log_callback=log_callback,
			)
			stdout = (result.stdout or "").lower()
			if result.success and ("is behind" in stdout or "waf detected" in stdout):
				waf_name = ""
				for line in (result.stdout or "").splitlines():
					if "is behind" in line.lower():
						waf_name = line.strip()
						break
				if log_callback:
					await log_callback(
						f"[ReconAgent] WAF 检测到: {waf_name or 'unknown'} — 将降低扫描并发"
					)
				return True
			if log_callback:
				await log_callback("[ReconAgent] 未检测到 WAF")
		except Exception as e:
			logger.debug(f"[ReconAgent] WAF 检测失败 (非致命): {e}")
			if log_callback:
				await log_callback(f"[ReconAgent] WAF 检测跳过: {e}")
		return False

	async def _quick_fingerprint(
		self,
		target: str,
		web_ports: list[PortInfo],
		task_id: Optional[str],
		log_callback: LogCallback = None,
	) -> list[str]:
		"""Lightweight fingerprinting via whatweb/httpx before dir scan.

		Returns a list of technology hints like ["PHP", "Tomcat", "WordPress"].
		"""
		tech_hints: list[str] = []
		if log_callback:
			await log_callback("[ReconAgent] 轻量级 Web 指纹识别...")

		for wp in web_ports[:3]:
			scheme = "https" if wp.port in (443, 8443) else "http"
			url = f"{scheme}://{target}:{wp.port}"

			try:
				ww_result: ExecuteResult = await self.executor.run(
					tool="whatweb",
					args=[url, "--color=never", "-q"],
					timeout=20,
					task_id=task_id,
				)
				if ww_result.success and ww_result.stdout:
					tech_hints.extend(
						self._parse_whatweb_techs(ww_result.stdout)
					)
			except Exception as e:
				logger.debug(f"[ReconAgent] whatweb 失败 (port {wp.port}): {e}")

			try:
				hx_result: ExecuteResult = await self.executor.run(
					tool="httpx",
					args=["-u", url, "-silent", "-tech-detect", "-status-code", "-title"],
					timeout=20,
					task_id=task_id,
				)
				if hx_result.success and hx_result.stdout:
					tech_hints.extend(
						self._parse_httpx_techs(hx_result.stdout)
					)
			except Exception as e:
				logger.debug(f"[ReconAgent] httpx 失败 (port {wp.port}): {e}")

			combined = f"{wp.service} {wp.version} {wp.banner}".lower()
			tech_hints.extend(self._extract_tech_from_nmap(combined))

		unique = list(dict.fromkeys(tech_hints))
		if log_callback and unique:
			await log_callback(
				f"[ReconAgent] 指纹识别结果: {', '.join(unique)}"
			)
		return unique

	@staticmethod
	def _parse_whatweb_techs(output: str) -> list[str]:
		known = {
			"php": "PHP", "jsp": "JSP", "asp": "ASP",
			"tomcat": "Tomcat", "apache": "Apache", "nginx": "Nginx",
			"iis": "IIS", "wordpress": "WordPress", "drupal": "Drupal",
			"joomla": "Joomla", "django": "Django", "flask": "Flask",
			"spring": "Spring", "struts": "Struts", "weblogic": "WebLogic",
			"jboss": "JBoss", "wildfly": "JBoss", "laravel": "PHP",
			"rails": "Rails", "express": "Express", "next.js": "React",
			"vue": "Vue", "react": "React", "thinkphp": "ThinkPHP",
		}
		text = output.lower()
		return [label for kw, label in known.items() if kw in text]

	@staticmethod
	def _parse_httpx_techs(output: str) -> list[str]:
		known = {
			"php": "PHP", "tomcat": "Tomcat", "apache": "Apache",
			"nginx": "Nginx", "iis": "IIS", "wordpress": "WordPress",
			"django": "Django", "flask": "Flask", "spring": "Spring",
			"weblogic": "WebLogic", "jboss": "JBoss",
		}
		text = output.lower()
		return [label for kw, label in known.items() if kw in text]

	@staticmethod
	def _extract_tech_from_nmap(combined: str) -> list[str]:
		known = {
			"apache": "Apache", "nginx": "Nginx", "iis": "IIS",
			"tomcat": "Tomcat", "weblogic": "WebLogic", "jboss": "JBoss",
			"php": "PHP", "wordpress": "WordPress",
		}
		return [label for kw, label in known.items() if kw in combined]

	async def _dir_scan(
		self,
		web_target: str,
		task_id: Optional[str],
		log_callback: LogCallback = None,
		has_waf: bool = False,
		tech_hints: list[str] | None = None,
		scan_strategy: dict | None = None,
		record_callback: RecordCallback = None,
		deep_coord: "DeepScanCoordinator | None" = None,
	) -> tuple[list[str], str, CoverageReport, PathAggregator]:
		"""LLM-in-the-loop adaptive directory discovery via DirScanOrchestrator."""
		from backend.tools.dir_scan_orchestrator import DirScanOrchestrator

		planner = ToolCoveragePlanner(
			categories=["dir_discovery"],
			max_tools=6,
			max_stage_runtime=480,
		)
		plan = planner.build_plan(
			web_target, has_waf=has_waf, tech_hints=tech_hints,
			scan_strategy=scan_strategy,
			operator_plan=getattr(self, "_operator_plan", None),
		)
		aggregator = PathAggregator()

		orchestrator = DirScanOrchestrator(
			executor=self.executor,
			aggregator=aggregator,
			planner=planner,
			log_callback=log_callback,
			record_callback=record_callback,
			task_id=task_id,
			coordinator=deep_coord,
		)
		result = await orchestrator.run(plan, web_target, scan_strategy)

		if not result.coverage_report.satisfied:
			for v in result.coverage_report.violations:
				logger.warning(f"[ReconAgent] 覆盖率不足: {v}")

		return result.paths, result.raw_output, result.coverage_report, result.aggregator


	async def _llm_plan_dir_strategy(
		self,
		primary_target: str,
		tech_hints: list[str],
		ports: list[PortInfo],
		has_waf: bool,
		log_callback: LogCallback = None,
	) -> dict:
		"""Ask LLM to plan directory scanning strategy based on fingerprint intel."""
		try:
			from backend.llm.router import LLMRouter
			from backend.llm.prompts.templates import DIR_SCAN_STRATEGY

			service_info = ", ".join(
				f"{p.port}/{p.service}({p.version[:40]})" for p in ports[:15]
			)
			initial_resp = ""
			try:
				probe = await self.executor.run_script(
					script_content=(
						f'curl -sS -L --max-time 6 -D - -o /dev/null "{primary_target}" 2>/dev/null '
						f'| head -20'
					),
					timeout=12,
				)
				initial_resp = (probe.stdout or "")[:800]
			except Exception:
				pass

			prompt = DIR_SCAN_STRATEGY.format(
				target_url=primary_target,
				tech_hints=", ".join(tech_hints) if tech_hints else "未检测到",
				service_info=service_info or "无",
				waf_status="检测到 WAF" if has_waf else "未检测到 WAF",
				initial_response=initial_resp or "无",
			)
			from backend.agents.prompt_utils import wrap_prompt_with_block
			prompt = wrap_prompt_with_block(prompt, self._operator_block)

			llm = LLMRouter()
			raw = await llm.chat(
				prompt, response_format="json", temperature=0.1, max_tokens=1536,
			)
			strategy = json.loads(raw)
			if log_callback:
				assessment = strategy.get("tech_assessment", "")
				profile = strategy.get("scan_profile", "balanced")
				n_priority = len(strategy.get("priority_paths", []))
				await log_callback(
					f"[ReconAgent] LLM 扫描策略: {assessment} "
					f"(profile={profile}, priority_paths={n_priority})"
				)
			return strategy
		except Exception as exc:
			logger.warning(f"[ReconAgent] LLM dir strategy failed, using defaults: {exc}")
			if log_callback:
				await log_callback(
					f"[ReconAgent] LLM 策略规划失败，使用默认策略: {exc}"
				)
			return {}


	async def _llm_deep_dive(
		self,
		base_url: str,
		tech_hints: list[str],
		aggregator: PathAggregator,
		task_id: Optional[str],
		log_callback: LogCallback = None,
		record_callback: RecordCallback = None,
		scan_strategy: dict | None = None,
		deep_coord: "DeepScanCoordinator | None" = None,
	) -> None:
		"""Ask LLM to plan post-scan deep dive actions and execute them."""
		try:
			from backend.llm.router import LLMRouter
			from backend.llm.prompts.templates import DIR_DEEP_DIVE_PLAN

			inventory = aggregator.get_inventory(min_confidence=0.4)
			path_inventory_text = "\n".join(
				f"  {item['path']} (status={item.get('status', 0)}, "
				f"hints={','.join(item.get('hints', []))}, "
				f"conf={item.get('confidence', 0):.2f})"
				for item in inventory[:50]
			)

			special_results = []
			special_checks = (scan_strategy or {}).get("special_checks", [])
			for chk in special_checks:
				ctype = chk.get("type", "") if isinstance(chk, dict) else ""
				special_results.append(f"  {ctype}: 待检查")

			prompt = DIR_DEEP_DIVE_PLAN.format(
				base_url=base_url,
				tech_stack=", ".join(tech_hints) if tech_hints else "未知",
				total_count=aggregator.count,
				path_inventory=path_inventory_text or "  无发现",
				dirlist_summary="  无目录列表检测结果",
				special_checks_results="\n".join(special_results) if special_results else "  无",
			)
			from backend.agents.prompt_utils import wrap_prompt_with_block
			prompt = wrap_prompt_with_block(prompt, self._operator_block)

			llm = LLMRouter()
			raw = await llm.chat(
				prompt, response_format="json", temperature=0.1, max_tokens=1536,
			)
			deep_plan = json.loads(raw)
			if log_callback:
				summary = deep_plan.get("priority_summary", "")
				await log_callback(f"[ReconAgent] LLM 深挖规划: {summary}")

			await self._execute_deep_dive_actions(
				base_url, deep_plan, aggregator,
				task_id, log_callback, record_callback,
				deep_coord=deep_coord,
			)
		except Exception as exc:
			logger.warning(f"[ReconAgent] LLM deep dive planning failed: {exc}")
			if log_callback:
				await log_callback(f"[ReconAgent] LLM 深挖规划失败: {exc}")

	async def _execute_deep_dive_actions(
		self,
		base_url: str,
		deep_plan: dict,
		aggregator: PathAggregator,
		task_id: Optional[str],
		log_callback: LogCallback = None,
		record_callback: RecordCallback = None,
		deep_coord: "DeepScanCoordinator | None" = None,
	) -> None:
		"""Execute deep dive actions from LLM plan concurrently.

		Recursive scan requests are routed through the shared
		`DeepScanCoordinator` (when provided) so that they share dedup /
		budget with orchestrator-initiated queues. Robots/sitemap/git/API
		probes remain fan-out tasks (cheap, no overlap risk).
		"""
		from backend.tools.deep_scan_coordinator import (
			DeepScanTarget as _DeepScanTarget,
		)

		tasks: list[asyncio.Task] = []
		task_labels: list[str] = []

		async def _emit_deep_detail(msg: str) -> None:
			logger.info("[ReconAgent] %s", msg)
			if log_callback:
				await log_callback(f"[ReconAgent] {msg}")

		queued_recursive = 0
		for scan in deep_plan.get("recursive_scans", [])[:3]:
			sub_base = scan.get("base", "")
			if not sub_base:
				continue
			reason = (scan.get("reason") or "").strip()
			wl = scan.get("wordlist", "") or "small"
			depth = scan.get("depth", 2)
			if deep_coord is not None:
				enqueued = deep_coord.enqueue(_DeepScanTarget(
					path=sub_base,
					reason=reason or "LLM 深挖规划",
					wordlist=wl if wl in ("small", "medium", "large") else "small",
					priority=60,
					base_url=base_url,
				))
				if enqueued:
					queued_recursive += 1
					await _emit_deep_detail(
						f"深挖子任务 [入队 coordinator] base={sub_base} "
						f"depth={depth} priority=60"
						f"{f' | 理由: {reason[:200]}' if reason else ''}"
					)
				else:
					await _emit_deep_detail(
						f"深挖子任务 [跳过入队] base={sub_base}（已扫或已在队列）"
					)
				continue

			label = (
				f"深挖子任务 [递归目录爆破] base={sub_base} depth={depth}"
				f"{f' wordlist={wl}' if wl else ''}"
				f"{f' | 理由: {reason[:200]}' if reason else ''}"
			)
			task_labels.append(label)
			tasks.append(asyncio.create_task(
				self._deep_recursive_scan(
					base_url, sub_base, depth,
					aggregator, task_id, log_callback, record_callback,
					reason=reason,
				)
			))

		if deep_coord is not None and queued_recursive:
			await _emit_deep_detail(
				f"深挖: 已向共享深扫队列入队 {queued_recursive} 个 LLM 推荐目标"
				f" | {deep_coord.budget_report()}"
			)

		for action in deep_plan.get("info_source_actions", []):
			if not isinstance(action, dict):
				continue
			atype = action.get("type", "")
			apath = action.get("path", "")
			exp = action.get("expected_value", "")
			if atype == "parse_robots":
				label = "深挖子任务 [robots.txt] GET /robots.txt 解析 Disallow/Allow/Sitemap"
				task_labels.append(label)
				tasks.append(asyncio.create_task(
					self._parse_robots_txt(
						base_url, aggregator, task_id, log_callback, record_callback,
					)
				))
			elif atype == "parse_sitemap":
				label = "深挖子任务 [sitemap.xml] GET /sitemap.xml 提取 <loc> 路径"
				task_labels.append(label)
				tasks.append(asyncio.create_task(
					self._parse_sitemap_xml(
						base_url, aggregator, task_id, log_callback, record_callback,
					)
				))
			elif atype == "git_dump":
				p = apath or "/.git/"
				label = (
					f"深挖子任务 [.git 泄露检查] 探测 {p}HEAD / config"
					f"{f' | 预期价值={exp}' if exp else ''}"
				)
				task_labels.append(label)
				tasks.append(asyncio.create_task(
					self._check_git_exposure(
						base_url, aggregator, task_id, log_callback, record_callback,
					)
				))

		api_checks = deep_plan.get("api_schema_checks", [])
		if api_checks:
			preview = ", ".join(str(p) for p in api_checks[:8] if p)
			if len(api_checks) > 8:
				preview += f" …(+{len(api_checks) - 8})"
			label = f"深挖子任务 [API 文档探测] 额外路径: {preview or '(仅默认列表)'}"
			task_labels.append(label)
			tasks.append(asyncio.create_task(
				self._check_api_schemas(
					base_url, api_checks, aggregator, task_id, log_callback, record_callback,
				)
			))

		if tasks:
			await _emit_deep_detail(
				f"深挖: 并发执行 {len(tasks)} 个子任务 — 明细如下:"
			)
			for i, line in enumerate(task_labels, 1):
				await _emit_deep_detail(f"  ({i}/{len(task_labels)}) {line}")
			for hint in (deep_plan.get("attack_chain_hints") or [])[:5]:
				if isinstance(hint, dict):
					paths = hint.get("paths") or []
					chain = hint.get("chain", "")
					conf = hint.get("confidence", "")
					await _emit_deep_detail(
						f"深挖线索 [攻击链] paths={paths} confidence={conf} | {chain}"
					)
			results = await asyncio.gather(*tasks, return_exceptions=True)
			failures = [r for r in results if isinstance(r, Exception)]
			if failures:
				for exc in failures:
					logger.warning("[ReconAgent] 深挖子任务异常: %s", exc)
					if log_callback:
						await log_callback(
							f"[ReconAgent] 深挖子任务异常: {exc}"
						)
			else:
				await _emit_deep_detail(
					f"深挖: {len(tasks)} 个子任务已全部结束（无未捕获异常）"
				)

	async def _deep_recursive_scan(
		self,
		base_url: str,
		sub_path: str,
		depth: int,
		aggregator: PathAggregator,
		task_id: Optional[str],
		log_callback: LogCallback = None,
		record_callback: RecordCallback = None,
		*,
		reason: str = "",
		deep_coord: "DeepScanCoordinator | None" = None,
	) -> None:
		"""Execute one feroxbuster deep scan and (optionally) feed newly
		discovered directory-like paths back into the shared coordinator.

		When `deep_coord` is supplied, this function:
		  1. Guards against re-scanning paths already marked done
		  2. Records elapsed + mark_scanned so the coordinator budget stays accurate
		  3. Enqueues scored followups (same scoring as DirScanOrchestrator)
		     so both Phase 2 and Phase 3 contribute to a single queue.
		"""
		from backend.tools.deep_scan_coordinator import (
			pick_followups as _pick_followups,
			DeepScanTarget as _DeepScanTarget,
		)

		if deep_coord is not None and deep_coord.has_been_scanned(sub_path):
			msg = f"深扫跳过 {sub_path}（coordinator 已记录扫过）"
			logger.info("[ReconAgent] %s", msg)
			if log_callback:
				await log_callback(f"[ReconAgent] {msg}")
			return

		sub_url = f"{base_url.rstrip('/')}{sub_path}"
		d = min(depth, 3)
		start_msg = (
			f"深扫开始 feroxbuster url={sub_url} depth={d} timeout=120s"
			f"{f' | {reason[:180]}' if reason else ''}"
		)
		logger.info("[ReconAgent] %s", start_msg)
		if log_callback:
			await log_callback(f"[ReconAgent] {start_msg}")
		script = (
			f'WL="/usr/share/wordlists/dirb/common.txt"; '
			f'feroxbuster -u "{sub_url}" -w "$WL" -t 30 --depth {d} '
			f'--no-state -q -C 404 2>/dev/null'
		)
		scan_elapsed = 0.0
		try:
			paths_before = set(aggregator._entries.keys())
			t0 = time.time()
			result = await self.executor.run_script(
				script_content=script, timeout=120, task_id=task_id,
				log_callback=log_callback,
				record_callback=record_callback,
				record_phase="recon",
				record_purpose=f"deep_scan_{sub_path.strip('/')}",
			)
			scan_elapsed = time.time() - t0
			raw_out = result.stdout or ""
			new = aggregator.ingest("feroxbuster", raw_out, base_url)
			new_paths = [p for p in aggregator._entries if p not in paths_before]
			root_norm = _normalize_deep_scan_root(sub_path)
			under_root = _paths_under_deep_root(sub_path, new_paths)
			display_paths = under_root if under_root else new_paths
			sample = _ferox_stdout_sample(raw_out)
			logger.info(
				"[ReconAgent] 深扫根=%s | 扫描 URL=%s | 本轮解析新增 %d 条 | "
				"落在该根下 %d 条",
				root_norm, sub_url, len(new_paths), len(under_root),
			)
			logger.info(
				"[ReconAgent] 深扫根=%s 新增路径明细: %s",
				root_norm, _preview_path_list(display_paths, 60),
			)
			logger.info(
				"[ReconAgent] 深扫根=%s ferox 输出样本:\n%s",
				root_norm, sample,
			)
			if log_callback:
				await log_callback(
					f"[ReconAgent] 深扫根 {root_norm} → 新增 {len(new_paths)} 条 "
					f"(根下 {len(under_root)} 条): {_preview_path_list(display_paths, 35)}"
				)
				await log_callback(
					f"[ReconAgent] 深扫根 {root_norm} ferox 样本:\n{sample}"
				)

			if deep_coord is not None:
				scanned_snapshot = {root_norm}
				followup_pool = under_root or new_paths
				followups = _pick_followups(
					followup_pool, aggregator, scanned_snapshot,
				)
				enqueued = 0
				for fp in followups:
					if deep_coord.enqueue(_DeepScanTarget(
						path=fp,
						reason=f"从 {root_norm} 深扫中回流",
						wordlist="small",
						priority=30,
						base_url=base_url,
					)):
						enqueued += 1
				if enqueued and log_callback:
					await log_callback(
						f"[ReconAgent] 深扫根 {root_norm} 回流 {enqueued} 个子目标到共享队列"
						f" | {deep_coord.budget_report()}"
					)

		except Exception as e:
			logger.warning(f"[ReconAgent] Deep scan {sub_path} failed: {e}")
			if log_callback:
				await log_callback(
					f"[ReconAgent] 深扫失败 {sub_path}: {e}"
				)
		finally:
			if deep_coord is not None:
				deep_coord.mark_scanned(sub_path, elapsed_s=scan_elapsed)

	async def _drain_deep_scan_queue(
		self,
		*,
		base_url: str,
		aggregator: PathAggregator,
		coord: "DeepScanCoordinator",
		task_id: Optional[str],
		log_callback: LogCallback = None,
		record_callback: RecordCallback = None,
		max_rounds: int = 3,
		batch_size: int = 5,
	) -> None:
		"""Drain the shared deep-scan queue to convergence (or budget exhausted).

		Invoked once at the end of Phase 3 after both the per-port orchestrators
		and the LLM deep-dive have finished enqueueing their candidates. Each
		round pops a priority-ordered batch and runs them sequentially so the
		same target isn't hit by multiple concurrent ferox processes.
		"""
		if coord is None:
			return
		if not coord.has_pending():
			if log_callback:
				await log_callback(
					f"[ReconAgent] 深扫收尾: 共享队列为空 | {coord.budget_report()}"
				)
			return

		for round_idx in range(max_rounds):
			if not coord.can_scan():
				if log_callback:
					await log_callback(
						f"[ReconAgent] 深扫收尾: 预算耗尽，停止 | {coord.budget_report()}"
					)
				break
			batch = coord.pop_batch(batch_size)
			if not batch:
				break

			preview = ", ".join(
				f"{t.path}(p={t.priority})" for t in batch
			)
			msg = (
				f"深扫收尾 第{round_idx + 1}/{max_rounds}轮: "
				f"{len(batch)} 目标 | {coord.budget_report()} | {preview}"
			)
			logger.info("[ReconAgent] %s", msg)
			if log_callback:
				await log_callback(f"[ReconAgent] {msg}")

			for target in batch:
				scan_base = target.base_url or base_url
				await self._deep_recursive_scan(
					scan_base, target.path, 2,
					aggregator, task_id, log_callback, record_callback,
					reason=target.reason or "shared queue drain",
					deep_coord=coord,
				)

		stats = coord.stats()
		final_msg = (
			f"深扫收尾结束: scanned={stats.scanned}, "
			f"queued_remaining={stats.queued}, elapsed={stats.elapsed_s:.1f}s"
		)
		logger.info("[ReconAgent] %s", final_msg)
		if log_callback:
			await log_callback(f"[ReconAgent] {final_msg}")

	async def _parse_robots_txt(
		self, base_url: str, aggregator: PathAggregator,
		task_id: Optional[str], log_callback: LogCallback = None,
		record_callback: RecordCallback = None,
	) -> None:
		logger.info("[ReconAgent] robots.txt 开始 GET %s/robots.txt", base_url.rstrip("/"))
		if log_callback:
			await log_callback(
				f"[ReconAgent] robots.txt 开始: {base_url.rstrip('/')}/robots.txt"
			)
		try:
			result = await self.executor.run_script(
				script_content=f'curl -sS --max-time 8 "{base_url}/robots.txt" 2>/dev/null',
				timeout=15, task_id=task_id,
				log_callback=log_callback,
				record_callback=record_callback,
				record_phase="recon", record_purpose="parse_robots",
			)
			body = result.stdout or ""
			if not body or "<html" in body.lower():
				logger.info("[ReconAgent] robots.txt无有效内容或返回 HTML，跳过解析")
				if log_callback:
					await log_callback("[ReconAgent] robots.txt: 无有效内容，跳过")
				return
			paths = []
			for line in body.splitlines():
				line = line.strip()
				if line.lower().startswith(("disallow:", "allow:")):
					path = line.split(":", 1)[1].strip()
					if path and path != "/" and not path.startswith("#"):
						path = path.split("#")[0].strip()
						path = path.split("*")[0].strip()
						if path and path.startswith("/"):
							paths.append(path)
				elif line.lower().startswith("sitemap:"):
					url = line.split(":", 1)[1].strip()
					if url:
						parsed = urlparse(url)
						if parsed.path:
							paths.append(parsed.path)
			if paths:
				aggregator.add_paths(paths, source="robots_txt", status=0)
				logger.info(
					"[ReconAgent] robots.txt 解析命中 %d 条: %s",
					len(paths), _preview_path_list(paths, 30),
				)
				if log_callback:
					await log_callback(
						f"[ReconAgent] robots.txt 解析: +{len(paths)} 路径 — "
						f"{_preview_path_list(paths, 25)}"
					)
		except Exception as e:
			logger.debug(f"[ReconAgent] robots.txt parse failed: {e}")

	async def _parse_sitemap_xml(
		self, base_url: str, aggregator: PathAggregator,
		task_id: Optional[str], log_callback: LogCallback = None,
		record_callback: RecordCallback = None,
	) -> None:
		logger.info("[ReconAgent] sitemap.xml 开始 GET %s/sitemap.xml", base_url.rstrip("/"))
		if log_callback:
			await log_callback(
				f"[ReconAgent] sitemap.xml 开始: {base_url.rstrip('/')}/sitemap.xml"
			)
		try:
			result = await self.executor.run_script(
				script_content=(
					f'curl -sS --max-time 10 "{base_url}/sitemap.xml" 2>/dev/null '
					f'| head -c 50000'
				),
				timeout=18, task_id=task_id,
				log_callback=log_callback,
				record_callback=record_callback,
				record_phase="recon", record_purpose="parse_sitemap",
			)
			body = result.stdout or ""
			if not body or "<urlset" not in body.lower():
				logger.info("[ReconAgent] sitemap.xml 非标准或为空，跳过")
				if log_callback:
					await log_callback("[ReconAgent] sitemap.xml: 无有效 XML，跳过")
				return
			loc_re = re.compile(r"<loc>\s*(https?://[^<]+)\s*</loc>", re.IGNORECASE)
			paths = []
			for m in loc_re.finditer(body):
				parsed = urlparse(m.group(1))
				if parsed.path and parsed.path != "/":
					paths.append(parsed.path)
			if paths:
				aggregator.add_paths(paths[:100], source="sitemap_xml", status=0)
				logger.info(
					"[ReconAgent] sitemap.xml 解析命中 %d 条: %s",
					len(paths), _preview_path_list(paths, 35),
				)
				if log_callback:
					await log_callback(
						f"[ReconAgent] sitemap.xml 解析: +{len(paths)} 路径 — "
						f"{_preview_path_list(paths, 25)}"
					)
		except Exception as e:
			logger.debug(f"[ReconAgent] sitemap.xml parse failed: {e}")

	async def _check_git_exposure(
		self, base_url: str, aggregator: PathAggregator,
		task_id: Optional[str], log_callback: LogCallback = None,
		record_callback: RecordCallback = None,
	) -> None:
		git_head = f"{base_url.rstrip('/')}/.git/HEAD"
		logger.info("[ReconAgent] .git 检查开始 HEAD=%s", git_head)
		if log_callback:
			await log_callback(f"[ReconAgent] .git 检查开始: {git_head}")
		try:
			result = await self.executor.run_script(
				script_content=(
					f'HEAD_CODE=$(curl -sS -o /dev/null -w "%{{http_code}}" '
					f'--max-time 5 "{base_url}/.git/HEAD" 2>/dev/null); '
					f'echo "HEAD:$HEAD_CODE"; '
					f'if [ "$HEAD_CODE" = "200" ]; then '
					f'  curl -sS --max-time 5 "{base_url}/.git/HEAD" 2>/dev/null; '
					f'  echo "---CONFIG---"; '
					f'  curl -sS --max-time 5 "{base_url}/.git/config" 2>/dev/null; '
					f'fi'
				),
				timeout=20, task_id=task_id,
				log_callback=log_callback,
				record_callback=record_callback,
				record_phase="recon", record_purpose="git_exposure",
			)
			body = result.stdout or ""
			if "HEAD:200" in body and "ref:" in body.lower():
				git_paths = ["/.git/HEAD", "/.git/config", "/.git/"]
				aggregator.add_paths(
					git_paths,
					source="git_exposure", status=200,
				)
				logger.info(
					"[ReconAgent] .git 泄露确认 (HTTP 200 + ref:) | 关键路径: %s",
					_preview_path_list(git_paths, 10),
				)
				if log_callback:
					await log_callback(
						"[ReconAgent] .git 泄露确认! 源码可能可提取 — "
						f"{_preview_path_list(git_paths, 10)}"
					)
			else:
				logger.info("[ReconAgent] .git 未发现泄露或 HEAD 非 200")
				if log_callback:
					await log_callback("[ReconAgent] .git: 未发现可访问的 HEAD/ref")
		except Exception as e:
			logger.debug(f"[ReconAgent] git exposure check failed: {e}")

	async def _check_api_schemas(
		self, base_url: str, schema_paths: list[str],
		aggregator: PathAggregator,
		task_id: Optional[str], log_callback: LogCallback = None,
		record_callback: RecordCallback = None,
	) -> None:
		default_schemas = [
			"/swagger.json", "/openapi.yaml", "/openapi.json",
			"/api-docs", "/v2/api-docs", "/v3/api-docs",
			"/.well-known/openid-configuration",
		]
		targets = list(dict.fromkeys(
			[p for p in schema_paths if isinstance(p, str)] + default_schemas
		))[:12]

		probe_cmds = []
		for p in targets:
			p = p if p.startswith("/") else f"/{p}"
			probe_cmds.append(
				f'CODE=$(curl -s -o /dev/null -w "%{{http_code}}" '
				f'--max-time 5 "{base_url}{p}"); '
				f'[ "$CODE" = "200" ] && echo "{p} $CODE"'
			)
		script = "set +e\n" + "\n".join(probe_cmds)
		tgt_str = ", ".join(targets[:10])
		if len(targets) > 10:
			tgt_str += f" …共{len(targets)}个"
		logger.info("[ReconAgent] API Schema 探测开始 targets=[%s]", tgt_str)
		if log_callback:
			await log_callback(f"[ReconAgent] API Schema 探测: {tgt_str}")
		try:
			result = await self.executor.run_script(
				script_content=script, timeout=40, task_id=task_id,
				log_callback=log_callback,
				record_callback=record_callback,
				record_phase="recon", record_purpose="api_schema_check",
			)
			found = 0
			hit_list: list[str] = []
			if result.stdout:
				for line in result.stdout.strip().splitlines():
					parts = line.strip().split()
					if len(parts) >= 2:
						aggregator.add_paths([parts[0]], source="api_schema", status=200)
						found += 1
						hit_list.append(f"{parts[0]}→200")
			if found:
				logger.info(
					"[ReconAgent] API Schema 命中 %d: %s",
					found, ", ".join(hit_list[:12]),
				)
			else:
				logger.info("[ReconAgent] API Schema无 HTTP 200 命中")
			if found and log_callback:
				await log_callback(
					f"[ReconAgent] API Schema 发现 {found} 个: {', '.join(hit_list[:10])}"
				)
			elif log_callback and not found:
				await log_callback("[ReconAgent] API Schema: 未发现 200 端点")
		except Exception as e:
			logger.debug(f"[ReconAgent] API schema check failed: {e}")

	def _pick_content_probe_candidates(
		self,
		aggregator: PathAggregator,
		max_items: int = 20,
	) -> list[dict[str, Any]]:
		high_value_hints = {
			"admin", "login", "api", "config",
			"backup", "upload", "info_disclosure", "leak",
		}
		inventory = aggregator.get_inventory(min_confidence=0.45)
		candidates = [
			item for item in inventory
			if "static" not in item.get("hints", [])
		]
		prioritized = [
			item for item in candidates
			if high_value_hints.intersection(set(item.get("hints", [])))
		]
		selected = prioritized or candidates[:8]
		selected.sort(key=lambda x: (-float(x.get("confidence", 0.0)), x.get("path", "")))
		return selected[:max_items]

	async def _probe_path_contents(
		self,
		web_target: str,
		aggregator: PathAggregator,
		task_id: Optional[str],
		log_callback: LogCallback = None,
	) -> list[dict[str, Any]]:
		candidates = self._pick_content_probe_candidates(aggregator, max_items=20)
		if not candidates:
			return []

		base_url = web_target.rstrip("/")
		path_lines = "\n".join(item.get("path", "") for item in candidates if item.get("path"))
		if not path_lines:
			return []

		cand_paths = [item.get("path", "") for item in candidates if item.get("path")]
		logger.info(
			"[ReconAgent] 路径内容探测 base=%s | 候选 %d 条: %s",
			base_url, len(cand_paths), _preview_path_list(cand_paths, 30),
		)
		if log_callback:
			await log_callback(
				f"[ReconAgent] 路径内容探测: 准备探测 {len(candidates)} 条 — "
				f"{_preview_path_list(cand_paths, 20)}"
			)

		probe_script = f"""
set +e
BASE={shlex.quote(base_url)}
while IFS= read -r PATH_ITEM; do
  [ -z "$PATH_ITEM" ] && continue
  URL="${{BASE}}${{PATH_ITEM}}"
  TMP_BODY=$(mktemp)
  TMP_HEADER=$(mktemp)
  CODE=$(curl -sS -L --max-time 8 -D "$TMP_HEADER" -o "$TMP_BODY" -w "%{{http_code}}" "$URL" 2>/dev/null || echo "000")
  SERVER=$(awk 'BEGIN{{IGNORECASE=1}} /^Server:/{{sub(/^Server:[[:space:]]*/,""); print; exit}}' "$TMP_HEADER" | tr -d '\\r' | tr '\\n' ' ' | cut -c1-140)
  POWERED=$(awk 'BEGIN{{IGNORECASE=1}} /^X-Powered-By:/{{sub(/^X-Powered-By:[[:space:]]*/,""); print; exit}}' "$TMP_HEADER" | tr -d '\\r' | tr '\\n' ' ' | cut -c1-140)
  LINKS=$(grep -Eoi 'href=["'"'"'][^"'"'"']+["'"'"']' "$TMP_BODY" | head -n 25 | sed -E 's/^href=["'"'"']|["'"'"']$//g' | paste -sd'|' -)
  BODY=$(tr '\\r\\n' '  ' < "$TMP_BODY" | sed -E 's/[[:space:]]+/ /g' | cut -c1-2000)
  echo "__PATH_PROBE_BEGIN__"
  echo "PATH:$PATH_ITEM"
  echo "CODE:$CODE"
  echo "SERVER:$SERVER"
  echo "POWERED:$POWERED"
  echo "LINKS:$LINKS"
  echo "BODY:$BODY"
  echo "__PATH_PROBE_END__"
  rm -f "$TMP_BODY" "$TMP_HEADER"
done <<'EOF_PATHS'
{path_lines}
EOF_PATHS
""".strip()

		try:
			result: ExecuteResult = await self.executor.run_script(
				script_content=probe_script,
				timeout=240,
				task_id=task_id,
				log_callback=log_callback,
				record_purpose="path_content_probe",
				record_runtime_command=f"batch-curl {base_url} ({len(candidates)} paths)",
			)
		except Exception as e:
			logger.warning(f"[ReconAgent] 路径内容探测异常: {e}")
			return []

		path_hint_map = {item["path"]: item.get("hints", []) for item in candidates}
		probed: list[dict[str, Any]] = []
		new_paths = 0
		for block in self._parse_probe_blocks(result.stdout or ""):
			path = str(block.get("PATH", "")).strip()
			if not path:
				continue
			code = self._safe_int(str(block.get("CODE", "0")), default=0)
			body = str(block.get("BODY", "")).strip()
			title = self._extract_title(body)
			server = str(block.get("SERVER", "")).strip()
			powered = str(block.get("POWERED", "")).strip()
			tech_clues = self._extract_tech_clues(body, title, server, powered)
			keywords = self._extract_keywords(body)

			links_field = str(block.get("LINKS", "")).strip()
			discovered = self._extract_paths_from_links(path, links_field)
			if discovered:
				aggregator.add_paths(discovered, source="content_probe", status=200)
				new_paths += len(discovered)

			is_dirlist = (
				"index of" in title.lower()
				or "parent directory" in body.lower()
			)

			probed.append({
				"path": path,
				"status": code,
				"title": title,
				"hints": path_hint_map.get(path, []),
				"tech_clues": tech_clues,
				"keywords": keywords,
				"server": server,
				"powered_by": powered,
				"content_snippet": body[:500],
				"dir_listing": is_dirlist,
			})
			tshort = (title or "")[:72].replace("\n", " ")
			logger.info(
				"[ReconAgent] 探测 %s | HTTP %s | dirlist=%s | title=%s",
				path, code, is_dirlist, tshort or "(无标题)",
			)
			if log_callback:
				await log_callback(
					f"[ReconAgent] 探测 {path} → HTTP {code} "
					f"{'[目录列表]' if is_dirlist else ''} | {tshort or '—'}"
				)

		logger.info(
			"[ReconAgent] 路径内容探测完成: %d 条响应, 从页面链接新增路径 %d 条",
			len(probed), new_paths,
		)
		if log_callback:
			await log_callback(
				f"[ReconAgent] 路径内容探测完成: 采集 {len(probed)} 条, 新增候选路径 {new_paths} 条"
			)

		dirlist_paths = [item["path"] for item in probed if item.get("dir_listing")]
		if dirlist_paths:
			logger.info(
				"[ReconAgent] 目录列表深扫种子 %d 个: %s",
				len(dirlist_paths), _preview_path_list(dirlist_paths, 15),
			)
			if log_callback:
				await log_callback(
					f"[ReconAgent] 目录列表深扫种子: {_preview_path_list(dirlist_paths, 12)}"
				)
			from backend.tools.parsers.dirlist_crawler import crawl_directory_listings
			try:
				dirlist_result = await crawl_directory_listings(
					base_url=web_target,
					seed_paths=dirlist_paths,
					executor=self.executor,
					max_depth=4,
					max_total_entries=150,
					log_callback=log_callback,
				)
				for dl_entry in dirlist_result.entries:
					aggregator.add_paths(
						[dl_entry.path],
						source="dirlist_deep_crawl",
						status=200 if not dl_entry.is_dir else 0,
					)
				interesting = [e for e in dirlist_result.entries if e.interesting]
				all_entry_paths = [e.path for e in dirlist_result.entries]
				int_paths = [e.path for e in interesting]
				logger.info(
					"[ReconAgent] 目录列表深扫完成: 总条目 %d, 高价值文件 %d | 条目: %s",
					len(dirlist_result.entries), len(interesting),
					_preview_path_list(all_entry_paths, 35),
				)
				if int_paths:
					logger.info(
						"[ReconAgent] 目录列表高价值文件: %s",
						_preview_path_list(int_paths, 25),
					)
				if log_callback:
					await log_callback(
						f"[ReconAgent] 目录列表深度爬取: "
						f"{len(dirlist_result.entries)} 条目, "
						f"{len(interesting)} 个有价值 — "
						f"{_preview_path_list(int_paths or all_entry_paths, 25)}"
					)
			except Exception as e:
				logger.warning(f"[ReconAgent] 目录列表深度爬取失败: {e}")

		return probed

	@staticmethod
	def _parse_probe_blocks(raw: str) -> list[dict[str, str]]:
		records: list[dict[str, str]] = []
		current: dict[str, str] | None = None
		for line in raw.splitlines():
			if line.strip() == "__PATH_PROBE_BEGIN__":
				current = {}
				continue
			if line.strip() == "__PATH_PROBE_END__":
				if current:
					records.append(current)
				current = None
				continue
			if current is None or ":" not in line:
				continue
			key, value = line.split(":", 1)
			current[key.strip()] = value.strip()
		return records

	@staticmethod
	def _safe_int(raw: str, default: int = 0) -> int:
		try:
			return int(raw)
		except Exception:
			return default

	@staticmethod
	def _extract_title(body: str) -> str:
		if not body:
			return ""
		m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE)
		if not m:
			return ""
		return re.sub(r"\s+", " ", m.group(1)).strip()[:120]

	@staticmethod
	def _extract_tech_clues(body: str, title: str, server: str, powered: str) -> list[str]:
		text = f"{body} {title} {server} {powered}".lower()
		mapping = {
			"php": "PHP",
			"jsp": "JSP",
			"spring": "Spring",
			"struts": "Struts",
			"tomcat": "Tomcat",
			"weblogic": "WebLogic",
			"nginx": "Nginx",
			"apache": "Apache",
			"iis": "IIS",
			"wordpress": "WordPress",
			"django": "Django",
			"flask": "Flask",
			"react": "React",
			"vue": "Vue",
		}
		out: list[str] = []
		for kw, label in mapping.items():
			if kw in text and label not in out:
				out.append(label)
		return out[:8]

	@staticmethod
	def _extract_keywords(body: str) -> list[str]:
		text = (body or "").lower()
		kw_order = [
			"login", "password", "token", "apikey", "secret", "upload",
			"admin", "database", "sql", "debug", "traceback", "exception",
		]
		return [kw for kw in kw_order if kw in text][:8]

	def _extract_paths_from_links(self, current_path: str, links_blob: str) -> list[str]:
		if not links_blob:
			return []
		paths: list[str] = []
		for raw in links_blob.split("|"):
			path = self._normalize_link_to_path(raw.strip(), current_path)
			if path and path not in paths:
				paths.append(path)
		return paths[:20]

	@staticmethod
	def _normalize_link_to_path(link: str, current_path: str) -> str:
		if not link:
			return ""
		lower = link.lower()
		if lower.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
			return ""
		if link.startswith(("http://", "https://")):
			path = urlparse(link).path or "/"
		elif link.startswith("/"):
			path = link
		else:
			base_dir = current_path if current_path.endswith("/") else (current_path.rsplit("/", 1)[0] + "/")
			path = urlparse(urljoin(f"http://dummy{base_dir}", link)).path or "/"
		if not path.startswith("/"):
			path = "/" + path
		return path.rstrip("/") or "/"