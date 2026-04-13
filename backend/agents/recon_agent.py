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
import logging
import os
import re
import shlex
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from backend.agents.models import PortInfo
from backend.tools.executor import ToolExecutor, ExecuteResult, LogCallback, RecordCallback
from backend.tools.parsers.nmap_parser import NmapParser
from backend.tools.parsers.path_aggregator import PathAggregator
from backend.tools.tool_coverage_planner import ToolCoveragePlanner, CoverageReport

logger = logging.getLogger(__name__)


class ReconAgent:
	def __init__(self):
		self.executor = ToolExecutor()
		self.nmap_parser = NmapParser()

	async def run(
		self,
		target: str,
		target_port: Optional[int] = None,
		task_id: Optional[str] = None,
		log_callback: LogCallback = None,
		record_callback: RecordCallback = None,
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
		"""
		if log_callback or record_callback:
			origin_run = self.executor.run
			origin_run_script = self.executor.run_script

			async def _run_with_hooks(*args, **kwargs):
				if log_callback:
					kwargs.setdefault("log_callback", log_callback)
				if record_callback:
					kwargs.setdefault("record_callback", record_callback)
					kwargs.setdefault("record_phase", "recon")
				return await origin_run(*args, **kwargs)

			async def _run_script_with_hooks(*args, **kwargs):
				if log_callback:
					kwargs.setdefault("log_callback", log_callback)
				if record_callback:
					kwargs.setdefault("record_callback", record_callback)
					kwargs.setdefault("record_phase", "recon")
				return await origin_run_script(*args, **kwargs)

			self.executor.run = _run_with_hooks
			self.executor.run_script = _run_script_with_hooks

		logger.info(f"[ReconAgent] 开始侦察: {target}" +
		            (f" (用户指定端口: {target_port})" if target_port else ""))

		ports, os_info, raw_nmap = await self._nmap_scan(
			target, target_port, task_id, log_callback,
		)

		# 4th pass: targeted per-service nmap vuln scripts
		nmap_vuln_hints = await self._nmap_vuln_scan(
			target, [p.port for p in ports], task_id, log_callback,
			ports_info=ports,
		)

		llm_recon_hints = await self._llm_analyze_nmap(
			target, raw_nmap, ports, log_callback,
		)

		web_ports = [
			p for p in ports
			if p.service in ("http", "https")
			or p.port in (80, 443, 8080, 8443, 8888)
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

		if web_ports:
			primary_scheme = "https" if web_ports[0].port in (443, 8443) else "http"
			primary_target = f"{primary_scheme}://{target}:{web_ports[0].port}"

			has_waf = await self._detect_waf(
				primary_target, task_id, log_callback,
			)
			tech_hints = await self._quick_fingerprint(
				target, web_ports, task_id, log_callback,
			)

			aggregator = PathAggregator()
			raw_outputs_all: list[str] = []
			coverage_reports: list[dict] = []

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
				)
				raw_outputs_all.append(raw_out)
				coverage_reports.append(coverage_rpt.to_log_dict())
				for p_entry in port_aggregator._entries.values():
					if p_entry.path in aggregator._entries:
						aggregator._entries[p_entry.path].merge(p_entry)
					else:
						aggregator._entries[p_entry.path] = p_entry

			path_contents = await self._probe_path_contents(
				web_target=primary_target,
				aggregator=aggregator,
				task_id=task_id,
				log_callback=log_callback,
			)
			web_paths = aggregator.get_actionable_paths()
			raw_gobuster = "\n".join(raw_outputs_all)
			dir_coverage = coverage_reports[0] if coverage_reports else {}

		subdomains = await self._subdomain_enum(
			target, task_id, log_callback,
		)

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
		}

	async def _nmap_scan(
		self,
		target: str,
		target_port: Optional[int],
		task_id: Optional[str],
		log_callback: LogCallback = None,
	) -> tuple[list[PortInfo], dict, str]:
		# 常用端口列表
		common_ports_list = [
			21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143, 443, 445, 993, 995,
			1433, 1521, 2049, 2181, 3000, 3306, 3389, 5432, 5900, 5985, 6379,
			7001, 7002, 8000, 8008, 8080, 8081, 8090, 8161, 8443, 8888, 9000,
			9001, 9090, 9200, 9443, 10000, 27017, 61616,
		]

		# 如果用户显式指定了端口，确保它在常用端口列表中
		if target_port and target_port not in common_ports_list:
			common_ports_list.append(target_port)

		common_ports = ",".join(str(p) for p in sorted(common_ports_list))

		# 第一轮：常用端口精确扫描（快速、稳定）
		precise_result: ExecuteResult = await self.executor.run(
			tool="nmap",
			args=["-T4", "-Pn", "--open", "-p", common_ports, "-oX", "-", target],
			timeout=120,
			task_id=task_id,
			log_callback=log_callback,
		)

		precise_ports = []
		if precise_result.success:
			precise_ports = self.nmap_parser.extract_open_ports(precise_result.stdout)

		# 第二轮：全端口扫描（覆盖所有 65535 端口）
		fast_result: ExecuteResult = await self.executor.run(
			tool="nmap",
			args=["-T4", "-Pn", "--open", "--min-rate", "2000", "-p-", "-oX", "-", target],
			timeout=600,
			task_id=task_id,
			log_callback=log_callback,
		)

		fast_ports = []
		if fast_result.success:
			fast_ports = self.nmap_parser.extract_open_ports(fast_result.stdout)

		# 合并两轮结果
		all_ports = list(set(precise_ports + fast_ports))
		if not all_ports:
			logger.warning("两轮扫描均未发现开放端口")
			return [], {}, precise_result.stdout or ""

		port_str = ",".join(str(p) for p in sorted(all_ports)[:50])
		try:
			_is_private = _ipaddress.ip_address(target).is_private
		except ValueError:
			_is_private = False
		if _is_private:
			nmap_detail_args = ["-A", "--osscan-guess", "-Pn", "-p", port_str, "-oX", "-", target]
		else:
			nmap_detail_args = ["-sV", "--version-all", "-sC", "-Pn", "-p", port_str, "-oX", "-", target]
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
		return ports, os_info, detail_result.stdout

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
						"-sT", "-Pn",
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
						"-sT", "-Pn", "--script=vuln",
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

			if log_callback:
				await log_callback("[ReconAgent] LLM 分析 Nmap 扫描结果...")

			llm = LLMRouter()
			prompt = RECON_ANALYSIS.format(
				target=target,
				raw_output=nmap_snippet,
			)
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
	) -> tuple[list[str], str, CoverageReport, PathAggregator]:
		"""Planner-driven multi-tool directory discovery chain."""
		planner = ToolCoveragePlanner(
			categories=["dir_discovery"],
			max_tools=6,
			max_stage_runtime=480,
		)
		plan = planner.build_plan(
			web_target, has_waf=has_waf, tech_hints=tech_hints,
		)
		aggregator = PathAggregator()
		raw_outputs: list[str] = []

		for tool_spec in plan:
			should, skip_reason = planner.should_run(tool_spec)
			if not should:
				planner.record_result(
					tool_spec["name"], "skipped", skip_reason=skip_reason,
				)
				if log_callback:
					await log_callback(
						f"[ReconAgent] 跳过 {tool_spec['name']}: {skip_reason}"
					)
				continue

			tool_name = tool_spec["name"]
			runtime_command = str(tool_spec.get("runtime_command") or tool_spec.get("script") or "").strip()
			command_preview = " ".join(runtime_command.split())
			if len(command_preview) > 260:
				command_preview = command_preview[:260] + "..."
			if log_callback:
				await log_callback(
					f"[ReconAgent] 目录发现: 执行 {tool_name} | "
					f"timeout={tool_spec['timeout']}s | cmd={command_preview}"
				)
			t0 = time.monotonic()
			try:
				result: ExecuteResult = await self.executor.run_script(
					script_content=tool_spec["script"],
					timeout=tool_spec["timeout"],
					task_id=task_id,
					log_callback=log_callback,
					record_purpose=f"{tool_name}_dir_scan",
					record_runtime_command=runtime_command,
				)
				elapsed = time.monotonic() - t0
				stdout = result.stdout or ""
				raw_outputs.append(f"=== {tool_name} ===\n{stdout}")

				new_count = aggregator.ingest(tool_name, stdout, web_target)
				actionable_count = len(aggregator.get_actionable_paths())
				planner.record_result(
					tool_name, "executed",
					paths_found=new_count,
					actionable_found=actionable_count,
					raw_len=len(stdout),
					elapsed=elapsed,
				)
				if log_callback:
					await log_callback(
						f"[ReconAgent] {tool_name} 完成: "
						f"+{new_count} 路径 (累计 {aggregator.count}), "
						f"{elapsed:.1f}s"
					)
			except asyncio.TimeoutError:
				elapsed = time.monotonic() - t0
				planner.record_result(
					tool_name, "timeout", elapsed=elapsed,
					skip_reason=f"timeout after {elapsed:.0f}s",
				)
				if log_callback:
					await log_callback(
						f"[ReconAgent] {tool_name} 超时 ({elapsed:.0f}s)"
					)
			except Exception as e:
				elapsed = time.monotonic() - t0
				planner.record_result(
					tool_name, "failed",
					skip_reason=str(e)[:200], elapsed=elapsed,
				)
				logger.warning(f"[ReconAgent] {tool_name} 异常: {e}")

		report = planner.coverage_report()
		paths = aggregator.get_actionable_paths()
		combined_raw = "\n".join(raw_outputs)

		if log_callback:
			await log_callback(
				f"[ReconAgent] 目录发现完成: {len(paths)} 路径, "
				f"覆盖率{'达标' if report.satisfied else '未达标'} "
				f"({report.total_elapsed:.0f}s)"
			)
		if not report.satisfied:
			for v in report.violations:
				logger.warning(f"[ReconAgent] 覆盖率不足: {v}")

		return paths, combined_raw, report, aggregator

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

		if log_callback:
			await log_callback(
				f"[ReconAgent] 路径内容探测: 准备探测 {len(candidates)} 条高价值路径"
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

		if log_callback:
			await log_callback(
				f"[ReconAgent] 路径内容探测完成: 采集 {len(probed)} 条, 新增候选路径 {new_paths} 条"
			)
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