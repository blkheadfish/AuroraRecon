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
import logging
import time
from typing import Any, Optional

from backend.agents.models import PortInfo
from backend.tools.executor import ToolExecutor, ExecuteResult, LogCallback, RecordCallback
from backend.tools.parsers.nmap_parser import NmapParser
from backend.tools.parsers.gobuster_parser import GobusterParser
from backend.tools.parsers.path_aggregator import PathAggregator
from backend.tools.tool_coverage_planner import ToolCoveragePlanner, CoverageReport

logger = logging.getLogger(__name__)


class ReconAgent:
	def __init__(self):
		self.executor = ToolExecutor()
		self.nmap_parser = NmapParser()
		self.gobuster_parser = GobusterParser()

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

		# 4th pass: nmap --script=vuln on discovered open ports
		nmap_vuln_hints = await self._nmap_vuln_scan(
			target, [p.port for p in ports], task_id, log_callback,
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
		raw_gobuster = ""
		dir_coverage: dict = {}

		if web_ports:
			scheme = "https" if any(p.port in (443, 8443) for p in web_ports) else "http"
			web_target = f"{scheme}://{target}:{web_ports[0].port}"
			web_paths, raw_gobuster, coverage_rpt = await self._dir_scan(
				web_target, task_id, log_callback,
			)
			dir_coverage = coverage_rpt.to_log_dict()

		return {
			"ports": ports,
			"os_info": os_info,
			"web_paths": web_paths,
			"subdomains": [],
			"raw_nmap": raw_nmap,
			"raw_gobuster": raw_gobuster,
			"nmap_vuln_hints": nmap_vuln_hints,
			"dir_coverage": dir_coverage,
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

		# 第二轮：Top 3000 端口广扫（覆盖非标准端口）
		fast_result: ExecuteResult = await self.executor.run(
			tool="nmap",
			args=["-T4", "-Pn", "--open", "--top-ports", "3000", "-oX", "-", target],
			timeout=300,
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

		# 对合并后的端口做精细探测（公网目标跳过 -O，降低脚本强度）
		port_str = ",".join(str(p) for p in sorted(all_ports)[:50])
		import ipaddress as _ipaddress
		try:
			_is_private = _ipaddress.ip_address(target).is_private
		except ValueError:
			_is_private = False
		if _is_private:
			nmap_detail_args = ["-sV", "-sC", "-O", "--osscan-guess", "-Pn", "-p", port_str, "-oX", "-", target]
		else:
			nmap_detail_args = ["-sV", "--version-intensity", "5", "-Pn", "-p", port_str, "-oX", "-", target]
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
	) -> list[dict]:
		"""4th nmap pass: --script=vuln on discovered open ports."""
		if not open_ports:
			return []
		port_str = ",".join(str(p) for p in sorted(open_ports)[:30])
		logger.info(f"[ReconAgent] Nmap vuln script 扫描: {port_str}")
		result: ExecuteResult = await self.executor.run(
			tool="nmap",
			args=[
				"-sT", "-Pn", "--script=vuln",
				"-p", port_str, "-oX", "-", target,
			],
			timeout=240,
			task_id=task_id,
			log_callback=log_callback,
		)
		if not result.success and not result.stdout:
			logger.warning(f"[ReconAgent] Nmap vuln scan 失败: {(result.stderr or '')[:200]}")
			return []
		hints = self.nmap_parser.parse_vuln_scripts(result.stdout or "")
		if hints:
			logger.info(f"[ReconAgent] Nmap vuln scan 发现 {len(hints)} 个漏洞提示")
		return hints

	async def _dir_scan(
		self,
		web_target: str,
		task_id: Optional[str],
		log_callback: LogCallback = None,
	) -> tuple[list[str], str, CoverageReport]:
		"""Planner-driven multi-tool directory discovery chain."""
		planner = ToolCoveragePlanner(
			categories=["dir_discovery"],
			max_tools=6,
			max_stage_runtime=480,
		)
		plan = planner.build_plan(web_target)
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
			if log_callback:
				await log_callback(f"[ReconAgent] 目录发现: 执行 {tool_name}")
			t0 = time.monotonic()
			try:
				result: ExecuteResult = await self.executor.run_script(
					script_content=tool_spec["script"],
					timeout=tool_spec["timeout"],
					record_purpose=f"{tool_name}_dir_scan",
				)
				elapsed = time.monotonic() - t0
				stdout = result.stdout or ""
				raw_outputs.append(f"=== {tool_name} ===\n{stdout}")

				new_count = aggregator.ingest(tool_name, stdout, web_target)
				planner.record_result(
					tool_name, "executed",
					paths_found=new_count,
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

		return paths, combined_raw, report