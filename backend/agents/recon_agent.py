"""
recon_agent.py
侦察 Agent —— 端口扫描 / 服务识别 / 目录爆破 / 子域名枚举
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from backend.agents.models import PortInfo
from backend.tools.executor import ToolExecutor, ExecuteResult, LogCallback
from backend.tools.parsers.nmap_parser import NmapParser
from backend.tools.parsers.gobuster_parser import GobusterParser

logger = logging.getLogger(__name__)


class ReconAgent:
	def __init__(self):
		self.executor = ToolExecutor()
		self.nmap_parser = NmapParser()
		self.gobuster_parser = GobusterParser()

	async def run(
		self,
		target: str,
		task_id: Optional[str] = None,
		log_callback: LogCallback = None,
	) -> dict[str, Any]:
		logger.info(f"[ReconAgent] 开始侦察: {target}")

		ports, os_info, raw_nmap = await self._nmap_scan(target, task_id, log_callback)

		web_ports = [p for p in ports if p.service in ("http", "https") or p.port in (80, 443, 8080, 8443, 8888)]
		web_paths: list[str] = []
		raw_gobuster = ""

		if web_ports:
			scheme = "https" if any(p.port in (443, 8443) for p in web_ports) else "http"
			web_target = f"{scheme}://{target}:{web_ports[0].port}"
			web_paths, raw_gobuster = await self._gobuster_scan(web_target, task_id, log_callback)

		return {
			"ports": ports,
			"os_info": os_info,
			"web_paths": web_paths,
			"subdomains": [],
			"raw_nmap": raw_nmap,
			"raw_gobuster": raw_gobuster,
		}

	async def _nmap_scan(
		self,
		target: str,
		task_id: Optional[str],
		log_callback: LogCallback = None,
	) -> tuple[list[PortInfo], dict, str]:
		# 第一轮：常用端口精确扫描（快速、稳定）
		common_ports = "21,22,23,25,53,80,81,110,135,139,143,443,445,993,995,1433,1521,2049,2181,3000,3306,3389,5432,5900,5985,6379,7001,7002,8000,8008,8080,8081,8090,8161,8443,8888,9000,9001,9090,9200,9443,10000,27017,61616"
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

		# 对合并后的端口做精细探测
		port_str = ",".join(str(p) for p in sorted(all_ports)[:50])
		detail_result: ExecuteResult = await self.executor.run(
			tool="nmap",
			args=["-sV", "-sC", "-O", "--osscan-guess", "-Pn", "-p", port_str, "-oX", "-", target],
			timeout=300,
			task_id=task_id,
			log_callback=log_callback,
		)

		if not detail_result.success:
			logger.warning("Nmap 精细扫描失败，使用快速扫描结果")
			return self.nmap_parser.parse_xml(precise_result.stdout or fast_result.stdout), {}, ""

		ports, os_info = self.nmap_parser.parse_xml_full(detail_result.stdout)
		return ports, os_info, detail_result.stdout

	async def _gobuster_scan(
		self,
		web_target: str,
		task_id: Optional[str],
		log_callback: LogCallback = None,
	) -> tuple[list[str], str]:
		# 目标对不存在路径返回 302 时，--wildcard 强制继续扫描
		# -b 排除 302/301/404 避免通配符误报
		# 注意：gobuster 找到路径时 exit_code=1，不能只看 success
		result: ExecuteResult = await self.executor.run(
			tool="gobuster",
			args=[
				"dir",
				"-u", web_target,
				"-w", "/usr/share/wordlists/dirb/common.txt",
				"-t", "30",
				"-q",
				"--no-error",
				"--wildcard",
				"-b", "302,301,404",
			],
			timeout=120,
			task_id=task_id,
			log_callback=log_callback,
		)
		if not result.stdout.strip():
			logger.warning(f"Gobuster 无输出: {result.stderr[:200]}")
			return [], ""

		paths = self.gobuster_parser.parse(result.stdout)
		return paths, result.stdout