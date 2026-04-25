"""nmap_parser.py —— 解析 Nmap XML 输出"""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
import logging
from backend.agents.models import PortInfo

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)


class NmapParser:
	def extract_open_ports(self, xml_output: str) -> list[int]:
		"""从 XML 中快速提取开放端口号列表"""
		ports = []
		try:
			root = ET.fromstring(xml_output)
			for port_elem in root.iter("port"):
				state_elem = port_elem.find("state")
				if state_elem is not None and state_elem.get("state") == "open":
					ports.append(int(port_elem.get("portid", 0)))
		except ET.ParseError as e:
			logger.warning(f"Nmap XML 解析失败（快速模式）: {e}")
		return ports
	
	def parse_xml(self, xml_output: str) -> list[PortInfo]:
		"""解析 XML，返回基础 PortInfo 列表"""
		ports, _ = self.parse_xml_full(xml_output)
		return ports
	
	def parse_xml_full(self, xml_output: str) -> tuple[list[PortInfo], dict]:
		"""
		解析完整 Nmap XML，提取端口信息和 OS 指纹。
	
		Returns:
		    (ports, os_info)
		"""
		ports: list[PortInfo] = []
		os_info: dict = {}
		
		if not xml_output or not xml_output.strip():
			return ports, os_info
		
		try:
			root = ET.fromstring(xml_output)
		except ET.ParseError as e:
			logger.warning(f"Nmap XML 解析失败: {e}")
			return ports, os_info
		
		for host in root.iter("host"):
			# 解析端口
			for port_elem in host.iter("port"):
				state_elem = port_elem.find("state")
				if state_elem is None or state_elem.get("state") != "open":
					continue
				
				service_elem = port_elem.find("service")
				service_name = ""
				service_version = ""
				banner = ""
				
				if service_elem is not None:
					service_name = service_elem.get("name", "")
					product = service_elem.get("product", "")
					version = service_elem.get("version", "")
					extra_info = service_elem.get("extrainfo", "")
					service_version = f"{product} {version} {extra_info}".strip()
					
					# 收集 script 输出作为 banner
					for script in port_elem.iter("script"):
						if script.get("id") in ("banner", "http-title", "ssh-hostkey"):
							banner += f"{script.get('id')}: {script.get('output', '')[:100]} "
				
				ports.append(PortInfo(port=int(port_elem.get("portid", 0)), protocol=port_elem.get("protocol", "tcp"), state="open", service=service_name, version=service_version, banner=banner.strip(), ))
			
			# 解析 OS 指纹
			os_elem = host.find("os")
			if os_elem is not None:
				osmatch = os_elem.find("osmatch")
				if osmatch is not None:
					os_name = osmatch.get("name", "")
					accuracy = osmatch.get("accuracy", "0")
					os_type = "unknown"
					os_lower = os_name.lower()
					if "windows" in os_lower:
						os_type = "windows"
					elif any(k in os_lower for k in ["linux", "ubuntu", "debian", "centos", "unix"]):
						os_type = "linux"
					os_info = {"os_name": os_name, "accuracy": accuracy, "os_type": os_type, }
		
		logger.info(f"Nmap 解析完成: {len(ports)} 个开放端口, OS={os_info.get('os_name', '未知')}")
		return ports, os_info

	def parse_vuln_scripts(self, xml_output: str) -> list[dict]:
		"""Parse nmap --script=vuln XML output into vulnerability hint dicts.

		Returns list of:
		  {"port": int, "script_id": str, "cves": [str], "output": str, "state": str}
		  state is "VULNERABLE" / "LIKELY VULNERABLE" / "info"
		"""
		hints: list[dict] = []
		if not xml_output or not xml_output.strip():
			return hints
		try:
			root = ET.fromstring(xml_output)
		except ET.ParseError as e:
			logger.warning(f"Nmap vuln XML 解析失败: {e}")
			return hints

		for host in root.iter("host"):
			for port_elem in host.iter("port"):
				state_elem = port_elem.find("state")
				if state_elem is None or state_elem.get("state") != "open":
					continue
				port_id = int(port_elem.get("portid", 0))
				for script in port_elem.iter("script"):
					hint = self._parse_vuln_script(script, port_id)
					if hint:
						hints.append(hint)
			hostscript = host.find("hostscript")
			if hostscript is not None:
				for script in hostscript.iter("script"):
					hint = self._parse_vuln_script(script, 0)
					if hint:
						hints.append(hint)
		if hints:
			logger.info(f"Nmap vuln scripts: 发现 {len(hints)} 个漏洞提示")
		return hints

	_VULN_FAIL_MARKERS = (
		"script execution failed",
		"no script results",
		"error:",
		"caused no output",
		"connection refused",
		"connection timed out",
	)

	@staticmethod
	def _parse_vuln_script(script_elem, port: int) -> dict | None:
		sid = script_elem.get("id", "")
		output = script_elem.get("output", "")
		if not sid or not output:
			return None
		out_lower = output.lower()
		is_vuln_script = "vuln" in sid.lower()
		has_vuln_signal = "vulnerable" in out_lower or "exploitable" in out_lower

		if not is_vuln_script and not has_vuln_signal:
			return None
		if "not vulnerable" in out_lower and "vulnerable" not in out_lower.replace("not vulnerable", ""):
			return None

		# Discard scripts that failed to execute — these are NOT vulnerability evidence
		has_failure = any(m in out_lower for m in NmapParser._VULN_FAIL_MARKERS)
		if has_failure and not has_vuln_signal:
			return None

		cves = _CVE_RE.findall(output)

		if has_vuln_signal and "vulnerable" in out_lower:
			state = "VULNERABLE"
		elif "likely" in out_lower:
			state = "LIKELY VULNERABLE"
		else:
			state = "info"

		return {
			"port": port,
			"script_id": sid,
			"cves": [c.upper() for c in cves],
			"output": output[:1500],
			"state": state,
		}
