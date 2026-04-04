"""
models.py
所有共享数据模型，集中定义避免循环导入
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class TaskStatus(str, Enum):
	PENDING = "pending"
	RUNNING = "running"
	COMPLETED = "completed"
	FAILED = "failed"


class PortInfo(BaseModel):
	port: int
	protocol: str = "tcp"
	state: str = "open"
	service: str = ""
	version: str = ""
	banner: str = ""


class VulnFinding(BaseModel):
	vuln_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
	name: str
	severity: str = "medium"
	cve: Optional[str] = None
	target: str = ""
	port: Optional[int] = None
	description: str = ""
	evidence: str = ""
	exploitable: bool = False
	tool: str = ""


class ExploitResult(BaseModel):
	vuln_id: str
	success: bool
	shell_type: str = ""
	session_info: dict = Field(default_factory=dict)
	evidence: str = ""
	commands_run: list[str] = Field(default_factory=list)
	# 每条命令对应的执行结果（命令→输出 配对）
	command_results: list[dict] = Field(default_factory=list)
	# command_results 格式: [{"command": "...", "stdout": "...", "stderr": "...", "exit_code": 0, "elapsed": 1.2}, ...]
	command_records: list[dict] = Field(default_factory=list)  # command_records 格式: [{"command": "...", "stdout": "...", "stderr": "...", "exit_code": 0, "elapsed": 1.2, "purpose": "..."}]


class PentestState(BaseModel):
	task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
	target: str = ""
	target_os: str = "unknown"
	scope_note: str = ""
	extra_hint: str = ""
	user_prompt: str = ""
	workflow_mode: str = "standard"
	created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
	
	status: TaskStatus = TaskStatus.PENDING
	current_phase: str = "init"
	error_msg: str = ""
	phase_log: list[str] = Field(default_factory=list)
	
	open_ports: list[PortInfo] = Field(default_factory=list)
	os_info: dict = Field(default_factory=dict)
	web_paths: list[str] = Field(default_factory=list)
	subdomains: list[str] = Field(default_factory=list)
	raw_recon: dict = Field(default_factory=dict)
	
	findings: list[VulnFinding] = Field(default_factory=list)
	raw_vuln: dict = Field(default_factory=dict)
	# VulnAgent 指纹识别结果：{port: {summary, whatweb, httpx, json_probe, ...}}
	fingerprints: dict = Field(default_factory=dict)
	
	exploit_results: list[ExploitResult] = Field(default_factory=list)
	got_shell: bool = False
	privilege_level: str = ""
	
	post_findings: dict = Field(default_factory=dict)
	
	report_path: str = ""
	report_md: str = ""
	
	# 人工审批标志（由 resume() 注入，默认 False）
	approved: bool = False
	
	def log(self, msg: str) -> None:
		import logging
		ts = datetime.utcnow().strftime("%H:%M:%S")
		entry = f"[{ts}] [{self.current_phase}] {msg}"
		self.phase_log.append(entry)
		logging.getLogger(__name__).info(entry)
	
	@field_validator("fingerprints", mode="before")
	@classmethod
	def _coerce_fingerprint_keys(cls, v: dict) -> dict:
		"""确保 fingerprints 的 key 全部是 str，兼容 msgpack strict_map_key"""
		if isinstance(v, dict):
			return {str(k): val for k, val in v.items()}
		return v
