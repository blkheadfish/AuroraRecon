"""
models.py
所有共享数据模型，集中定义避免循环导入
"""
from __future__ import annotations

import os
import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

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


class CommandExecutionRecord(BaseModel):
	"""统一命令执行记录结构，供 exploit_results 与 decision_event 复用。"""
	id: str = ""
	phase: str = ""
	tool: str = ""
	backend: str = ""
	runtime_command: str = ""
	round: Optional[int] = None
	purpose: str = ""
	timestamp: str = ""  # ISO8601
	command: str = ""
	stdout: str = ""
	stderr: str = ""
	exit_code: Optional[int] = None
	elapsed: Optional[float] = None
	truncated: bool = False
	total_len: int = 0


class DecisionEvent(BaseModel):
	id: str
	timestamp: str = ""
	phase: str = ""
	action: str = "log"
	tool: str = ""
	backend: str = ""
	poc_or_vuln: str = ""
	command: str = ""
	runtime_command: str = ""
	stdout: str = ""
	stderr: str = ""
	exit_code: Optional[int] = None
	elapsed_ms: Optional[int] = None
	purpose: str = ""
	round: Optional[int] = None
	truncated: bool = False
	total_len: int = 0
	message: str = ""
	raw: str = ""
	tone: str = "info"


class ExploitResult(BaseModel):
	vuln_id: str
	success: bool
	shell_type: str = ""
	session_info: dict = Field(default_factory=dict)
	evidence: str = ""
	commands_run: list[str] = Field(default_factory=list)
	# 每条命令对应的执行结果（命令→输出 配对）
	command_results: list[CommandExecutionRecord] = Field(default_factory=list)
	# command_results 格式: [{"command": "...", "stdout": "...", "stderr": "...", "exit_code": 0, "elapsed": 1.2}, ...]
	command_records: list[CommandExecutionRecord] = Field(default_factory=list)  # 兼容旧字段名

	@field_validator("command_results", "command_records", mode="before")
	@classmethod
	def _coerce_command_records(cls, v):
		if not v:
			return []
		if not isinstance(v, list):
			return []
		normalized: list[dict] = []
		for item in v:
			if isinstance(item, dict):
				normalized.append(item)
				continue
			if isinstance(item, str):
				normalized.append({"command": item})
				continue
			if hasattr(item, "model_dump"):
				normalized.append(item.model_dump())
				continue
			if hasattr(item, "__dict__"):
				normalized.append(dict(item.__dict__))
		return normalized


# ───────────────────────────────────────────────────────
# 目标地址解析工具
# ───────────────────────────────────────────────────────

class ParsedTarget(BaseModel):
	"""parse_target() 的返回值"""
	host: str          # 纯主机名或 IP（不含端口、协议）
	port: Optional[int] = None   # 显式指定的端口，None 表示用户未指定
	scheme: str = ""   # http / https / ""（空 = 用户未指定协议）
	path: str = ""     # URL 路径（用户传完整 URL 时保留）
	raw: str = ""      # 原始输入，原样保留


def parse_target(raw: str) -> ParsedTarget:
	"""
	将用户输入的目标字符串统一解析为结构化信息。

	支持的输入格式（与前端 isValidTarget 对齐）:
	  192.168.1.1
	  192.168.1.1:8080
	  example.com
	  example.com:443
	  http://192.168.1.1:8080/path
	  https://example.com:8443/path

	返回:
	  ParsedTarget(host="192.168.1.1", port=8080, scheme="http", path="/path")
	"""
	raw = raw.strip()
	if not raw:
		return ParsedTarget(raw=raw, host="")

	# ── 尝试按 URL 解析（带协议头的情况）──────────────
	if re.match(r'^https?://', raw, re.IGNORECASE):
		parsed = urlparse(raw)
		host = parsed.hostname or ""
		port = parsed.port  # None if not explicit
		scheme = (parsed.scheme or "").lower()
		path = parsed.path or ""
		return ParsedTarget(raw=raw, host=host, port=port, scheme=scheme, path=path)

	# ── 无协议头：host 或 host:port ──────────────────
	match = re.match(r'^(.+?):(\d{1,5})$', raw)
	if match:
		host = match.group(1)
		port_str = match.group(2)
		port = int(port_str)
		if 1 <= port <= 65535:
			return ParsedTarget(raw=raw, host=host, port=port)
		# 端口越界，当作纯 host
		return ParsedTarget(raw=raw, host=raw)

	# ── 纯 host ──────────────────────────────────────
	return ParsedTarget(raw=raw, host=raw)


class PentestState(BaseModel):
	task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
	target: str = ""
	target_os: str = "unknown"
	scope_note: str = ""
	extra_hint: str = ""
	user_prompt: str = ""
	workflow_mode: str = "standard"
	created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

	# ── 解析后的目标信息（parse_target 写入）──────────
	target_host: str = ""          # 纯 host/IP，各 agent 统一使用
	target_port: Optional[int] = None  # 用户显式指定的端口，None = 未指定
	target_scheme: str = ""        # http/https/""
	target_path: str = ""          # URL 路径
	target_raw: str = ""           # 原始用户输入（= target，留作对照）

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
	# 全阶段（recon/vuln/exploit）结构化命令执行记录，供 DecisionChat 展示
	tool_records: list[CommandExecutionRecord] = Field(default_factory=list)
	got_shell: bool = False
	privilege_level: str = ""
	# 利用阶段首轮全部失败后，是否已执行过二次攻击重试
	secondary_attack_done: bool = False
	# 首轮即拿到立足点，未进入二次利用节点（供 UI 标记跳过）
	secondary_elided: bool = False

	# ── 主机攻链状态（VulnHub / 靶机向）：与 findings 并存，策略以攻链为主 ──
	# foothold: none | web_rce | shell | ssh | meterpreter
	foothold_status: str = "none"
	credential_store: list[dict[str, Any]] = Field(default_factory=list)
	loot_store: list[dict[str, Any]] = Field(default_factory=list)
	privesc_hypotheses: list[dict[str, Any]] = Field(default_factory=list)
	# user_proof / root_proof / report_ready 等
	objective_status: dict[str, Any] = Field(default_factory=dict)
	# Agent 给出的结构化「下一步」建议（供编排与前端展示）
	attack_next_steps: list[dict[str, Any]] = Field(default_factory=list)
	privesc_attempt_count: int = 0
	max_privesc_rounds: int = Field(
		default_factory=lambda: max(1, int(os.getenv("MAX_PRIVESC_ROUNDS", "3")))
	)
	chain_summary: str = ""
	# 实际执行过的攻链阶段（有序），供前端进度条精确展示
	chain_visited: list[str] = Field(default_factory=list)

	post_findings: dict = Field(default_factory=dict)

	report_path: str = ""
	report_md: str = ""

	# 人工审批标志（由 resume() 注入，默认 False）
	approved: bool = False

	# 用户-代理对话（决策视图交互式对话）
	user_messages: list[dict] = Field(default_factory=list)
	agent_replies: list[dict] = Field(default_factory=list)

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