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
from typing import Any, Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


# ───────────────────────────────────────────────────────
# 工作流模式(workflow_mode)常量与默认值矩阵
# 说明:
#   一次任务只携带一个 workflow_mode,它决定默认的审批策略 / 证据门槛 /
#   风险预算 / 轮次上限 / Skill 匹配阈值。用户也可以在创建任务时对单项
#   进行覆盖,覆盖值会被 `apply_mode_defaults` 保留。
# ───────────────────────────────────────────────────────

WorkflowMode = Literal["pentest_engineer", "ctf_expert"]

_MODE_DEFAULTS: dict[str, dict[str, Any]] = {
	"pentest_engineer": {
		"auto_approve":        False,      # 企业渗透默认强制人工审批
		"success_gate_level":  "strict",   # 严格证据门槛,避免误报
		"risk_budget":         3,          # 高风险操作额度
		"max_react_rounds":    25,         # ReAct 单漏洞最大轮次
		"max_explore_rounds":  15,         # 探索阶段最大轮次
		"skill_min_score":     20,         # Skill 匹配下限(需要较强信号)
		"skill_weak_boost":    0,          # 不额外加权弱信号
	},
	"ctf_expert": {
		"auto_approve":        True,       # CTF/靶场跳过审批,一把梭
		"success_gate_level":  "lenient",  # 放宽证据门槛(拿 flag 优先)
		"risk_budget":         10,
		"max_react_rounds":    40,
		"max_explore_rounds":  25,
		"skill_min_score":     5,          # 接受弱信号匹配
		"skill_weak_boost":    10,         # 对弱信号命中额外加权
	},
}


def mode_defaults(workflow_mode: str) -> dict[str, Any]:
	"""返回指定 workflow_mode 的默认值,非法 mode 回退到 pentest_engineer。"""
	return dict(_MODE_DEFAULTS.get(workflow_mode, _MODE_DEFAULTS["pentest_engineer"]))


def apply_mode_defaults(
	state: "PentestState",
	overrides: Optional[dict[str, Any]] = None,
) -> "PentestState":
	"""
	将 workflow_mode 的默认值填入 state,随后以 `overrides` 里的非空值覆盖。

	设计要点:
	  - 只写入未被覆盖(或仍为默认零值/None)的字段,避免覆盖用户显式传入的参数。
	  - 调用链:router 收到 CreateTaskRequest → 构造 state(只填 workflow_mode)
	    → 再调用本函数,把 mode 默认值 + 用户显式覆盖写入。
	"""
	defaults = mode_defaults(state.workflow_mode)
	overrides = {k: v for k, v in (overrides or {}).items() if v is not None}

	for key, val in defaults.items():
		if key in overrides:
			setattr(state, key, overrides[key])
		else:
			setattr(state, key, val)
	return state


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
	exploit_level: str = ""  # "rce" | "file_read" | "source_read" | "info_leak" | ""
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
	# ── 工作流模式 + per-task 运行时策略 ───────────────
	# workflow_mode 决定一组默认值(见 _MODE_DEFAULTS),
	# 其余字段允许在创建任务时显式覆盖,不再依赖全局环境变量。
	workflow_mode: WorkflowMode = "pentest_engineer"
	auto_approve: bool = False                        # 自动通过审批(CTF 模式默认 True)
	success_gate_level: str = "strict"                # strict | medium | lenient
	risk_budget: int = 3                              # 允许的高风险操作次数
	max_react_rounds: int = 25                        # ReAct 单漏洞最大轮次
	max_explore_rounds: int = 15                      # 探索阶段最大轮次
	skill_min_score: int = 20                         # SkillRegistry 匹配下限
	skill_weak_boost: int = 0                         # 弱信号命中的额外加权
	created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

	# ── 解析后的目标信息（parse_target 写入）──────────
	target_host: str = ""          # 纯 host/IP，各 agent 统一使用
	target_port: Optional[int] = None  # 用户显式指定的端口，None = 未指定
	target_scheme: str = ""        # http/https/""
	target_path: str = ""          # URL 路径
	target_raw: str = ""           # 原始用户输入（= target，留作对照）

	owner_id: str = ""

	status: TaskStatus = TaskStatus.PENDING
	current_phase: str = "init"
	error_msg: str = ""
	phase_log: list[str] = Field(default_factory=list)

	open_ports: list[PortInfo] = Field(default_factory=list)
	os_info: dict = Field(default_factory=dict)
	web_paths: list[str] = Field(default_factory=list)
	web_paths_inventory: list[dict[str, Any]] = Field(default_factory=list)
	path_contents: list[dict[str, Any]] = Field(default_factory=list)
	dirlist_tree: str = ""
	dirlist_interesting_files: list[str] = Field(default_factory=list)

	# ── LLM 自适应目录探测引擎产出 ──────────────────────
	dir_scan_strategy: dict = Field(default_factory=dict)
	dir_intel: dict = Field(default_factory=dict)
	supplementary_dir_scan_done: bool = False

	# ── intel_harvest 阶段产出 ──────────────────────────
	# 通用 service-info 事实桶（per-service）：
	#   runtime_facts["php"]    -> phpinfo_parser 抽取结果（等价于旧 php_runtime）
	#   runtime_facts["apache"] -> server-status/server-info
	#   runtime_facts["nginx"]  -> stub_status + Server 头
	#   runtime_facts["tomcat"] -> manager/status + manager/serverinfo
	#   runtime_facts["spring"] -> actuator/env|mappings|info|health|configprops
	#   runtime_facts["env_file"] -> .env 类配置文件抽取
	# 每个桶内都带 ``_attack_surface`` 子字段作为高层约束提示。
	runtime_facts: dict[str, dict[str, Any]] = Field(default_factory=dict)
	# 结构化的 PHP 运行时事实 (phpinfo_parser 输出)，保留为 ``runtime_facts['php']``
	# 的兼容别名，旧代码/测试仍能访问：
	#   php_version, sapi, doc_root, disable_functions(list),
	#   allow_url_include(bool), allow_url_fopen(bool), open_basedir,
	#   session_save_path, upload_tmp_dir, loaded_extensions(list), ...
	php_runtime: dict[str, Any] = Field(default_factory=dict)
	# 利用阶段可复用的「已确认事实」：
	#   {"lfi": {"param": ..., "depth": ..., "style": ...,
	#             "readable_files": [...]},
	#    "services": {"ssh_port": 22, "log_readable": [...]},
	#    "creds": [{"user":..., "source":..., "value":...}]}
	confirmed_facts: dict[str, Any] = Field(default_factory=dict)
	# 每个 finding.id 首轮产出的原始 Skill 探测变量（如 lfi_param/lfi_depth…）
	exploit_probe_variables: dict[str, dict[str, Any]] = Field(default_factory=dict)
	# 每个 finding.id 已知失败的命令集合，二次利用避开
	failed_commands_by_vuln: dict[str, list[str]] = Field(default_factory=dict)
	# 文件情报提取结果: [{"path": "/backup/db.sql", "content_snippet": "...", "intel": {LLM结果}}]
	intel_files: list[dict[str, Any]] = Field(default_factory=list)
	# 页面参数发现+验证: [{"url": "http://x/info.php?file=", "param_name": "file",
	#   "method": "GET", "vuln_type": "lfi", "verified": True, "evidence": "..."}]
	page_params: list[dict[str, Any]] = Field(default_factory=list)
	# Paths discovered from file content analysis (new_paths from FILE_INTEL_EXTRACT),
	# consumed by vuln_scan to expand the attack surface
	intel_discovered_paths: list[str] = Field(default_factory=list)

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

	# 结构化决策事件队列（ReAct thinking / Skill reasoning），供 WS 增量推送
	live_decision_events: list[dict] = Field(default_factory=list)

	def log(self, msg: str) -> None:
		import logging
		ts = datetime.utcnow().strftime("%H:%M:%S")
		entry = f"[{ts}] [{self.current_phase}] {msg}"
		self.phase_log.append(entry)
		logging.getLogger(__name__).info(entry)

	def push_decision(self, event: dict) -> None:
		"""Append a structured decision event for real-time WS push."""
		if "id" not in event:
			event["id"] = f"de-{len(self.live_decision_events)}-{datetime.utcnow().strftime('%H%M%S%f')}"
		if "timestamp" not in event:
			event["timestamp"] = datetime.utcnow().strftime("%H:%M:%S")
		self.live_decision_events.append(event)

	@field_validator("fingerprints", mode="before")
	@classmethod
	def _coerce_fingerprint_keys(cls, v: dict) -> dict:
		"""确保 fingerprints 的 key 全部是 str，兼容 msgpack strict_map_key"""
		if isinstance(v, dict):
			return {str(k): val for k, val in v.items()}
		return v