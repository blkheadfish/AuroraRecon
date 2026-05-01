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

from pydantic import BaseModel, Field, PrivateAttr, field_validator


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
	AWAITING_APPROVAL = "awaiting_approval"
	WAITING_USER = "waiting_user"
	COMPLETED = "completed"
	FAILED = "failed"


# ───────────────────────────────────────────────────────
# OperatorPlan — 操作员实时重规划计划
#
# 设计:
#   用户在任务执行过程中给出新指令时, Operator Replanner 一次 LLM 调用把
#   "用户的话 + 当前事实"翻译成一份**结构化战术计划**, 沿 PentestState
#   透传到 supervisor / 各阶段节点 / ToolCoveragePlanner, 让下游确定性逻辑
#   按计划执行, 而不是各自再去解读一遍 pending_user_prompt 字符串。
#
# 字段语义:
#   - 阶段层(`next_phase` / `target_phases` / `skip_phases` / `rerun_current`)
#     由 supervisor / linear-edge 直接消费, 决定路由
#   - 战术层(`focus_targets` / `preferred_tools` / `avoided_tools` /
#     `keyword_hints` / `extra_constraints`)由节点内 planner 消费, 影响工具
#     选择 / 路径过滤 / 字典生成
#   - 安全层(`needs_human_approval`)由 human_approval / privesc 节点消费,
#     用户明确授权时才允许跳过审批
# ───────────────────────────────────────────────────────


class OperatorFocusTarget(BaseModel):
	"""一个聚焦目标。``type`` 通常是 port/path/host/service/cve, ``value`` 是值。"""
	type: str
	value: str


class OperatorPlan(BaseModel):
	plan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
	created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

	# 触发本次重规划时的"原始用户指令"(operator_guidance_block 的拼接产物),
	# 仅作审计 / 回放用, 不应直接喂给下游节点。
	user_request: str = ""

	# 触发时的当前阶段, 用于 rerun_current / 派生 re_<phase>_for_operator 信号。
	source_phase: str = ""

	# ── LLM 输出的语义层 ─────────────────────────────────────
	intent_summary: str = ""    # 一句话回放你听到的核心意图(给前端展示)
	rationale: str = ""         # 2~4 句解释为什么这么规划

	# ── 阶段层 ────────────────────────────────────────────────
	next_phase: Optional[str] = None       # 强烈建议下一阶段(supervisor 优先采纳)
	target_phases: list[str] = Field(default_factory=list)
	skip_phases: list[str] = Field(default_factory=list)
	rerun_current: bool = False            # 当前阶段是否要求重跑

	# ── 战术层 ────────────────────────────────────────────────
	focus_targets: list[OperatorFocusTarget] = Field(default_factory=list)
	preferred_tools: list[str] = Field(default_factory=list)
	avoided_tools: list[str] = Field(default_factory=list)
	keyword_hints: list[str] = Field(default_factory=list)
	extra_constraints: dict[str, Any] = Field(default_factory=dict)

	# ── 安全层 ────────────────────────────────────────────────
	needs_human_approval: bool = True

	# ── 协同 / 衍生 ──────────────────────────────────────────
	# 已经被哪些节点 / 路由消费过, 用于"一次性指令"语义和过期判断。
	consumed_by: list[str] = Field(default_factory=list)
	# 由 _derive_signals 计算, 写到 state.replan_signals 让 feedback DAG 复用
	# 现有的 re_recon_for_hosts / re_vuln_scan_for_creds 等信号通路。
	derived_replan_signals: dict[str, int] = Field(default_factory=dict)

	@field_validator("focus_targets", mode="before")
	@classmethod
	def _coerce_focus_targets(cls, v):
		if not v:
			return []
		out: list[Any] = []
		for item in v:
			if isinstance(item, OperatorFocusTarget):
				out.append(item)
				continue
			if isinstance(item, dict):
				ttype = str(item.get("type", "")).strip().lower()
				tval = str(item.get("value", "")).strip()
				if ttype and tval:
					out.append(OperatorFocusTarget(type=ttype, value=tval))
		return out


# ───────────────────────────────────────────────────────
# 分支(branch)模型 — 见 conversation_branching_like_claude_kimi 计划
# ───────────────────────────────────────────────────────

BranchStatus = Literal["running", "paused", "completed", "failed"]


class TaskBranch(BaseModel):
	"""一条任务对话/执行分支(类似 Claude/Kimi 的 message branch)。

	每个分支映射到 LangGraph 一个独立的 ``thread_id`` ——
	``thread_id = f"{task_id}:{branch_id}"`` —— 因此 checkpoint 树是物理
	隔离的, fork 后两个分支的执行不会互相污染。

	Sibling 计算规则: 共享 ``parent_branch_id`` 与 ``fork_event_id`` 的所有
	分支构成 sibling 集合, UI 上 ``<n/m>`` 在那个 fork 点上展示。
	"""
	branch_id: str
	task_id: str
	parent_branch_id: Optional[str] = None
	fork_event_id: Optional[str] = None     # 父分支 timeline 上的 decision_event.id
	fork_phase: str = ""
	fork_round: Optional[int] = None
	thread_id: str = ""                     # f"{task_id}:{branch_id}"
	status: BranchStatus = "running"
	created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
	updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
	label: str = ""                         # 自动从 prompt 截 30 字
	initiating_prompt: str = ""             # 触发本分支的 user_prompt(root 为空)
	is_root: bool = False                   # 兼容老任务: 第一个 branch 标 is_root=True


# ── 意图解析与安全卡口 ──────────────────────────────────

TargetType = Literal["ip", "cidr", "domain", "hostname_pattern", "unknown"]
AmbiguityLevel = Literal["clear", "partial", "vague"]
RiskLevel = Literal["safe", "warning", "blocked"]


class ParsedIntent(BaseModel):
	"""任务意图解析结果——正则优先提取，LLM 辅助语义补充。

	仅在 LLM 可用时才填充 scope_hint / task_focus / pentest_phase 等语义字段；
	基础正则（IP/CIDR/域名）是确定性逻辑，不依赖 LLM。
	"""
	target_type: TargetType = "unknown"
	targets: list[str] = Field(default_factory=list)
	scope_hint: Optional[str] = None       # "intranet", "dmz", "specific_host"
	task_focus: list[str] = Field(default_factory=list)    # ["web", "database"]
	pentest_phase: list[str] = Field(default_factory=list)  # ["recon", "exploit"]
	priority_vulns: list[str] = Field(default_factory=list) # ["shiro", "fastjson"]
	requires_discovery: bool = False  # 是否需要先做主机发现（masscan 存活扫描）
	ambiguity_level: AmbiguityLevel = "vague"
	clarification_needed: list[str] = Field(default_factory=list)
	raw_prompt: str = ""


class SafetyCheckResult(BaseModel):
	"""确定性安全校验结果——不依赖 LLM，所有规则来自 YAML 配置。

	三层模型：
	  - 有 authorization_token → 放行（仅记录审计日志）
	  - 命中黑名单（云服务商/政府IP段 + 无授权）→ blocked
	  - 命中灰名单（公网IP无授权 / CIDR过大 / exploit阶段无明确目标）→ warning
	"""
	passed: bool
	risk_level: RiskLevel = "safe"
	block_reason: Optional[str] = None
	warnings: list[str] = Field(default_factory=list)
	required_confirmations: list[str] = Field(default_factory=list)


class PortInfo(BaseModel):
	port: int
	protocol: str = "tcp"
	state: str = "open"
	service: str = ""
	version: str = ""
	banner: str = ""


CONFIDENCE_THRESHOLD_EXPLOIT = 60

VerificationStatus = Literal[
	"confirmed", "likely", "suspected", "unverified", "rejected"
]


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
	confidence: int = 50
	verification_status: VerificationStatus = "unverified"
	verification_reasons: list[str] = Field(default_factory=list)
	evidence_snippets: list[dict[str, str]] = Field(default_factory=list)


class CommandExecutionRecord(BaseModel):
	"""统一命令执行记录结构，供 exploit_results 与 decision_event 复用。

	``tool`` 是后端逻辑用的工具 key（可能是 ``/bin/bash`` 这类 shell 包装），
	``display_tool`` 是给 UI 显示的友好名（``nmap``/``curl``/``script`` 等），
	避免前端工具链节点出现一堆 ``/bin/bash``。
	"""
	id: str = ""
	phase: str = ""
	tool: str = ""
	display_tool: str = ""
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
	display_tool: str = ""
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


class TaskFact(BaseModel):
	"""任务级统一事实对象。"""
	fact_key: str
	fact_type: str = ""
	value: Any = None
	source: str = ""
	source_node: str = ""
	version: int = 1
	first_seen_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
	last_seen_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
	confidence: float = 1.0


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


# ───────────────────────────────────────────────────────
# AttackGraph — 结构化的攻击图模型
# ───────────────────────────────────────────────────────

AttackNodeType = Literal[
	"host", "service", "finding", "credential", "foothold", "loot",
	"objective", "path",
]

AttackEdgeRelation = Literal[
	"enables", "leads_to", "exposes", "consumes", "discovers",
]


class AttackGraphNode(BaseModel):
	"""一个攻击图节点（host/service/finding/credential 等）。"""
	id: str
	type: AttackNodeType
	label: str = ""
	facts: dict[str, Any] = Field(default_factory=dict)
	discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
	discovered_by: str = ""


class AttackGraphEdge(BaseModel):
	"""攻击图边。"""
	src: str
	dst: str
	relation: AttackEdgeRelation = "leads_to"
	note: str = ""
	created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class AttackGraph(BaseModel):
	"""轻量级攻击图，记录可视化所需的节点 / 边。

	设计要点：
	  - upsert_node：若同 id 节点已存在则合并 facts，不会覆盖发现时间；
	  - add_edge：自动去重；
	  - 大小有上限，防止反馈循环导致 checkpoint payload 失控。
	"""
	nodes: list[AttackGraphNode] = Field(default_factory=list)
	edges: list[AttackGraphEdge] = Field(default_factory=list)
	max_nodes: int = 500
	max_edges: int = 2000

	def _index(self) -> dict[str, int]:
		return {n.id: i for i, n in enumerate(self.nodes)}

	def upsert_node(
		self,
		node_id: str,
		*,
		type: AttackNodeType,
		label: str = "",
		facts: Optional[dict[str, Any]] = None,
		discovered_by: str = "",
	) -> AttackGraphNode:
		idx = self._index().get(node_id)
		if idx is not None:
			existing = self.nodes[idx]
			if facts:
				merged = dict(existing.facts or {})
				merged.update(facts)
				existing.facts = merged
			if label and not existing.label:
				existing.label = label
			if discovered_by and not existing.discovered_by:
				existing.discovered_by = discovered_by
			return existing
		if len(self.nodes) >= self.max_nodes:
			# 简单保护：到达上限后丢弃最旧的非 host/objective 节点
			drop_at: Optional[int] = None
			for i, n in enumerate(self.nodes):
				if n.type not in ("host", "objective"):
					drop_at = i
					break
			if drop_at is not None:
				dropped = self.nodes.pop(drop_at)
				self.edges = [
					e for e in self.edges
					if e.src != dropped.id and e.dst != dropped.id
				]
		node = AttackGraphNode(
			id=node_id, type=type, label=label or node_id,
			facts=dict(facts or {}), discovered_by=discovered_by,
		)
		self.nodes.append(node)
		return node

	def add_edge(
		self,
		src: str,
		dst: str,
		*,
		relation: AttackEdgeRelation = "leads_to",
		note: str = "",
	) -> Optional[AttackGraphEdge]:
		if not src or not dst or src == dst:
			return None
		# 去重
		for e in self.edges:
			if e.src == src and e.dst == dst and e.relation == relation:
				return e
		if len(self.edges) >= self.max_edges:
			# 简单保护：丢弃最旧的非 enables 类型边
			drop_at: Optional[int] = None
			for i, ee in enumerate(self.edges):
				if ee.relation != "enables":
					drop_at = i
					break
			if drop_at is not None:
				self.edges.pop(drop_at)
		edge = AttackGraphEdge(src=src, dst=dst, relation=relation, note=note)
		self.edges.append(edge)
		return edge

	def to_payload(self) -> dict[str, Any]:
		return {
			"nodes": [n.model_dump() for n in self.nodes],
			"edges": [e.model_dump() for e in self.edges],
		}


class PentestState(BaseModel):
	task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
	target: str = ""
	target_os: str = "unknown"
	scope_note: str = ""
	extra_hint: str = ""
	user_prompt: str = ""
	# ── 意图解析 + 安全卡口（新增）─────────────────
	# raw_prompt: 用户自然语言描述（兼容旧 target 字段）
	raw_prompt: str = ""
	# parsed_intent: 意图解析器产出的结构化结果
	parsed_intent: Optional[dict[str, Any]] = None
	# safety_check_result: 安全卡口的校验结果
	safety_check_result: Optional[dict[str, Any]] = None
	# authorization_token: 用户提供的授权证明
	authorization_token: Optional[str] = None
	# ── 工作流模式 + per-task 运行时策略 ───────────────
	# workflow_mode 决定一组默认值(见 _MODE_DEFAULTS),
	# 其余字段允许在创建任务时显式覆盖,不再依赖全局环境变量。
	workflow_mode: WorkflowMode = "pentest_engineer"
	auto_approve: bool = False                        # 自动通过审批(CTF 模式默认 True)
	success_gate_level: str = "strict"                # strict | medium | lenient
	risk_budget: int = 3                              # 允许的高风险操作次数
	risk_budget_used: int = 0                         # 已消耗的高风险操作次数
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
	tenant_id: str = "default"

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
	# 统一事实仓（强一致主存储）；confirmed_facts 为兼容投影视图
	task_facts: dict[str, TaskFact] = Field(default_factory=dict)
	fact_version: int = 0
	last_fact_normalized_at: str = ""
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
	# KB 探针扫描命中：在 intel_harvest 阶段由 ProbeScanner 产出
	# 结构：[{"vuln_id": "shiro_cve2016_4437", "dispatch_skill": "shiro_rce",
	#         "confidence": 0.95, "base_url": "http://10.0.0.5:8080",
	#         "port": 8080, "evidence": "...", "cves": [...]}]
	# 后续 SkillRegistry.match() 会读取此字段加权对应 Skill。
	kb_probe_hits: list[dict[str, Any]] = Field(default_factory=list)

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
	# 注：feedback / supervisor 模式下改为按计数判断（见 secondary_attack_count）
	secondary_attack_done: bool = False
	# 首轮即拿到立足点，未进入二次利用节点（供 UI 标记跳过）
	secondary_elided: bool = False
	# 二次攻击执行次数（feedback 模式可重入，linear 模式仍兼容 secondary_attack_done）
	secondary_attack_count: int = 0
	max_secondary_attacks: int = 2

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
	report_error: str = ""

	# 人工审批标志（由 resume() 注入，默认 False）
	approved: bool = False
	# 后渗透阶段独立审批标志，与 approved 互不干扰
	post_approved: bool = False

	# ── 通用决策 checkpoint 协议 ─────────────────────────
	# pending_checkpoint: 当前正在等待用户响应的 checkpoint(若有),
	#   结构见 CheckpointPayload(下方),为 None 表示当前无人工干预需求。
	# checkpoint_history:  已经完成的 checkpoint(含用户响应),用于审计和
	#   断线重连后的回放;新条目追加在末尾,前端按 checkpoint_id 去重。
	# pending_user_prompt: 上一轮 checkpoint 的 user_prompt,会拼接到
	#   下一阶段的 LLM system prompt 末尾,做软引导。
	pending_checkpoint: Optional[dict[str, Any]] = None
	checkpoint_history: list[dict[str, Any]] = Field(default_factory=list)
	pending_user_prompt: str = ""

	# 用户-代理对话（决策视图交互式对话）
	user_messages: list[dict] = Field(default_factory=list)
	agent_replies: list[dict] = Field(default_factory=list)

	# ── 操作员实时重规划(Operator Replanner)───────────────────
	# 由 backend.agents.operator_replanner.llm_replan() 在 chat 触发 fork 时
	# 同步生成一份结构化战术计划; supervisor / 各阶段节点 / ToolCoveragePlanner
	# 统一从这里取数, 避免每个节点各自再去解读 pending_user_prompt 字符串。
	# 计划是 sticky 的, 直到下一次新指令产生新的 OperatorPlan 才被覆盖。
	operator_plan: Optional[OperatorPlan] = None
	# 历史计划(末尾追加, 限长 20), 用于审计 / 调试 / 回放。
	operator_plan_history: list[OperatorPlan] = Field(default_factory=list)

	# guard_stats 记录每类拦截 (preflight reject / repeat failed / reprobe) 的累计次数,
	# 走 ``health.metrics_overview`` 透出, 并不依赖事件流。
	guard_stats: dict[str, int] = Field(default_factory=dict)
	trace_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])

	# ── 攻击链反馈循环（feedback / supervisor 模式共用）────────────
	# 待消费的"种子"事实：在反馈/监督模式下，下游节点（如 post_foothold_enum）
	# 发现新事实后，写入对应 bucket，上游节点（recon/surface_enum/vuln_scan）
	# 重新进入时把它们并入本次输入再执行。
	pending_seeds: dict[str, list[Any]] = Field(default_factory=lambda: {
		"hosts": [],
		"ports": [],
		"web_paths": [],
		"credentials": [],
	})
	# 每个阶段的进入次数与上次输入签名（避免相同输入重复执行）
	phase_visit_count: dict[str, int] = Field(default_factory=dict)
	phase_signature: dict[str, str] = Field(default_factory=dict)
	# 各阶段的访问次数上限（防止反馈循环里某阶段被无限拉起）
	max_phase_visits: dict[str, int] = Field(default_factory=lambda: {
		"recon": 3,
		"surface_enum": 4,
		"intel_harvest": 3,
		"vuln_scan": 4,
		"foothold_attempt": 3,
		"secondary_attack": 2,
		"post_foothold_enum": 4,
		"privesc_attempt": 3,
	})
	# 信号驱动的"重新规划"信号桶：见 fact_hooks.emit_replan_signals
	replan_signals: dict[str, int] = Field(default_factory=dict)
	# 已执行的反馈跳数（保护：超过 max_replan 后强制走默认分支）
	replan_count: int = 0
	max_replan: int = 3

	# ── Supervisor 模式状态字段 ──────────────────────────────
	# supervisor 路由出的"下一阶段"
	next_phase: str = ""
	# supervisor 已进入的轮次（防 LLM 路由失控）
	supervisor_round: int = 0
	supervisor_round_limit: int = 30
	# supervisor 决策历史尾部（用于"连续 3 轮选同 phase 且无新 fact → 强制 report"）
	supervisor_history: list[dict[str, Any]] = Field(default_factory=list)
	# 给 foothold/privesc 接力使用：审批是否已通过一次（避免 supervisor
	# 模式下星形拓扑反复在 interrupt_before 暂停）
	approved_once: bool = False
	post_approved_once: bool = False

	# ── AttackGraph（结构化的攻击图，可视化用）────────────────
	# 单点写入入口：fact_sink / apply_service_info_extraction 中产生新事实时
	# 顺手 upsert 进来。非 supervisor 模式也会被填充，前端可以独立展示。
	attack_graph: AttackGraph = Field(default_factory=AttackGraph)

	# ── 对话分支(Claude/Kimi 风格) ──────────────────────────
	# 每个 task 是一棵以 root branch 为根的分支森林。BranchManager 维护
	# task_branches 表 + 每个 branch 一个 LangGraph thread_id;
	# active_branch_id 在切换时更新, 写到 PentestState 仅为前端 / API 回显。
	# root_branch_id 在第一次 fork 之前, 由 lazy_init_root 写入。
	active_branch_id: str = ""
	root_branch_id: str = ""

	# ── log seq 持久化(与 ``phase_log`` 等长) ─────────────────
	# 每条日志在 task 维度上的单调 seq, 由 ``TaskStateManager.next_log_seq``
	# 分配。fork 出的子分支会拷贝父分支的 phase_log + phase_log_seqs, 后续
	# 各自向前推进时 seq 仍然由 task 级 counter 给, 因此跨分支重连用 bisect
	# 定位 ``after_log_seq=K`` 的 start_idx, 不会再因为分支切换导致 seq 回退
	# 让前端误以为"已经看过了, 跳过补丁"。
	phase_log_seqs: list[int] = Field(default_factory=list)

	def log(self, msg: str) -> None:
		import logging
		ts = datetime.utcnow().strftime("%H:%M:%S")
		entry = f"[{ts}] [{self.current_phase}] {msg}"
		# 先拿 seq 再 append: ``next_log_seq`` 内部加锁, 与 phase_log 自身
		# 写入保持顺序对齐(seqs 与 phase_log 等长)。
		try:
			from backend.api.state import get_state_manager
			anchor = self.phase_log_seqs[-1] if self.phase_log_seqs else None
			seq = get_state_manager().next_log_seq(self.task_id, anchor=anchor)
		except Exception:
			seq = len(self.phase_log)
		self.phase_log.append(entry)
		self.phase_log_seqs.append(int(seq))
		# 滚动淘汰: 反馈/监督模式下 phase_log 会随循环爆炸增长,
		# 超过 5000 行截留最近 2500 行 (phase_log 主要供 DB 持久化与 logs 接口
		# 翻页回看, 实时推送已经走 Redis Stream, 不依赖这块内存)。
		# phase_log_seqs 必须与 phase_log 等长一起裁。
		if len(self.phase_log) > 5000:
			self.phase_log = self.phase_log[-2500:]
			self.phase_log_seqs = self.phase_log_seqs[-2500:]
		logging.getLogger(__name__).info(entry)
		# 实时广播: 普通 phase_log 行也通过 EventBus 立刻送到 WS,
		# 不再等下一次节点 yield 才随 phase_update 批量下发,
		# 这样前端聊天流不会出现"卡半天突然涌一堆日志"的体感。
		# 主协程线程: ``get_running_loop`` + ``create_task`` 直接派发;
		# worker 线程(LLM 同步调用 / 阻塞 IO 线程池)走 ``set_task_loop``
		# 注册的主 loop + ``run_coroutine_threadsafe`` 投递, 避免被
		# ``RuntimeError: no running event loop`` 静默吞掉。
		try:
			import asyncio
			from backend.api.event_bus import get_log_sink, get_task_loop
			sink = get_log_sink(self.task_id)
			if not sink:
				return
			# 直接复用刚刚分配的真实 seq(已写入 phase_log_seqs),
			# 不再 ``len(phase_log)-1``: fork 后两条分支独立增长,
			# 局部下标对 task 级 WS 客户端没有意义。
			seq_emit = self.phase_log_seqs[-1] if self.phase_log_seqs else (len(self.phase_log) - 1)
			try:
				loop = asyncio.get_running_loop()
				loop.create_task(sink(entry, seq_emit))
			except RuntimeError:
				main_loop = get_task_loop(self.task_id)
				if main_loop is not None and not main_loop.is_closed():
					try:
						asyncio.run_coroutine_threadsafe(sink(entry, seq_emit), main_loop)
					except Exception as exc:
						logging.getLogger(__name__).warning(
							"[state.log] cross-thread sink 投递失败: %s", exc,
						)
				else:
					logging.getLogger(__name__).warning(
						"[state.log] 无可用 main_loop, 丢弃日志事件 task=%s",
						self.task_id,
					)
		except Exception:
			pass

	# 进程级单调计数器, 用于给 push_decision 生成 client 级业务 id;
	# 真正的 transport id 由 Redis Stream 在 XADD 时分配, 这里只是兜底
	# 让 WS 不可用 / sink 未注册时事件结构里仍然有可读的 id 字段。
	_push_decision_idx: int = PrivateAttr(default=0)

	def push_decision(self, event: dict) -> None:
		"""Fire-and-forget 把结构化决策事件投递到事件流 (Redis Stream)。

		协议 v2 之后, ``live_decision_events`` 不再保留在 state 内; 历史事件
		由 Redis Stream 持久化, 前端用 last_event_id 增量重连即可补差量。

		``timestamp`` 采用 ISO-8601 完整格式(``YYYY-MM-DDTHH:MM:SS.ffffff``),
		业务 id 仅作为兼容字段保留 (前端去重已切换到 envelope.id), sink 不
		注册时这里直接 fallthrough, 不会让 LangGraph 节点崩溃。
		"""
		now = datetime.utcnow()
		self._push_decision_idx += 1
		if "id" not in event:
			event["id"] = f"de-{self._push_decision_idx}-{now.strftime('%H%M%S%f')}"
		if "timestamp" not in event:
			event["timestamp"] = now.isoformat(timespec="microseconds")
		if "branch_id" not in event:
			event["branch_id"] = self.active_branch_id or ""
		# 跨线程 fallback 同 ``log()``: worker 线程拿不到 running loop 时,
		# 退到 BranchManager / task_runner 入口 ``set_task_loop`` 注册的主 loop。
		try:
			import asyncio
			from backend.api.event_bus import get_task_sink, get_task_loop
			sink = get_task_sink(self.task_id)
			if not sink:
				return
			try:
				loop = asyncio.get_running_loop()
				loop.create_task(sink(event))
			except RuntimeError:
				main_loop = get_task_loop(self.task_id)
				if main_loop is not None and not main_loop.is_closed():
					try:
						asyncio.run_coroutine_threadsafe(sink(event), main_loop)
					except Exception as exc:
						import logging as _lg
						_lg.getLogger(__name__).warning(
							"[push_decision] cross-thread sink 投递失败: %s", exc,
						)
				else:
					import logging as _lg
					_lg.getLogger(__name__).warning(
						"[push_decision] 无可用 main_loop, 丢弃 decision 事件 task=%s",
						self.task_id,
					)
		except Exception:
			pass

	# ── 通用 checkpoint 协议(Plan 模式确认框)──────────────
	def open_checkpoint(self, payload: dict[str, Any]) -> dict[str, Any]:
		"""Register a pending checkpoint and broadcast it to the frontend.

		Frontend receives the same payload via decision_event(action=
		"checkpoint_request") so the live timeline / Plan 风格确认卡片可以
		立刻渲染。Backend 节点随后应当主动结束本轮(return)并依靠 LangGraph
		``interrupt_before`` 暂停在下一节点之前,等待 ``/checkpoint/respond``。
		"""
		cp_id = payload.get("checkpoint_id") or (
			f"cp-{self.task_id[:8]}-{len(self.checkpoint_history)}-"
			f"{datetime.utcnow().strftime('%H%M%S%f')}"
		)
		now = datetime.utcnow().isoformat()
		ckpt = {
			"checkpoint_id": cp_id,
			"checkpoint_type": payload.get("checkpoint_type", "generic"),
			"phase": payload.get("phase", self.current_phase),
			"status": "pending",
			"created_at": now,
			"thinking": payload.get("thinking", ""),
			"summary": payload.get("summary", ""),
			"recommendation": payload.get("recommendation", ""),
			"risk": payload.get("risk", ""),
			"options": payload.get("options", []),
			"requires_input": bool(payload.get("requires_input", True)),
			"default_action": payload.get("default_action", "approve"),
			"context": payload.get("context", {}),
		}
		self.pending_checkpoint = ckpt
		# 决策事件流里也广播一份,方便前端时间线统一展示
		self.push_decision({
			"action": "checkpoint_request",
			"phase": ckpt["phase"],
			"checkpoint_id": cp_id,
			"checkpoint_type": ckpt["checkpoint_type"],
			"thinking": ckpt["thinking"],
			"summary": ckpt["summary"],
			"recommendation": ckpt["recommendation"],
			"risk": ckpt["risk"],
			"options": ckpt["options"],
			"requires_input": ckpt["requires_input"],
			"default_action": ckpt["default_action"],
			"message": ckpt["summary"] or ckpt["recommendation"] or "等待人工确认",
			"tone": "warning",
		})
		return ckpt

	def resolve_checkpoint(self, response: dict[str, Any]) -> Optional[dict[str, Any]]:
		"""Consume the pending checkpoint with the user's response.

		``response`` 可包含: action(approve|reject|modify|skip)、
		selected_option、user_prompt、note。返回已归档的 checkpoint 副本,
		没有 pending 时返回 None。同时:
		  - 把 user_prompt 追加到 ``pending_user_prompt`` 给后续节点参考
		  - 把 user_prompt 作为 user_messages 入库,与 chat 时间线合并
		"""
		ckpt = self.pending_checkpoint
		if not ckpt:
			return None
		now = datetime.utcnow().isoformat()
		archived = dict(ckpt)
		archived.update({
			"status": "resolved",
			"resolved_at": now,
			"response": {
				"action": response.get("action", "approve"),
				"selected_option": response.get("selected_option", ""),
				"user_prompt": response.get("user_prompt", ""),
				"note": response.get("note", ""),
				"next_action": response.get("next_action", ""),
			},
		})
		self.checkpoint_history.append(archived)
		# 限长,避免 checkpoint payload 在 LangGraph snapshot 里无限增长
		if len(self.checkpoint_history) > 200:
			self.checkpoint_history = self.checkpoint_history[-100:]
		self.pending_checkpoint = None

		user_prompt = (response.get("user_prompt") or "").strip()
		if user_prompt:
			# 软引导:拼到 pending_user_prompt 末尾,下一节点的 prompt builder
			# 可以读取这个字段把它注入 system prompt。
			joined = (self.pending_user_prompt or "").strip()
			self.pending_user_prompt = (
				f"{joined}\n{user_prompt}" if joined else user_prompt
			)
			self.user_messages.append({
				"role": "user",
				"text": user_prompt,
				"timestamp": now,
				"checkpoint_id": archived["checkpoint_id"],
			})

		self.push_decision({
			"action": "checkpoint_resolved",
			"phase": archived["phase"],
			"checkpoint_id": archived["checkpoint_id"],
			"checkpoint_type": archived["checkpoint_type"],
			"response": archived["response"],
			"message": (
				f"用户响应: {archived['response']['action']}"
				+ (f" — {user_prompt[:80]}" if user_prompt else "")
			),
			"tone": (
				"success" if archived["response"]["action"] == "approve"
				else ("danger" if archived["response"]["action"] == "reject" else "info")
			),
		})
		return archived

	@field_validator("fingerprints", mode="before")
	@classmethod
	def _coerce_fingerprint_keys(cls, v: dict) -> dict:
		"""确保 fingerprints 的 key 全部是 str，兼容 msgpack strict_map_key"""
		if isinstance(v, dict):
			return {str(k): val for k, val in v.items()}
		return v