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



WorkflowMode = Literal["pentest_engineer", "ctf_expert"]

_MODE_DEFAULTS: dict[str, dict[str, Any]] = {
	"pentest_engineer": {
		"auto_approve":        False,
		"success_gate_level":  "strict",
		"risk_budget":         3,
		"max_react_rounds":    25,
		"max_explore_rounds":  15,
		"skill_min_score":     20,
		"skill_weak_boost":    0,
	},
	"ctf_expert": {
		"auto_approve":        True,
		"success_gate_level":  "lenient",
		"risk_budget":         10,
		"max_react_rounds":    40,
		"max_explore_rounds":  25,
		"skill_min_score":     5,
		"skill_weak_boost":    10,
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




class OperatorFocusTarget(BaseModel):
	"""一个聚焦目标。``type`` 通常是 port/path/host/service/cve, ``value`` 是值。"""
	type: str
	value: str


class OperatorPlan(BaseModel):
	plan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
	created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

	user_request: str = ""

	source_phase: str = ""

	intent_summary: str = ""
	rationale: str = ""

	next_phase: Optional[str] = None
	target_phases: list[str] = Field(default_factory=list)
	skip_phases: list[str] = Field(default_factory=list)
	rerun_current: bool = False

	focus_targets: list[OperatorFocusTarget] = Field(default_factory=list)
	preferred_tools: list[str] = Field(default_factory=list)
	avoided_tools: list[str] = Field(default_factory=list)
	keyword_hints: list[str] = Field(default_factory=list)
	extra_constraints: dict[str, Any] = Field(default_factory=dict)

	needs_human_approval: bool = True

	consumed_by: list[str] = Field(default_factory=list)
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
	fork_event_id: Optional[str] = None
	fork_phase: str = ""
	fork_round: Optional[int] = None
	thread_id: str = ""
	status: BranchStatus = "running"
	created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
	updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
	label: str = ""
	initiating_prompt: str = ""
	is_root: bool = False



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
	scope_hint: Optional[str] = None
	task_focus: list[str] = Field(default_factory=list)
	pentest_phase: list[str] = Field(default_factory=list)
	priority_vulns: list[str] = Field(default_factory=list)
	intents: list[str] = Field(default_factory=list)
	requires_discovery: bool = False
	ambiguity_level: AmbiguityLevel = "vague"
	clarification_needed: list[str] = Field(default_factory=list)
	raw_prompt: str = ""
	chain_template_id: str = "web"


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
	reason: str = ""
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
	remediation: str = ""
	impact: str = ""
	cvss_score: Optional[float] = None
	cvss_vector: str = ""
	cwe: str = ""


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
	timestamp: str = ""
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
	exploit_level: str = ""
	session_info: dict = Field(default_factory=dict)
	evidence: str = ""
	commands_run: list[str] = Field(default_factory=list)
	command_results: list[CommandExecutionRecord] = Field(default_factory=list)
	command_records: list[CommandExecutionRecord] = Field(default_factory=list)

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



class ParsedTarget(BaseModel):
	"""parse_target() 的返回值"""
	host: str
	port: Optional[int] = None
	scheme: str = ""
	path: str = ""
	raw: str = ""


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

	if re.match(r'^https?://', raw, re.IGNORECASE):
		parsed = urlparse(raw)
		host = parsed.hostname or ""
		port = parsed.port
		scheme = (parsed.scheme or "").lower()
		path = parsed.path or ""
		return ParsedTarget(raw=raw, host=host, port=port, scheme=scheme, path=path)

	match = re.match(r'^(.+?):(\d{1,5})$', raw)
	if match:
		host = match.group(1)
		port_str = match.group(2)
		port = int(port_str)
		if 1 <= port <= 65535:
			return ParsedTarget(raw=raw, host=host, port=port)
		return ParsedTarget(raw=raw, host=raw)

	return ParsedTarget(raw=raw, host=raw)



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
		for e in self.edges:
			if e.src == src and e.dst == dst and e.relation == relation:
				return e
		if len(self.edges) >= self.max_edges:
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
	raw_prompt: str = ""
	parsed_intent: Optional[dict[str, Any]] = None
	safety_check_result: Optional[dict[str, Any]] = None
	authorization_token: Optional[str] = None
	workflow_mode: WorkflowMode = "pentest_engineer"
	chain_template_id: str = "web"
	auto_approve: bool = False
	success_gate_level: str = "strict"
	risk_budget: int = 3
	risk_budget_used: int = 0
	max_react_rounds: int = 25
	max_explore_rounds: int = 15
	skill_min_score: int = 20
	skill_weak_boost: int = 0
	created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

	target_host: str = ""
	target_port: Optional[int] = None
	target_scheme: str = ""
	target_path: str = ""
	target_raw: str = ""

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

	dir_scan_strategy: dict = Field(default_factory=dict)
	dir_intel: dict = Field(default_factory=dict)
	supplementary_dir_scan_done: bool = False

	runtime_facts: dict[str, dict[str, Any]] = Field(default_factory=dict)
	php_runtime: dict[str, Any] = Field(default_factory=dict)
	confirmed_facts: dict[str, Any] = Field(default_factory=dict)
	task_facts: dict[str, TaskFact] = Field(default_factory=dict)
	fact_version: int = 0
	last_fact_normalized_at: str = ""
	exploit_probe_variables: dict[str, dict[str, Any]] = Field(default_factory=dict)
	failed_commands_by_vuln: dict[str, list[str]] = Field(default_factory=dict)
	intel_files: list[dict[str, Any]] = Field(default_factory=list)
	page_params: list[dict[str, Any]] = Field(default_factory=list)
	intel_discovered_paths: list[str] = Field(default_factory=list)
	kb_probe_hits: list[dict[str, Any]] = Field(default_factory=list)

	subdomains: list[str] = Field(default_factory=list)
	raw_recon: dict = Field(default_factory=dict)

	findings: list[VulnFinding] = Field(default_factory=list)
	raw_vuln: dict = Field(default_factory=dict)
	fingerprints: dict = Field(default_factory=dict)

	exploit_results: list[ExploitResult] = Field(default_factory=list)
	tool_records: list[CommandExecutionRecord] = Field(default_factory=list)
	got_shell: bool = False
	privilege_level: str = ""
	secondary_attack_done: bool = False
	secondary_elided: bool = False
	secondary_attack_count: int = 0
	max_secondary_attacks: int = 2

	foothold_status: str = "none"
	credential_store: list[dict[str, Any]] = Field(default_factory=list)
	loot_store: list[dict[str, Any]] = Field(default_factory=list)

	lateral_results: dict[str, Any] = Field(default_factory=dict)
	persistence_entries: list[dict[str, Any]] = Field(default_factory=list)
	internal_network: dict[str, Any] = Field(default_factory=dict)

	privesc_hypotheses: list[dict[str, Any]] = Field(default_factory=list)
	objective_status: dict[str, Any] = Field(default_factory=dict)
	attack_next_steps: list[dict[str, Any]] = Field(default_factory=list)
	privesc_attempt_count: int = 0
	max_privesc_rounds: int = Field(
		default_factory=lambda: max(1, int(os.getenv("MAX_PRIVESC_ROUNDS", "3")))
	)
	chain_summary: str = ""
	chain_visited: list[str] = Field(default_factory=list)

	executive_summary: str = ""
	attack_timeline: list[dict[str, str]] = Field(default_factory=list)
	filtered_log: list[str] = Field(default_factory=list)

	post_findings: dict = Field(default_factory=dict)

	report_path: str = ""
	report_md: str = ""
	report_error: str = ""

	approved: bool = False
	post_approved: bool = False

	pending_checkpoint: Optional[dict[str, Any]] = None
	checkpoint_history: list[dict[str, Any]] = Field(default_factory=list)
	pending_user_prompt: str = ""

	user_messages: list[dict] = Field(default_factory=list)
	agent_replies: list[dict] = Field(default_factory=list)

	operator_plan: Optional[OperatorPlan] = None
	pentest_plan: Optional[dict[str, Any]] = None
	operator_plan_history: list[OperatorPlan] = Field(default_factory=list)

	guard_stats: dict[str, int] = Field(default_factory=dict)
	trace_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])

	pending_seeds: dict[str, list[Any]] = Field(default_factory=lambda: {
		"hosts": [],
		"ports": [],
		"web_paths": [],
		"credentials": [],
	})
	phase_visit_count: dict[str, int] = Field(default_factory=dict)
	phase_signature: dict[str, str] = Field(default_factory=dict)
	max_phase_visits: dict[str, int] = Field(default_factory=lambda: {
		"recon": 3,
		"surface_enum": 2,
		"intel_harvest": 2,
		"vuln_scan": 3,
		"foothold_attempt": 3,
		"secondary_attack": 2,
		"post_foothold_enum": 3,
		"privesc_attempt": 3,
	})
	replan_signals: dict[str, int] = Field(default_factory=dict)
	replan_count: int = 0
	max_replan: int = 3

	next_phase: str = ""
	supervisor_round: int = 0
	supervisor_round_limit: int = 30
	supervisor_history: list[dict[str, Any]] = Field(default_factory=list)
	approved_once: bool = False
	post_approved_once: bool = False

	attack_graph: AttackGraph = Field(default_factory=AttackGraph)

	active_branch_id: str = ""
	root_branch_id: str = ""

	phase_log_seqs: list[int] = Field(default_factory=list)

	def log(self, msg: str) -> None:
		import logging
		ts = datetime.utcnow().strftime("%H:%M:%S")
		entry = f"[{ts}] [{self.current_phase}] {msg}"
		try:
			from backend.api.state import get_state_manager
			anchor = self.phase_log_seqs[-1] if self.phase_log_seqs else None
			seq = get_state_manager().next_log_seq(self.task_id, anchor=anchor)
		except Exception:
			seq = len(self.phase_log)
		self.phase_log.append(entry)
		self.phase_log_seqs.append(int(seq))
		if len(self.phase_log) > 5000:
			self.phase_log = self.phase_log[-2500:]
			self.phase_log_seqs = self.phase_log_seqs[-2500:]
		logging.getLogger(__name__).info(entry)
		try:
			import asyncio
			from backend.api.event_bus import get_log_sink, get_task_loop
			sink = get_log_sink(self.task_id)
			if not sink:
				return
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
		if len(self.checkpoint_history) > 200:
			self.checkpoint_history = self.checkpoint_history[-100:]
		self.pending_checkpoint = None

		user_prompt = (response.get("user_prompt") or "").strip()
		if user_prompt:
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