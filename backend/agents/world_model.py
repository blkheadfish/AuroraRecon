"""
world_model.py — 世界模型只读查询门面 (W1-T1 + W2-T1 增强)

为 attack_graph 提供结构化决策查询, 纯读、无副作用、可单测。
W2-T1: rank_frontier 增强为多因子评分(严重度×通向高价值×skill覆盖×代价)。
"""

from __future__ import annotations

import os
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

import yaml

if TYPE_CHECKING:
	from backend.agents.models import AttackGraph, PentestState


def _load_scoring_config() -> dict[str, Any]:
	cfg_path = Path(__file__).resolve().parent.parent / "config" / "path_reasoning.yaml"
	if not cfg_path.exists():
		return {}
	try:
		with open(cfg_path, "r") as fh:
			raw = yaml.safe_load(fh) or {}
		return raw.get("frontier_scoring", {})
	except Exception:
		return {}


@dataclass
class WMNode:
	"""世界模型节点的扁平投影, 供查询返回。"""
	id: str
	type: str
	label: str = ""
	attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class WMPath:
	"""从立足点到 objective 的候选路径。"""
	nodes: list[str] = field(default_factory=list)
	gaps: list[str] = field(default_factory=list)


@dataclass
class WMChain:
	"""finding + credential 可组合的攻击链候选。"""
	start: str = ""
	via: str = ""
	target: str = ""
	score: float = 0.0
	reason: str = ""


class WorldModelQuery:
	"""attack_graph 的只读门面, 不复制状态。"""

	def __init__(self, graph: AttackGraph, state: PentestState) -> None:
		self._graph = graph
		self._state = state

	@staticmethod
	def _to_wmnode(node: Any) -> WMNode:
		attrs = dict(getattr(node, "attrs", None) or {})
		facts = dict(getattr(node, "facts", None) or {})
		merged = {**facts, **attrs}
		return WMNode(
			id=getattr(node, "id", ""),
			type=getattr(node, "type", ""),
			label=getattr(node, "label", "") or getattr(node, "id", ""),
			attrs=merged,
		)

	@property
	def _node_map(self) -> dict[str, Any]:
		return {n.id: n for n in self._graph.nodes}

	@property
	def _in_degree(self) -> dict[str, set[str]]:
		deg: dict[str, set[str]] = {}
		for e in self._graph.edges:
			deg.setdefault(e.dst, set()).add(e.src)
		return deg

	@property
	def _out_edges(self) -> dict[str, list[Any]]:
		out: dict[str, list[Any]] = {}
		for e in self._graph.edges:
			out.setdefault(e.src, []).append(e)
		return out

	def exploitable_frontier(self) -> list[WMNode]:
		"""exploitable=True 且尚未 exploited 的 finding 节点。"""
		result: list[WMNode] = []
		for n in self._graph.nodes:
			if n.type != "finding":
				continue
			a = self._to_wmnode(n).attrs
			if a.get("exploitable") and not a.get("exploited"):
				result.append(self._to_wmnode(n))
		return result

	def unreached_high_value(self) -> list[WMNode]:
		"""objective 或 credential 类型、入边为 0 的高价值节点。"""
		in_deg = self._in_degree
		result: list[WMNode] = []
		for n in self._graph.nodes:
			if n.type not in ("objective", "credential"):
				continue
			if n.id not in in_deg or len(in_deg[n.id]) == 0:
				result.append(self._to_wmnode(n))
		return result

	def pivot_candidates(self) -> list[WMNode]:
		"""从已有 session/foothold 节点经 pivots_to/runs_on 可达的新 host。"""
		session_ids: set[str] = set()
		for n in self._graph.nodes:
			if n.type in ("session", "foothold"):
				session_ids.add(n.id)

		out_edges = self._out_edges
		node_map = self._node_map
		result: list[WMNode] = []
		for sid in session_ids:
			for e in out_edges.get(sid, []):
				if e.relation in ("pivots_to", "runs_on", "enables"):
					dst = node_map.get(e.dst)
					if dst and dst.type == "host" and dst.id not in session_ids:
						result.append(self._to_wmnode(dst))
		return result

	def usable_credentials(self) -> list[WMNode]:
		"""validated 凭据节点。"""
		result: list[WMNode] = []
		for n in self._graph.nodes:
			if n.type != "credential":
				continue
			a = self._to_wmnode(n).attrs
			if a.get("validated"):
				result.append(self._to_wmnode(n))
		return result

	def paths_to_objective(self) -> list[WMPath]:
		"""BFS 从 session/foothold 到 objective 的所有路径。"""
		node_map = self._node_map
		out_edges = self._out_edges

		starts: list[str] = []
		objectives: set[str] = set()
		for n in self._graph.nodes:
			if n.type in ("session", "foothold"):
				starts.append(n.id)
			elif n.type == "objective":
				objectives.add(n.id)

		if not starts or not objectives:
			return []

		results: list[WMPath] = []
		for start_id in starts:
			paths = self._bfs_paths(start_id, objectives, node_map, out_edges)
			for path_nodes in paths:
				gaps: list[str] = []
				for i in range(len(path_nodes) - 1):
					src = path_nodes[i]
					dst = path_nodes[i + 1]
					has_edge = any(
						e.dst == dst
						for e in out_edges.get(src, [])
					)
					if not has_edge:
						gaps.append(f"{src}→{dst}")
				results.append(WMPath(nodes=path_nodes, gaps=gaps))

		return results

	def _bfs_paths(
		self,
		start: str,
		targets: set[str],
		node_map: dict[str, Any],
		out_edges: dict[str, list[Any]],
		limit: int = 20,
	) -> list[list[str]]:
		queue: deque[tuple[str, list[str]]] = deque()
		queue.append((start, [start]))
		results: list[list[str]] = []
		while queue and len(results) < limit:
			current, path = queue.popleft()
			if current in targets and len(path) > 1:
				results.append(path)
				continue
			for e in out_edges.get(current, []):
				nxt = e.dst
				if nxt in path:
					continue
				queue.append((nxt, path + [nxt]))
		return results

	def chains(self) -> list[WMChain]:
		"""finding 经 credential 到 session/objective 的可组合攻击链。

		逻辑: 对每个 exploitable finding, 找其连接的 credential 节点,
		再找 credential 能 yield 的 session 或通向 objective 的路径。
		"""
		node_map = self._node_map
		out_edges = self._out_edges
		frontier = self.exploitable_frontier()

		results: list[WMChain] = []
		for fn in frontier:
			fid = fn.id
			for e in out_edges.get(fid, []):
				if e.relation != "yields":
					continue
				cred_node = node_map.get(e.dst)
				if not cred_node or cred_node.type != "credential":
					continue
				cid = cred_node.id
				for e2 in out_edges.get(cid, []):
					if e2.relation not in ("yields", "enables", "pivots_to"):
						continue
					dst_node = node_map.get(e2.dst)
					if not dst_node:
						continue
					if dst_node.type in ("session", "foothold", "objective", "host"):
						chain = WMChain(
							start=fid,
							via=cid,
							target=dst_node.id,
							score=self._score_node(fn),
							reason=f"finding {fn.label} → credential {cred_node.label} → {dst_node.type} {dst_node.label}",
						)
						results.append(chain)
		return results

	def rank_frontier(self) -> list[tuple[WMNode, float]]:
		"""对 exploitable_frontier 评分排序, 高分在前 (W2-T1 多因子增强)。"""
		cfg = _load_scoring_config()
		frontier = self.exploitable_frontier()
		scored: list[tuple[WMNode, float]] = []
		for n in frontier:
			s = self._score_node(n, cfg)
			scored.append((n, s))
		scored.sort(key=lambda x: x[1], reverse=True)
		return scored

	def _score_node(self, wn: WMNode, cfg: dict[str, Any] | None = None) -> float:
		"""多因子评分 (W2-T1): severity + CVE + 通向高价值 + skill 覆盖 + 代价。"""
		if cfg is None:
			cfg = _load_scoring_config()
		score = 0.0
		a = wn.attrs
		sev_cfg = cfg.get("severity", {})
		sev = (a.get("severity") or "unknown").lower()
		score += float(sev_cfg.get(sev, sev_cfg.get("unknown", 2.0)))

		if a.get("cve"):
			score += float(cfg.get("cve_bonus", 5.0))
		if a.get("exploited"):
			score += float(cfg.get("exploited_penalty", -10.0))

		if wn.id:
			if self._leads_to_high_value(wn.id):
				score += float(cfg.get("leads_to_high_value", 8.0))
			maturity_score = self._exploit_maturity_score(wn, cfg)
			score += maturity_score
			if self._has_skill_coverage(wn):
				score += float(cfg.get("skill_coverage", 4.0))
			chain_depth = self._chain_depth(wn.id)
			if chain_depth > 0:
				score += chain_depth * float(cfg.get("cost_penalty_per_step", -1.0))
		return score

	def _leads_to_high_value(self, node_id: str) -> bool:
		"""finding 节点是否经 yields/enables 边通向 unreached objective/credential。"""
		out_edges = self._out_edges
		node_map = self._node_map
		visited: set[str] = set()
		stack = [node_id]
		while stack:
			cur = stack.pop()
			if cur in visited:
				continue
			visited.add(cur)
			for e in out_edges.get(cur, []):
				dst_node = node_map.get(e.dst)
				if not dst_node:
					continue
				if dst_node.type in ("objective", "credential"):
					attrs = self._to_wmnode(dst_node).attrs
					if dst_node.type == "objective":
						return True
					if not attrs.get("validated"):
						return True
				if e.relation in ("yields", "enables", "pivots_to", "leads_to", "requires"):
					stack.append(e.dst)
		return False

	def _exploit_maturity_score(self, wn: WMNode, cfg: dict[str, Any]) -> float:
		"""根据 skill 注册/KB 覆盖评估利用成熟度加分。"""
		maturity_cfg = cfg.get("exploit_maturity", {})
		a = wn.attrs
		score = 0.0
		if a.get("kb_match"):
			score += float(maturity_cfg.get("kb_entry", 2.0))
		if a.get("skill_match"):
			score += float(maturity_cfg.get("skill_registered", 3.0))
		if a.get("has_public_poc"):
			score += float(maturity_cfg.get("public_poc", 4.0))
		if a.get("has_msf_module"):
			score += float(maturity_cfg.get("msf_module", 6.0))
		return score

	def _has_skill_coverage(self, wn: WMNode) -> bool:
		"""检查该 finding 是否有已注册的匹配 Skill。"""
		a = wn.attrs
		if a.get("skill_match"):
			return True
		cve = a.get("cve", "")
		if cve:
			for f in (self._state.findings or []):
				if getattr(f, "cve", "") == cve and getattr(f, "skill_matched", False):
					return True
		return False

	def _chain_depth(self, node_id: str) -> int:
		"""从 finding 到 session/objective 的最短跳数, 用于代价扣分。"""
		out_edges = self._out_edges
		node_map = self._node_map
		from collections import deque as _deque
		q: _deque[tuple[str, int]] = _deque()
		q.append((node_id, 0))
		visited: set[str] = {node_id}
		while q:
			cur, dist = q.popleft()
			nd = node_map.get(cur)
			if nd and nd.type in ("session", "foothold", "objective"):
				return dist
			for e in out_edges.get(cur, []):
				if e.dst not in visited:
					visited.add(e.dst)
					q.append((e.dst, dist + 1))
		return 0


class WorldModelWriter:
	"""统一写入入口 (C2): 凡产生 host/service/finding/credential/session 处走它。

	整合现有 fact_hooks.attach_*_to_graph, 保证写入幂等、同时建立边关系。
	"""

	def __init__(self, state: PentestState) -> None:
		self._state = state

	@property
	def _g(self):
		return self._state.attack_graph

	def upsert_node(
		self, type: str, key: str,
		attrs: dict[str, Any] | None = None,
		label: str = "",
		discovered_by: str = "",
	) -> str:
		"""幂等: 同 key 的节点已存在则合并 attrs。"""
		node_id = key
		self._g.upsert_node(node_id, type=type, label=label or key,
		                    attrs=attrs, discovered_by=discovered_by)
		return node_id

	def add_edge(
		self, src_id: str, dst_id: str, relation: str,
		attrs: dict[str, Any] | None = None,
	) -> None:
		self._g.add_edge(src_id, dst_id, relation=relation, attrs=attrs)

	def add_finding(self, finding: Any) -> str:
		"""高层封装: 建 finding 节点 + 与 service 的 vulnerable_to 边。"""
		fid = f"finding:{finding.vuln_id}"
		self.upsert_node(
			"finding", fid,
			attrs={
				"cve": getattr(finding, "cve", "") or "",
				"severity": getattr(finding, "severity", ""),
				"exploitable": getattr(finding, "exploitable", False),
				"exploited": False,
				"tool": getattr(finding, "tool", ""),
			},
			label=getattr(finding, "name", "") or finding.vuln_id,
		)
		port = getattr(finding, "port", None)
		if port:
			host = ""
			raw_target = getattr(finding, "target", "") or ""
			if "://" in raw_target:
				host = raw_target.split("/")[2].split(":")[0]
			if not host:
				host = raw_target.split(":")[0]
			if host:
				sid = f"svc:{host}:{port}"
				self.add_edge(sid, fid, "vulnerable_to")
		return fid

	def add_credential(self, cred: dict[str, Any]) -> str:
		"""高层封装: 建 credential 节点。"""
		from backend.agents.fact_hooks import _ag_credential_id
		cid = _ag_credential_id(cred)
		self.upsert_node(
			"credential", cid,
			attrs={
				"service": cred.get("service") or cred.get("source") or "",
				"username": cred.get("user") or cred.get("username") or "",
				"has_secret": bool(cred.get("value") or cred.get("password")),
				"validated": cred.get("validated", False),
			},
			label=f"{cred.get('user') or '?'}@{cred.get('source') or '?'}",
		)
		return cid

	def add_session(self, host: str, privilege: str, shell_type: str) -> str:
		"""高层封装: 建 session 节点 + runs_on 边。"""
		sid = f"session:{host}:{privilege}"
		self.upsert_node(
			"session", sid,
			attrs={"host": host, "privilege": privilege, "shell_type": shell_type},
			label=f"{privilege}@{host}",
		)
		host_id = f"host:{host}"
		self.add_edge(sid, host_id, "runs_on")
		return sid
