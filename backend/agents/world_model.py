"""
world_model.py — 世界模型只读查询门面 (W1-T1)

为 attack_graph 提供结构化决策查询, 纯读、无副作用、可单测。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
	from backend.agents.models import AttackGraph, PentestState


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
		"""对 exploitable_frontier 评分排序, 高分在前。"""
		frontier = self.exploitable_frontier()
		scored: list[tuple[WMNode, float]] = []
		for n in frontier:
			s = self._score_node(n)
			scored.append((n, s))
		scored.sort(key=lambda x: x[1], reverse=True)
		return scored

	@staticmethod
	def _score_node(wn: WMNode) -> float:
		"""综合评分: severity 权重 + CVE 加分 + credential 关联加分。"""
		score = 0.0
		a = wn.attrs
		sev = (a.get("severity") or "").lower()
		sev_weights = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0, "info": 0.5}
		score += sev_weights.get(sev, 2.0)
		if a.get("cve"):
			score += 5.0
		if a.get("exploited"):
			score -= 10.0
		return score
