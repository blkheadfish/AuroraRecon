"""
engagement_memory.py — 跨 engagement 记忆：从历史任务提取先验情报注入世界模型

PriorIntel: 摘要历史发现，凭据只存存在性提示 {service, username, has_secret:true}，
不含明文。

注入约定：前置进 attack_graph（source=prior 节点 + discovers 边）+
写 runtime_facts["prior_intel"]，供 recon/vuln prompt 消费。
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from backend.agents.models import AttackGraph, PentestState

logger = logging.getLogger(__name__)


@dataclass
class PriorService:
    host: str
    port: int
    service: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class PriorFingerprint:
    key: str
    value: str
    source: str = ""


@dataclass
class PriorFinding:
    vuln_id: str
    name: str
    severity: str = "info"
    cve: str = ""


@dataclass
class PriorCredentialHint:
    service: str
    username: str
    has_secret: bool
    source: str = ""


@dataclass
class PriorIntel:
    known_services: list[PriorService] = field(default_factory=list)
    known_fingerprints: dict[str, str] = field(default_factory=dict)
    known_findings: list[PriorFinding] = field(default_factory=list)
    credential_hints: list[PriorCredentialHint] = field(default_factory=list)
    source_task_count: int = 0
    source_task_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "known_services": [
                {"host": s.host, "port": s.port, "service": s.service,
                 "version": s.version, "banner": s.banner[:120] if s.banner else ""}
                for s in self.known_services
            ],
            "known_fingerprints": dict(self.known_fingerprints),
            "known_findings": [
                {"vuln_id": f.vuln_id, "name": f.name,
                 "severity": f.severity, "cve": f.cve}
                for f in self.known_findings
            ],
            "credential_hints": [
                {"service": c.service, "username": c.username,
                 "has_secret": c.has_secret, "source": c.source}
                for c in self.credential_hints
            ],
            "source_task_count": self.source_task_count,
            "source_task_ids": self.source_task_ids,
        }

    def is_empty(self) -> bool:
        return (
            not self.known_services
            and not self.known_fingerprints
            and not self.known_findings
            and not self.credential_hints
        )


def _canonical_service_key(host: str, port: int) -> str:
    h = hashlib.sha1(f"{host}:{port}".encode()).hexdigest()[:16]
    return f"svc:{host}:{port}"


def _canonical_fingerprint_key(k: str, v: str) -> str:
    h = hashlib.sha1(f"{k}:{v}".encode()).hexdigest()[:16]
    return f"fp:{h}"


def extract_prior_intel(rows: list) -> PriorIntel:
    """从历史 TaskRecord 列表提取 PriorIntel。

    rows: 每个元素需有 .state_json (str) 属性，为 PentestState 的 JSON dump。
    若反序列化失败则跳过。
    """
    intel = PriorIntel()
    seen_services: set[str] = set()
    seen_fps: set[str] = set()
    seen_findings: set[str] = set()
    seen_creds: set[str] = set()

    for row in rows:
        try:
            raw = getattr(row, "state_json", "") or ""
            if not raw or raw == "{}":
                continue
            data = json.loads(raw)
        except Exception:
            continue

        tid = data.get("task_id", "")
        if tid:
            intel.source_task_ids.append(tid)
            intel.source_task_count += 1

        for port_info in data.get("open_ports", []) or []:
            port = port_info.get("port")
            host = data.get("target_host", "")
            if not port or not host:
                continue
            key = f"{host}:{port}"
            if key in seen_services:
                continue
            seen_services.add(key)
            intel.known_services.append(PriorService(
                host=host,
                port=port,
                service=port_info.get("service", "") or "",
                version=port_info.get("version", "") or "",
                banner=port_info.get("banner", "") or "",
            ))

        fps = data.get("fingerprints", {}) or {}
        for k, v in fps.items():
            if not v:
                continue
            fk = f"{k}:{v}"
            if fk in seen_fps:
                continue
            seen_fps.add(fk)
            intel.known_fingerprints[k] = str(v)

        for finding in data.get("findings", []) or []:
            vid = finding.get("vuln_id", "")
            if not vid or vid in seen_findings:
                continue
            seen_findings.add(vid)
            intel.known_findings.append(PriorFinding(
                vuln_id=vid,
                name=finding.get("name", vid),
                severity=finding.get("severity", "info"),
                cve=finding.get("cve", "") or "",
            ))

        for cred in data.get("credential_store", []) or []:
            user = cred.get("username", "") or cred.get("user", "")
            service = cred.get("service", "") or cred.get("source", "")
            if not user:
                continue
            ck = f"{service}:{user}"
            if ck in seen_creds:
                continue
            seen_creds.add(ck)
            has_pw = bool(cred.get("password") or cred.get("value") or cred.get("ntlm_hash"))
            intel.credential_hints.append(PriorCredentialHint(
                service=service or "unknown",
                username=user,
                has_secret=has_pw,
                source=cred.get("source", ""),
            ))

    logger.info(
        f"[eng_memory] extract_prior_intel: {intel.source_task_count} tasks, "
        f"{len(intel.known_services)} services, "
        f"{len(intel.known_fingerprints)} fingerprints, "
        f"{len(intel.known_findings)} findings, "
        f"{len(intel.credential_hints)} credential hints"
    )
    return intel


def inject_prior_into_state(state: PentestState, prior: PriorIntel) -> None:
    """将 PriorIntel 预填进 PentestState 的世界模型 + runtime_facts。

    - attack_graph: 新增 source=prior 节点 + discovers 边
    - runtime_facts["prior_intel"]: PriorIntel.to_dict()
    """
    if prior.is_empty():
        return

    state.runtime_facts["prior_intel"] = prior.to_dict()

    graph: AttackGraph = getattr(state, "attack_graph", AttackGraph())
    if not isinstance(graph, AttackGraph):
        graph = AttackGraph()
    state.attack_graph = graph

    host_nodes: dict[str, str] = {}
    for svc in prior.known_services:
        if svc.host and svc.host not in host_nodes:
            n = graph.upsert_node(
                node_id=f"host:{svc.host}",
                type="host",
                label=svc.host,
                facts={"source": "prior", "from_history": True},
                discovered_by="engagement_memory",
            )
            host_nodes[svc.host] = n.id
        svc_id = _canonical_service_key(svc.host, svc.port)
        graph.upsert_node(
            node_id=svc_id,
            type="service",
            label=f"{svc.service or 'svc'}:{svc.port}",
            facts={
                "port": svc.port,
                "service": svc.service,
                "version": svc.version,
                "source": "prior",
                "from_history": True,
            },
            discovered_by="engagement_memory",
        )
        graph.add_edge(f"host:{svc.host}", svc_id, relation="discovers",
                       note="历史已知")

    for f in prior.known_findings:
        fid = f"finding:{f.vuln_id}"
        graph.upsert_node(
            node_id=fid,
            type="finding",
            label=f.name or f.vuln_id,
            facts={
                "severity": f.severity,
                "cve": f.cve,
                "source": "prior",
                "from_history": True,
            },
            discovered_by="engagement_memory",
        )

    for fp_key, fp_val in prior.known_fingerprints.items():
        fpid = _canonical_fingerprint_key(fp_key, fp_val)
        graph.upsert_node(
            node_id=fpid,
            type="path",
            label=f"fp:{fp_key}",
            facts={
                "fingerprint_key": fp_key,
                "fingerprint_value": fp_val,
                "source": "prior",
                "from_history": True,
            },
            discovered_by="engagement_memory",
        )

    for ch in prior.credential_hints:
        service = ch.service or "unknown"
        username = ch.username
        cred_id = f"cred:history:{service}:{username}"
        graph.upsert_node(
            node_id=cred_id,
            type="credential",
            label=f"{username}@{service}",
            facts={
                "service": service,
                "username": username,
                "has_secret": ch.has_secret,
                "source": "prior",
                "from_history": True,
            },
            discovered_by="engagement_memory",
        )

    state.log(
        f"[eng_memory] 注入历史先验: "
        f"{len(prior.known_services)} 服务, "
        f"{len(prior.known_fingerprints)} 指纹, "
        f"{len(prior.known_findings)} 发现, "
        f"{len(prior.credential_hints)} 凭据提示"
    )
