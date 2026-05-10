"""
skills/registry.py
Skill 注册表

匹配策略（v3 评分制）：
  KB 探针 dispatch_skill +150  （最强信号，KB 主动探针已确认漏洞 + 显式派发）
  CVE 精确命中           +100  （强信号，明确就是这个漏洞）
  漏洞名称命中           +60   （VulnAgent 已经识别了漏洞名）
  json_probe 命中        +40   （主动探测确认）
  指纹关键词命中         +20   （框架级匹配，可能是宿主而非漏洞本身）
  证据关键词命中         +10   （最弱信号，容易误触发）

  多个 Skill 匹配时，选评分最高的。
  同分时，category 越具体越优先（java_deserialization > server_misconfig）。
"""
from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

from backend.agents.models import VulnFinding
from backend.skills.loader import load_all_skills
from backend.skills.models import MatchRule, Skill

logger = logging.getLogger(__name__)

_CATEGORY_PRIORITY = {
    "java_deserialization": 10,
    "web_rce": 9,
    "web_inject": 8,
    "network": 7,
    "server_misconfig": 5,
    "credential": 4,
    "recon_skill": 3,
}

# (port, service_lower) → skill_id — 当标准评分匹配不到任何 skill 时兜底
_SERVICE_PORT_FALLBACK: dict[tuple[int, str], str] = {
    (389, "ldap"): "ldap_exploit",
    (636, "ldaps"): "ldap_exploit",
    (3268, "ldap"): "ldap_exploit",
    (3269, "ldaps"): "ldap_exploit",
    (88, "kerberos"): "kerberos_exploit",
    (88, "kerberos-sec"): "kerberos_exploit",
    (464, "kpasswd5"): "kerberos_exploit",
    (5985, "winrm"): "winrm_exploit",
    (5985, "ws-management"): "winrm_exploit",
    (5986, "winrm"): "winrm_exploit",
    (5986, "ws-management"): "winrm_exploit",
    (1433, "ms-sql-s"): "mssql_exploit",
    (1433, "ms-sql-m"): "mssql_exploit",
    (1433, "mssql"): "mssql_exploit",
    (6379, "redis"): "redis_exploit",
    (3306, "mysql"): "mysql_exploit",
    (3306, "mariadb"): "mysql_exploit",
    (5432, "postgresql"): "mysql_exploit",
    (5432, "pgsql"): "mysql_exploit",
    (6443, "kubernetes"): "k8s_exploit",
    (6443, "kube-apiserver"): "k8s_exploit",
    (10250, "kubelet"): "k8s_exploit",
    (10255, "kubelet"): "k8s_exploit",
    (2379, "etcd"): "k8s_exploit",
    (2049, "nfs"): "nfs_exploit",
    (2049, "nfs-acl"): "nfs_exploit",
    (111, "rpcbind"): "nfs_exploit",
    (111, "portmapper"): "nfs_exploit",
    (161, "snmp"): "snmp_exploit",
    (53, "domain"): "dns_exploit",
    (53, "dns"): "dns_exploit",
    (25, "smtp"): "smtp_exploit",
    (587, "submission"): "smtp_exploit",
    (3389, "ms-wbt-server"): "rdp_exploit",
    (3389, "rdp"): "rdp_exploit",
}

_SERVICE_FINDING_NAMES = frozenset({
    "ssh service", "ftp service", "smb service", "rdp service",
    "telnet service", "mysql service", "postgresql service",
    "redis service", "mongodb service", "snmp service", "vnc service",
})

_MODE_MATCH_CONFIG: dict[str, dict] = {
    "pentest_engineer": {
        "min_score": 20,
        "weak_signal_boost": 0,
    },
    "ctf_expert": {
        "min_score": 5,
        "weak_signal_boost": 10,
    },
}


class SkillRegistry:
    def __init__(self):
        self._skills: list[Skill] = []
        self._loaded = False

    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._skills = load_all_skills()
        self._loaded = True
        logger.info(f"[SkillRegistry] 注册 {len(self._skills)} 个 Skill")

    @property
    def size(self) -> int:
        self.ensure_loaded()
        return len(self._skills)

    def match(
        self,
        finding: VulnFinding,
        fingerprint: str = "",
        json_probe: str = "",
        workflow_mode: str = "pentest_engineer",
        min_score: Optional[int] = None,
        weak_signal_boost: Optional[int] = None,
        kb_hits: Optional[list[dict]] = None,
        context_vars: Optional[dict[str, Any]] = None,
    ) -> Optional[Skill]:
        """
        根据漏洞发现匹配最适用的 Skill(评分制 + mode 权重)。

        Args:
            workflow_mode: pentest_engineer / ctf_expert,用作阈值兜底。
            min_score: 任务显式指定的下限(per-task,覆盖 mode 默认值)。
            weak_signal_boost: 任务显式指定的弱信号加权。
            kb_hits: KB 探针扫描产出的命中列表。每条 dict 形如 ``{
              "vuln_id", "dispatch_skill", "confidence", "base_url", "port",
              "cves", "finding_vuln_id"}``。当 kb_hit 与当前 finding 关联
              （finding_vuln_id 匹配 / target+cve 匹配 / port 匹配）时，
              其 dispatch_skill 指向的 Skill 直接 +150 分，压过一切关键词匹配。
            context_vars: 当前上下文变量字典（如 auth_log_readable 等），供
              MatchRule.variable_present 条件使用。
        """
        self.ensure_loaded()

        combined_fp = " ".join(filter(None, [
            fingerprint,
            finding.name,
            finding.description,
            finding.evidence[:500],
        ]))

        cfg = _MODE_MATCH_CONFIG.get(workflow_mode) or _MODE_MATCH_CONFIG["pentest_engineer"]
        min_threshold = cfg["min_score"] if min_score is None else int(min_score)
        boost = cfg["weak_signal_boost"] if weak_signal_boost is None else int(weak_signal_boost)

        kb_skill_boost = self._compute_kb_dispatch_boost(finding, kb_hits or [])

        scored: list[tuple[int, Skill]] = []

        for skill in self._skills:
            score = self._score_skill(skill, finding, combined_fp, json_probe, context_vars)
            kb_extra = kb_skill_boost.get(skill.skill_id, 0)
            if kb_extra:
                score += kb_extra
            if score > 0 and boost and score < 60 and not kb_extra:
                score += boost
            if score >= min_threshold:
                scored.append((score, skill))

        if not scored:
            logger.debug(
                f"[SkillRegistry] 无匹配 Skill: {finding.name} ({finding.cve})"
            )
            return None

        scored.sort(
            key=lambda x: (
                x[0],
                _CATEGORY_PRIORITY.get(x[1].category, 0),
            ),
            reverse=True,
        )

        if len(scored) > 1:
            top3 = [
                f"{s.skill_id}({score}分)"
                for score, s in scored[:3]
            ]
            logger.info(
                f"[SkillRegistry] 匹配评分: {', '.join(top3)}"
            )

        best_score, chosen = scored[0]
        kb_marker = " [KB 派发]" if kb_skill_boost.get(chosen.skill_id) else ""
        logger.info(
            f"[SkillRegistry] ✅ 选择 Skill: {chosen.skill_id} "
            f"(得分={best_score}{kb_marker}) ← {finding.name} ({finding.cve})"
        )
        return chosen

    @staticmethod
    def _compute_kb_dispatch_boost(
        finding: VulnFinding,
        kb_hits: list[dict],
    ) -> dict[str, int]:
        """
        从 KB 探针命中里挑出与当前 finding 关联的 hit，返回 ``{skill_id: 加分}``。

        关联策略（任一满足即视为关联）：
          1. ``finding_vuln_id`` 与 ``finding.vuln_id`` 一致（最强信号，直接是
             由这次 KB 探针生成的 finding）；
          2. ``port`` 一致 + (CVE 一致 / target host 一致 / 描述包含 vuln_id)。
        """
        if not kb_hits:
            return {}

        boost: dict[str, int] = {}
        finding_vuln_id = getattr(finding, "vuln_id", "") or ""
        finding_cves = {(finding.cve or "").lower()} if finding.cve else set()
        finding_port = finding.port
        finding_target = (finding.target or "").lower()
        finding_text = " ".join([
            (finding.name or ""), (finding.description or ""),
            (finding.evidence or "")[:300],
        ]).lower()

        for hit in kb_hits:
            if not isinstance(hit, dict):
                continue
            skill_id = hit.get("dispatch_skill")
            if not skill_id:
                continue

            associated = False

            if hit.get("finding_vuln_id") and hit.get("finding_vuln_id") == finding_vuln_id:
                associated = True
            else:
                same_port = (
                    finding_port and hit.get("port") == finding_port
                )
                hit_cves = {str(c).lower() for c in (hit.get("cves") or [])}
                cve_overlap = bool(finding_cves & hit_cves)
                same_target = bool(
                    finding_target and (hit.get("base_url") or "").lower()
                    and (hit.get("base_url") or "").lower() in finding_target
                )
                kb_vuln_id = (hit.get("vuln_id") or "").lower()
                vuln_id_in_text = bool(kb_vuln_id) and kb_vuln_id in finding_text

                if same_port and (cve_overlap or vuln_id_in_text or same_target):
                    associated = True
                elif cve_overlap:
                    associated = True

            if not associated:
                continue

            confidence = float(hit.get("confidence") or 0.7)
            extra = 150 if confidence >= 0.85 else 120
            prev = boost.get(skill_id, 0)
            if extra > prev:
                boost[skill_id] = extra

        return boost

    def match_all(
        self,
        finding: VulnFinding,
        fingerprint: str = "",
        json_probe: str = "",
    ) -> list[Skill]:
        """返回所有匹配的 Skill（按评分排序）"""
        self.ensure_loaded()

        combined_fp = " ".join(filter(None, [
            fingerprint, finding.name, finding.description,
            finding.evidence[:500],
        ]))

        scored = []
        for s in self._skills:
            score = self._score_skill(s, finding, combined_fp, json_probe)
            if score > 0:
                scored.append((score, s))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored]

    def get_by_id(self, skill_id: str) -> Optional[Skill]:
        self.ensure_loaded()
        for s in self._skills:
            if s.skill_id == skill_id:
                return s
        return None

    def list_all(self) -> list[dict]:
        self.ensure_loaded()
        return [
            {
                "skill_id": s.skill_id,
                "name": s.name,
                "category": s.category,
                "phase": s.phase,
                "paths_count": len(s.exploit_paths),
                "probes_count": len(s.probes),
                "source": s.source_file,
            }
            for s in self._skills
        ]

    def list_by_phase(self, phase: str) -> list[Skill]:
        """Return all skills tagged for the given attack phase."""
        self.ensure_loaded()
        return [s for s in self._skills if s.phase == phase]

    def reload(self) -> None:
        """Atomic reload: load into a new list first, then swap."""
        new_skills = load_all_skills()
        self._skills = new_skills
        self._loaded = True
        logger.info(f"[SkillRegistry] 重载完成，共 {len(new_skills)} 个 Skill")


    @staticmethod
    def _score_skill(
        skill: Skill,
        finding: VulnFinding,
        fingerprint: str,
        json_probe: str,
        context_vars: Optional[dict[str, Any]] = None,
    ) -> int:
        """
        计算 Skill 的匹配得分。0 = 不匹配。

        评分维度（每条规则独立打分，取最高分）：
          CVE 精确匹配    +100
          漏洞名称命中    +60
          运行时变量命中  +30   (NEW: variable_present)
          json_probe 命中 +40
          指纹关键词命中  +20
          证据关键词命中  +10
        """
        match_cfg = skill.match
        fp_lower = fingerprint.lower()
        name_lower = finding.name.lower() if finding.name else ""
        cve_lower = (finding.cve or "").lower()
        ev_lower = (finding.evidence or "").lower()
        jp_lower = json_probe.lower()
        vars_dict = context_vars or {}

        for ex_rule in match_cfg.exclude:
            if ex_rule.matches(
                fingerprint=fingerprint,
                cve=finding.cve or "",
                evidence=finding.evidence,
                json_probe=json_probe,
                service="",
                port=finding.port,
                tool=finding.tool or "",
                variables=vars_dict,
            ):
                return 0

        best_score = 0

        for rule in match_cfg.rules:
            rule_score = 0

            if rule.variable_present:
                if not any(bool(vars_dict.get(v)) for v in rule.variable_present):
                    continue
                rule_score += 30

            if rule.tool_is and finding.tool:
                if rule.tool_is.lower() == finding.tool.lower():
                    rule_score += 120

            if rule.cve_matches and cve_lower:
                if any(c.lower() == cve_lower for c in rule.cve_matches):
                    rule_score += 100

            if rule.fingerprint_contains:
                if any(kw.lower() in name_lower for kw in rule.fingerprint_contains):
                    rule_score += 60
                elif any(kw.lower() in fp_lower for kw in rule.fingerprint_contains):
                    rule_score += 20

            if rule.json_probe_result and jp_lower:
                if rule.json_probe_result.lower() in jp_lower:
                    rule_score += 40

            if rule.evidence_contains:
                if any(kw.lower() in ev_lower for kw in rule.evidence_contains):
                    rule_score += 10

            if rule.port_is and finding.port:
                if finding.port in rule.port_is:
                    is_service_finding = name_lower in _SERVICE_FINDING_NAMES
                    rule_score += 30 if is_service_finding else 15

            if rule.service_is and name_lower:
                svc_kw = rule.service_is.lower()
                if svc_kw in name_lower or svc_kw in fp_lower:
                    rule_score += 25

            best_score = max(best_score, rule_score)

        return best_score

    def match_by_port(
        self,
        port: int,
        service: str = "",
        fingerprint: str = "",
        context_vars: Optional[dict[str, Any]] = None,
    ) -> Optional[Skill]:
        """Match a skill purely by port/service when no VulnFinding matched.

        Creates a synthetic minimal finding for scoring purposes, then falls
        back to ``_SERVICE_PORT_FALLBACK`` if standard scoring returns None.
        """
        self.ensure_loaded()
        synthetic = VulnFinding(
            name=f"{service.upper() or 'Unknown'} Service",
            port=port,
            target=f":{port}",
            evidence=fingerprint[:500],
            exploitable=True,
            tool="port-match",
        )
        result = self.match(
            finding=synthetic,
            fingerprint=fingerprint,
            context_vars=context_vars,
        )
        if result is not None:
            return result

        # Last-chance: direct port→skill lookup
        svc_lower = (service or "").lower()
        skill_id = _SERVICE_PORT_FALLBACK.get((port, svc_lower))
        if skill_id:
            fallback = self.get_by_id(skill_id)
            if fallback:
                logger.info(
                    f"[SkillRegistry] port fallback → {skill_id} "
                    f"(port={port}, service={svc_lower})"
                )
                return fallback
        return None


_registry_lock = threading.Lock()
_registry_singleton: SkillRegistry | None = None


def get_registry() -> SkillRegistry:
    global _registry_singleton
    if _registry_singleton is not None:
        return _registry_singleton
    with _registry_lock:
        if _registry_singleton is None:
            reg = SkillRegistry()
            reg.ensure_loaded()
            _registry_singleton = reg
            if os.getenv("DEV_MODE", "").lower() in ("1", "true", "yes"):
                _start_yaml_watcher(reg)
    return _registry_singleton


_watcher_started = False


def _start_yaml_watcher(registry: SkillRegistry) -> None:
    """Start a background thread that watches skill YAML files for changes."""
    global _watcher_started
    if _watcher_started:
        return

    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        logger.info("[SkillRegistry] watchdog not installed, hot-reload disabled")
        return

    skills_dir = Path(__file__).resolve().parent
    if not skills_dir.is_dir():
        return

    class _YamlReloadHandler(FileSystemEventHandler):
        def __init__(self, reg: SkillRegistry):
            self._reg = reg
            self._debounce_timer: threading.Timer | None = None

        def _schedule_reload(self) -> None:
            if self._debounce_timer is not None:
                self._debounce_timer.cancel()
            self._debounce_timer = threading.Timer(1.0, self._do_reload)
            self._debounce_timer.daemon = True
            self._debounce_timer.start()

        def _do_reload(self) -> None:
            logger.info("[SkillRegistry] YAML change detected, reloading skills")
            try:
                self._reg.reload()
            except Exception:
                logger.warning("[SkillRegistry] Hot-reload failed", exc_info=True)

        def on_modified(self, event):
            if event.src_path.endswith((".yaml", ".yml")):
                self._schedule_reload()

        def on_created(self, event):
            if event.src_path.endswith((".yaml", ".yml")):
                self._schedule_reload()

    observer = Observer()
    observer.schedule(_YamlReloadHandler(registry), str(skills_dir), recursive=True)
    observer.daemon = True
    observer.start()
    _watcher_started = True
    logger.info(f"[SkillRegistry] YAML hot-reload watcher started on {skills_dir}")