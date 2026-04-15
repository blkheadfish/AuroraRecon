"""
skills/registry.py
Skill 注册表

匹配策略（v2 评分制）：
  CVE 精确命中    +100  （最强信号，明确就是这个漏洞）
  漏洞名称命中    +60   （VulnAgent 已经识别了漏洞名）
  json_probe 命中 +40   （主动探测确认）
  指纹关键词命中  +20   （框架级匹配，可能是宿主而非漏洞本身）
  证据关键词命中  +10   （最弱信号，容易误触发）

  多个 Skill 匹配时，选评分最高的。
  同分时，category 越具体越优先（java_deserialization > server_misconfig）。
"""
from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Optional

from backend.agents.models import VulnFinding
from backend.skills.loader import load_all_skills
from backend.skills.models import MatchRule, Skill

logger = logging.getLogger(__name__)

# 类别优先级：越具体越优先（同分时的 tiebreaker）
_CATEGORY_PRIORITY = {
    "java_deserialization": 10,
    "web_rce": 9,
    "web_inject": 8,
    "network": 7,
    "server_misconfig": 5,
    "credential": 4,
    "recon_skill": 3,
}

_SERVICE_FINDING_NAMES = frozenset({
    "ssh service", "ftp service", "smb service", "rdp service",
    "telnet service", "mysql service", "postgresql service",
    "redis service", "mongodb service", "snmp service", "vnc service",
})


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
    ) -> Optional[Skill]:
        """
        根据漏洞发现匹配最适用的 Skill（评分制）。

        Returns:
            评分最高的 Skill，未匹配返回 None
        """
        self.ensure_loaded()

        combined_fp = " ".join(filter(None, [
            fingerprint,
            finding.name,
            finding.description,
            finding.evidence[:500],
        ]))

        scored: list[tuple[int, Skill]] = []

        for skill in self._skills:
            score = self._score_skill(skill, finding, combined_fp, json_probe)
            if score > 0:
                scored.append((score, skill))

        if not scored:
            logger.debug(
                f"[SkillRegistry] 无匹配 Skill: {finding.name} ({finding.cve})"
            )
            return None

        # 按分数降序，同分按类别优先级降序
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
        logger.info(
            f"[SkillRegistry] ✅ 选择 Skill: {chosen.skill_id} "
            f"(得分={best_score}) ← {finding.name} ({finding.cve})"
        )
        return chosen

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
                "paths_count": len(s.exploit_paths),
                "probes_count": len(s.probes),
                "source": s.source_file,
            }
            for s in self._skills
        ]

    def reload(self) -> None:
        """Atomic reload: load into a new list first, then swap."""
        new_skills = load_all_skills()
        self._skills = new_skills
        self._loaded = True
        logger.info(f"[SkillRegistry] 重载完成，共 {len(new_skills)} 个 Skill")

    # ─────────────────────────────────────────────────────

    @staticmethod
    def _score_skill(
        skill: Skill,
        finding: VulnFinding,
        fingerprint: str,
        json_probe: str,
    ) -> int:
        """
        计算 Skill 的匹配得分。0 = 不匹配。

        评分维度（每条规则独立打分，取最高分）：
          CVE 精确匹配    +100
          漏洞名称命中    +60
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

        # 排除规则优先
        for ex_rule in match_cfg.exclude:
            if ex_rule.matches(
                fingerprint=fingerprint,
                cve=finding.cve or "",
                evidence=finding.evidence,
                json_probe=json_probe,
                service="",
                port=finding.port,
            ):
                return 0

        best_score = 0

        for rule in match_cfg.rules:
            rule_score = 0

            # CVE 精确匹配（最强信号）
            if rule.cve_matches and cve_lower:
                if any(c.lower() == cve_lower for c in rule.cve_matches):
                    rule_score += 100

            # 漏洞名称命中 Skill 关键词
            # 比如 finding.name="Apache Shiro 反序列化" 命中 shiro skill 的
            # fingerprint_contains=["shiro"]
            if rule.fingerprint_contains:
                if any(kw.lower() in name_lower for kw in rule.fingerprint_contains):
                    rule_score += 60
                # 指纹匹配（比名称弱——"tomcat" 出现在指纹里可能只是宿主）
                elif any(kw.lower() in fp_lower for kw in rule.fingerprint_contains):
                    rule_score += 20

            # JSON 探测结果
            if rule.json_probe_result and jp_lower:
                if rule.json_probe_result.lower() in jp_lower:
                    rule_score += 40

            # 证据关键词（最弱信号）
            if rule.evidence_contains:
                if any(kw.lower() in ev_lower for kw in rule.evidence_contains):
                    rule_score += 10

            # 端口/服务匹配
            # For generic service findings (e.g. "SSH Service"), port match
            # is a strong signal (+30); for specific CVE findings it's weaker (+5)
            if rule.port_is and finding.port:
                if finding.port in rule.port_is:
                    is_service_finding = name_lower in _SERVICE_FINDING_NAMES
                    rule_score += 30 if is_service_finding else 5

            # service_is matching (for service-level findings)
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
    ) -> Optional[Skill]:
        """Match a skill purely by port/service when no VulnFinding matched.

        Creates a synthetic minimal finding for scoring purposes.
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
        return self.match(
            finding=synthetic,
            fingerprint=fingerprint,
        )


# ── Module-level singleton (thread-safe) ─────────────────
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


# ── Dev-mode YAML hot-reload watcher ────────────────────
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