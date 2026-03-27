"""
skills/registry.py
Skill 注册表

职责：
  - 维护所有已加载 Skill 的索引
  - 根据漏洞信息匹配最适用的 Skill
  - 支持多 Skill 匹配时按优先级排序
"""
from __future__ import annotations

import logging
from typing import Optional

from backend.agents.models import VulnFinding
from backend.skills.loader import load_all_skills
from backend.skills.models import Skill

logger = logging.getLogger(__name__)


class SkillRegistry:
    """
    Skill 注册表。

    启动时加载所有 YAML，运行时根据漏洞信息匹配。

    用法：
        registry = SkillRegistry()
        skill = registry.match(finding)
        if skill:
            # 交给 SkillEngine 执行
    """

    def __init__(self):
        self._skills: list[Skill] = []
        self._loaded = False

    def ensure_loaded(self) -> None:
        """延迟加载：首次调用时加载所有 Skill"""
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
        根据漏洞发现匹配最适用的 Skill。

        匹配信息来源：
          - finding.name         漏洞名称
          - finding.cve          CVE 编号
          - finding.evidence     扫描证据
          - finding.description  漏洞描述
          - finding.tool         发现工具
          - fingerprint          VulnAgent 的指纹识别结果
          - json_probe           VulnAgent 的 JSON 探测结果

        Returns:
            匹配到的 Skill，未匹配返回 None
        """
        self.ensure_loaded()

        # 构建匹配用的综合文本
        combined_fp = " ".join(filter(None, [
            fingerprint,
            finding.name,
            finding.description,
            finding.evidence[:500],
        ]))

        candidates: list[Skill] = []

        for skill in self._skills:
            if self._matches_skill(
                skill, finding, combined_fp, json_probe
            ):
                candidates.append(skill)

        if not candidates:
            logger.debug(
                f"[SkillRegistry] 无匹配 Skill: {finding.name} ({finding.cve})"
            )
            return None

        if len(candidates) > 1:
            logger.info(
                f"[SkillRegistry] 多个 Skill 匹配: "
                f"{[s.skill_id for s in candidates]}，选择第一个"
            )

        chosen = candidates[0]
        logger.info(
            f"[SkillRegistry] 匹配到 Skill: {chosen.skill_id} "
            f"← {finding.name} ({finding.cve})"
        )
        return chosen

    def match_all(
        self,
        finding: VulnFinding,
        fingerprint: str = "",
        json_probe: str = "",
    ) -> list[Skill]:
        """返回所有匹配的 Skill（按加载顺序）"""
        self.ensure_loaded()

        combined_fp = " ".join(filter(None, [
            fingerprint,
            finding.name,
            finding.description,
            finding.evidence[:500],
        ]))

        return [
            s for s in self._skills
            if self._matches_skill(s, finding, combined_fp, json_probe)
        ]

    def get_by_id(self, skill_id: str) -> Optional[Skill]:
        """按 ID 精确查找"""
        self.ensure_loaded()
        for s in self._skills:
            if s.skill_id == skill_id:
                return s
        return None

    def list_all(self) -> list[dict]:
        """列出所有已注册 Skill（用于 API / 调试）"""
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
        """重新加载所有 Skill（开发调试用）"""
        self._loaded = False
        self.ensure_loaded()

    # ─────────────────────────────────────────────────────

    @staticmethod
    def _matches_skill(
        skill: Skill,
        finding: VulnFinding,
        fingerprint: str,
        json_probe: str,
    ) -> bool:
        """检查单个 Skill 是否匹配"""
        match_cfg = skill.match

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
                return False

        # 匹配规则：满足 ANY 一条即可
        for rule in match_cfg.rules:
            if rule.matches(
                fingerprint=fingerprint,
                cve=finding.cve or "",
                evidence=finding.evidence,
                json_probe=json_probe,
                service="",
                port=finding.port,
            ):
                return True

        return False
