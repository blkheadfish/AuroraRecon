"""
skills/registry.py
Skill 注册表 — 渐进式加载

匹配策略（v3 评分制）：
  CVE 精确命中           +100  （强信号，明确就是这个漏洞）
  漏洞名称命中           +60   （VulnAgent 已经识别了漏洞名）
  json_probe 命中        +40   （主动探测确认）
  指纹关键词命中         +20   （框架级匹配，可能是宿主而非漏洞本身）
  证据关键词命中         +10   （最弱信号，容易误触发）

  多个 Skill 匹配时，选评分最高的。
  同分时，category 越具体越优先（java_deserialization > server_misconfig）。

渐进式加载：
  启动时只加载 SkillMeta（~50 tokens/skill），匹配命中后才 load_skill_full()。
"""
from __future__ import annotations

import asyncio
import json as _json
import logging
import os
import threading
import time as _time
from pathlib import Path
from typing import Any, Optional

from backend.agents.models import VulnFinding
from backend.skills.loader import load_all_skills, load_skill_full, load_skills_metadata
from backend.skills.models import MatchRule, Skill, SkillMeta

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
        self._metas: list[SkillMeta] = []  # 轻量元数据（启动时加载）
        self._skill_cache: dict[str, Skill] = {}  # 全量 Skill 缓存（按需加载）
        self._loaded = False
        # RAG 语义路由
        self._embeddings: dict[str, list[float]] = {}  # skill_id → vector
        self._embeddings_ready: bool = False
        self._query_embed_cache: dict[str, tuple[list[float], float]] = {}
        self._embed_cache_ttl: float = 3600.0
        self._embed_semaphore = asyncio.Semaphore(3)

    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        # 启动时只加载轻量元数据
        self._metas = load_skills_metadata()
        self._loaded = True
        logger.info(f"[SkillRegistry] 注册 {len(self._metas)} 个 Skill (渐进式加载)")

    @property
    def size(self) -> int:
        self.ensure_loaded()
        return len(self._metas)

    def _resolve_full(self, meta: SkillMeta) -> Skill | None:
        """按需加载完整 Skill（含 probes/paths/references）。"""
        skill_id = meta.skill_id
        if skill_id not in self._skill_cache:
            full = load_skill_full(meta.source_file)
            if full:
                self._skill_cache[skill_id] = full
            else:
                # Fallback: 从全量加载中获取
                for s in load_all_skills():
                    if s.skill_id == skill_id:
                        self._skill_cache[skill_id] = s
                        break
        cached = self._skill_cache.get(skill_id)
        if cached is None:
            logger.warning("[SkillRegistry] 无法加载完整 Skill: %s", skill_id)
        return cached

    def match(
        self,
        finding: VulnFinding,
        fingerprint: str = "",
        json_probe: str = "",
        workflow_mode: str = "pentest_engineer",
        min_score: Optional[int] = None,
        weak_signal_boost: Optional[int] = None,
        context_vars: Optional[dict[str, Any]] = None,
    ) -> Optional[Skill]:
        """
        根据漏洞发现匹配最适用的 Skill(评分制 + mode 权重)。

        匹配基于轻量 SkillMeta，命中后按需加载完整 Skill。

        Args:
            workflow_mode: pentest_engineer / ctf_expert,用作阈值兜底。
            min_score: 任务显式指定的下限(per-task,覆盖 mode 默认值)。
            weak_signal_boost: 任务显式指定的弱信号加权。
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

        scored: list[tuple[int, SkillMeta]] = []

        for meta in self._metas:
            score = self._score_skill(meta, finding, combined_fp, json_probe, context_vars)
            if score > 0 and boost and score < 60:
                score += boost
            if score >= min_threshold:
                scored.append((score, meta))

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

        best_score, chosen_meta = scored[0]
        logger.info(
            f"[SkillRegistry] ✅ 选择 Skill: {chosen_meta.skill_id} "
            f"(得分={best_score}) ← {finding.name} ({finding.cve})"
        )

        # 按需加载完整 Skill（含 probes/paths/references）
        return self._resolve_full(chosen_meta)

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
        for meta in self._metas:
            score = self._score_skill(meta, finding, combined_fp, json_probe)
            if score > 0:
                scored.append((score, meta))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, m in scored if (s := self._resolve_full(m))]

    def get_by_id(self, skill_id: str) -> Optional[Skill]:
        self.ensure_loaded()
        # Check cache first
        if skill_id in self._skill_cache:
            return self._skill_cache[skill_id]
        # Search metas then lazy-load
        for meta in self._metas:
            if meta.skill_id == skill_id:
                return self._resolve_full(meta)
        return None

    def list_all(self) -> list[dict]:
        self.ensure_loaded()
        return [
            {
                "skill_id": m.skill_id,
                "name": m.name,
                "category": m.category,
                "phase": m.phase,
                "source": m.source_file,
            }
            for m in self._metas
        ]

    def list_by_phase(self, phase: str) -> list[Skill]:
        """Return all skills tagged for the given attack phase."""
        self.ensure_loaded()
        return [s for m in self._metas if m.phase == phase and (s := self._resolve_full(m))]

    def reload(self) -> None:
        """Atomic reload: reload metadata, inject learner adjustments, clear caches."""
        new_metas = load_skills_metadata()

        # ---- NEW: inject execution learner adjustments ----
        try:
            from backend.skills.execution_learner import get_learner
            learner = get_learner()
            for meta in new_metas:
                adjustments = learner.get_adaptive_priorities(meta.skill_id)
                if adjustments:
                    meta.dynamic_priority_adjustments = adjustments
            logger.info(
                "[SkillRegistry] 执行学习器: 注入 %d skills 的优先级调整",
                sum(1 for m in new_metas if m.dynamic_priority_adjustments),
            )
        except Exception as e:
            logger.debug("[SkillRegistry] 执行学习器加载跳过: %s", e)

        self._metas = new_metas
        self._skill_cache.clear()
        self._embeddings.clear()
        self._query_embed_cache.clear()
        self._embeddings_ready = False
        self._loaded = True
        logger.info(f"[SkillRegistry] 重载完成，共 {len(new_metas)} 个 Skill")

    # ── RAG 语义技能路由 ──────────────────────────────────────────────

    @staticmethod
    def _build_skill_search_text(meta: SkillMeta) -> str:
        """构建用于 embedding 的 skill 搜索文本。

        从 SkillMeta 的 match.rules 中提取 CVE / fingerprint / service 等
        关键词，与 name / category 拼接为 embedding 输入。
        """
        parts = [
            meta.name,
            meta.description or "",
            meta.category or "",
        ]
        # 从 match.rules 提取关键词
        for rule in meta.match.rules:
            if rule.cve_matches:
                parts.append(" ".join(rule.cve_matches))
            if rule.fingerprint_contains:
                parts.append(" ".join(rule.fingerprint_contains))
            if rule.service_is:
                parts.append(rule.service_is)
            if rule.evidence_contains:
                parts.append(" ".join(rule.evidence_contains))
        return " ".join(filter(None, parts))

    async def precompute_embeddings(self) -> None:
        """启动时预计算所有 Skill 的 embedding 向量。

        - 检查磁盘缓存 ``skills/.embeddings_cache/{skill_id}.json``
        - 缺失的调用 embedding API 生成
        - 用 asyncio.Semaphore(3) 限制并发
        """
        self.ensure_loaded()
        if not self._metas:
            return

        from backend.knowledge.exploit_kb import get_embedding
        import os as _os

        _ekey = _os.getenv("KB_EMBEDDING_API_KEY", _os.getenv("LLM_API_KEY", ""))
        _eurl = _os.getenv("KB_EMBEDDING_BASE_URL", _os.getenv("LLM_BASE_URL", ""))
        _emodel = _os.getenv("KB_EMBEDDING_MODEL", "")

        logger.info(
            "[SkillRegistry] Embedding 配置: key=%s..., base_url=%s, model=%s",
            (_ekey[:8] + "..." if len(_ekey) > 8 else "(空)"),
            _eurl or "(空)",
            _emodel or "(空，fallback text-embedding-3-small)",
        )

        if not _ekey or not _eurl:
            logger.warning(
                "[SkillRegistry] Embedding API 未配置，语义路由不可用"
            )
            return
        if "deepseek" in _eurl.lower() and not _emodel:
            logger.warning(
                "[SkillRegistry] DeepSeek 不支持 embedding，请单独配置 provider"
            )
            return

        # 快速预检：用一个 skill 测试 API 连通性，不通则快速降级
        test_meta = self._metas[0]
        test_text = self._build_skill_search_text(test_meta)
        try:
            test_vec = await get_embedding(test_text)
            if not test_vec:
                logger.warning(
                    "[SkillRegistry] Embedding API 连通性测试失败，跳过预计算"
                )
                return
        except Exception as e:
            logger.warning(
                f"[SkillRegistry] Embedding API 预检异常: {e}，跳过预计算"
            )
            return

        cache_dir = Path(__file__).resolve().parent / ".embeddings_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)

        # 用 list 做可变计数器，避免 nonlocal 在 asyncio.gather 里的潜在问题
        counters = [0, 0]  # [new_count, cached_count]
        # 先存好测试结果的缓存
        self._embeddings[test_meta.skill_id] = test_vec
        counters[0] += 1

        async def _compute_one(meta: SkillMeta) -> None:
            cache_file = cache_dir / f"{meta.skill_id}.json"

            if cache_file.exists():
                try:
                    data = _json.loads(cache_file.read_text(encoding="utf-8"))
                    vec = data.get("embedding")
                    if isinstance(vec, list) and len(vec) > 0:
                        self._embeddings[meta.skill_id] = vec
                        counters[1] += 1
                        return
                except Exception:
                    pass

            search_text = self._build_skill_search_text(meta)
            if not search_text.strip():
                return

            async with self._embed_semaphore:
                try:
                    vec = await get_embedding(search_text)
                except Exception as e:
                    logger.warning(
                        f"[SkillRegistry] embedding API 异常 {meta.skill_id}: {e}"
                    )
                    return

            if vec and len(vec) > 0:
                self._embeddings[meta.skill_id] = vec
                counters[0] += 1
                try:
                    cache_file.write_text(
                        _json.dumps({"embedding": vec}, ensure_ascii=False),
                        encoding="utf-8",
                    )
                except Exception:
                    pass
            else:
                _empty_count = getattr(self, "_embed_empty_logged", 0)
                if _empty_count < 3:
                    self._embed_empty_logged = _empty_count + 1
                    logger.warning(
                        f"[SkillRegistry] get_embedding 返回空 ({meta.skill_id})，"
                        f"检查 base_url={_eurl}"
                    )

        tasks = [_compute_one(m) for m in self._metas]
        await asyncio.gather(*tasks)

        self._embeddings_ready = bool(self._embeddings)
        logger.info(
            f"[SkillRegistry] embedding 预计算完成: "
            f"新增 {counters[0]}, 缓存命中 {counters[1]}, "
            f"总计 {len(self._embeddings)}/{len(self._metas)}"
        )

    async def _match_by_embedding(
        self,
        finding: VulnFinding,
        fingerprint: str = "",
        json_probe: str = "",
    ) -> Optional[Skill]:
        """用 embedding 语义匹配 Skill。

        若 ``_embeddings_ready`` 为 False 或无 embedding API 配置，返回 None。
        对 finding 构建 query text → embedding → 对所有 skill 计算 cosine similarity。
        取最高相似度 >= 0.60 的 skill。
        """
        if not self._embeddings_ready or not self._embeddings:
            return None

        from backend.knowledge.exploit_kb import get_embedding, cosine_similarity

        # 构建 query text
        query_parts = [
            finding.name,
            finding.cve or "",
            finding.description or "",
            (finding.evidence or "")[:500],
            fingerprint[:500],
            json_probe[:300],
        ]
        query_text = " ".join(filter(None, query_parts))
        if not query_text.strip():
            return None

        # 检查 query 缓存
        now = _time.monotonic()
        query_vec = None
        cached = self._query_embed_cache.get(query_text)
        if cached:
            vec, ts = cached
            if now - ts < self._embed_cache_ttl:
                query_vec = vec

        if query_vec is None:
            try:
                query_vec = await get_embedding(query_text)
            except Exception as e:
                logger.warning(f"[SkillRegistry] query embedding 失败: {e}")
                return None
            if not query_vec:
                return None
            self._query_embed_cache[query_text] = (query_vec, now)
            # 清理过期缓存
            if len(self._query_embed_cache) > 500:
                expired = [
                    k for k, (_, t) in self._query_embed_cache.items()
                    if now - t > self._embed_cache_ttl
                ]
                for k in expired:
                    self._query_embed_cache.pop(k, None)

        # 计算 cosine similarity 对所有 skill
        best_score = 0.0
        best_skill_id = ""
        for skill_id, skill_vec in self._embeddings.items():
            sim = cosine_similarity(query_vec, skill_vec)
            if sim > best_score:
                best_score = sim
                best_skill_id = skill_id

        MIN_SIMILARITY = 0.60
        if best_score >= MIN_SIMILARITY and best_skill_id:
            skill = self.get_by_id(best_skill_id)
            if skill:
                logger.info(
                    f"[SkillRegistry] 🧠 embedding 匹配: {best_skill_id} "
                    f"(相似度={best_score:.3f}) ← {finding.name}"
                )
                return skill

        logger.debug(
            f"[SkillRegistry] embedding 无匹配 (最高={best_score:.3f} < {MIN_SIMILARITY})"
        )
        return None

    # ── LLM 语义匹配兜底 ──────────────────────────────────────────────

    def _build_skill_list_for_llm(self) -> str:
        """Build a compact skill catalog for LLM semantic matching."""
        self.ensure_loaded()
        lines = ["Available Skills:"]
        for m in self._metas:
            desc = m.description or m.name
            lines.append(f"- skill_id: {m.skill_id}")
            lines.append(f"  description: {desc}")
        return "\n".join(lines)

    async def _llm_select_skill(
        self,
        finding: VulnFinding,
        fingerprint: str = "",
        json_probe: str = "",
    ) -> Optional[Skill]:
        """
        LLM semantic fallback: when algorithmic scoring fails, ask LLM to pick
        the best matching skill from the catalog.

        Returns the matched Skill or None.
        """
        from backend.llm.router import LLMRouter

        llm = LLMRouter()
        skill_list = self._build_skill_list_for_llm()

        finding_info = (
            f"漏洞名称: {finding.name}\n"
            f"CVE: {finding.cve or 'N/A'}\n"
            f"描述: {finding.description or '无'}\n"
            f"证据: {(finding.evidence or '')[:500]}\n"
            f"指纹: {fingerprint[:500]}\n"
            f"JSON探针: {json_probe[:300]}\n"
        )

        prompt = (
            f"根据以下漏洞发现信息，从 Skill 列表中选择最匹配的一个 skill_id。\n"
            f"如果没有任何 Skill 匹配，返回 \"none\"。\n\n"
            f"{finding_info}\n\n"
            f"{skill_list}\n\n"
            f"请严格返回 JSON: {{\"skill_id\": \"<skill_id 或 none>\", \"reason\": \"简短理由\"}}"
        )

        try:
            response_raw = await llm.chat_multi_turn(
                messages=[{"role": "user", "content": prompt}],
                system_prompt="你是一名渗透测试 Skill 路由器。根据漏洞信息选择最匹配的 Skill。",
                response_format="json",
                temperature=0.1,
            )
        except Exception as e:
            logger.warning(f"[SkillRegistry] LLM 语义匹配失败: {e}")
            return None

        try:
            response_text = response_raw if isinstance(response_raw, str) else response_raw[0]
            result = _json.loads(response_text)
            chosen_id = (result.get("skill_id") or "").strip()
            reason = result.get("reason", "")
        except Exception:
            logger.warning("[SkillRegistry] LLM 返回非法 JSON")
            return None

        if not chosen_id or chosen_id.lower() == "none":
            logger.info("[SkillRegistry] LLM 语义匹配: 无匹配")
            return None

        skill = self.get_by_id(chosen_id)
        if skill:
            logger.info(
                f"[SkillRegistry] 🤖 LLM 语义匹配: {chosen_id} — {reason}"
            )
        else:
            logger.warning(
                f"[SkillRegistry] LLM 选择了不存在的 skill_id: {chosen_id}"
            )
        return skill

    async def match_with_llm_fallback(
        self,
        finding: VulnFinding,
        fingerprint: str = "",
        json_probe: str = "",
        workflow_mode: str = "pentest_engineer",
        min_score: Optional[int] = None,
        weak_signal_boost: Optional[int] = None,
        context_vars: Optional[dict[str, Any]] = None,
    ) -> Optional[Skill]:
        """
        算法匹配 + LLM 语义匹配兜底。

        先跑算法评分，无匹配时用 LLM 从 skill catalog 中选择。
        """
        # 1. 算法评分匹配
        skill = self.match(
            finding=finding,
            fingerprint=fingerprint,
            json_probe=json_probe,
            workflow_mode=workflow_mode,
            min_score=min_score,
            weak_signal_boost=weak_signal_boost,
            context_vars=context_vars,
        )
        if skill:
            return skill

        # 2. embedding 语义匹配
        skill = await self._match_by_embedding(
            finding=finding,
            fingerprint=fingerprint,
            json_probe=json_probe,
        )
        if skill:
            return skill

        # 3. LLM 语义兜底
        logger.info("[SkillRegistry] 算法+embedding 无匹配，启动 LLM 语义兜底...")
        return await self._llm_select_skill(
            finding=finding,
            fingerprint=fingerprint,
            json_probe=json_probe,
        )

    @staticmethod
    def _score_skill(
        skill: Skill | SkillMeta,
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