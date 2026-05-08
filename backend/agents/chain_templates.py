"""
chain_templates.py —— 动态攻击链模板

根据 scope_hint 选择不同的攻击链拓扑，解决当前"一条链走到底"的
Web 中心主义问题。模板决定：
  - 哪些 phase 节点参与图构建
  - phase 的默认线性顺序
  - 前端 PipelineFlow 显示的步骤

三个模板：
  web       —— 默认，Web 应用渗透全流程
  intranet  —— 内网/AD 域渗透，跳过 Web 枚举，优先 SMB/LDAP/Kerberos
  cloud     —— 云环境渗透，聚焦 IMDS/S3/IAM/K8s API
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ── 阶段中文标签（供前端 PhaseTree 使用）──────────────────────────
PHASE_LABELS: dict[str, str] = {
    "init": "初始化",
    "recon": "信息侦察",
    "surface_enum": "表面枚举",
    "intel_harvest": "情报采集",
    "vuln_scan": "漏洞扫描",
    "exploit_decision": "利用决策",
    "awaiting_approval": "人工审批",
    "foothold_attempt": "立足点获取",
    "exploit": "漏洞利用",
    "secondary_attack": "二次利用",
    "post_foothold_enum": "立足后枚举",
    "post_foothold_approval": "立足后审批",
    "internal_scan": "内网扫描",
    "privesc_attempt": "权限提升",
    "lateral_movement": "横向移动",
    "persistence": "持久化",
    "objective_collect": "目标收集",
    "post_exploit": "后渗透",
    "report": "报告生成",
    # intranet 新增
    "smb_enum": "SMB枚举",
    "ldap_enum": "LDAP枚举",
    "kerberos_attack": "Kerberos攻击",
    # cloud 新增
    "cloud_enum": "云资产发现",
    "cloud_exploit": "云漏洞利用",
}

# ── 阶段类别映射（供前端 PhaseTree 颜色分组）──────────────────────
PHASE_CATEGORY: dict[str, str] = {
    "init": "init",
    "recon": "recon",
    "surface_enum": "recon",
    "intel_harvest": "recon",
    "smb_enum": "recon",
    "ldap_enum": "recon",
    "cloud_enum": "recon",
    "vuln_scan": "scan",
    "exploit_decision": "exploit",
    "awaiting_approval": "approval",
    "foothold_attempt": "exploit",
    "exploit": "exploit",
    "secondary_attack": "exploit",
    "kerberos_attack": "exploit",
    "cloud_exploit": "exploit",
    "post_foothold_enum": "post",
    "post_foothold_approval": "post",
    "internal_scan": "post",
    "privesc_attempt": "post",
    "lateral_movement": "post",
    "persistence": "post",
    "objective_collect": "post",
    "post_exploit": "post",
    "report": "report",
}


@dataclass
class ChainTemplate:
    template_id: str
    label: str
    phases: list[str]          # 有序阶段列表（不含 report，report 是终端节点）
    pipeline_steps: list[dict]  # [{key, label}] 前端 PipelineFlow 显示
    default_chain_mode: str    # linear | feedback | supervisor

    def phase_set(self) -> set[str]:
        return set(self.phases) | {"report"}

    def successor_table(self) -> dict[str, list[str]]:
        """从 phase 列表构建 _LINEAR_CHAIN_SUCCESSORS 风格的前驱映射。

        每个 phase 可达其后所有阶段（通过 _edge_plan_forward 跳过机制），
        最大跳跃步数由 phase 间距离决定。
        """
        tbl: dict[str, list[str]] = {}
        for i, ph in enumerate(self.phases):
            successors = []
            for j in range(i + 1, min(i + 5, len(self.phases))):
                successors.append(self.phases[j])
            if not successors:
                successors = ["report"]
            tbl[ph] = successors
        return tbl


# ── 模板定义 ───────────────────────────────────────────────────────

CHAIN_TEMPLATES: dict[str, ChainTemplate] = {
    "web": ChainTemplate(
        template_id="web",
        label="Web应用渗透",
        phases=[
            "recon", "surface_enum", "intel_harvest", "vuln_scan",
            "exploit_decision", "awaiting_approval", "foothold_attempt",
            "secondary_attack", "post_foothold_enum", "post_foothold_approval",
            "internal_scan", "privesc_attempt", "lateral_movement",
            "persistence", "objective_collect",
        ],
        pipeline_steps=[
            {"key": "recon", "label": "信息侦察"},
            {"key": "vuln_scan", "label": "漏洞扫描"},
            {"key": "exploit_decision", "label": "AI 决策"},
            {"key": "exploit", "label": "漏洞利用"},
            {"key": "post_exploit", "label": "后渗透"},
            {"key": "report", "label": "报告生成"},
        ],
        default_chain_mode="linear",
    ),
    "intranet": ChainTemplate(
        template_id="intranet",
        label="内网/AD域渗透",
        phases=[
            "recon", "smb_enum", "ldap_enum", "vuln_scan",
            "exploit_decision", "awaiting_approval", "foothold_attempt",
            "kerberos_attack", "post_foothold_enum", "post_foothold_approval",
            "internal_scan", "privesc_attempt", "lateral_movement",
            "persistence", "objective_collect",
        ],
        pipeline_steps=[
            {"key": "recon", "label": "侦察发现"},
            {"key": "smb_enum", "label": "服务枚举"},
            {"key": "kerberos_attack", "label": "凭据攻击"},
            {"key": "exploit", "label": "漏洞利用"},
            {"key": "post_exploit", "label": "后渗透"},
            {"key": "report", "label": "报告生成"},
        ],
        default_chain_mode="linear",
    ),
    "cloud": ChainTemplate(
        template_id="cloud",
        label="云环境渗透",
        phases=[
            "recon", "cloud_enum", "vuln_scan",
            "exploit_decision", "awaiting_approval", "foothold_attempt",
            "cloud_exploit", "post_foothold_enum", "post_foothold_approval",
            "privesc_attempt", "lateral_movement",
            "persistence", "objective_collect",
        ],
        pipeline_steps=[
            {"key": "recon", "label": "云资产发现"},
            {"key": "cloud_enum", "label": "IAM枚举"},
            {"key": "vuln_scan", "label": "存储探测"},
            {"key": "exploit", "label": "漏洞利用"},
            {"key": "post_exploit", "label": "后渗透"},
            {"key": "report", "label": "报告生成"},
        ],
        default_chain_mode="linear",
    ),
}


# ── scope_hint → template_id 映射 ──────────────────────────────────

_SCOPE_TO_TEMPLATE: dict[str, str] = {
    "intranet": "intranet",
    "subnet": "intranet",
    "c_segment": "intranet",
    "dmz": "intranet",
    "corporate_network": "intranet",
    "ad_domain": "intranet",
    "cloud": "cloud",
}


def select_template(scope_hint: Optional[str] = None) -> ChainTemplate:
    if scope_hint:
        tid = _SCOPE_TO_TEMPLATE.get(scope_hint.strip().lower())
        if tid and tid in CHAIN_TEMPLATES:
            return CHAIN_TEMPLATES[tid]
    return CHAIN_TEMPLATES["web"]


def get_template(template_id: str) -> ChainTemplate:
    return CHAIN_TEMPLATES.get(template_id, CHAIN_TEMPLATES["web"])


def pipeline_steps_for(template_id: str) -> list[dict]:
    return get_template(template_id).pipeline_steps


def phase_labels_for(template_id: str) -> dict[str, str]:
    """返回该模板相关 phase 的中文标签（包含通用 phase 兜底）。"""
    tpl = get_template(template_id)
    relevant = tpl.phase_set()
    return {k: v for k, v in PHASE_LABELS.items() if k in relevant or k in ("init", "report")}


def phase_categories_for(template_id: str) -> dict[str, str]:
    """返回该模板相关 phase 的类别映射。"""
    tpl = get_template(template_id)
    relevant = tpl.phase_set()
    return {k: v for k, v in PHASE_CATEGORY.items() if k in relevant or k in ("init", "report")}
