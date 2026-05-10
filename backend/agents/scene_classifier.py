"""
scene_classifier.py —— 攻击场景感知分类器

在 Recon 阶段完成后运行，根据发现的端口/服务/版本指纹自动：
  1. 识别目标场景类型（Web / 内网AD / 云 / 数据库 / 网络服务）
  2. 推荐链模板切换
  3. 输出适应提示（跳过的阶段 / 聚焦的阶段 / 首选工具）

设计原则：
  - 版本指纹 > banner > 服务名 > 端口号（权重递减）
  - 非默认端口但有服务指纹确认 = 高置信度
  - 组合特征（如 88+389+445 同时出现）有额外加成
  - 不重复计分（每个端口的证据只入一次）
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from backend.agents.models import PentestState, PortInfo

logger = logging.getLogger(__name__)

SCENE_WEB = "web"
SCENE_INTRANET = "intranet"
SCENE_CLOUD = "cloud"
SCENE_DATABASE = "database"
SCENE_NETWORK_SERVICE = "network_service"

ALL_SCENES = (SCENE_WEB, SCENE_INTRANET, SCENE_CLOUD, SCENE_DATABASE, SCENE_NETWORK_SERVICE)

# ═══════════════════════════════════════════════════════════════════════
# Layer 1 — 版本/banner 指纹匹配（最高权重）→ 某端口"就是"某服务
#    格式: (关键词列表, 场景, 权重)
#    匹配 version 或 banner 字段，不区分大小写
# ═══════════════════════════════════════════════════════════════════════

_FINGERPRINT_RULES: list[tuple[list[str], str, float]] = [

    # ── Web 服务器指纹 ──
    (["nginx", "nginx/"], SCENE_WEB, 8.0),
    (["apache", "apache/", "httpd"], SCENE_WEB, 8.0),
    (["microsoft-iis", "iis/", "microsoft-httpapi"], SCENE_WEB, 8.0),
    (["tomcat", "apache tomcat", "coyote"], SCENE_WEB, 8.0),
    (["jetty"], SCENE_WEB, 7.0),
    (["gunicorn", "uwsgi", "waitress", "golang net/http"], SCENE_WEB, 6.0),
    (["node.js", "express", "nodejs"], SCENE_WEB, 6.0),
    (["weblogic", "bea weblogic"], SCENE_WEB, 8.0),
    (["jboss", "jbossas", "wildfly", "jboss web"], SCENE_WEB, 8.0),
    (["jenkins", "hudson"], SCENE_WEB, 7.0),
    (["gitlab", "gitlab-ce", "gitlab-ee"], SCENE_WEB, 7.0),
    (["grafana"], SCENE_WEB, 6.0),
    (["php", "php/"], SCENE_WEB, 5.0),
    (["wordpress", "wp-"], SCENE_WEB, 7.0),
    (["joomla"], SCENE_WEB, 7.0),
    (["drupal"], SCENE_WEB, 7.0),
    (["flask", "werkzeug", "python/wsgi"], SCENE_WEB, 5.0),
    (["django", "django rest"], SCENE_WEB, 5.0),
    (["laravel"], SCENE_WEB, 5.0),
    (["spring", "springboot", "spring boot"], SCENE_WEB, 5.0),
    (["struts", "struts2"], SCENE_WEB, 6.0),

    # ── 内网/Win 服务指纹 ──
    (["microsoft windows", "windows server", "win32"], SCENE_INTRANET, 8.0),
    (["active directory", "domain controller"], SCENE_INTRANET, 10.0),
    (["microsoft-ds", "smb", "samba"], SCENE_INTRANET, 8.0),
    (["microsoft ldap", "ad ldap"], SCENE_INTRANET, 9.0),
    (["kerberos", "microsoft kerberos"], SCENE_INTRANET, 9.0),
    (["microsoft rpc", "msrpc", "dcerpc"], SCENE_INTRANET, 7.0),
    (["microsoft sql server", "ms-sql", "mssql"], SCENE_INTRANET, 9.0),
    (["remote desktop", "rdp", "terminal services"], SCENE_INTRANET, 8.0),
    (["winrm", "ws-management"], SCENE_INTRANET, 8.0),
    (["netbios", "netbios-ssn"], SCENE_INTRANET, 7.0),
    (["microsoft exchange", "exchange server"], SCENE_INTRANET, 8.0),
    (["microsoft sharepoint"], SCENE_INTRANET, 7.0),

    # ── 数据库指纹 ──
    (["mysql", "mariadb"], SCENE_DATABASE, 8.0),
    (["postgresql", "pgsql"], SCENE_DATABASE, 8.0),
    (["redis"], SCENE_DATABASE, 7.0),
    (["mongodb"], SCENE_DATABASE, 7.0),
    (["oracle database", "oracle tns", "oracle db"], SCENE_DATABASE, 8.0),
    (["cassandra"], SCENE_DATABASE, 7.0),
    (["elasticsearch", "elastic"], SCENE_DATABASE, 7.0),
    (["memcached", "memcache"], SCENE_DATABASE, 6.0),

    # ── 云/K8s 指纹 ──
    (["kubernetes", "kube-apiserver", "kubelet"], SCENE_CLOUD, 10.0),
    (["etcd"], SCENE_CLOUD, 9.0),
    (["aws", "amazon"], SCENE_CLOUD, 8.0),
    (["azure", "microsoft azure"], SCENE_CLOUD, 8.0),
    (["google cloud", "gcp"], SCENE_CLOUD, 8.0),
    (["docker", "containerd"], SCENE_CLOUD, 6.0),
    (["consul", "nomad"], SCENE_CLOUD, 7.0),
    (["vault", "hashicorp vault"], SCENE_CLOUD, 7.0),

    # ── 网络服务指纹 ──
    (["openssh", "openssh_"], SCENE_NETWORK_SERVICE, 6.0),
    (["vsftpd", "proftpd", "pure-ftpd"], SCENE_NETWORK_SERVICE, 6.0),
    (["bind", "bind9", "named", "powerdns", "dnsmasq"], SCENE_NETWORK_SERVICE, 6.0),
    (["postfix", "exim", "sendmail", "exchange smtp"], SCENE_NETWORK_SERVICE, 6.0),
    (["dovecot", "courier-imap"], SCENE_NETWORK_SERVICE, 6.0),
    (["nfs", "rpcbind", "portmapper", "nlockmgr"], SCENE_NETWORK_SERVICE, 6.0),
    (["snmp", "net-snmp"], SCENE_NETWORK_SERVICE, 5.0),
]

# ═══════════════════════════════════════════════════════════════════════
# Layer 2 — 服务名匹配（Nmap 的 service 字段）→ nmap 认为这是 X
#    权重低于指纹，因为 nmap 的 service 识别有时会错
# ═══════════════════════════════════════════════════════════════════════

_SERVICE_NAME_RULES: list[tuple[list[str], str, float]] = [

    # Web
    (["http", "https", "http-proxy", "http-alt", "ssl/http", "ssl/https",
      "http-mgmt", "http-rpc-epmap", "www", "soap", "wsman"], SCENE_WEB, 3.0),

    # Intranet
    (["microsoft-ds", "netbios-ssn", "netbios-ns"], SCENE_INTRANET, 5.0),
    (["ldap", "ldaps", "ldap-admin", "globalcatldap", "globalcatldaps"], SCENE_INTRANET, 5.0),
    (["kerberos", "kerberos-adm", "kerberos-sec", "kpasswd5"], SCENE_INTRANET, 5.0),
    (["msrpc", "epmap", "dcerpc", "ncacn_http"], SCENE_INTRANET, 4.0),
    (["ms-sql-m", "ms-sql-s", "ms-sql", "mssql"], SCENE_INTRANET, 5.0),
    (["ms-wbt-server", "ms-term-serv", "rdp", "rdp-tcp"], SCENE_INTRANET, 5.0),
    (["wsman", "winrm"], SCENE_INTRANET, 5.0),
    (["msrpc", "ms-wbt-server"], SCENE_INTRANET, 4.0),

    # Database
    (["mysql", "mariadb"], SCENE_DATABASE, 4.0),
    (["postgresql", "postgres", "pgsql"], SCENE_DATABASE, 4.0),
    (["redis"], SCENE_DATABASE, 4.0),
    (["mongod", "mongodb"], SCENE_DATABASE, 4.0),
    (["oracle-tns", "oracle-tns-ssl", "oracle", "tnslsnr"], SCENE_DATABASE, 4.0),
    (["cassandra", "cassandra-thrift"], SCENE_DATABASE, 4.0),
    (["elasticsearch", "elastic"], SCENE_DATABASE, 4.0),
    (["memcached", "memcache"], SCENE_DATABASE, 3.0),

    # Cloud
    (["kubernetes", "kube-apiserver", "kubelet", "kube-proxy"], SCENE_CLOUD, 5.0),
    (["etcd", "etcd-client"], SCENE_CLOUD, 5.0),
    (["consul", "consul-http"], SCENE_CLOUD, 4.0),

    # Network Service
    (["ssh"], SCENE_NETWORK_SERVICE, 3.0),
    (["ftp", "ftp-data", "ftps"], SCENE_NETWORK_SERVICE, 3.0),
    (["telnet"], SCENE_NETWORK_SERVICE, 3.0),
    (["smtp", "smtps", "submission"], SCENE_NETWORK_SERVICE, 3.0),
    (["domain", "dns", "dns-tcp"], SCENE_NETWORK_SERVICE, 3.0),
    (["pop3", "pop3s", "imap", "imaps"], SCENE_NETWORK_SERVICE, 3.0),
    (["snmp", "snmp-trap"], SCENE_NETWORK_SERVICE, 3.0),
    (["nfs", "nfs-acl", "mountd", "nlockmgr", "rpcbind", "portmapper", "rquotad"],
     SCENE_NETWORK_SERVICE, 4.0),
    (["rsync"], SCENE_NETWORK_SERVICE, 3.0),
]

# ═══════════════════════════════════════════════════════════════════════
# Layer 3 — 端口默认映射（仅当 service 字段为空或模糊时启用）
#    每个端口只出现在一个字典里，不会重复计分
# ═══════════════════════════════════════════════════════════════════════

_PORT_DEFAULTS: dict[int, tuple[str, float]] = {
    # Web
    80:   (SCENE_WEB, 1.5),  443:  (SCENE_WEB, 1.5),
    8080: (SCENE_WEB, 1.5),  8443: (SCENE_WEB, 1.5),
    8000: (SCENE_WEB, 1.0),  8888: (SCENE_WEB, 1.0),
    3000: (SCENE_WEB, 1.0),  5000: (SCENE_WEB, 1.0),
    9000: (SCENE_WEB, 1.0),  9090: (SCENE_WEB, 1.0),

    # Intranet
    445:  (SCENE_INTRANET, 2.0),  139:  (SCENE_INTRANET, 1.5),
    389:  (SCENE_INTRANET, 2.0),  636:  (SCENE_INTRANET, 1.5),
    3268: (SCENE_INTRANET, 1.5),  3269: (SCENE_INTRANET, 1.5),
    88:   (SCENE_INTRANET, 2.0),  135:  (SCENE_INTRANET, 1.5),
    1433: (SCENE_INTRANET, 1.5),  3389: (SCENE_INTRANET, 1.5),
    5985: (SCENE_INTRANET, 1.5),  5986: (SCENE_INTRANET, 1.5),

    # Database
    3306:  (SCENE_DATABASE, 1.5),  5432:  (SCENE_DATABASE, 1.5),
    1521:  (SCENE_DATABASE, 1.5),  6379:  (SCENE_DATABASE, 1.0),
    27017: (SCENE_DATABASE, 1.0),  9042:  (SCENE_DATABASE, 1.0),

    # Cloud / K8s
    6443:  (SCENE_CLOUD, 1.5),  10250: (SCENE_CLOUD, 1.0),

    # Network Service
    22:   (SCENE_NETWORK_SERVICE, 1.0),  21:    (SCENE_NETWORK_SERVICE, 1.0),
    23:   (SCENE_NETWORK_SERVICE, 1.0),  25:    (SCENE_NETWORK_SERVICE, 1.0),
    53:   (SCENE_NETWORK_SERVICE, 1.0),  161:   (SCENE_NETWORK_SERVICE, 1.0),
    2049: (SCENE_NETWORK_SERVICE, 1.5),  111:   (SCENE_NETWORK_SERVICE, 1.5),
    873:  (SCENE_NETWORK_SERVICE, 1.0),
}

# ═══════════════════════════════════════════════════════════════════════
# Layer 4 — 组合特征加成（端口对/三元组同时出现时的乘数）
#    格式: (frozenset of ports, 场景, 额外加分)
# ═══════════════════════════════════════════════════════════════════════

_COMBO_BOOSTS: list[tuple[frozenset[int], str, float]] = [
    # AD 域控：LDAP + Kerberos + SMB
    (frozenset({88, 389}), SCENE_INTRANET, 6.0),
    (frozenset({88, 445}), SCENE_INTRANET, 6.0),
    (frozenset({389, 445}), SCENE_INTRANET, 6.0),
    (frozenset({88, 389, 445}), SCENE_INTRANET, 10.0),
    # SMB + NetBIOS
    (frozenset({139, 445}), SCENE_INTRANET, 4.0),
    # WinRM 双端口
    (frozenset({5985, 5986}), SCENE_INTRANET, 3.0),
    # Web + DB combo (LAMP/LEMP)
    (frozenset({80, 3306}), SCENE_WEB, 3.0),
    (frozenset({443, 3306}), SCENE_WEB, 3.0),
    (frozenset({80, 5432}), SCENE_WEB, 3.0),
    # K8s 全套
    (frozenset({6443, 10250}), SCENE_CLOUD, 5.0),
    # Redis on standard port + Web → 可能是缓存
    (frozenset({80, 6379}), SCENE_WEB, 2.0),
]

# ═══════════════════════════════════════════════════════════════════════
# 云 metadata IP
# ═══════════════════════════════════════════════════════════════════════

_CLOUD_METADATA_IPS = {"169.254.169.254", "100.100.100.200"}


@dataclass
class SceneClassification:
    primary_scene: str
    secondary_scenes: list[str] = field(default_factory=list)
    recommended_template: str = "web"
    adaptation_hints: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    rationale: str = ""
    evidence_summary: dict[str, float] = field(default_factory=dict)

    @property
    def has_web(self) -> bool:
        return SCENE_WEB in self.all_scenes()

    @property
    def has_intranet(self) -> bool:
        return SCENE_INTRANET in self.all_scenes()

    @property
    def has_cloud(self) -> bool:
        return SCENE_CLOUD in self.all_scenes()

    def all_scenes(self) -> set[str]:
        return {self.primary_scene} | set(self.secondary_scenes)


def classify_scene(state: PentestState) -> SceneClassification:
    """根据 state 中的端口、服务、版本指纹推断攻击场景。"""
    open_ports: list[PortInfo] = list(state.open_ports or [])

    if not open_ports:
        return SceneClassification(
            primary_scene=SCENE_WEB,
            recommended_template="web",
            confidence=0.0,
            rationale="无开放端口，无法判断场景，默认 Web",
        )

    scores: dict[str, float] = {s: 0.0 for s in ALL_SCENES}
    evidence_log: list[str] = []
    open_port_nums: set[int] = set()

    for p in open_ports:
        if not p.port:
            continue
        port = int(p.port)
        open_port_nums.add(port)
        service = (p.service or "").lower().strip()
        version = (p.version or "").lower().strip()
        banner = (p.banner or "").lower().strip()
        version_text = f"{version} {banner}".strip()
        has_service_name = bool(service)

        matched_by_fingerprint = False

        # ── Layer 1: 版本/banner 指纹（权重最高）──
        if version_text:
            for keywords, scene, weight in _FINGERPRINT_RULES:
                for kw in keywords:
                    if kw in version_text:
                        scores[scene] += weight
                        evidence_log.append(
                            f"  +{weight:.0f} {scene} ← 指纹匹配 '{kw}' "
                            f"@ {port}/{service or '?'}"
                        )
                        matched_by_fingerprint = True
                        break
                if matched_by_fingerprint:
                    break

        # ── Layer 2: 服务名匹配（指纹未命中时启用）──
        if not matched_by_fingerprint and has_service_name:
            for svc_names, scene, weight in _SERVICE_NAME_RULES:
                if service in svc_names:
                    scores[scene] += weight
                    evidence_log.append(
                        f"  +{weight:.0f} {scene} ← 服务名 '{service}' @ {port}"
                    )
                    break

        # ── Layer 3: 端口默认（仅当无指纹且服务名为空/模糊时）──
        if not matched_by_fingerprint and not has_service_name:
            default = _PORT_DEFAULTS.get(port)
            if default:
                scene, weight = default
                scores[scene] += weight
                evidence_log.append(
                    f"  +{weight:.1f} {scene} ← 默认端口 {port}"
                )

    # ── Layer 4: 组合特征加成 ──
    for port_set, scene, boost in _COMBO_BOOSTS:
        if port_set.issubset(open_port_nums):
            scores[scene] += boost
            evidence_log.append(
                f"  +{boost:.0f} {scene} ← 组合特征 {sorted(port_set)}"
            )

    # ── Layer 5: Web 路径 / 子域名明显证据 ──
    if state.web_paths or state.web_paths_inventory:
        scores[SCENE_WEB] += 4.0
        evidence_log.append(f"  +4.0 web ← 已发现 Web 路径/目录清单")

    if state.subdomains:
        scores[SCENE_WEB] += 2.0
        evidence_log.append(f"  +2.0 web ← 已发现子域名")

    # ── Layer 6: 云 metadata IP 检测 ──
    if state.target_host in _CLOUD_METADATA_IPS:
        scores[SCENE_CLOUD] += 10.0
        evidence_log.append(f"  +10 cloud ← 目标 IP 为云 metadata 地址")

    # ── Layer 7: OS 指纹弱信号 ──
    os_name = str(state.os_info.get("name", "")).lower()
    if "windows" in os_name:
        scores[SCENE_INTRANET] += 1.5
        evidence_log.append("  +1.5 intranet ← OS 指纹 Windows")
    elif "linux" in os_name:
        # Linux 不偏向任何场景，但排除纯 Windows 内网
        pass

    # ── 排名 ──
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    max_score = ranked[0][1]

    # 主场景：最高分
    primary = ranked[0][0] if max_score > 0 else SCENE_WEB

    # 次场景：分数 ≥ max_score 的 30% 且 ≥ 3.0（最小信号门槛）
    secondary = [
        r[0] for r in ranked[1:]
        if r[1] >= max_score * 0.3 and r[1] >= 3.0
    ]

    # ── 置信度：基于证据层 ──
    # 指纹命中数 / 总端口数的比例决定
    fingerprint_hit_count = sum(
        1 for log in evidence_log if "指纹匹配" in log
    )
    total_ports = len(open_port_nums)
    fingerprint_ratio = fingerprint_hit_count / max(total_ports, 1)

    if max_score >= 12 and fingerprint_ratio >= 0.5:
        confidence = 0.9
    elif max_score >= 8:
        confidence = 0.7
    elif max_score >= 4:
        confidence = 0.5
    else:
        confidence = 0.3

    # ── 推荐模板 ──
    recommended = _pick_template(scores, fingerprint_ratio)

    # ── 适应提示 ──
    hints = _build_adaptation_hints(primary, secondary, state)

    # ── rationale ──
    port_brief = ", ".join(
        f"{p.port}/{p.service or '?'}" + (f"({p.version})" if p.version else "")
        for p in open_ports[:15]
    )
    evidence_brief = "\n".join(evidence_log[:12])
    rationale = (
        f"端口: {port_brief or '无'}\n"
        f"主场景: {primary}(score={max_score:.1f}), "
        f"推荐模板: {recommended}, confidence={confidence:.1%}\n"
        + (f"次场景: {', '.join(secondary)}\n" if secondary else "")
        + f"证据链:\n{evidence_brief}"
    )

    return SceneClassification(
        primary_scene=primary,
        secondary_scenes=secondary,
        recommended_template=recommended,
        adaptation_hints=hints,
        confidence=confidence,
        rationale=rationale,
        evidence_summary={s: scores[s] for s in ALL_SCENES},
    )


def _pick_template(
    scores: dict[str, float],
    fingerprint_ratio: float,
) -> str:
    """根据场景分数和指纹置信度选择链模板。"""
    intranet_score = scores[SCENE_INTRANET]
    cloud_score = scores[SCENE_CLOUD]

    # 云模板：需要较高门槛，避免误判
    if cloud_score >= 8 or (cloud_score >= 5 and fingerprint_ratio >= 0.3):
        return "cloud"

    # 内网模板
    if intranet_score >= 6 or (intranet_score >= 3 and fingerprint_ratio >= 0.5):
        return "intranet"

    return "web"


def _build_adaptation_hints(
    primary: str, secondary: list[str], state: PentestState
) -> dict[str, Any]:
    """根据场景类型生成下游可消费的阶段调整提示。"""
    hints: dict[str, Any] = {
        "skip_phases": [],
        "focus_phases": [],
        "prefer_tools": [],
        "avoid_tools": [],
        "focus_ports": [],
        "focus_services": [],
    }

    all_scenes = {primary} | set(secondary)

    # ── 从端口列表提取聚焦目标 ──
    for p in (state.open_ports or []):
        svc = (p.service or "").lower()
        if SCENE_WEB not in all_scenes and p.port in (80, 443, 8080, 8443):
            continue
        if SCENE_INTRANET in all_scenes and svc in (
            "microsoft-ds", "ldap", "kerberos", "ms-sql-m", "ms-wbt-server",
        ):
            hints["focus_services"].append(svc)
            hints["focus_ports"].append(p.port)

    # ── 无 Web 场景：跳过 Web 表面枚举和情报采集 ──
    if SCENE_WEB not in all_scenes:
        hints["skip_phases"].extend(["surface_enum", "intel_harvest"])
        hints["avoid_tools"].extend([
            "gobuster", "ffuf", "dirb", "feroxbuster", "dirsearch",
            "nikto", "whatweb", "wafw00f",
        ])

    # ── Web 场景 ──
    if SCENE_WEB in all_scenes:
        hints["focus_phases"].append("surface_enum")
        hints["prefer_tools"].extend(["gobuster", "ffuf", "nikto", "whatweb", "curl"])

    # ── 内网场景：聚焦 SMB/LDAP/Kerberos ──
    if SCENE_INTRANET in all_scenes:
        hints["focus_phases"].extend(["smb_enum", "ldap_enum", "kerberos_attack"])
        hints["prefer_tools"].extend([
            "enum4linux", "smbclient", "crackmapexec",
            "impacket-mssqlclient", "evil-winrm",
            "hydra", "rpcclient",
        ])

    # ── 云场景 ──
    if SCENE_CLOUD in all_scenes:
        hints["focus_phases"].extend(["cloud_enum", "cloud_exploit"])
        hints["prefer_tools"].extend(["curl", "wget"])

    # ── 纯数据库场景（无 Web 无内网）──
    if primary == SCENE_DATABASE and not (all_scenes & {SCENE_WEB, SCENE_INTRANET}):
        hints["skip_phases"].extend(["surface_enum", "intel_harvest"])
        hints["prefer_tools"].extend(["hydra", "sqlmap"])

    # ── 纯网络服务场景 ──
    if primary == SCENE_NETWORK_SERVICE and not all_scenes:
        hints["prefer_tools"].extend(["hydra", "ssh", "sshpass", "nmap"])

    # 去重
    for k in ("skip_phases", "focus_phases", "prefer_tools", "avoid_tools",
              "focus_ports", "focus_services"):
        hints[k] = list(dict.fromkeys(hints[k]))

    return hints


def apply_scene_to_state(
    state: PentestState, scene: SceneClassification
) -> PentestState:
    """将场景分类结果写入 state + 模板切换 + 推送前端 decision 事件。"""
    old_template = state.chain_template_id

    if scene.recommended_template != old_template:
        state.log(
            f"[Scene] 场景识别: {scene.primary_scene} "
            f"(conf={scene.confidence:.0%}), "
            f"模板切换 {old_template} → {scene.recommended_template}"
        )
        state.chain_template_id = scene.recommended_template
        state.push_decision({
            "action": "scene_classified",
            "phase": "recon",
            "thinking": scene.rationale,
            "purpose": "攻击场景自动识别",
            "message": (
                f"识别场景: {scene.primary_scene}"
                + (f" + {', '.join(scene.secondary_scenes)}" if scene.secondary_scenes else "")
                + f", 模板 {old_template} → {scene.recommended_template}"
            ),
            "tone": "info",
            "scene": scene.primary_scene,
            "template": scene.recommended_template,
            "confidence": scene.confidence,
        })
    else:
        state.log(
            f"[Scene] 场景识别: {scene.primary_scene} "
            f"(conf={scene.confidence:.0%}), 模板不变 ({old_template})"
        )

    if scene.secondary_scenes:
        state.log(f"[Scene] 次场景: {', '.join(scene.secondary_scenes)}")

    # ── 适应提示写入 runtime_facts，供下游阶段节点消费 ──
    if scene.adaptation_hints:
        existing = dict(state.runtime_facts or {})
        hints = scene.adaptation_hints
        existing["scene_classification"] = {
            "primary": scene.primary_scene,
            "secondary": scene.secondary_scenes,
            "template": scene.recommended_template,
            "confidence": scene.confidence,
            "skip_phases": hints.get("skip_phases", []),
            "focus_phases": hints.get("focus_phases", []),
            "prefer_tools": hints.get("prefer_tools", []),
            "avoid_tools": hints.get("avoid_tools", []),
            "focus_ports": hints.get("focus_ports", []),
            "focus_services": hints.get("focus_services", []),
        }
        state.runtime_facts = existing

    return state


# ═══════════════════════════════════════════════════════════════════════
# 工具方法：下游阶段节点读取场景提示
# ═══════════════════════════════════════════════════════════════════════

def get_scene_skip_phases(state: PentestState) -> set[str]:
    """当前场景建议跳过的阶段集合。"""
    scene = (state.runtime_facts or {}).get("scene_classification", {})
    return set(scene.get("skip_phases", []))


def get_scene_prefer_tools(state: PentestState) -> list[str]:
    """当前场景建议的首选工具列表。"""
    scene = (state.runtime_facts or {}).get("scene_classification", {})
    return scene.get("prefer_tools", [])


def get_scene_avoid_tools(state: PentestState) -> list[str]:
    """当前场景建议禁用的工具列表。"""
    scene = (state.runtime_facts or {}).get("scene_classification", {})
    return scene.get("avoid_tools", [])


def get_scene_focus_ports(state: PentestState) -> list[int]:
    """当前场景建议聚焦的端口列表。"""
    scene = (state.runtime_facts or {}).get("scene_classification", {})
    return scene.get("focus_ports", [])


def scene_is_web_only(state: PentestState) -> bool:
    """快速判断：纯 Web 场景（无内网/云特征）。"""
    scene = (state.runtime_facts or {}).get("scene_classification", {})
    return scene.get("primary") == SCENE_WEB and not scene.get("secondary")


def scene_should_skip(state: PentestState, phase_name: str) -> bool:
    """判断某个阶段是否应该被场景适配跳过。"""
    return phase_name in get_scene_skip_phases(state)
