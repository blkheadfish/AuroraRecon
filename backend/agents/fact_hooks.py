"""
fact_hooks.py — pure-Python helpers used by the orchestrator.

Kept here (not inside ``orchestrator.py``) so tests can exercise them
without having to import the full LangGraph pipeline (which pulls in
``langgraph`` and its optional dependencies).
"""
from __future__ import annotations

import logging
import re
from typing import Any

from backend.agents.evidence_verifier import _passwd_content_detected
from backend.agents.models import ExploitResult, PentestState, VulnFinding

logger = logging.getLogger(__name__)


def _rec_get(rec, key: str, default=""):
    if isinstance(rec, dict):
        return rec.get(key, default)
    return getattr(rec, key, default)


_LFI_HIT_RE = re.compile(
    r"LFI_PASSWD_OK(?::(?P<param>[A-Za-z_]\w*))?(?::(?P<depth>\d+))?(?::(?P<style>\w+))?",
    re.IGNORECASE,
)
_SSH_PORT_RE = re.compile(r"\b(?:SSH|OpenSSH)\b[^\n]{0,80}?\bport\s*[=:]?\s*(\d{1,5})", re.IGNORECASE)
_AUTH_LOG_RE = re.compile(r"(/var/log/(?:auth|secure|apache2/access)[\w./-]*)", re.IGNORECASE)


def extract_discoveries_list(
    result: ExploitResult,
    finding: VulnFinding,
) -> list[dict[str, Any]]:
    """Pure structural extraction -- no mutation.

    Returns typed events for the fact sink to consolidate.
    """
    events: list[dict[str, Any]] = []
    records = result.command_records or result.command_results or []
    for rec in records:
        out = str(_rec_get(rec, "stdout", "") or "")
        cmd = str(_rec_get(rec, "command", "") or "")
        combined = out + "\n" + cmd

        for m in _LFI_HIT_RE.finditer(combined):
            param = m.group("param")
            depth = m.group("depth")
            style = m.group("style")
            if param or depth:
                events.append({
                    "type": "lfi_hit",
                    "param": param,
                    "depth": depth,
                    "style": style or "relative",
                })
        if _passwd_content_detected(out):
            m_param = re.search(r"[?&](page|file|include|path|image|content|template|doc|folder|view)=",
                                cmd, re.IGNORECASE)
            m_depth = re.search(r"(\.\./){1,20}", cmd)
            if m_param:
                events.append({
                    "type": "lfi_hit",
                    "param": m_param.group(1),
                    "depth": str(m_depth.group(0).count("../")) if m_depth else None,
                    "style": "relative",
                })

        for lm in _AUTH_LOG_RE.finditer(out):
            if len(out) > 100 and "no such file" not in out.lower():
                events.append({"type": "readable_log", "path": lm.group(1)})

        sm = _SSH_PORT_RE.search(out)
        if sm:
            try:
                events.append({"type": "ssh_port", "port": int(sm.group(1))})
            except ValueError:
                pass

        cred_m = re.search(
            r"(DB_PASS|db_password|POSTGRES_PASSWORD|mysql_pwd)\s*[=:]\s*(\S+)",
            out, re.IGNORECASE,
        )
        if cred_m:
            events.append({
                "type": "credential",
                "user": "",
                "source": cred_m.group(1),
                "value": cred_m.group(2)[:80],
            })

    return events


def extract_facts(result: ExploitResult, finding: VulnFinding) -> dict[str, Any]:
    """Distill confirmed facts from a single exploit attempt.

    Shape::

        {
            "vuln_id": finding.vuln_id,
            "probe_variables": {...},
            "confirmed": {"lfi": {...}, "services": {...}, "creds": [...]},
            "failed_commands": [cmd, ...],
        }
    """
    facts: dict[str, Any] = {"vuln_id": finding.vuln_id}

    session = result.session_info or {}
    probe_vars = session.get("probe_variables") or {}
    if probe_vars:
        facts["probe_variables"] = dict(probe_vars)

    confirmed: dict[str, Any] = {}

    lfi_info: dict[str, Any] = {}
    for k in ("lfi_param", "lfi_depth", "lfi_style", "lfi_path"):
        v = probe_vars.get(k)
        if v:
            short = k.replace("lfi_", "")
            lfi_info[short] = v

    readable_files: list[str] = []
    failed_cmds: list[str] = []
    for rec in (result.command_records or result.command_results or []):
        out = _rec_get(rec, "stdout", "") or ""
        cmd = _rec_get(rec, "command", "") or ""
        exit_c = _rec_get(rec, "exit_code", 0)
        if _passwd_content_detected(out):
            readable_files.append("/etc/passwd")
            m = re.search(r"(/etc/\w[\w./-]+|/var/log/[\w./-]+|/root/[\w./-]+)", cmd)
            if m:
                readable_files.append(m.group(1))
        if exit_c not in (0, None) and cmd:
            failed_cmds.append(cmd[:400])

    for disc in extract_discoveries_list(result, finding):
        t = disc.get("type")
        if t == "lfi_hit":
            if disc.get("param"):
                lfi_info.setdefault("param", disc["param"])
            if disc.get("depth"):
                lfi_info.setdefault("depth", disc["depth"])
            if disc.get("style"):
                lfi_info.setdefault("style", disc["style"])
        elif t == "ssh_port":
            confirmed.setdefault("services", {})["ssh_port"] = disc.get("port")
        elif t == "readable_log":
            confirmed.setdefault("services", {}).setdefault(
                "log_readable", []
            ).append(disc.get("path"))
        elif t == "credential":
            confirmed.setdefault("creds", []).append(disc)

    if readable_files:
        lfi_info["readable_files"] = sorted(set(readable_files))
    if lfi_info:
        confirmed["lfi"] = lfi_info

    if confirmed:
        facts["confirmed"] = confirmed
    if failed_cmds:
        facts["failed_commands"] = failed_cmds

    return facts


# ── Fact sink ─────────────────────────────────────────────

_LFI_REPROBE_PATTERNS = [
    re.compile(r"for\s+\w+\s+in\s+\$?\(?\s*seq\s+\d+\s+\d+", re.IGNORECASE),
    re.compile(r"for\s+\w+\s+in\s+\{\s*\d+\s*\.\.\s*\d+\s*\}", re.IGNORECASE),
    re.compile(r"(\.\./\s*){3,}", re.IGNORECASE),
    re.compile(
        r"for\s+\w+\s+in\s+(?:page|file|include|path|image|content|template|doc|folder|view)\b",
        re.IGNORECASE,
    ),
]


def is_lfi_reprobe_command(cmd: str) -> bool:
    """Detect bash command patterns that re-enumerate LFI param/depth."""
    if not cmd:
        return False
    hits = 0
    for pat in _LFI_REPROBE_PATTERNS:
        if pat.search(cmd):
            hits += 1
    if hits >= 2:
        return True
    if hits >= 1 and cmd.count("../") >= 3:
        return True
    return False


def make_fact_sink(state: PentestState):
    """Return a callback that merges per-finding facts into ``state``.

    See the doc on ``ExploitAgent._extract_facts`` for the expected shape.
    """

    def _merge_lists(a: list, b: list) -> list:
        out = list(a or [])
        for item in (b or []):
            if item not in out:
                out.append(item)
        return out

    def _sink(facts: dict) -> None:
        try:
            vuln_id = facts.get("vuln_id") or "*"
            pv = facts.get("probe_variables") or {}
            if pv:
                existing_pv = dict(state.exploit_probe_variables.get(vuln_id, {}))
                existing_pv.update(pv)
                state.exploit_probe_variables[vuln_id] = existing_pv

            confirmed = facts.get("confirmed") or {}
            cf: dict[str, Any] = dict(state.confirmed_facts or {})
            for section, payload in confirmed.items():
                if section == "creds" and isinstance(payload, list):
                    cf_creds = list(cf.get("creds", []))
                    for c in payload:
                        if c not in cf_creds:
                            cf_creds.append(c)
                    cf["creds"] = cf_creds
                elif isinstance(payload, dict):
                    existing = dict(cf.get(section, {}))
                    for k, v in payload.items():
                        if isinstance(v, list):
                            existing[k] = _merge_lists(existing.get(k, []), v)
                        else:
                            existing.setdefault(k, v)
                    cf[section] = existing
            state.confirmed_facts = cf

            failed = facts.get("failed_commands") or []
            if failed:
                existing_f = list(state.failed_commands_by_vuln.get(vuln_id, []))
                for cmd in failed:
                    if cmd not in existing_f:
                        existing_f.append(cmd)
                state.failed_commands_by_vuln[vuln_id] = existing_f[-60:]
        except Exception as exc:
            logger.warning(f"[fact_sink] merge 失败: {exc}")

    return _sink


# ── service-info extraction hook ──────────────────────────

def _merge_facts(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    """Shallow merge with list-union semantics. ``dst`` is mutated and returned."""
    for k, v in (src or {}).items():
        if isinstance(v, list):
            existing = dst.get(k)
            if isinstance(existing, list):
                merged_list = list(existing)
                seen = {str(x) for x in existing}
                for item in v:
                    if str(item) not in seen:
                        merged_list.append(item)
                        seen.add(str(item))
                dst[k] = merged_list
            else:
                dst[k] = list(v)
        elif isinstance(v, dict):
            existing = dst.get(k)
            if isinstance(existing, dict):
                dst[k] = _merge_facts(dict(existing), v)
            else:
                dst[k] = dict(v)
        else:
            dst[k] = v
    return dst


def _emit_php_findings(state: PentestState, matches, merged, base_url, port) -> None:
    """Translate high-value PHP attack-surface into VulnFinding + logs."""
    surface = merged.get("_attack_surface") or {}
    if surface.get("rfi_possible"):
        finding_target = f"{base_url}{matches[0].path}"
        if not any(f.name.startswith("allow_url_include=On") for f in state.findings):
            state.findings.append(VulnFinding(
                name="allow_url_include=On (可能 RFI)",
                severity="high",
                target=finding_target,
                port=port,
                description=(
                    "phpinfo 披露 allow_url_include=On，若存在 include 类可控参数，"
                    "可直接通过 http/php://input 进行远程文件包含达到 RCE。"
                ),
                evidence=(f"来源: {matches[0].path}；"
                          f"allow_url_fopen={merged.get('allow_url_fopen')}"),
                exploitable=True,
                tool="phpinfo_parser",
            ))
            state.log("情报采集: allow_url_include=On 已转化为 high 级 RFI finding")

    disabled = merged.get("disable_functions") or []
    if isinstance(disabled, list) and disabled:
        cmd_funcs = {"system", "exec", "passthru", "shell_exec", "popen", "proc_open"}
        if cmd_funcs.issubset({d.lower() for d in disabled}):
            state.log(
                "情报采集: disable_functions 禁用所有 shell 执行函数，"
                "优先走 include/assert/file_put_contents 路径"
            )
    if merged.get("open_basedir"):
        state.log(f"情报采集: open_basedir={merged['open_basedir']}，文件系统访问受限")

    if merged.get("php_version") or merged.get("sapi"):
        state.log(
            f"情报采集: PHP {merged.get('php_version', 'unknown')} / "
            f"SAPI {merged.get('sapi', 'unknown')}"
        )


def _emit_apache_findings(state: PentestState, matches, merged, base_url, port) -> None:
    surface = merged.get("_attack_surface") or {}
    ver = merged.get("server_version") or surface.get("version")
    if ver:
        state.log(f"情报采集: Apache 版本 {ver}")
    if surface.get("cve_2021_41773_candidate"):
        if not any("CVE-2021-41773" in f.name for f in state.findings):
            state.findings.append(VulnFinding(
                name="Apache 2.4.49/50 路径遍历候选 (CVE-2021-41773)",
                severity="high",
                target=f"{base_url}{matches[0].path}",
                port=port,
                description="Apache 版本落在 CVE-2021-41773 / 42013 受影响区间，若启用 mod_cgi 可达到 RCE。",
                evidence=f"server_version={ver}",
                exploitable=True,
                tool="apache_status_parser",
            ))
    if surface.get("webdav_enabled"):
        state.log("情报采集: Apache mod_dav(_fs) 已加载 → WebDAV 上传路径潜在可用")
    if surface.get("cgi_enabled"):
        state.log("情报采集: Apache mod_cgi(d) 已加载 → CGI 路径是 RCE 优先通路")
    if merged.get("request_samples"):
        state.log(f"情报采集: Apache scoreboard 样本 URI: "
                  f"{', '.join(merged['request_samples'][:5])}")


def _emit_nginx_findings(state: PentestState, matches, merged, base_url, port) -> None:
    ver = merged.get("nginx_version")
    if ver:
        state.log(f"情报采集: Nginx 版本 nginx/{ver}")
    surface = merged.get("_attack_surface") or {}
    if surface.get("version_disclosure"):
        state.log("情报采集: Nginx Server 头泄露精确版本号")


def _emit_tomcat_findings(state: PentestState, matches, merged, base_url, port) -> None:
    surface = merged.get("_attack_surface") or {}
    ver = merged.get("tomcat_version") or surface.get("version")
    if ver:
        state.log(f"情报采集: Apache Tomcat/{ver}")
    if surface.get("ghostcat_risk") or surface.get("cve_2020_1938_ghostcat_candidate"):
        if not any("Ghostcat" in f.name for f in state.findings):
            state.findings.append(VulnFinding(
                name="Tomcat Ghostcat 文件读取 (CVE-2020-1938) 候选",
                severity="high",
                target=f"{base_url}{matches[0].path}",
                port=port,
                description="AJP Connector 暴露 + 受影响 Tomcat 版本，Ghostcat 可任意读取 /WEB-INF。",
                evidence=f"tomcat_version={ver}, ajp={surface.get('ajp_connector')}",
                exploitable=True,
                tool="tomcat_status_parser",
            ))
    if surface.get("manager_reachable"):
        if not any("manager" in f.name.lower() for f in state.findings):
            state.findings.append(VulnFinding(
                name="Tomcat Manager 暴露 (可能弱口令 RCE)",
                severity="high",
                target=f"{base_url}{matches[0].path}",
                port=port,
                description="Tomcat /manager 可访问，若存在弱口令/默认凭据，可上传 WAR 达到 RCE。",
                evidence=f"endpoint={matches[0].path}",
                exploitable=True,
                tool="tomcat_status_parser",
            ))


def _emit_spring_findings(state: PentestState, matches, merged, base_url, port) -> None:
    surface = merged.get("_attack_surface") or {}
    if surface.get("credential_leak"):
        if not any("Actuator" in f.name for f in state.findings):
            state.findings.append(VulnFinding(
                name="Spring Actuator 凭据泄露",
                severity="high",
                target=f"{base_url}{matches[0].path}",
                port=port,
                description=(
                    "Spring Boot Actuator 端点（/env 或 /configprops）暴露敏感凭据，"
                    "可直接用于数据库/中间件登录。"
                ),
                evidence=f"endpoints={merged.get('endpoints_seen')}",
                exploitable=True,
                tool="spring_actuator_parser",
            ))
    if surface.get("heapdump_exposed"):
        if not any("heapdump" in f.name.lower() for f in state.findings):
            state.findings.append(VulnFinding(
                name="Spring Actuator Heapdump 暴露 (可离线提取凭据)",
                severity="high",
                target=f"{base_url}/actuator/heapdump",
                port=port,
                description="可下载 JVM heapdump，通过 JDumpSpider 等工具离线提取密码/密钥。",
                evidence="/actuator/heapdump HTTP 200",
                exploitable=True,
                tool="spring_actuator_parser",
            ))
    if surface.get("dev_profile_active"):
        state.log("情报采集: Spring 当前激活 dev profile，建议关注调试端点与默认凭据")


def _emit_env_file_findings(state: PentestState, matches, merged, base_url, port) -> None:
    surface = merged.get("_attack_surface") or {}
    if surface.get("credential_leak"):
        key_count = surface.get("credential_count", 0)
        if not any(".env 凭据泄露" in f.name for f in state.findings):
            state.findings.append(VulnFinding(
                name=f".env 凭据泄露 (共 {key_count} 条)",
                severity="high" if surface.get("prod_credential_leak") else "medium",
                target=f"{base_url}{matches[0].path}",
                port=port,
                description=(
                    ".env 文件对外可读，包含数据库/JWT/云厂商等凭据，"
                    "直接转化为横向移动或后端登录凭据池。"
                ),
                evidence=(
                    f"path={matches[0].path}, "
                    f"frameworks={merged.get('frameworks')}, "
                    f"deployment_env={merged.get('deployment_env')}"
                ),
                exploitable=True,
                tool="env_file_parser",
            ))
    if surface.get("debug_mode"):
        state.log("情报采集: .env 披露 APP_DEBUG=true / DEBUG=true，生产环境不应开启")


_EMIT_DISPATCH = {
    "php":      _emit_php_findings,
    "apache":   _emit_apache_findings,
    "nginx":    _emit_nginx_findings,
    "tomcat":   _emit_tomcat_findings,
    "spring":   _emit_spring_findings,
    "env_file": _emit_env_file_findings,
}


def apply_service_info_extraction(
    state: PentestState,
    harvested: list[dict[str, Any]],
    base_url: str,
    port: int,
) -> None:
    """Deterministic service-info extraction across all known disclosure surfaces.

    Fans out to per-technology parsers (phpinfo / apache / nginx / tomcat /
    spring actuator / .env) via ``service_info_dispatcher`` and merges results
    into ``state.runtime_facts[kind]``. Also writes the PHP bucket back into
    ``state.php_runtime`` for backward-compat so existing downstream code
    (LFI gate, ExploitAgent `_build_php_runtime_block`, skills `env.php.*` checks)
    keeps working unchanged.
    """
    try:
        from backend.tools.parsers import service_info_dispatcher as _dispatcher
    except Exception as exc:
        logger.warning(f"[IntelHarvest] service_info_dispatcher import failed: {exc}")
        return

    matches = _dispatcher.parse_harvested(harvested or [])
    if not matches:
        return

    by_kind: dict[str, list] = {}
    for m in matches:
        by_kind.setdefault(m.kind, []).append(m)

    runtime_facts: dict[str, dict[str, Any]] = dict(state.runtime_facts or {})
    for kind, match_list in by_kind.items():
        merged: dict[str, Any] = dict(runtime_facts.get(kind) or {})
        for m in match_list:
            _merge_facts(merged, m.facts)
        runtime_facts[kind] = merged

        emitter = _EMIT_DISPATCH.get(kind)
        if emitter:
            try:
                emitter(state, match_list, merged, base_url, port)
            except Exception as exc:
                logger.warning(f"[IntelHarvest] emit_{kind}_findings failed: {exc}")

        paths_str = ", ".join(m.path for m in match_list[:3])
        state.log(f"情报采集: {kind} 结构化抽取完成 ({paths_str})")

    state.runtime_facts = runtime_facts
    if "php" in runtime_facts:
        state.php_runtime = runtime_facts["php"]


def apply_phpinfo_extraction(
    state: PentestState,
    harvested: list[dict[str, Any]],
    base_url: str,
    port: int,
) -> None:
    """Backward-compat alias — delegates to the generalised dispatcher."""
    apply_service_info_extraction(state, harvested, base_url, port)
