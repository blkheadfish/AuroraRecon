"""
fact_hooks.py — pure-Python helpers used by the orchestrator.

Kept here (not inside ``orchestrator.py``) so tests can exercise them
without having to import the full LangGraph pipeline (which pulls in
``langgraph`` and its optional dependencies).
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime
from typing import Any, Optional

from backend.agents.evidence_verifier import _passwd_content_detected
from backend.agents.models import ExploitResult, PentestState, TaskFact, VulnFinding

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


def canonical_command_hash(command: str) -> str:
    normalized = " ".join((command or "").strip().lower().split())
    return hashlib.sha1(normalized.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _safe_fact_key(fact_type: str, value: Any) -> str:
    return f"{fact_type}:{canonical_command_hash(str(value))}"


def _project_confirmed_from_task_facts(task_facts: dict[str, TaskFact]) -> dict[str, Any]:
    confirmed: dict[str, Any] = {"lfi": {}, "services": {}, "creds": []}
    sorted_facts = sorted(
        (task_facts or {}).values(),
        key=lambda f: getattr(f, "first_seen_at", "") or "",
    )
    for fact in sorted_facts:
        ft = fact.fact_type
        val = fact.value
        if ft == "lfi_param":
            confirmed["lfi"].setdefault("param", val)
        elif ft == "lfi_depth":
            confirmed["lfi"].setdefault("depth", val)
        elif ft == "lfi_style":
            confirmed["lfi"].setdefault("style", val)
        elif ft == "lfi_readable_file":
            confirmed["lfi"].setdefault("readable_files", [])
            if val not in confirmed["lfi"]["readable_files"]:
                confirmed["lfi"]["readable_files"].append(val)
        elif ft == "service_ssh_port":
            confirmed["services"].setdefault("ssh_port", val)
        elif ft == "service_log_readable":
            confirmed["services"].setdefault("log_readable", [])
            if val not in confirmed["services"]["log_readable"]:
                confirmed["services"]["log_readable"].append(val)
        elif ft == "credential" and isinstance(val, dict):
            if val not in confirmed["creds"]:
                confirmed["creds"].append(val)
    if not confirmed["lfi"]:
        confirmed.pop("lfi", None)
    if not confirmed["services"]:
        confirmed.pop("services", None)
    if not confirmed["creds"]:
        confirmed.pop("creds", None)
    return confirmed


def normalize_and_dedupe_state_facts(state: PentestState, source_node: str = "") -> None:
    """Normalize task_facts and backfill compatibility projections."""
    task_facts: dict[str, TaskFact] = dict(state.task_facts or {})
    if not task_facts:
        lfi = (state.confirmed_facts or {}).get("lfi") or {}
        services = (state.confirmed_facts or {}).get("services") or {}
        creds = (state.confirmed_facts or {}).get("creds") or []
        if lfi.get("param"):
            k = _safe_fact_key("lfi_param", lfi["param"])
            task_facts[k] = TaskFact(fact_key=k, fact_type="lfi_param", value=lfi["param"], source="legacy", source_node=source_node or "legacy")
        if lfi.get("depth"):
            k = _safe_fact_key("lfi_depth", lfi["depth"])
            task_facts[k] = TaskFact(fact_key=k, fact_type="lfi_depth", value=lfi["depth"], source="legacy", source_node=source_node or "legacy")
        if lfi.get("style"):
            k = _safe_fact_key("lfi_style", lfi["style"])
            task_facts[k] = TaskFact(fact_key=k, fact_type="lfi_style", value=lfi["style"], source="legacy", source_node=source_node or "legacy")
        for rf in (lfi.get("readable_files") or []):
            k = _safe_fact_key("lfi_readable_file", rf)
            task_facts[k] = TaskFact(fact_key=k, fact_type="lfi_readable_file", value=rf, source="legacy", source_node=source_node or "legacy")
        if services.get("ssh_port"):
            k = _safe_fact_key("service_ssh_port", services["ssh_port"])
            task_facts[k] = TaskFact(fact_key=k, fact_type="service_ssh_port", value=services["ssh_port"], source="legacy", source_node=source_node or "legacy")
        for lp in (services.get("log_readable") or []):
            k = _safe_fact_key("service_log_readable", lp)
            task_facts[k] = TaskFact(fact_key=k, fact_type="service_log_readable", value=lp, source="legacy", source_node=source_node or "legacy")
        for c in creds:
            k = _safe_fact_key("credential", c)
            task_facts[k] = TaskFact(fact_key=k, fact_type="credential", value=c, source="legacy", source_node=source_node or "legacy")

    state.task_facts = task_facts
    state.confirmed_facts = _project_confirmed_from_task_facts(task_facts)
    state.last_fact_normalized_at = datetime.utcnow().isoformat()

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



_LFI_REPROBE_PATTERNS = [
    re.compile(r"for\s+\w+\s+in\s+\$?\(?\s*seq\s+\d+\s+\d+", re.IGNORECASE),
    re.compile(r"seq\s+\d+\s+\$\w+", re.IGNORECASE),
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
    return hits >= 2


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
            now = datetime.utcnow().isoformat()
            pv = facts.get("probe_variables") or {}
            if pv:
                existing_pv = dict(state.exploit_probe_variables.get(vuln_id, {}))
                existing_pv.update(pv)
                state.exploit_probe_variables[vuln_id] = existing_pv

            confirmed = facts.get("confirmed") or {}
            task_facts: dict[str, TaskFact] = dict(state.task_facts or {})
            for section, payload in confirmed.items():
                if section == "creds" and isinstance(payload, list):
                    for c in payload:
                        key = _safe_fact_key("credential", c)
                        existing = task_facts.get(key)
                        if existing:
                            existing.last_seen_at = now
                            existing.version += 1
                        else:
                            task_facts[key] = TaskFact(
                                fact_key=key,
                                fact_type="credential",
                                value=c,
                                source="fact_sink",
                                source_node="exploit_agent",
                                first_seen_at=now,
                                last_seen_at=now,
                            )
                            try:
                                cred_dict = c if isinstance(c, dict) else {"value": str(c)}
                                if cred_dict not in (state.credential_store or []):
                                    state.credential_store.append(cred_dict)
                                attach_credential_to_graph(
                                    state, cred_dict, discovered_by="fact_sink",
                                )
                                push_pending_seed(state, "credentials", cred_dict)
                            except Exception:
                                pass
                elif isinstance(payload, dict):
                    for k, v in payload.items():
                        if isinstance(v, list) and section == "lfi" and k == "readable_files":
                            for item in v:
                                key = _safe_fact_key("lfi_readable_file", item)
                                existing = task_facts.get(key)
                                if existing:
                                    existing.last_seen_at = now
                                    existing.version += 1
                                else:
                                    task_facts[key] = TaskFact(
                                        fact_key=key,
                                        fact_type="lfi_readable_file",
                                        value=item,
                                        source="fact_sink",
                                        source_node="exploit_agent",
                                        first_seen_at=now,
                                        last_seen_at=now,
                                    )
                        elif section == "services" and k == "log_readable" and isinstance(v, list):
                            for item in v:
                                key = _safe_fact_key("service_log_readable", item)
                                existing = task_facts.get(key)
                                if existing:
                                    existing.last_seen_at = now
                                    existing.version += 1
                                else:
                                    task_facts[key] = TaskFact(
                                        fact_key=key,
                                        fact_type="service_log_readable",
                                        value=item,
                                        source="fact_sink",
                                        source_node="exploit_agent",
                                        first_seen_at=now,
                                        last_seen_at=now,
                                    )
                        else:
                            fact_type = f"{section}_{k}"
                            key = _safe_fact_key(fact_type, v)
                            existing = task_facts.get(key)
                            if existing:
                                existing.last_seen_at = now
                                existing.version += 1
                            else:
                                task_facts[key] = TaskFact(
                                    fact_key=key,
                                    fact_type=fact_type,
                                    value=v,
                                    source="fact_sink",
                                    source_node="exploit_agent",
                                    first_seen_at=now,
                                    last_seen_at=now,
                                )

            failed = facts.get("failed_commands") or []
            if failed:
                existing_f = list(state.failed_commands_by_vuln.get(vuln_id, []))
                existing_hashes = {canonical_command_hash(c): c for c in existing_f}
                for cmd in failed:
                    ch = canonical_command_hash(cmd)
                    if ch not in existing_hashes:
                        existing_f.append(cmd)
                        existing_hashes[ch] = cmd
                state.failed_commands_by_vuln[vuln_id] = existing_f[-60:]
            state.task_facts = task_facts
            state.fact_version = int(state.fact_version or 0) + 1
            normalize_and_dedupe_state_facts(state, source_node="fact_sink")
        except Exception as exc:
            logger.warning(f"[fact_sink] merge 失败: {exc}")

    return _sink



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

    try:
        host = ""
        if "://" in (base_url or ""):
            host = base_url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
        if host:
            attach_service_to_graph(
                state, host, port, service="http", discovered_by="intel_harvest",
            )
        for f in state.findings[-10:]:
            if f.tool in ("intel_harvest", "phpinfo_parser", "apache_status_parser",
                          "nginx_stub_parser", "tomcat_status_parser",
                          "spring_actuator_parser", "env_file_parser"):
                attach_finding_to_graph(state, f, discovered_by=f.tool or "intel_harvest")
    except Exception as exc:
        logger.debug(f"[fact_hooks] attack_graph upsert from intel skipped: {exc}")


def apply_phpinfo_extraction(
    state: PentestState,
    harvested: list[dict[str, Any]],
    base_url: str,
    port: int,
) -> None:
    """Backward-compat alias — delegates to the generalised dispatcher."""
    apply_service_info_extraction(state, harvested, base_url, port)



import json as _json


def consume_pending_seeds(state: PentestState, bucket: str) -> list[Any]:
    """Pop and return the pending seeds in *bucket* (idempotency-friendly).

    上游节点在入口处调用本函数，把"待处理种子"取出后并入本次输入，
    然后清空对应桶，避免下次重入时再次合并相同种子。
    """
    seeds = list((state.pending_seeds or {}).get(bucket) or [])
    if not state.pending_seeds:
        state.pending_seeds = {
            "hosts": [], "ports": [], "web_paths": [], "credentials": [],
        }
    state.pending_seeds[bucket] = []
    return seeds


def push_pending_seed(state: PentestState, bucket: str, value: Any) -> None:
    """Append *value* into *bucket* if not already present."""
    if not state.pending_seeds:
        state.pending_seeds = {
            "hosts": [], "ports": [], "web_paths": [], "credentials": [],
        }
    seeds = state.pending_seeds.setdefault(bucket, [])
    try:
        marker = _json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        marker = repr(value)
    existing_markers = set()
    for s in seeds:
        try:
            existing_markers.add(_json.dumps(s, ensure_ascii=False, sort_keys=True, default=str))
        except Exception:
            existing_markers.add(repr(s))
    if marker not in existing_markers:
        seeds.append(value)


def compute_phase_signature(payload: Any) -> str:
    """Stable sha1 over the canonical JSON dump of *payload*."""
    try:
        text = _json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        text = repr(payload)
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()


def should_skip_phase(
    state: PentestState,
    phase: str,
    signature: str,
) -> tuple[bool, str]:
    """Decide whether to short-circuit *phase* on this re-entry.

    Returns (skip, reason). The caller should still call ``mark_phase_visited``
    even when skipping so that ``replan_count`` accounting stays consistent.
    """
    visits = int((state.phase_visit_count or {}).get(phase, 0))
    cap = int((state.max_phase_visits or {}).get(phase, 99))
    if visits >= cap:
        return True, f"phase_visit_cap_reached: {visits}/{cap}"
    prior_sig = (state.phase_signature or {}).get(phase, "")
    if visits > 0 and prior_sig and prior_sig == signature:
        return True, "duplicate_input_signature"
    return False, ""


def mark_phase_visited(
    state: PentestState,
    phase: str,
    signature: str,
) -> None:
    """Bookkeep visit count + last input signature."""
    pvc = dict(state.phase_visit_count or {})
    pvc[phase] = int(pvc.get(phase, 0)) + 1
    state.phase_visit_count = pvc
    psig = dict(state.phase_signature or {})
    psig[phase] = signature
    state.phase_signature = psig


def snapshot_facts(state: PentestState) -> dict[str, Any]:
    """Take a small snapshot of"interesting"sets for replan-signal diffing."""
    creds: list[Any] = list(state.credential_store or [])
    web_paths: list[str] = list(state.web_paths or [])
    intel_paths: list[str] = list(state.intel_discovered_paths or [])
    hosts: set[str] = set()
    if state.target_host:
        hosts.add(state.target_host)
    for h in (state.subdomains or []):
        if h:
            hosts.add(h)
    open_ports = [getattr(p, "port", None) or (p.get("port") if isinstance(p, dict) else None) for p in (state.open_ports or []) if getattr(p, "state", "open") == "open"]
    open_ports = [p for p in open_ports if p]
    return {
        "credentials": [_json.dumps(c, sort_keys=True, default=str) if isinstance(c, (dict, list)) else str(c) for c in creds],
        "web_paths": list(web_paths),
        "intel_paths": list(intel_paths),
        "hosts": sorted(hosts),
        "ports": sorted({int(p) for p in open_ports if isinstance(p, (int, str)) and str(p).isdigit()}),
    }


def _resolve_new_credentials(
    state: PentestState, before: dict[str, Any], after: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return the actual credential dicts that are new in *after* vs *before*."""
    before_set = set(before.get("credentials") or [])
    after_set = set(after.get("credentials") or [])
    new_keys = after_set - before_set
    if not new_keys:
        return []
    new_creds: list[dict[str, Any]] = []
    for c in (state.credential_store or []):
        try:
            c_key = _json.dumps(c, sort_keys=True, default=str)
        except Exception:
            c_key = repr(c)
        if c_key in new_keys:
            if c not in new_creds:
                new_creds.append(c)
    return new_creds


def _resolve_new_paths(
    paths: list[str], before: dict[str, Any], after: dict[str, Any], key: str,
) -> list[str]:
    """Return the actual path strings that are new in *after* vs *before*."""
    before_set = set(before.get(key) or [])
    after_set = set(after.get(key) or [])
    new_keys = after_set - before_set
    if not new_keys:
        return []
    return [p for p in paths if p in new_keys]


def emit_replan_signals(
    state: PentestState,
    *,
    before: dict[str, Any],
    after: dict[str, Any],
    source_node: str,
) -> dict[str, int]:
    """Compare ``before`` / ``after`` snapshots and increment replan signals.

    Also populates ``state.replan_contexts`` with structured context so
    downstream phase nodes can act on specific targets (WHICH credentials,
    WHICH hosts, WHICH ports) instead of just knowing *that* something changed.

    Signal vocabulary (consumed by ``edge_after_*_v2`` in feedback mode and by
    ``_rule_decide`` in supervisor mode):

      - ``re_recon_for_hosts``        — 新发现 host
      - ``re_surface_enum_for_paths`` — 新发现 web_path
      - ``re_vuln_scan_for_creds``    — 新发现凭据
      - ``re_vuln_scan_for_ports``    — 新发现 open_port
      - ``re_intel_harvest_for_paths``— intel_discovered_paths 增长
    """
    from backend.agents.models import ReplanContext

    signals = dict(state.replan_signals or {})
    contexts = dict(state.replan_contexts or {})
    log_lines: list[str] = []

    def _diff(key: str) -> int:
        b = set(map(str, before.get(key) or []))
        a = set(map(str, after.get(key) or []))
        return len(a - b)

    def _diff_values(key: str) -> set[str]:
        b = set(map(str, before.get(key) or []))
        a = set(map(str, after.get(key) or []))
        return a - b

    new_creds = _diff("credentials")
    new_paths = _diff("web_paths")
    new_intel_paths = _diff("intel_paths")
    new_hosts = _diff("hosts")
    new_ports = _diff("ports")

    if new_creds:
        signals["re_vuln_scan_for_creds"] = int(signals.get("re_vuln_scan_for_creds", 0)) + new_creds
        log_lines.append(f"+{new_creds} 凭据")
        new_cred_items = _resolve_new_credentials(state, before, after)
        ctx = contexts.get("re_vuln_scan_for_creds", ReplanContext(
            signal_key="re_vuln_scan_for_creds", source_node=source_node,
        ))
        ctx.credentials.extend(new_cred_items)
        contexts["re_vuln_scan_for_creds"] = ctx

    if new_paths:
        signals["re_surface_enum_for_paths"] = int(signals.get("re_surface_enum_for_paths", 0)) + new_paths
        log_lines.append(f"+{new_paths} 路径")
        new_path_items = _resolve_new_paths(state.web_paths or [], before, after, "web_paths")
        ctx = contexts.get("re_surface_enum_for_paths", ReplanContext(
            signal_key="re_surface_enum_for_paths", source_node=source_node,
        ))
        for p in new_path_items:
            if p not in ctx.web_paths:
                ctx.web_paths.append(p)
        contexts["re_surface_enum_for_paths"] = ctx

    if new_intel_paths:
        signals["re_intel_harvest_for_paths"] = int(signals.get("re_intel_harvest_for_paths", 0)) + new_intel_paths
        new_intel_items = _resolve_new_paths(state.intel_discovered_paths or [], before, after, "intel_paths")
        ctx = contexts.get("re_intel_harvest_for_paths", ReplanContext(
            signal_key="re_intel_harvest_for_paths", source_node=source_node,
        ))
        for p in new_intel_items:
            if p not in ctx.intel_paths:
                ctx.intel_paths.append(p)
        contexts["re_intel_harvest_for_paths"] = ctx

    if new_hosts:
        signals["re_recon_for_hosts"] = int(signals.get("re_recon_for_hosts", 0)) + new_hosts
        log_lines.append(f"+{new_hosts} 主机")
        new_host_values = _diff_values("hosts")
        ctx = contexts.get("re_recon_for_hosts", ReplanContext(
            signal_key="re_recon_for_hosts", source_node=source_node,
        ))
        for h in new_host_values:
            if h not in ctx.hosts:
                ctx.hosts.append(str(h))
        contexts["re_recon_for_hosts"] = ctx

    if new_ports:
        signals["re_vuln_scan_for_ports"] = int(signals.get("re_vuln_scan_for_ports", 0)) + new_ports
        log_lines.append(f"+{new_ports} 端口")
        new_port_values = _diff_values("ports")
        ctx = contexts.get("re_vuln_scan_for_ports", ReplanContext(
            signal_key="re_vuln_scan_for_ports", source_node=source_node,
        ))
        for p_str in new_port_values:
            try:
                p_int = int(p_str)
                if p_int not in ctx.ports:
                    ctx.ports.append(p_int)
            except ValueError:
                pass
        contexts["re_vuln_scan_for_ports"] = ctx

    state.replan_signals = signals
    state.replan_contexts = contexts

    if log_lines:
        items_detail: list[str] = []
        for ctx in contexts.values():
            if ctx.credentials:
                items_detail.append(f"凭据={len(ctx.credentials)}条")
            if ctx.hosts:
                items_detail.append(f"主机={ctx.hosts}")
            if ctx.ports:
                items_detail.append(f"端口={ctx.ports}")
            if ctx.web_paths:
                items_detail.append(f"路径={len(ctx.web_paths)}条")
        detail_str = "; ".join(items_detail) if items_detail else ""
        state.log(f"[replan] {source_node}: {', '.join(log_lines)} → 信号 {signals}" + (f" | {detail_str}" if detail_str else ""))
        try:
            state.push_decision({
                "action": "replan_signal",
                "phase": source_node,
                "thinking": f"{source_node} 检测到新事实，发出 replan 信号" + (f" | {detail_str}" if detail_str else ""),
                "message": f"replan: {', '.join(log_lines)}",
                "raw": _json.dumps(signals, ensure_ascii=False),
                "tone": "info",
            })
        except Exception:
            pass

    return signals


def consume_replan_signal(state: PentestState, key: str) -> None:
    """Drop a single replan signal after it has been honoured by an edge."""
    signals = dict(state.replan_signals or {})
    if key in signals:
        signals.pop(key, None)
        state.replan_signals = signals


def get_replan_context(state: PentestState, signal_key: str) -> "Optional[Any]":
    """Read the structured context for *signal_key* without consuming it.

    Returns None if no context exists for that key.
    """
    from backend.agents.models import ReplanContext
    ctx = (state.replan_contexts or {}).get(signal_key)
    if ctx is None:
        return None
    if isinstance(ctx, ReplanContext):
        return ctx
    if isinstance(ctx, dict):
        return ReplanContext(**ctx)
    return None


def consume_replan_context(state: PentestState, signal_key: str) -> "Optional[Any]":
    """Read and remove the structured context for *signal_key*.

    Call this in phase node entry when the node is about to act on the
    context, so the same context isn't re-applied on re-entry.
    """
    ctx = get_replan_context(state, signal_key)
    if ctx is not None:
        contexts = dict(state.replan_contexts or {})
        contexts.pop(signal_key, None)
        state.replan_contexts = contexts
    return ctx


def merge_operator_context(state: PentestState) -> None:
    """Merge operator-derived replan context into existing replan_contexts.

    Called by ``apply_plan_to_state`` after the OperatorPlan is validated,
    so focus_targets / preferred_tools / keyword_hints from the operator
    are stored as structured context keyed by each derived signal.
    """
    plan = getattr(state, "operator_plan", None)
    if plan is None:
        return
    from backend.agents.models import ReplanContext

    contexts = dict(state.replan_contexts or {})
    sig = dict(state.replan_signals or {})

    # Build a single operator context from the plan's focus_targets / hints
    op_ctx = ReplanContext(
        signal_key="operator",
        source_node="operator_replanner",
        preferred_tools=list(plan.preferred_tools or []),
        keyword_hints=list(plan.keyword_hints or []),
        operator_notes=(plan.intent_summary or ""),
    )
    for ft in (plan.focus_targets or []):
        if isinstance(ft, dict):
            op_ctx.focus_targets.append({"type": ft.get("type", ""), "value": ft.get("value", "")})
        else:
            op_ctx.focus_targets.append({"type": getattr(ft, "type", ""), "value": getattr(ft, "value", "")})

    # Merge operator context into each signal-specific context that was
    # derived from this plan, so that e.g. re_vuln_scan_for_creds context
    # carries both the new credentials AND the operator's tool preferences.
    for signal_key in sig:
        if signal_key in ("operator_intent",):
            continue
        ctx = contexts.get(signal_key, ReplanContext(
            signal_key=signal_key, source_node="operator_replanner",
        ))
        ctx.merge(op_ctx)
        contexts[signal_key] = ctx

    state.replan_contexts = contexts



def _ag_host_id(host: str) -> str:
    return f"host:{host}"


def _ag_service_id(host: str, port: int | str) -> str:
    return f"svc:{host}:{port}"


def _ag_finding_id(finding_id: str) -> str:
    return f"finding:{finding_id}"


def _ag_credential_id(cred: dict[str, Any]) -> str:
    user = cred.get("user") or cred.get("username") or ""
    src = cred.get("source") or ""
    val = cred.get("value") or cred.get("password") or ""
    digest = canonical_command_hash(f"{user}|{src}|{val}")
    return f"cred:{digest}"


def attach_host_to_graph(state: PentestState, host: str, *, discovered_by: str = "") -> str:
    if not host:
        return ""
    nid = _ag_host_id(host)
    state.attack_graph.upsert_node(
        nid, type="host", label=host, discovered_by=discovered_by,
        attrs={"ip": host},
    )
    return nid


def attach_service_to_graph(
    state: PentestState,
    host: str,
    port: int | str,
    *,
    service: str = "",
    version: str = "",
    discovered_by: str = "recon",
) -> str:
    if not host or not port:
        return ""
    host_id = attach_host_to_graph(state, host, discovered_by=discovered_by)
    sid = _ag_service_id(host, port)
    state.attack_graph.upsert_node(
        sid,
        type="service",
        label=f"{service or 'service'}:{port}".strip(":"),
        facts={"port": port, "service": service, "version": version},
        attrs={"port": port, "service": service, "version": version},
        discovered_by=discovered_by,
    )
    state.attack_graph.add_edge(host_id, sid, relation="exposes")
    return sid


def attach_finding_to_graph(
    state: PentestState,
    finding: VulnFinding,
    *,
    discovered_by: str = "vuln_scan",
) -> str:
    fid = _ag_finding_id(finding.vuln_id)
    facts_data = {
        "severity": finding.severity,
        "cve": finding.cve or "",
        "exploitable": finding.exploitable,
        "tool": finding.tool,
    }
    attrs_data = {
        "cve": finding.cve or "",
        "severity": finding.severity,
        "exploitable": finding.exploitable,
        "exploited": False,
    }
    state.attack_graph.upsert_node(
        fid,
        type="finding",
        label=finding.name or finding.vuln_id,
        facts=facts_data,
        attrs=attrs_data,
        discovered_by=discovered_by,
    )
    if finding.port:
        host = (finding.target or "").split("/")[2].split(":")[0] if "://" in (finding.target or "") else ""
        if not host:
            host = (finding.target or "").split(":")[0]
        if host:
            sid = _ag_service_id(host, finding.port)
            state.attack_graph.add_edge(sid, fid, relation="enables")
    return fid


def attach_credential_to_graph(
    state: PentestState,
    cred: dict[str, Any],
    *,
    discovered_by: str = "exploit_agent",
) -> str:
    cid = _ag_credential_id(cred)
    state.attack_graph.upsert_node(
        cid,
        type="credential",
        label=f"{cred.get('user') or '?'}@{cred.get('source') or '?'}",
        facts=dict(cred),
        attrs={
            "service": cred.get("service") or cred.get("source") or "",
            "username": cred.get("user") or cred.get("username") or "",
            "has_secret": bool(cred.get("value") or cred.get("password")),
            "validated": cred.get("validated", False),
        },
        discovered_by=discovered_by,
    )
    return cid
