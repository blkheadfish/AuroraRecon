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


# ── phpinfo extraction hook ───────────────────────────────

_PHPINFO_PATH_RE = re.compile(r'(?:^|/)(?:phpinfo|info)(?:\.php|$)', re.IGNORECASE)


def apply_phpinfo_extraction(
    state: PentestState,
    harvested: list[dict[str, Any]],
    base_url: str,
    port: int,
) -> None:
    """Deterministically extract phpinfo facts from harvested pages/files.

    Writes ``state.php_runtime`` (merged across multiple phpinfo endpoints)
    and sprouts high-value findings (e.g. ``allow_url_include=On`` ⇒ RFI)
    without waiting for the per-entry LLM audit.
    """
    try:
        from backend.tools.parsers import phpinfo_parser as _pp
    except Exception as exc:
        logger.warning(f"[IntelHarvest] phpinfo_parser import failed: {exc}")
        return

    matches: list[dict[str, Any]] = []
    for entry in harvested:
        body = entry.get("body") or ""
        path = entry.get("path") or ""
        if not body:
            continue
        looks_like = bool(_PHPINFO_PATH_RE.search(path)) or _pp.is_phpinfo_content(body)
        if not looks_like:
            continue
        facts = _pp.parse_phpinfo(body)
        if not facts:
            continue
        matches.append({"path": path, "facts": facts})

    if not matches:
        return

    merged: dict[str, Any] = dict(state.php_runtime or {})
    for m in matches:
        for k, v in m["facts"].items():
            if isinstance(v, list):
                existing = merged.get(k)
                if isinstance(existing, list):
                    merged[k] = sorted(set(existing) | set(v), key=str)
                else:
                    merged[k] = v
            else:
                merged[k] = v
    state.php_runtime = merged
    surface = _pp.derive_attack_surface(merged)
    if surface:
        merged["_attack_surface"] = surface

    paths_str = ", ".join(m["path"] for m in matches[:3])
    state.log(f"情报采集: phpinfo 结构化抽取完成 ({paths_str})")

    if merged.get("php_version") or merged.get("sapi"):
        version = merged.get("php_version") or "unknown"
        sapi = merged.get("sapi") or "unknown"
        state.log(f"情报采集: PHP {version} / SAPI {sapi}")

    if surface.get("rfi_possible"):
        finding_target = f"{base_url}{matches[0]['path']}"
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
                evidence=(f"来源: {matches[0]['path']}；"
                          f"allow_url_fopen={merged.get('allow_url_fopen')}"),
                exploitable=True,
                tool="phpinfo_parser",
            ))
            state.log("情报采集: allow_url_include=On 已转化为 high 级 RFI finding")

    disabled = merged.get("disable_functions") or []
    if isinstance(disabled, list) and disabled:
        cmd_funcs = {"system", "exec", "passthru", "shell_exec", "popen", "proc_open"}
        disabled_set = {d.lower() for d in disabled}
        if cmd_funcs.issubset(disabled_set):
            state.log(
                "情报采集: disable_functions 禁用所有 shell 执行函数，"
                "优先走 include/assert/file_put_contents 路径"
            )

    if merged.get("open_basedir"):
        state.log(f"情报采集: open_basedir={merged['open_basedir']}，文件系统访问受限")
