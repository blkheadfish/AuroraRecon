"""
skills/engine.py
Skill 执行引擎

核心流程：
  1. 执行探测阶段（Probes）→ 收集环境变量
  2. 按优先级遍历利用路径（Exploit Paths）
  3. 检查每条路径的前置条件
  4. 按步骤执行利用（Steps）
  5. 处理步骤间跳转（成功/失败/切换路径）
  6. 所有确定性路径失败后 → 带完整上下文进入 LLM 自由推理

设计要点：
  - 引擎直接执行命令，不经过 LLM（确定性路径）
  - 每步结果完整记录，供报告和 LLM 兜底使用
  - 变量替换在执行时做，Skill YAML 中用占位符
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

from backend.agents.models import ExploitResult, VulnFinding
from backend.skills.models import (
    ExploitPath,
    ExploitStep,
    Probe,
    ProbeStep,
    Skill,
    SkillContext,
    StepOutcome,
)
from backend.skills.execution_log import persist_execution
from backend.tools.executor import DecisionCallback, ExecuteResult, TaskContainerManager, ToolExecutor

logger = logging.getLogger(__name__)


class SkillEngine:
    """
    Skill 执行引擎。

    用法：
        engine = SkillEngine()
        result = await engine.execute(skill, finding, target_url, env_profile)
    """

    def __init__(self):
        self.executor = ToolExecutor()

    _GLOBAL_TIMEOUT = int(os.getenv("SKILL_GLOBAL_TIMEOUT", "900"))

    async def execute(
        self,
        skill: Skill,
        finding: VulnFinding,
        target_url: str,
        env_can_reverse: bool = False,
        lhost: str = "",
        target_os: str = "unknown",
        task_id: Optional[str] = None,
        decision_callback: DecisionCallback = None,
    ) -> ExploitResult:
        """
        执行 Skill 完整流程，带全局超时保护。
        """
        t0 = time.monotonic()
        result: ExploitResult
        try:
            result = await asyncio.wait_for(
                self._execute_inner(
                    skill, finding, target_url, env_can_reverse,
                    lhost, target_os, task_id, decision_callback,
                ),
                timeout=self._GLOBAL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning(
                f"[SkillEngine] Skill {skill.skill_id} 全局超时 "
                f"({self._GLOBAL_TIMEOUT}s)"
            )
            result = ExploitResult(
                vuln_id=finding.vuln_id,
                success=False,
                evidence=f"Skill {skill.skill_id} global timeout ({self._GLOBAL_TIMEOUT}s)",
                commands_run=[],
                command_records=[],
            )

        elapsed = round(time.monotonic() - t0, 2)
        persist_execution({
            "skill_id": skill.skill_id,
            "target": target_url,
            "success": result.success,
            "total_elapsed": elapsed,
            "commands_count": len(result.commands_run),
            "evidence_preview": (result.evidence or "")[:200],
        })
        return result

    async def _execute_inner(
        self,
        skill: Skill,
        finding: VulnFinding,
        target_url: str,
        env_can_reverse: bool = False,
        lhost: str = "",
        target_os: str = "unknown",
        task_id: Optional[str] = None,
        decision_callback: DecisionCallback = None,
    ) -> ExploitResult:
        self._decision_callback = decision_callback

        # ── 初始化上下文 ──────────────────────────────
        parsed = urlparse(target_url)
        ctx = SkillContext(
            endpoint=target_url,
            target_ip=parsed.hostname or "",
            target_port=parsed.port or (443 if parsed.scheme == "https" else 80),
            target_os=target_os,
            lhost=lhost,
            can_reverse=env_can_reverse,
            task_id=task_id,
        )

        logger.info(
            f"[SkillEngine] 开始执行 Skill: {skill.skill_id} "
            f"→ {target_url} (can_reverse={env_can_reverse})"
        )

        # ── Phase 1: 探测 ────────────────────────────
        await self._run_probes(skill.probes, ctx, task_id)

        logger.info(
            f"[SkillEngine] 探测完成，上下文变量: "
            f"{json.dumps(ctx.variables, ensure_ascii=False, default=str)}"
        )

        # ── Phase 2: 按优先级尝试利用路径 ────────────
        sorted_paths = sorted(skill.exploit_paths, key=lambda p: p.priority)

        for path in sorted_paths:
            # LLM 兜底路径
            if path.mode == "react_freeform":
                logger.info(
                    f"[SkillEngine] 🤖 所有确定性路径已尝试，进入 LLM 自由推理兜底 "
                    f"(限定在 {skill.name} 范围内，最多 {path.max_rounds} 轮)"
                )
                return await self._react_freeform(
                    skill, finding, ctx, path.max_rounds
                )

            # 条件检查: conditions (AND) + conditions_any (OR groups)
            if path.conditions and not ctx.check(path.conditions):
                unmet = {k: v for k, v in path.conditions.items()
                         if not ctx.check({k: v})}
                logger.info(
                    f"[SkillEngine] ⏭ 路径 [{path.path_id}] {path.name} — "
                    f"条件不满足: {unmet}"
                )
                continue

            if path.conditions_any:
                if not any(ctx.check(group) for group in path.conditions_any):
                    logger.info(
                        f"[SkillEngine] ⏭ 路径 [{path.path_id}] {path.name} — "
                        f"conditions_any 无匹配组"
                    )
                    continue

            if path.skip_if and ctx.check(path.skip_if):
                logger.info(
                    f"[SkillEngine] ⏭ 路径 [{path.path_id}] {path.name} — "
                    f"命中排除条件: {path.skip_if}"
                )
                continue

            logger.info(
                f"[SkillEngine] ▶ 执行路径 [{path.path_id}] {path.name} "
                f"(优先级={path.priority}, {len(path.steps)}步)"
            )

            result = await self._execute_path(path, ctx, finding, task_id)

            if result.success:
                logger.info(
                    f"[SkillEngine] ✅ 路径 {path.path_id} 利用成功"
                )
                return result

            logger.info(
                f"[SkillEngine] ❌ 路径 {path.path_id} 未成功，继续"
            )

        # ── 所有路径失败 ─────────────────────────────
        logger.info(
            f"[SkillEngine] Skill {skill.skill_id} 所有路径失败"
        )
        return ExploitResult(
            vuln_id=finding.vuln_id,
            success=False,
            evidence=self._build_failure_summary(skill, ctx),
            commands_run=ctx.commands_run,
            command_records=ctx.step_records,
            session_info={"probe_variables": dict(ctx.variables)},
        )

    # ================================================================
    # Phase 1: 探测
    # ================================================================

    async def _run_probes(
        self,
        probes: list[Probe],
        ctx: SkillContext,
        task_id: Optional[str],
    ) -> None:
        """Execute probes, running independent ones concurrently."""
        independent: list[Probe] = []
        dependent: list[Probe] = []
        for p in probes:
            if p.depends_on or p.requires:
                dependent.append(p)
            else:
                independent.append(p)

        if len(independent) > 1:
            logger.info(
                f"[SkillEngine] 并发执行 {len(independent)} 个独立探测"
            )
            await asyncio.gather(
                *(self._run_single_probe(p, ctx, task_id) for p in independent)
            )
        else:
            for p in independent:
                await self._run_single_probe(p, ctx, task_id)

        for probe in dependent:
            if probe.depends_on and not ctx.check(probe.depends_on):
                logger.debug(f"[SkillEngine] 探测 {probe.id} 依赖不满足，跳过")
                continue
            if probe.requires and not ctx.check(probe.requires):
                logger.debug(f"[SkillEngine] 探测 {probe.id} 环境不满足，跳过")
                continue
            await self._run_single_probe(probe, ctx, task_id)

    async def _run_single_probe(
        self,
        probe: Probe,
        ctx: SkillContext,
        task_id: Optional[str],
    ) -> None:
        """Execute one probe (single or multi-step)."""
        logger.info(f"[SkillEngine] 执行探测: {probe.id} — {probe.description[:60]}")
        if probe.steps:
            for i, step in enumerate(probe.steps):
                logger.info(f"[SkillEngine]   探测子步骤 {i+1}/{len(probe.steps)}")
                await self._run_probe_command(
                    step.command, step.parse_rules, step.timeout, ctx, task_id
                )
        elif probe.command:
            await self._run_probe_command(
                probe.command, probe.parse_rules, probe.timeout, ctx, task_id
            )

    async def _run_probe_command(
        self,
        command_template: str,
        parse_rules: list,
        timeout: int,
        ctx: SkillContext,
        task_id: Optional[str],
    ) -> None:
        """执行单条探测命令并应用解析规则"""
        command = ctx.substitute(command_template)

        # 日志：显示命令摘要（去掉多余空白）
        cmd_preview = " ".join(command.split())[:500]
        logger.info(f"[SkillEngine]   命令: {cmd_preview}...")

        result = await self.executor.run_script(
            script_content=command,
            timeout=timeout,
            task_id=ctx.task_id,
            record_purpose="probe",
        )

        # 日志：显示输出摘要
        stdout_preview = result.stdout.strip().replace('\n', ' ')[:1000]
        logger.info(
            f"[SkillEngine]   输出: exit={result.exit_code}, "
            f"{len(result.stdout)}B: {stdout_preview}"
        )
        if result.stderr.strip():
            stderr_preview = result.stderr.strip().replace('\n', ' ')[:500]
            logger.info(f"[SkillEngine]   stderr: {stderr_preview}")

        # 记录
        ctx.probe_records.append(self._build_exec_record(
            command=command,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            elapsed=result.elapsed,
            purpose="probe",
            path_id="probe",
            step_id="probe",
        ))

        # 解析 HTTP 状态码
        status_code = result.exit_code
        stdout = result.stdout.strip()
        if stdout.isdigit() and len(stdout) == 3:
            status_code = int(stdout)

        # 应用解析规则
        any_triggered = False
        for rule in parse_rules:
            updates = rule.evaluate(result.stdout, result.stderr, status_code)
            if updates:
                any_triggered = True
                for k, v in updates.items():
                    ctx.set_var(k, v)
                    logger.info(f"[SkillEngine]   ✓ 设置变量: {k} = {v}")

        if not any_triggered and parse_rules:
            logger.info(f"[SkillEngine]   ✗ 无解析规则触发")

    # ================================================================
    # Phase 2: 路径执行
    # ================================================================

    async def _execute_path(
        self,
        path: ExploitPath,
        ctx: SkillContext,
        finding: VulnFinding,
        task_id: Optional[str],
    ) -> ExploitResult:
        """
        执行一条利用路径的所有步骤。

        步骤间跳转逻辑：
          on_success / on_fail 可以是：
            - "next_step"        → 继续下一步
            - "next_path"        → 放弃此路径
            - "conclude_success" → 利用成功
            - "conclude_fail"    → 利用失败
            - "step_id"          → 跳到指定步骤
        """
        steps = path.steps
        if not steps:
            return ExploitResult(vuln_id=finding.vuln_id, success=False)

        # 构建 step_id → index 映射
        step_map = {step.id: i for i, step in enumerate(steps)}
        current_idx = 0

        while 0 <= current_idx < len(steps):
            step = steps[current_idx]

            logger.info(
                f"[SkillEngine]   📌 步骤 [{step.id}]: {step.description}"
            )

            # 执行命令
            command = ctx.substitute(step.command)
            ctx.commands_run.append(command)

            # 日志：命令摘要
            cmd_preview = " ".join(command.split())[:500]
            logger.info(f"[SkillEngine]      命令: {cmd_preview}...")
            if step.publish_ports:
                container_name = TaskContainerManager.get_container(ctx.task_id) if ctx.task_id else None
                logger.info(
                    "[SkillEngine]      运行上下文: "
                    f"task_id={ctx.task_id or '-'}, "
                    f"container={container_name or 'none'}, "
                    f"lhost={os.getenv('LHOST', '') or '-'}, "
                    f"publish_ports={step.publish_ports}"
                )

            exec_result = await self.executor.run_script(
                script_content=command,
                timeout=step.timeout,
                publish_ports=step.publish_ports or None,
                task_id=ctx.task_id,
                record_purpose=step.description,
            )

            # 记录
            ctx.step_records.append(self._build_exec_record(
                command=command,
                stdout=exec_result.stdout,
                stderr=exec_result.stderr,
                exit_code=exec_result.exit_code,
                elapsed=round(exec_result.elapsed, 1),
                purpose=step.description,
                path_id=path.path_id,
                step_id=step.id,
            ))

            # 日志：输出摘要
            stdout_preview = exec_result.stdout.strip().replace('\n', ' ')[:1000]
            logger.info(
                f"[SkillEngine]      输出: exit={exec_result.exit_code}, "
                f"{len(exec_result.stdout)}B, {exec_result.elapsed:.1f}s"
            )
            logger.info(f"[SkillEngine]      预览: {stdout_preview}")
            if exec_result.stderr.strip():
                stderr_preview = exec_result.stderr.strip().replace('\n', ' ')[:500]
                logger.info(f"[SkillEngine]      stderr: {stderr_preview}")

            # 判定成功/失败
            success = step.success_criteria.evaluate(
                exec_result.stdout, exec_result.stderr, exec_result.exit_code
            )

            # 日志：判定细节
            sc = step.success_criteria
            criteria_desc = []
            if sc.stdout_contains_any:
                criteria_desc.append(f"contains_any={sc.stdout_contains_any}")
            if sc.stdout_not_empty:
                criteria_desc.append("not_empty")
            if sc.stdout_regex:
                criteria_desc.append(f"regex={sc.stdout_regex[:30]}")
            logger.info(
                f"[SkillEngine]      判定: {'✅ 成功' if success else '❌ 失败'} "
                f"(条件: {', '.join(criteria_desc) or '无'})"
            )

            if success:
                outcome = step.on_success
            else:
                outcome = step.on_fail

            # ── 处理跳转 ────────────────────────────
            if outcome == "conclude_success":
                # 提取证据
                evidence_data = {}
                for key, source in step.evidence_capture.items():
                    if source == "stdout":
                        evidence_data[key] = exec_result.stdout.strip()
                    else:
                        evidence_data[key] = source

                # 记录成功的利用命令模板
                ctx.exploit_cmd_template = step.command

                return ExploitResult(
                    vuln_id=finding.vuln_id,
                    success=True,
                    shell_type=evidence_data.get("shell_type", "rce"),
                    session_info={
                        "method": f"skill:{path.path_id}",
                        "current_user": evidence_data.get("current_user", ""),
                        "skill_id": path.path_id,
                    },
                    evidence=(
                        f"Skill 路径 [{path.name}] 利用成功\n\n"
                        f"{self._format_exec_evidence(command, exec_result.stdout, exec_result.stderr)}"
                    ),
                    commands_run=ctx.commands_run,
                    command_records=ctx.step_records,
                )

            if outcome == "conclude_fail":
                return ExploitResult(
                    vuln_id=finding.vuln_id,
                    success=False,
                    evidence=f"Skill 路径 [{path.name}] 明确失败",
                    commands_run=ctx.commands_run,
                    command_records=ctx.step_records,
                )

            if outcome == "next_path":
                # 放弃当前路径
                return ExploitResult(
                    vuln_id=finding.vuln_id,
                    success=False,
                )

            if outcome == "next_step":
                current_idx += 1
                continue

            # 跳转到指定步骤
            if outcome in step_map:
                current_idx = step_map[outcome]
                continue

            # 未知跳转 → 当作 next_step
            logger.warning(f"[SkillEngine] 未知跳转: {outcome}，按 next_step 处理")
            current_idx += 1

        # 步骤全部执行完但没有明确 conclude → 视为失败
        return ExploitResult(
            vuln_id=finding.vuln_id,
            success=False,
            evidence=f"Skill 路径 [{path.name}] 步骤执行完毕但未成功",
            commands_run=ctx.commands_run,
            command_records=ctx.step_records,
        )

    # ================================================================
    # LLM 自由推理兜底
    # ================================================================

    async def _react_freeform(
        self,
        skill: Skill,
        finding: VulnFinding,
        ctx: SkillContext,
        max_rounds: int,
    ) -> ExploitResult:
        """
        所有确定性路径失败后的 LLM 兜底。

        与现有 ReAct 循环的区别：
          - LLM 拿到的不是笼统的"知识库文本"，而是：
            1. 漏洞原理（skill.principle）
            2. 精确的探测结果（ctx.variables）
            3. 之前所有路径的尝试记录和失败原因
          - 轮次更少（默认 5 轮而非 8 轮）
        """
        from backend.llm.router import LLMRouter

        llm = LLMRouter()

        # 构建 LLM 上下文
        tried_paths = set()
        failed_commands = []
        for rec in ctx.step_records:
            tried_paths.add(rec.get("path_id", ""))
            failed_commands.append({
                "command": rec["command"][:200],
                "stdout_preview": rec["stdout"][:300],
                "exit_code": rec["exit_code"],
            })

        context_for_llm = (
            f"## 漏洞原理\n{skill.principle}\n\n"
            f"## 环境信息\n"
            f"- 目标: {ctx.endpoint}\n"
            f"- 目标OS: {ctx.target_os}\n"
            f"- 攻击机IP: {ctx.lhost or '未配置(NAT环境)'}\n"
            f"- 可回连: {'是' if ctx.can_reverse else '否'}\n\n"
            f"## 探测结果\n"
            f"{json.dumps(ctx.variables, ensure_ascii=False, indent=2)}\n\n"
            f"## 已尝试路径（均失败）\n"
            f"{json.dumps(failed_commands, ensure_ascii=False, indent=2)}\n\n"
            f"## 扫描证据\n{finding.evidence[:2000]}\n"
        )

        system_prompt = (
            f"你是一名资深渗透测试工程师，正在合法授权的 CTF 靶场中测试。\n"
            f"你正在利用的漏洞是：{skill.name}（{finding.name}）。\n\n"
            f"【严格限制】\n"
            f"- 你只能尝试与 {skill.name} 相关的利用方法\n"
            f"- 禁止尝试其他类型的漏洞（如目标是 Shiro 就不要试 ThinkPHP/Struts/SSTI）\n"
            f"- 禁止做端口扫描、目录爆破等侦察操作（已经完成了）\n"
            f"- 每次只生成一条命令\n"
            f"- 如果你认为该漏洞在当前环境下无法利用，直接 conclude_fail\n\n"
            f"返回严格 JSON（不含 markdown）：\n"
            '{"action":"execute","command":"...","purpose":"..."}\n'
            '或 {"action":"conclude_success","evidence":"...","current_user":"..."}\n'
            '或 {"action":"conclude_fail","reason":"..."}\n'
        )

        conversation = [
            {"role": "user", "content": (
                context_for_llm +
                f"\n\n之前的自动化路径全部失败。请基于上述漏洞原理和探测结果，"
                f"只在 [{skill.name}] 这个漏洞范围内推理下一步利用命令。"
            )},
        ]

        logger.info(
            f"[SkillEngine] 🤖 LLM 兜底开始: 漏洞={skill.name}, "
            f"已知变量={list(ctx.variables.keys())}, "
            f"已执行={len(ctx.commands_run)}条命令"
        )

        for round_num in range(max_rounds):
            try:
                response_raw = await llm.chat_multi_turn(
                    messages=conversation,
                    system_prompt=system_prompt,
                    response_format="json",
                    temperature=0.2,
                )
            except Exception as e:
                logger.error(f"[SkillEngine] LLM 调用失败: {e}")
                break

            conversation.append({"role": "assistant", "content": response_raw})

            try:
                decision = json.loads(response_raw)
            except json.JSONDecodeError:
                conversation.append({
                    "role": "user",
                    "content": "输出不是合法 JSON，请重新回答。",
                })
                continue

            action = decision.get("action", "")
            purpose = decision.get("purpose", "")
            thinking = decision.get("thinking", "")

            logger.info(
                f"[SkillEngine] 🤖 LLM 第{round_num+1}轮: action={action}, "
                f"thinking={thinking[:120]}, purpose={purpose}"
            )

            if thinking and self._decision_callback:
                await self._decision_callback({
                    "action": "thought",
                    "phase": "foothold_attempt",
                    "round": round_num + 1,
                    "thinking": thinking,
                    "purpose": purpose,
                    "expected": decision.get("expected", ""),
                    "plan": decision.get("plan", []),
                    "message": thinking[:300],
                    "tone": "primary",
                    "vuln_name": f"{skill.name} (LLM兜底)",
                })

            if action == "conclude_success":
                logger.info(f"[SkillEngine] 🤖 LLM 判定利用成功，执行 id 命令二次验证...")
                verify = await self.executor.run_script(
                    "id",
                    timeout=10,
                    task_id=ctx.task_id,
                )
                if "uid=" not in (verify.stdout or ""):
                    logger.warning("[SkillEngine] 二次验证失败: id 命令未返回 uid=")
                    conversation.append({
                        "role": "user",
                        "content": "无法通过 id 命令确认 shell 访问（输出中未见 uid=），请重新评估。",
                    })
                    continue
                logger.info(f"[SkillEngine] ✅ 二次验证通过: {verify.stdout.strip()[:200]}")
                return ExploitResult(
                    vuln_id=finding.vuln_id,
                    success=True,
                    shell_type="rce",
                    session_info={
                        "method": f"skill:{skill.skill_id}:llm_freeform",
                        "current_user": decision.get("current_user", ""),
                        "rounds": round_num + 1,
                    },
                    evidence=f"{decision.get('evidence', '')} [verified: {verify.stdout.strip()[:100]}]",
                    commands_run=ctx.commands_run,
                    command_records=ctx.step_records,
                )

            if action == "conclude_fail":
                reason = decision.get("reason", "未知")
                logger.info(f"[SkillEngine] 🤖 LLM 判定利用失败: {reason}")
                break

            if action != "execute":
                conversation.append({
                    "role": "user",
                    "content": "请返回 execute / conclude_success / conclude_fail。",
                })
                continue

            cmd = decision.get("command", "").strip()
            if not cmd:
                continue

            cmd_preview = " ".join(cmd.split())[:500]
            logger.info(f"[SkillEngine] 🤖 执行: {cmd_preview}...")

            ctx.commands_run.append(cmd)
            exec_result = await self.executor.run_script(
                cmd,
                timeout=60,
                task_id=ctx.task_id,
                record_purpose=decision.get("purpose", ""),
                record_round=round_num + 1,
            )

            stdout_preview = exec_result.stdout.strip().replace('\n', ' ')[:1000]
            logger.info(
                f"[SkillEngine] 🤖 结果: exit={exec_result.exit_code}, "
                f"{len(exec_result.stdout)}B: {stdout_preview}"
            )

            ctx.step_records.append(self._build_exec_record(
                command=cmd,
                stdout=exec_result.stdout,
                stderr=exec_result.stderr,
                exit_code=exec_result.exit_code,
                elapsed=round(exec_result.elapsed, 1),
                purpose=decision.get("purpose", ""),
                path_id="llm_freeform",
                step_id=f"llm_round_{round_num + 1}",
                round_no=round_num + 1,
            ))

            if self._decision_callback:
                await self._decision_callback({
                    "action": "command_exec",
                    "phase": "foothold_attempt",
                    "round": round_num + 1,
                    "command": cmd,
                    "purpose": purpose,
                    "stdout": exec_result.stdout[:2000],
                    "stderr": exec_result.stderr[:500],
                    "exit_code": exec_result.exit_code,
                    "elapsed": round(exec_result.elapsed, 1),
                    "vuln_name": f"{skill.name} (LLM兜底)",
                    "message": f"命令执行: {cmd[:120]}",
                    "tone": "success" if exec_result.exit_code == 0 else "danger",
                })

            conversation.append({
                "role": "user",
                "content": (
                    f"命令执行结果:\nstdout:\n{exec_result.stdout[:3000]}\n"
                    f"stderr:\n{exec_result.stderr[:500]}\n"
                    f"exit_code: {exec_result.exit_code}\n"
                    "请分析结果，决定下一步。"
                ),
            })

        return ExploitResult(
            vuln_id=finding.vuln_id,
            success=False,
            evidence=self._build_failure_summary(skill, ctx),
            commands_run=ctx.commands_run,
            command_records=ctx.step_records,
        )

    # ================================================================
    # 辅助
    # ================================================================

    @staticmethod
    def _build_failure_summary(skill: Skill, ctx: SkillContext) -> str:
        """构建失败总结（写入报告）"""
        lines = [
            f"Skill [{skill.name}] 全部路径失败。",
            f"探测结果: {json.dumps(ctx.variables, ensure_ascii=False)}",
            f"共执行 {len(ctx.commands_run)} 条命令。",
        ]
        if ctx.step_records:
            lines.append("\n最后几条命令:")
            for rec in ctx.step_records[-3:]:
                lines.append(
                    f"  [{rec.get('path_id')}] {rec['command'][:120]} "
                    f"→ exit={rec['exit_code']}"
                )
        return "\n".join(lines)

    @staticmethod
    def _format_exec_evidence(command: str, stdout: str, stderr: str) -> str:
        return "\n\n".join([
            f"Command\n{command or '(empty command)'}",
            f"Stdout\n{stdout.strip() or '(empty)'}",
            f"Stderr\n{stderr.strip() or '(empty)'}",
        ])

    @staticmethod
    def _build_exec_record(
        *,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: Optional[int],
        elapsed: Optional[float],
        purpose: str = "",
        path_id: str = "",
        step_id: str = "",
        round_no: Optional[int] = None,
    ) -> dict:
        total_len = len(stdout or "") + len(stderr or "")
        return {
            "path_id": path_id,
            "step_id": step_id,
            "round": round_no,
            "purpose": purpose or "",
            "timestamp": datetime.utcnow().isoformat(),
            "command": command or "",
            "stdout": stdout or "",
            "stderr": stderr or "",
            "exit_code": exit_code,
            "elapsed": elapsed,
            "truncated": False,
            "total_len": total_len,
        }