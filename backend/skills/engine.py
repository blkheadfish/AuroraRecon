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

import json
import logging
import time
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
from backend.tools.executor import ExecuteResult, ToolExecutor

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

    async def execute(
        self,
        skill: Skill,
        finding: VulnFinding,
        target_url: str,
        env_can_reverse: bool = False,
        lhost: str = "",
        target_os: str = "unknown",
        task_id: Optional[str] = None,
    ) -> ExploitResult:
        """
        执行 Skill 完整流程。

        Args:
            skill:           匹配到的 Skill 定义
            finding:         漏洞发现信息
            target_url:      实际的目标 URL（VulnAgent 探测到的）
            env_can_reverse: 攻击机是否有公网 IP
            lhost:           攻击机 IP
            target_os:       目标操作系统
            task_id:         任务 ID（容器隔离用）

        Returns:
            ExploitResult
        """
        # ── 初始化上下文 ──────────────────────────────
        parsed = urlparse(target_url)
        ctx = SkillContext(
            endpoint=target_url,
            target_ip=parsed.hostname or "",
            target_port=parsed.port or (443 if parsed.scheme == "https" else 80),
            target_os=target_os,
            lhost=lhost,
            can_reverse=env_can_reverse,
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
                logger.info("[SkillEngine] 进入 LLM 自由推理兜底")
                return await self._react_freeform(
                    skill, finding, ctx, path.max_rounds
                )

            # 条件检查
            if path.conditions and not ctx.check(path.conditions):
                logger.info(
                    f"[SkillEngine] 路径 {path.path_id} 条件不满足，跳过"
                )
                continue

            if path.skip_if and ctx.check(path.skip_if):
                logger.info(
                    f"[SkillEngine] 路径 {path.path_id} 命中排除条件，跳过"
                )
                continue

            logger.info(
                f"[SkillEngine] 尝试路径: {path.path_id} ({path.name})"
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
        """依次执行探测，结果写入上下文"""
        for probe in probes:
            # 前置条件检查
            if probe.depends_on and not ctx.check(probe.depends_on):
                logger.debug(f"[SkillEngine] 探测 {probe.id} 依赖不满足，跳过")
                continue

            if probe.requires and not ctx.check(probe.requires):
                logger.debug(f"[SkillEngine] 探测 {probe.id} 环境不满足，跳过")
                continue

            logger.info(f"[SkillEngine] 执行探测: {probe.id}")

            if probe.steps:
                # 多步骤探测
                for step in probe.steps:
                    await self._run_probe_command(
                        step.command, step.parse_rules, step.timeout, ctx, task_id
                    )
            elif probe.command:
                # 单命令探测
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

        result = await self.executor.run_script(
            script_content=command,
            timeout=timeout,
            task_id=task_id,
        )

        # 记录
        ctx.probe_records.append({
            "command": command[:200],
            "stdout": result.stdout[:2000],
            "stderr": result.stderr[:500],
            "exit_code": result.exit_code,
        })

        # 解析 HTTP 状态码（如果命令输出中包含）
        status_code = result.exit_code  # 粗略近似
        # 尝试从 stdout 提取 HTTP 状态码
        stdout = result.stdout.strip()
        if stdout.isdigit() and len(stdout) == 3:
            status_code = int(stdout)

        # 应用解析规则
        for rule in parse_rules:
            updates = rule.evaluate(result.stdout, result.stderr, status_code)
            if updates:
                for k, v in updates.items():
                    ctx.set_var(k, v)
                    logger.info(f"[SkillEngine] 探测设置: {k} = {v}")

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
                f"[SkillEngine]   步骤 {step.id}: {step.description[:80]}"
            )

            # 执行命令
            command = ctx.substitute(step.command)
            ctx.commands_run.append(command)

            exec_result = await self.executor.run_script(
                script_content=command,
                timeout=step.timeout,
                task_id=task_id,
            )

            # 记录
            record = {
                "path_id": path.path_id,
                "step_id": step.id,
                "command": command[:500],
                "purpose": step.description,
                "stdout": exec_result.stdout[:5000],
                "stderr": exec_result.stderr[:2000],
                "exit_code": exec_result.exit_code,
                "elapsed": round(exec_result.elapsed, 1),
            }
            ctx.step_records.append(record)

            # 判定成功/失败
            success = step.success_criteria.evaluate(
                exec_result.stdout, exec_result.stderr, exec_result.exit_code
            )

            logger.info(
                f"[SkillEngine]   结果: {'成功' if success else '失败'} "
                f"(exit={exec_result.exit_code}, "
                f"stdout={len(exec_result.stdout)}B)"
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
                        evidence_data[key] = exec_result.stdout.strip()[:500]
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
                        f"Skill 路径 [{path.name}] 利用成功\n"
                        f"命令: {command[:300]}\n"
                        f"输出: {exec_result.stdout[:3000]}"
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
            "你是一名资深渗透测试工程师，正在合法授权的 CTF 靶场中测试。\n"
            "之前的自动化利用路径全部失败，现在需要你根据上下文信息自由推理。\n"
            "每次只生成一条命令，返回 JSON：\n"
            '{"action":"execute","command":"...","purpose":"..."}\n'
            '或 {"action":"conclude_success","evidence":"...","current_user":"..."}\n'
            '或 {"action":"conclude_fail","reason":"..."}\n'
            "不要重复已经失败的命令。"
        )

        conversation = [
            {"role": "user", "content": context_for_llm + "\n\n请分析情况，生成第一条利用命令。"},
        ]

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

            if action == "conclude_success":
                return ExploitResult(
                    vuln_id=finding.vuln_id,
                    success=True,
                    shell_type="rce",
                    session_info={
                        "method": f"skill:{skill.skill_id}:llm_freeform",
                        "current_user": decision.get("current_user", ""),
                        "rounds": round_num + 1,
                    },
                    evidence=decision.get("evidence", "")[:3000],
                    commands_run=ctx.commands_run,
                    command_records=ctx.step_records,
                )

            if action == "conclude_fail":
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

            ctx.commands_run.append(cmd)
            exec_result = await self.executor.run_script(cmd, timeout=60)

            ctx.step_records.append({
                "path_id": "llm_freeform",
                "step_id": f"llm_round_{round_num + 1}",
                "command": cmd[:500],
                "purpose": decision.get("purpose", ""),
                "stdout": exec_result.stdout[:5000],
                "stderr": exec_result.stderr[:2000],
                "exit_code": exec_result.exit_code,
                "elapsed": round(exec_result.elapsed, 1),
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
