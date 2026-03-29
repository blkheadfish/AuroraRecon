"""
tools/executor.py
工具执行调度层

执行后端（由 YAML 中 executor 字段路由）:
  local      直接在 API 容器内执行（subprocess）
             适合无状态工具：nmap、gobuster、nuclei、sqlmap…

  container  Docker 容器执行，两种模式自动切换：
             ① 持久化模式（推荐有状态工具）
                task_id 已通过 TaskContainerManager.start() 注册
                → docker exec 进已有容器，保留进程状态
                适合：MSF listener、JNDIExploit、反弹 Shell 监听
             ② 临时模式（兜底）
                task_id 未注册时自动降级
                → docker run --rm，与原来行为一致
                适合：一次性工具调用

  remote     （阶段二预留）SSH 到独立攻击机执行
             接口签名不变，上层代码零改动

多人扩展路线：
  单人阶段  → local + container（当前）
  多人阶段  → container 按 task_id 分配独立容器+端口
            → remote 后端 SSH 到每人专属攻击机
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Awaitable

from backend.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

TOOLBOX_IMAGE  = os.getenv("TOOLBOX_IMAGE", "pentest-toolbox:latest")
DOCKER_NETWORK = os.getenv("DOCKER_NETWORK", "pentest_net")
USE_HOST_TOOLS = os.getenv("USE_HOST_TOOLS", "false").lower() == "true"
DATA_VOLUME    = os.getenv("DATA_VOLUME", "/tmp/pentest_data")
REPORTS_DIR    = os.getenv("REPORTS_DIR", "/tmp/pentest_reports")

LogCallback = Optional[Callable[[str], Awaitable[None]]]


@dataclass
class ExecuteResult:
    """工具执行结果"""
    success:   bool
    stdout:    str
    stderr:    str
    exit_code: int
    elapsed:   float
    command:   str = ""
    tool_name: str = ""
    backend:   str = ""   # "local" | "container-exec" | "container-run" | "remote"


# ─────────────────────────────────────────────────────────────
# 持久化容器管理（有状态工具专用，阶段二多人模式扩展点）
# ─────────────────────────────────────────────────────────────

class TaskContainerManager:
    """
    为每个 task_id 维护一个长活 toolbox 容器。

    单人阶段用法（orchestrator 层调用）：
        await TaskContainerManager.start(task_id)   # node_recon 前
        ...                                          # agent 调用中自动使用
        await TaskContainerManager.stop(task_id)    # node_report 后

    阶段二多人扩展：
        - 改成按 user_id 或 team_id 分配容器
        - 或改成动态端口映射，供 RemoteBackend 使用
        - 接口 start/stop/get_container 不变，上层零改动
    """

    _containers: dict[str, str] = {}   # task_id → container_name
    _lock = asyncio.Lock()

    @classmethod
    async def start(cls, task_id: str) -> str:
        """启动任务专属容器，返回容器名。幂等。"""
        async with cls._lock:
            if task_id in cls._containers:
                return cls._containers[task_id]

            name = f"pentest_task_{task_id[:12]}"
            cmd = [
                "docker", "run", "-d",
                "--name", name,
                "--network", DOCKER_NETWORK,
                "--rm",
                "-v", f"{DATA_VOLUME}:/data",
                "-v", f"{REPORTS_DIR}:/reports",
                "--privileged",          # 与 docker run --rm 保持一致，nmap 需要
                "--cap-add", "NET_RAW",
                "--cap-add", "NET_ADMIN",
                TOOLBOX_IMAGE,
                "sleep", "86400",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(
                    f"容器启动失败: {stderr.decode(errors='replace').strip()}"
                )

            cls._containers[task_id] = name
            logger.info(f"[ContainerMgr] 容器已启动: {name}")
            return name

    @classmethod
    async def stop(cls, task_id: str) -> None:
        """停止并删除任务容器。"""
        async with cls._lock:
            name = cls._containers.pop(task_id, None)
        if not name:
            return
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        logger.info(f"[ContainerMgr] 容器已清理: {name}")

    @classmethod
    def get_container(cls, task_id: str) -> Optional[str]:
        return cls._containers.get(task_id)


# ─────────────────────────────────────────────────────────────
# 远程后端预留（阶段二：SSH 到独立攻击机）
# ─────────────────────────────────────────────────────────────

class _RemoteBackendStub:
    """
    阶段二实现提示：
      - 从 task_id 查询分配给该任务的攻击机 IP
      - asyncssh.connect(ip) 建立 SSH 连接（连接池复用）
      - conn.run(shlex.join(args)) 执行命令
      - 返回 (exit_code, stdout, stderr)

    多人场景：每个任务/用户分配独立攻击机，
    TaskContainerManager 扩展为 RemoteHostManager 即可，
    ToolExecutor 路由逻辑无需修改。
    """
    async def execute(self, args, *, timeout, env, workdir, task_id):
        raise NotImplementedError("RemoteBackend 阶段二实现")


_remote_stub = _RemoteBackendStub()


# ─────────────────────────────────────────────────────────────
# 主调度器
# ─────────────────────────────────────────────────────────────

class ToolExecutor:
    """
    工具执行调度器。

    路由规则（tool_def.executor 字段）：
      local      → subprocess 直接执行
      remote     → RemoteBackend（阶段二，当前抛 NotImplementedError）
      container  → 优先 docker exec（持久容器），降级 docker run --rm

    用法：
        executor = ToolExecutor()
        result = await executor.run(
            tool="nmap",
            args=["-sV", "-p", "80,443", "192.168.1.1"],
            timeout=120,
            task_id=state.task_id,   # 可选，有状态工具需要
        )
    """

    def __init__(self):
        self._registry = ToolRegistry()

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    async def run(
        self,
        tool: str,
        args: list[str],
        timeout: int = 0,
        input_data: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        workdir: str = "/tmp",
        log_callback: LogCallback = None,
        task_id: Optional[str] = None,
        publish_ports: list[int] | None = None,
    ) -> ExecuteResult:
        tool_def = self._registry.get_or_default(tool)
        effective_timeout = timeout or tool_def.timeout

        # ── 路由 ──────────────────────────────────────────
        executor_type = tool_def.executor  # "local" | "container" | "remote"

        if USE_HOST_TOOLS or executor_type == "local":
            cmd = [tool_def.command, *args]
            backend_label = "local"

        elif executor_type == "remote":
            # 阶段二：转交 RemoteBackend
            try:
                return await self._run_remote(
                    tool, args, timeout=effective_timeout,
                    env=env, workdir=workdir,
                    log_callback=log_callback, task_id=task_id,
                )
            except NotImplementedError:
                logger.error(f"[Executor] remote 后端未实现，无法执行 {tool}")
                return ExecuteResult(
                    success=False, stdout="", stderr="RemoteBackend 阶段二实现",
                    exit_code=-1, elapsed=0, command=tool, tool_name=tool, backend="remote",
                )

        else:
            # container 模式：有持久容器用 exec，否则用 run --rm
            container_name = TaskContainerManager.get_container(task_id) if task_id else None
            if container_name:
                return await self._run_docker_exec(
                    tool, args, container_name,
                    timeout=effective_timeout, env=env, workdir=workdir,
                    log_callback=log_callback,
                )
            else:
                cmd = self._build_docker_run_cmd(tool_def, args, env, workdir, publish_ports)
                backend_label = "container-run"

        # ── subprocess 执行（local 和 container-run 共用）──
        return await self._run_subprocess(
            tool, cmd, backend_label,
            timeout=effective_timeout,
            input_data=input_data,
            log_callback=log_callback,
        )

    # ── docker exec（持久容器）────────────────────────────

    async def _run_docker_exec(
        self,
        tool: str,
        args: list[str],
        container_name: str,
        *,
        timeout: int,
        env: Optional[dict],
        workdir: str,
        log_callback: LogCallback,
    ) -> ExecuteResult:
        tool_def = self._registry.get_or_default(tool)
        env_args: list[str] = []
        for k, v in (env or {}).items():
            env_args += ["-e", f"{k}={v}"]

        import shlex
        # docker exec 不自动加载镜像 ENV，需要显式注入 PATH
        # 路径覆盖 Kali 所有工具安装位置
        kali_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        path_args = ["-e", f"PATH={kali_path}"]
        cmd_parts = tool_def.command.split()
        inner_cmd = shlex.join(cmd_parts + args)
        cmd = (["docker", "exec", "-w", workdir]
               + path_args + env_args
               + [container_name, "bash", "-c", inner_cmd])

        log_msg = f"🔧 {tool} [exec→{container_name[:20]}]: {' '.join(args[:4])}"
        logger.info(f"[Executor] {log_msg}")
        if log_callback:
            try: await log_callback(log_msg)
            except Exception: pass

        return await self._run_subprocess(
            tool, cmd, "container-exec",
            timeout=timeout, input_data=None, log_callback=log_callback,
        )

    # ── docker run --rm（临时容器）────────────────────────

    def _build_docker_run_cmd(self, tool_def, args, env, workdir, publish_ports=None) -> list[str]:
        docker_cmd = [
            "docker", "run", "--rm", "-i",
            "--network", DOCKER_NETWORK,   # pentest_net：与 msf/postgres/redis 同网，Docker DNS 可解析
            "-w", workdir,
            "-v", f"{DATA_VOLUME}:/data",
            "--privileged",
        ]
        # 端口映射（用于反连回调，如 Shiro 利用）
        if publish_ports:
            for port in publish_ports:
                docker_cmd.extend(["-p", f"{port}:{port}"])
        lhost = os.getenv("LHOST", "")
        if lhost:
            docker_cmd.extend(["-e", f"LHOST={lhost}"])
        if env:
            for k, v in env.items():
                docker_cmd.extend(["-e", f"{k}={v}"])
        docker_cmd.append(TOOLBOX_IMAGE)
        docker_cmd.extend(tool_def.command.split())
        docker_cmd.extend(args)
        return docker_cmd

    # ── remote 后端（阶段二）─────────────────────────────

    async def _run_remote(self, tool, args, *, timeout, env, workdir, log_callback, task_id):
        await _remote_stub.execute(args, timeout=timeout, env=env, workdir=workdir, task_id=task_id)

    # ── 通用 subprocess 执行 ──────────────────────────────

    async def _run_subprocess(
        self,
        tool: str,
        cmd: list[str],
        backend_label: str,
        *,
        timeout: int,
        input_data: Optional[str],
        log_callback: LogCallback,
    ) -> ExecuteResult:
        cmd_display = " ".join(cmd[:8]) + ("..." if len(cmd) > 8 else "")
        log_msg = f"🔧 执行 {tool} [{backend_label}]: {cmd_display}"
        logger.info(f"[Executor] {log_msg}")
        if log_callback:
            try: await log_callback(log_msg)
            except Exception: pass

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdin_bytes = input_data.encode() if input_data else None

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(input=stdin_bytes), timeout=timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                elapsed = time.monotonic() - start
                msg = f"⏰ {tool} 超时 ({timeout}s)"
                logger.warning(f"[Executor] {msg}")
                if log_callback:
                    try: await log_callback(msg)
                    except Exception: pass
                return ExecuteResult(
                    success=False, stdout="", stderr=f"执行超时（{timeout}秒）",
                    exit_code=-1, elapsed=elapsed,
                    command=" ".join(cmd), tool_name=tool, backend=backend_label,
                )

            elapsed = time.monotonic() - start
            exit_code = proc.returncode or 0
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            success = exit_code == 0 or len(stdout.strip()) > 0

            status = "✅" if success else "❌"
            log_msg = f"{status} {tool} 完成: exit={exit_code}, 输出={len(stdout)}B, 耗时={elapsed:.1f}s"
            logger.info(f"[Executor] {log_msg}")
            if log_callback:
                try: await log_callback(log_msg)
                except Exception: pass

            return ExecuteResult(
                success=success, stdout=stdout, stderr=stderr,
                exit_code=exit_code, elapsed=elapsed,
                command=" ".join(cmd), tool_name=tool, backend=backend_label,
            )

        except FileNotFoundError:
            elapsed = time.monotonic() - start
            msg = f"命令未找到: {cmd[0]}"
            logger.error(f"[Executor] {msg}")
            return ExecuteResult(
                success=False, stdout="", stderr=msg, exit_code=127,
                elapsed=elapsed, command=" ".join(cmd), tool_name=tool, backend=backend_label,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.error(f"[Executor] 未预期异常: {e}")
            return ExecuteResult(
                success=False, stdout="", stderr=str(e), exit_code=-1,
                elapsed=elapsed, command=" ".join(cmd), tool_name=tool, backend=backend_label,
            )

    async def run_script(
        self,
        script_content: str,
        timeout: int = 60,
        shell: str = "/bin/bash",
        log_callback: LogCallback = None,
        publish_ports: list[int] | None = None,
    ) -> ExecuteResult:
        """执行 shell 脚本片段

        Args:
            publish_ports: 需要映射到宿主机的端口列表（用于反连回调）
        """
        return await self.run(
            tool=shell, args=["-s"], timeout=timeout,
            input_data=script_content, log_callback=log_callback,
            publish_ports=publish_ports,
        )

    # ── 容器生命周期快捷方法（供 orchestrator 调用）──────

    async def start_task_container(self, task_id: str) -> str:
        """task 开始时调用，启动专属持久容器。"""
        return await TaskContainerManager.start(task_id)

    async def stop_task_container(self, task_id: str) -> None:
        """task 结束时调用，清理容器。"""
        await TaskContainerManager.stop(task_id)