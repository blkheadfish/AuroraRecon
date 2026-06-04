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
import uuid
from datetime import datetime
from dataclasses import dataclass, field
from typing import Callable, Optional, Awaitable

from backend.tools.tool_registry import ToolRegistry
from backend.metrics.collector import get_collector

logger = logging.getLogger(__name__)

TOOLBOX_IMAGE  = os.getenv("TOOLBOX_IMAGE", "pentest-toolbox:latest")
DOCKER_NETWORK = os.getenv("DOCKER_NETWORK", "pentest_net")
TOOLBOX_NETWORK = os.getenv("TOOLBOX_NETWORK", "host")
USE_HOST_TOOLS = os.getenv("USE_HOST_TOOLS", "false").lower() == "true"
DATA_VOLUME    = os.getenv("DATA_VOLUME", "/tmp/pentest_data")
REPORTS_DIR    = os.getenv("REPORTS_DIR", "/tmp/pentest_reports")

LogCallback = Optional[Callable[[str], Awaitable[None]]]
RecordCallback = Optional[Callable[[dict], Awaitable[None]]]
DecisionCallback = Optional[Callable[[dict], Awaitable[None]]]


_DISPLAY_SHELL_NAMES = frozenset({"/bin/bash", "/bin/sh", "bash", "sh", "/bin/zsh", "zsh"})

import re as _display_re

_DISPLAY_SKIP_RE = _display_re.compile(
    r"^(set\s|export\s|cd\s|echo\s|#|if\s|then\b|else\b|fi\b|do\b|done\b|while\s|for\s|\[)"
)
_DISPLAY_VAR_RE = _display_re.compile(r"^\w+=")


def _infer_display_tool(tool: str, script_or_command: str = "", purpose: str = "") -> str:
    """Best-effort 友好工具名。

    优先级:
      1. 已有非 shell 的 tool key → 直接用
      2. 从脚本/命令第一段非赋值非控制流的 token 取
      3. 退回到 record_purpose 的前缀(便于区分 sensitive_file_probe 这种 purpose)
      4. 兜底 ``script``,绝不返回 ``/bin/bash``
    """
    if tool and tool not in _DISPLAY_SHELL_NAMES:
        return tool
    text = script_or_command or ""
    if text:
        for raw in _display_re.split(r"[;\n|]|&&|\|\|", text):
            seg = raw.strip()
            if not seg:
                continue
            if _DISPLAY_SKIP_RE.match(seg):
                continue
            if _DISPLAY_VAR_RE.match(seg):
                continue
            first = seg.split()[0]
            name = first.rsplit("/", 1)[-1]
            if name and name not in _DISPLAY_SHELL_NAMES:
                return name
    if purpose:
        return purpose.split("_", 1)[0] or "script"
    return "script"


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
    backend:   str = ""
    timed_out: bool = False
    container_crashed: bool = False



class TaskContainerManager:
    """
    为每个 task_id 维护一个长活 toolbox 容器。

    单人阶段用法（orchestrator 层调用）：
        await TaskContainerManager.start(task_id)
        ...
        await TaskContainerManager.stop(task_id)

    阶段二多人扩展：
        - 改成按 user_id 或 team_id 分配容器
        - 或改成动态端口映射，供 RemoteBackend 使用
        - 接口 start/stop/get_container 不变，上层零改动
    """

    _containers: dict[str, str] = {}
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
                "--network", TOOLBOX_NETWORK,
                "--rm",
                "-v", f"{DATA_VOLUME}:/data",
                "-v", f"{REPORTS_DIR}:/reports",
                "--privileged",
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

    @classmethod
    async def cleanup_orphans(cls) -> int:
        """Sweep and kill any orphaned pentest_task_* containers.

        Call on process startup and periodically to handle containers
        leaked by crashes, timeouts, or lost in-memory references.
        """
        proc = await asyncio.create_subprocess_exec(
            "docker", "ps", "-q", "--filter", "name=pentest_task_",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if not stdout or not stdout.strip():
            return 0

        container_ids = stdout.decode().strip().split("\n")
        tracked = set(cls._containers.values())
        orphans = []
        for cid in container_ids:
            cid = cid.strip()
            if not cid:
                continue
            name_proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", "--format", "{{.Name}}", cid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            name_out, _ = await name_proc.communicate()
            name = name_out.decode().strip().lstrip("/")
            if name not in tracked:
                orphans.append(name or cid)

        for orphan in orphans:
            kill_proc = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", orphan,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await kill_proc.wait()
            logger.info(f"[ContainerMgr] Orphan container cleaned: {orphan}")

        return len(orphans)



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
            task_id=state.task_id,
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
        record_callback: RecordCallback = None,
        record_phase: str = "",
        record_purpose: str = "",
        record_round: Optional[int] = None,
        record_command: Optional[str] = None,
        record_runtime_command: Optional[str] = None,
        task_id: Optional[str] = None,
        publish_ports: list[int] | None = None,
        stream_callback=None,
    ) -> ExecuteResult:
        tool_def = self._registry.get_or_default(tool)
        effective_timeout = timeout or tool_def.timeout
        effective_record_command = record_command or " ".join([tool_def.command, *args]).strip()

        executor_type = tool_def.executor

        if USE_HOST_TOOLS or executor_type == "local":
            cmd = [tool_def.command, *args]
            backend_label = "local"

        elif executor_type == "remote":
            try:
                return await self._run_remote(
                    tool, args, timeout=effective_timeout,
                    env=env, workdir=workdir,
                    log_callback=log_callback, task_id=task_id,
                    record_callback=record_callback,
                    record_phase=record_phase,
                    record_purpose=record_purpose,
                    record_round=record_round,
                    record_command=effective_record_command,
                    record_runtime_command=record_runtime_command,
                )
            except NotImplementedError:
                logger.error(f"[Executor] remote 后端未实现，无法执行 {tool}")
                return ExecuteResult(
                    success=False, stdout="", stderr="RemoteBackend 阶段二实现",
                    exit_code=-1, elapsed=0, command=tool, tool_name=tool, backend="remote",
                )

        else:
            container_name = TaskContainerManager.get_container(task_id) if task_id else None
            if container_name and not publish_ports:
                return await self._run_docker_exec(
                    tool, args, container_name,
                    timeout=effective_timeout, env=env, workdir=workdir,
                    log_callback=log_callback,
                    input_data=input_data,
                    record_callback=record_callback,
                    record_phase=record_phase,
                    record_purpose=record_purpose,
                    record_round=record_round,
                    record_command=effective_record_command,
                    record_runtime_command=record_runtime_command,
                    task_id=task_id,
                )
            else:
                if publish_ports and container_name:
                    logger.info(
                        f"[Executor] publish_ports={publish_ports}，"
                        f"绕过持久容器 {container_name}，使用临时容器"
                    )
                cmd = self._build_docker_run_cmd(tool_def, args, env, workdir, publish_ports)
                backend_label = "container-run"

        return await self._run_subprocess(
            tool, cmd, backend_label,
            timeout=effective_timeout,
            input_data=input_data,
            log_callback=log_callback,
            record_callback=record_callback,
            record_phase=record_phase,
            record_purpose=record_purpose,
            record_round=record_round,
            record_command=effective_record_command,
            record_runtime_command=record_runtime_command,
            stream_callback=stream_callback,
        )


    _CRASH_PATTERNS = (
        "No such container",
        "container is not running",
        "is not running",
    )

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
        record_callback: RecordCallback,
        record_phase: str = "",
        record_purpose: str = "",
        record_round: Optional[int] = None,
        record_command: Optional[str] = None,
        record_runtime_command: Optional[str] = None,
        input_data: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> ExecuteResult:
        tool_def = self._registry.get_or_default(tool)
        env_args: list[str] = []
        for k, v in (env or {}).items():
            env_args += ["-e", f"{k}={v}"]

        import shlex
        import base64 as _b64
        kali_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        path_args = ["-e", f"PATH={kali_path}"]
        lhost_val = os.getenv("LHOST", "")
        if lhost_val:
            path_args += ["-e", f"LHOST={lhost_val}"]

        cmd_parts = tool_def.command.split()

        if input_data:
            b64_script = _b64.b64encode(input_data.encode("utf-8")).decode("ascii")
            tool_cmd = shlex.join(cmd_parts + args)
            inner_cmd = f"echo '{b64_script}' | base64 -d | {tool_cmd}"
            cmd = (["docker", "exec", "-w", workdir]
                   + path_args + env_args
                   + [container_name, "bash", "-c", inner_cmd])
            effective_input = None
        else:
            inner_cmd = shlex.join(cmd_parts + args)
            cmd = (["docker", "exec", "-w", workdir]
                   + path_args + env_args
                   + [container_name, "bash", "-c", inner_cmd])
            effective_input = None

        runtime_display_cmd = " ".join(
            ["docker", "exec", "-w", workdir] + path_args + env_args + [container_name] + cmd_parts + args
        ).strip()

        display_tool = _infer_display_tool(
            tool, script_or_command=record_command or "", purpose=record_purpose or "",
        )
        log_msg = f"🔧 {display_tool} [exec→{container_name[:20]}]: {runtime_display_cmd}"
        logger.info(f"[Executor] {log_msg}")
        if log_callback:
            try: await log_callback(log_msg)
            except Exception: pass

        result = await self._run_subprocess(
            tool, cmd, "container-exec",
            timeout=timeout, input_data=effective_input, log_callback=log_callback,
            record_callback=record_callback,
            record_phase=record_phase,
            record_purpose=record_purpose,
            record_round=record_round,
            record_command=record_command,
            record_runtime_command=record_runtime_command or runtime_display_cmd,
        )

        if not result.success and task_id:
            stderr_lower = result.stderr.lower()
            if any(p.lower() in stderr_lower for p in self._CRASH_PATTERNS):
                logger.warning(
                    f"[Executor] 容器 {container_name[:20]} 已退出，尝试重启并重试"
                )
                try:
                    new_name = await TaskContainerManager.start(task_id)
                    # rebuild cmd with the new container name
                    retry_cmd = [new_name if a == container_name else a for a in cmd]
                    retry_display = (record_runtime_command or runtime_display_cmd).replace(
                        container_name, new_name
                    )
                    if log_callback:
                        try:
                            await log_callback(f"🔄 容器已重启 {new_name[:20]}，重试命令...")
                        except Exception:
                            pass
                    result = await self._run_subprocess(
                        tool, retry_cmd, "container-exec",
                        timeout=timeout, input_data=effective_input,
                        log_callback=log_callback,
                        record_callback=record_callback,
                        record_phase=record_phase,
                        record_purpose=record_purpose,
                        record_round=record_round,
                        record_command=record_command,
                        record_runtime_command=retry_display,
                    )
                    result.container_crashed = True
                except Exception as e:
                    logger.error(f"[Executor] 容器重启失败: {e}")

        return result


    def _build_docker_run_cmd(self, tool_def, args, env, workdir, publish_ports=None) -> list[str]:
        docker_cmd = [
            "docker", "run", "--rm", "-i",
            "--network", TOOLBOX_NETWORK,
            "-w", workdir,
            "-v", f"{DATA_VOLUME}:/data",
            "-v", f"{REPORTS_DIR}:/reports",
            "--privileged",
        ]
        if publish_ports:
            if TOOLBOX_NETWORK == "host":
                logger.info(
                    f"[Executor] TOOLBOX_NETWORK=host，跳过 publish_ports={publish_ports} 的 -p 参数"
                )
            else:
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


    async def _run_remote(
        self,
        tool,
        args,
        *,
        timeout,
        env,
        workdir,
        log_callback,
        task_id,
        record_callback: RecordCallback = None,
        record_phase: str = "",
        record_purpose: str = "",
        record_round: Optional[int] = None,
        record_command: Optional[str] = None,
        record_runtime_command: Optional[str] = None,
    ):
        await _remote_stub.execute(args, timeout=timeout, env=env, workdir=workdir, task_id=task_id)


    async def _run_subprocess(
        self,
        tool: str,
        cmd: list[str],
        backend_label: str,
        *,
        timeout: int,
        input_data: Optional[str],
        log_callback: LogCallback,
        record_callback: RecordCallback = None,
        record_phase: str = "",
        record_purpose: str = "",
        record_round: Optional[int] = None,
        record_command: Optional[str] = None,
        record_runtime_command: Optional[str] = None,
        stream_callback=None,
    ) -> ExecuteResult:
        cmd_display = " ".join(cmd)
        display_tool = _infer_display_tool(
            tool, script_or_command=record_command or "", purpose=record_purpose or "",
        )
        stream_id = f"{display_tool}-{uuid.uuid4().hex[:8]}"
        log_msg = f"🔧 执行 {display_tool} [{backend_label}]: {cmd_display}"
        logger.info(f"[Executor] {log_msg}")
        if log_callback:
            try: await log_callback(log_msg)
            except Exception: pass

        start = time.monotonic()
        try:
            use_streaming = (
                (stream_callback is not None or log_callback is not None)
                and input_data is None
            )

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            if use_streaming:
                stdout_lines: list[str] = []
                stderr_lines: list[str] = []

                # 窗口合并: 累计 ~40 行或 ~120ms (先到为准) 合并成一次推送,
                # 把高输出工具的逐行 log / tool_stream 事件压缩一个数量级。
                # 逐行仍写入 buffer (供最终结果汇总), 仅推送频率被合并。
                _MERGE_MAX_LINES = 40
                _MERGE_MAX_SECONDS = 0.12
                _pending_log: dict[str, list[str]] = {"stdout": [], "stderr": []}
                _pending_text: dict[str, list[str]] = {"stdout": [], "stderr": []}
                _pending_since: dict[str, float] = {"stdout": 0.0, "stderr": 0.0}

                async def _flush(kind: str):
                    log_batch = _pending_log[kind]
                    text_batch = _pending_text[kind]
                    if not log_batch and not text_batch:
                        return
                    if log_callback and log_batch:
                        try: await log_callback("\n".join(log_batch))
                        except Exception: pass
                    if stream_callback and text_batch:
                        try:
                            await stream_callback({
                                "tool": tool, "display_tool": display_tool,
                                "kind": kind, "line": "\n".join(text_batch),
                                "stream_id": stream_id,
                            })
                        except Exception: pass
                    _pending_log[kind] = []
                    _pending_text[kind] = []
                    _pending_since[kind] = 0.0

                async def _pump(stream, kind: str, buffer: list[str]):
                    while True:
                        line = await stream.readline()
                        if not line:
                            break
                        text = line.decode("utf-8", errors="replace").rstrip("\n")
                        buffer.append(text)
                        if not _pending_log[kind] and not _pending_text[kind]:
                            _pending_since[kind] = time.monotonic()
                        if log_callback:
                            _pending_log[kind].append(f"[{kind}] {text}")
                        if stream_callback:
                            _pending_text[kind].append(text)
                        pend = max(len(_pending_log[kind]), len(_pending_text[kind]))
                        if (pend >= _MERGE_MAX_LINES
                                or time.monotonic() - _pending_since[kind] >= _MERGE_MAX_SECONDS):
                            await _flush(kind)
                    # 该流 EOF: flush 残留, 不丢尾部行
                    await _flush(kind)

                try:
                    await asyncio.wait_for(
                        asyncio.gather(
                            _pump(proc.stdout, "stdout", stdout_lines),
                            _pump(proc.stderr, "stderr", stderr_lines),
                            proc.wait(),
                        ),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    # 超时: _pump 被取消, EOF flush 未执行, 这里补 flush 残留
                    await _flush("stdout")
                    await _flush("stderr")
                    elapsed = time.monotonic() - start
                    msg = f"⏰ {display_tool} 超时 ({timeout}s)"
                    logger.warning(f"[Executor] {msg}")
                    if log_callback:
                        try: await log_callback(msg)
                        except Exception: pass
                    await self._emit_record(
                        record_callback=record_callback,
                        record={
                            "id": uuid.uuid4().hex[:16],
                            "phase": record_phase or "",
                            "tool": tool, "display_tool": display_tool,
                            "backend": backend_label,
                            "round": record_round,
                            "purpose": record_purpose or "",
                            "timestamp": datetime.utcnow().isoformat(),
                            "command": record_command or "",
                            "runtime_command": record_runtime_command or cmd_display,
                            "stdout": "\n".join(stdout_lines),
                            "stderr": f"执行超时（{timeout}秒）\n" + "\n".join(stderr_lines),
                            "exit_code": -1,
                            "elapsed": round(elapsed, 3),
                            "truncated": False,
                            "timed_out": True,
                            "total_len": sum(len(l) for l in stdout_lines + stderr_lines),
                        },
                    )
                    return ExecuteResult(
                        success=False,
                        stdout="\n".join(stdout_lines),
                        stderr=f"执行超时（{timeout}秒）",
                        exit_code=-1, elapsed=elapsed,
                        command=" ".join(cmd), tool_name=tool, backend=backend_label,
                        timed_out=True,
                    )
                except Exception:
                    # 其它流式异常: 先 flush 残留再抛给外层统一处理, 不丢尾部行
                    try:
                        await _flush("stdout")
                        await _flush("stderr")
                    except Exception:
                        pass
                    raise

                stdout = "\n".join(stdout_lines)
                stderr = "\n".join(stderr_lines)
                elapsed = time.monotonic() - start
                exit_code = proc.returncode or 0
            else:
                stdin_bytes = input_data.encode() if input_data else None
                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(input=stdin_bytes), timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    elapsed = time.monotonic() - start
                    msg = f"⏰ {display_tool} 超时 ({timeout}s)"
                    logger.warning(f"[Executor] {msg}")
                    if log_callback:
                        try: await log_callback(msg)
                        except Exception: pass
                    await self._emit_record(
                        record_callback=record_callback,
                        record={
                            "id": uuid.uuid4().hex[:16],
                            "phase": record_phase or "",
                            "tool": tool, "display_tool": display_tool,
                            "backend": backend_label,
                            "round": record_round,
                            "purpose": record_purpose or "",
                            "timestamp": datetime.utcnow().isoformat(),
                            "command": record_command or "",
                            "runtime_command": record_runtime_command or cmd_display,
                            "stdout": "",
                            "stderr": f"执行超时（{timeout}秒）",
                            "exit_code": -1,
                            "elapsed": round(elapsed, 3),
                            "truncated": False,
                            "timed_out": True,
                            "total_len": len(f"执行超时（{timeout}秒）"),
                        },
                    )
                    return ExecuteResult(
                        success=False, stdout="", stderr=f"执行超时（{timeout}秒）",
                        exit_code=-1, elapsed=elapsed,
                        command=" ".join(cmd), tool_name=tool, backend=backend_label,
                        timed_out=True,
                    )

                elapsed = time.monotonic() - start
                exit_code = proc.returncode or 0
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")

            success = exit_code == 0 or len(stdout.strip()) > 0

            status = "✅" if success else "❌"
            log_msg = f"{status} {display_tool} 完成: exit={exit_code}, 输出={len(stdout)}B, 耗时={elapsed:.1f}s"
            logger.info(f"[Executor] {log_msg}")
            if log_callback:
                try: await log_callback(log_msg)
                except Exception: pass
            await self._emit_record(
                record_callback=record_callback,
                record={
                    "id": uuid.uuid4().hex[:16],
                    "phase": record_phase or "",
                    "tool": tool,
                    "display_tool": display_tool,
                    "backend": backend_label,
                    "round": record_round,
                    "purpose": record_purpose or "",
                    "timestamp": datetime.utcnow().isoformat(),
                    "command": record_command or "",
                    "runtime_command": record_runtime_command or cmd_display,
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                    "elapsed": round(elapsed, 3),
                    "truncated": False,
                    "total_len": len(stdout) + len(stderr),
                },
            )

            return ExecuteResult(
                success=success, stdout=stdout, stderr=stderr,
                exit_code=exit_code, elapsed=elapsed,
                command=" ".join(cmd), tool_name=tool, backend=backend_label,
            )

        except FileNotFoundError:
            elapsed = time.monotonic() - start
            msg = f"命令未找到: {cmd[0]}"
            logger.error(f"[Executor] {msg}")
            await self._emit_record(
                record_callback=record_callback,
                record={
                    "id": uuid.uuid4().hex[:16],
                    "phase": record_phase or "",
                    "tool": tool,
                    "display_tool": display_tool,
                    "backend": backend_label,
                    "round": record_round,
                    "purpose": record_purpose or "",
                    "timestamp": datetime.utcnow().isoformat(),
                    "command": record_command or "",
                    "runtime_command": record_runtime_command or cmd_display,
                    "stdout": "",
                    "stderr": msg,
                    "exit_code": 127,
                    "elapsed": round(elapsed, 3),
                    "truncated": False,
                    "total_len": len(msg),
                },
            )
            return ExecuteResult(
                success=False, stdout="", stderr=msg, exit_code=127,
                elapsed=elapsed, command=" ".join(cmd), tool_name=tool, backend=backend_label,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.error(f"[Executor] 未预期异常: {e}")
            err = str(e)
            await self._emit_record(
                record_callback=record_callback,
                record={
                    "id": uuid.uuid4().hex[:16],
                    "phase": record_phase or "",
                    "tool": tool,
                    "display_tool": display_tool,
                    "backend": backend_label,
                    "round": record_round,
                    "purpose": record_purpose or "",
                    "timestamp": datetime.utcnow().isoformat(),
                    "command": record_command or "",
                    "runtime_command": record_runtime_command or cmd_display,
                    "stdout": "",
                    "stderr": err,
                    "exit_code": -1,
                    "elapsed": round(elapsed, 3),
                    "truncated": False,
                    "total_len": len(err),
                },
            )
            return ExecuteResult(
                success=False, stdout="", stderr=err, exit_code=-1,
                elapsed=elapsed, command=" ".join(cmd), tool_name=tool, backend=backend_label,
            )

    async def run_script(
        self,
        script_content: str,
        timeout: int = 60,
        shell: str = "/bin/bash",
        log_callback: LogCallback = None,
        record_callback: RecordCallback = None,
        record_phase: str = "",
        record_purpose: str = "",
        record_round: Optional[int] = None,
        record_runtime_command: Optional[str] = None,
        publish_ports: list[int] | None = None,
        task_id: Optional[str] = None,
        stream_callback=None,
    ) -> ExecuteResult:
        """执行 shell 脚本片段

        Args:
            publish_ports: 需要映射到宿主机的端口列表（用于反连回调）
            task_id: 任务 ID，传入后命令在持久容器中执行（保留进程状态）
            stream_callback: optional async callback for line-by-line output streaming
        """
        return await self.run(
            tool=shell, args=["-s"], timeout=timeout,
            input_data=script_content, log_callback=log_callback,
            record_callback=record_callback,
            record_phase=record_phase,
            record_purpose=record_purpose,
            record_round=record_round,
            record_command=script_content,
            record_runtime_command=record_runtime_command,
            publish_ports=publish_ports,
            stream_callback=stream_callback,
            task_id=task_id,
        )

    @staticmethod
    async def _emit_record(*, record_callback: RecordCallback, record: dict) -> None:
        try:
            get_collector().collect_tool_exec(
                tool_name=record.get("display_tool") or record.get("tool", ""),
                phase=record.get("phase", ""),
                success=record.get("exit_code", -1) == 0,
                elapsed=float(record.get("elapsed", 0) or 0),
                timed_out=bool(record.get("timed_out", False)),
            )
        except Exception:
            pass
        if not record_callback:
            return
        try:
            await record_callback(record)
        except Exception:
            pass


    async def start_task_container(self, task_id: str) -> str:
        """task 开始时调用，启动专属持久容器。"""
        return await TaskContainerManager.start(task_id)

    async def stop_task_container(self, task_id: str) -> None:
        """task 结束时调用，清理容器。"""
        await TaskContainerManager.stop(task_id)


class CallbackExecutorProxy:
    """Thin proxy that injects per-task log/record callbacks into every executor call.

    Instead of monkey-patching ``executor.run`` (which mutates a potentially
    shared object), callers create a short-lived proxy per task invocation.
    The proxy delegates to the real ``ToolExecutor`` while merging in the
    callbacks, making concurrent usage safe.
    """

    def __init__(
        self,
        executor: ToolExecutor,
        log_callback: LogCallback = None,
        record_callback: RecordCallback = None,
        record_phase: str = "",
    ):
        self._inner = executor
        self._log_cb = log_callback
        self._record_cb = record_callback
        self._record_phase = record_phase

    @property
    def registry(self) -> ToolRegistry:
        return self._inner.registry

    async def run(self, *args, **kwargs):
        if self._log_cb:
            kwargs.setdefault("log_callback", self._log_cb)
        if self._record_cb:
            kwargs.setdefault("record_callback", self._record_cb)
            kwargs.setdefault("record_phase", self._record_phase)
        return await self._inner.run(*args, **kwargs)

    async def run_script(self, *args, **kwargs):
        if self._log_cb:
            kwargs.setdefault("log_callback", self._log_cb)
        if self._record_cb:
            kwargs.setdefault("record_callback", self._record_cb)
            kwargs.setdefault("record_phase", self._record_phase)
        return await self._inner.run_script(*args, **kwargs)

    async def start_task_container(self, task_id: str) -> str:
        return await self._inner.start_task_container(task_id)

    async def stop_task_container(self, task_id: str) -> None:
        return await self._inner.stop_task_container(task_id)