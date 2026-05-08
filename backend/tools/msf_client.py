"""
msf_client.py
Metasploit Framework RPC 客户端

通过 msfrpcd 的 MessagePack over HTTP 接口与 MSF 通信，
避免启动 msfconsole 进程，更稳定、更可控。

依赖：
  pip install pymetasploit3

MSF RPC 启动方式（在 msf 容器内）：
  msfrpcd -P your_password -S -a 0.0.0.0 -p 55553
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

MSF_HOST = os.getenv("MSF_HOST", "127.0.0.1")
MSF_PORT = int(os.getenv("MSF_PORT", "55553"))
MSF_PASSWORD = os.getenv("MSF_PASSWORD", "your_msf_password")
MSF_SSL = os.getenv("MSF_SSL", "false").lower() == "true"

LHOST = os.getenv("LHOST", "")


@dataclass
class MsfModule:
    """MSF 模块配置"""
    module_path: str
    default_options: dict[str, str] = field(default_factory=dict)


class MsfClient:
    """
    Metasploit RPC 异步封装。

    核心方法：
      connect()            建立 RPC 连接
      execute_module()     执行 exploit/auxiliary 模块
      run_session_command()在已有 session 中执行命令
      get_session_info()   获取 session 详情
      list_sessions()      列出所有活跃 session
    """

    def __init__(self):
        self._client = None
        self._connected = False
        self._job_poll_interval = 2

    async def connect(self) -> None:
        """连接到 MSF RPC 服务（同步操作包装为 async）"""
        if self._connected:
            return

        await asyncio.get_event_loop().run_in_executor(None, self._sync_connect)

    def _sync_connect(self) -> None:
        """同步连接，在线程池内执行避免阻塞事件循环"""
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            self._client = MsfRpcClient(
                MSF_PASSWORD,
                server=MSF_HOST,
                port=MSF_PORT,
                ssl=MSF_SSL,
            )
            self._connected = True
            logger.info(f"[MsfClient] 已连接 MSF RPC: {MSF_HOST}:{MSF_PORT}")
        except ImportError:
            raise RuntimeError(
                "pymetasploit3 未安装，请执行: pip install pymetasploit3"
            )
        except Exception as e:
            self._connected = False
            raise RuntimeError(f"MSF RPC 连接失败: {e}") from e

    async def execute_module(
        self,
        module_path: str,
        options: dict[str, str],
        timeout: int = 60,
        module_type: str = "exploit",
    ) -> tuple[Optional[str], str]:
        """
        执行 MSF 模块。

        Args:
            module_path:  模块路径，如 exploit/multi/http/struts2_content_type_ognl
            options:      模块选项 {'RHOSTS': '...', 'RPORT': '...', 'PAYLOAD': '...'}
            timeout:      等待执行结果的最大秒数
            module_type:  exploit / auxiliary / post

        Returns:
            (session_id, output_text)
            session_id 为 None 表示未获得 shell，仅有 auxiliary 输出
        """
        if not self._connected:
            await self.connect()

        if LHOST and "PAYLOAD" in options and "reverse" in options.get("PAYLOAD", ""):
            options.setdefault("LHOST", LHOST)
            options.setdefault("LPORT", "4444")

        logger.info(f"[MsfClient] 执行模块: {module_path} | options={list(options.keys())}")

        return await asyncio.get_event_loop().run_in_executor(
            None,
            self._sync_execute,
            module_path,
            options,
            timeout,
            module_type,
        )

    def _sync_execute(
        self,
        module_path: str,
        options: dict[str, str],
        timeout: int,
        module_type: str,
    ) -> tuple[Optional[str], str]:
        """同步执行模块（在线程池内运行）"""
        try:
            if module_type == "exploit":
                mod = self._client.modules.use("exploit", module_path)
            elif module_type == "auxiliary":
                mod = self._client.modules.use("auxiliary", module_path)
            elif module_type == "post":
                mod = self._client.modules.use("post", module_path)
            else:
                return None, f"未知模块类型: {module_type}"

            for k, v in options.items():
                mod[k] = v

            result = mod.execute(payload=options.get("PAYLOAD", ""))
            if not isinstance(result, dict):
                result = {}
            job_id = result.get("job_id")
            uuid = result.get("uuid")

            output_lines: list[str] = []
            session_id: Optional[str] = None

            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(self._job_poll_interval)

                sessions = self._client.sessions.list
                for sid, sinfo in sessions.items():
                    if sinfo.get("via_exploit", "") in module_path:
                        session_id = str(sid)
                        output_lines.append(f"[+] 获得 Session {sid}: {sinfo}")
                        break

                if job_id and str(job_id) not in [str(j) for j in self._client.jobs.list]:
                    break

                if session_id:
                    break

            try:
                console_output = self._get_console_output(uuid)
                if console_output:
                    output_lines.append(console_output)
            except Exception:
                pass

            return session_id, "\n".join(output_lines)

        except Exception as e:
            logger.error(f"[MsfClient] 模块执行异常: {e}")
            return None, str(e)

    def _get_console_output(self, uuid: str) -> str:
        """通过 console API 获取执行输出"""
        try:
            console = self._client.consoles.console()
            console.write(f"jobs -i {uuid}\n")
            time.sleep(1)
            data = console.read()
            return data.get("data", "")
        except Exception:
            return ""

    async def run_session_command(
        self, session_id: str, command: str, timeout: int = 15
    ) -> str:
        """在已有 Meterpreter/Shell Session 中执行命令"""
        if not self._connected:
            await self.connect()

        return await asyncio.get_event_loop().run_in_executor(
            None,
            self._sync_run_command,
            session_id,
            command,
            timeout,
        )

    def _sync_run_command(
        self, session_id: str, command: str, timeout: int
    ) -> str:
        try:
            session = self._client.sessions.session(session_id)

            if hasattr(session, "run_with_output"):
                output = session.run_with_output(command, timeout=timeout)
                return output or ""

            session.write(command + "\n")
            time.sleep(min(timeout, 3))
            data = session.read()
            return data or ""

        except Exception as e:
            logger.error(f"[MsfClient] Session 命令执行失败: {e}")
            return f"命令执行失败: {e}"

    async def get_session_info(self, session_id: str) -> dict[str, Any]:
        """获取 Session 详细信息"""
        if not self._connected:
            await self.connect()

        try:
            sessions = self._client.sessions.list
            info = sessions.get(int(session_id), sessions.get(session_id, {}))
            return {
                "session_id": session_id,
                "type": info.get("type", "unknown"),
                "tunnel_peer": info.get("tunnel_peer", ""),
                "via_exploit": info.get("via_exploit", ""),
                "platform": info.get("platform", ""),
                "privilege": "root" if info.get("info", "").startswith("root") else "user",
                "raw": info,
            }
        except Exception as e:
            return {"session_id": session_id, "error": str(e)}

    async def list_sessions(self) -> dict[str, Any]:
        """列出所有活跃 Session"""
        if not self._connected:
            await self.connect()

        try:
            return self._client.sessions.list
        except Exception:
            return {}

    async def kill_session(self, session_id: str) -> bool:
        """关闭指定 Session"""
        if not self._connected:
            await self.connect()

        try:
            self._client.sessions.session(session_id).stop()
            return True
        except Exception as e:
            logger.warning(f"[MsfClient] 关闭 Session 失败: {e}")
            return False

    def is_connected(self) -> bool:
        return self._connected