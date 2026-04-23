"""
routers/admin_terminal.py — 管理员 SSH WebSocket 代理

提供 WebSocket /admin/terminal 端点，通过 asyncssh 建立到目标服务器的
SSH 隧道，在浏览器 xterm.js 和远端 PTY 之间双向转发数据流。
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/admin", tags=["admin-terminal"])
logger = logging.getLogger(__name__)


async def _verify_admin_ws(ws: WebSocket) -> dict | None:
    """从 WebSocket query 参数中验证 JWT 并确认 admin 角色。"""
    token = ws.query_params.get("token", "")
    if not token:
        return None
    from backend.api.deps import decode_jwt, get_current_user_role
    payload = decode_jwt(token)
    if not payload:
        return None
    user_id = payload.get("sub", "")
    role = await get_current_user_role(user_id)
    if role != "admin":
        return None
    return {"user_id": user_id, "username": payload.get("username", "")}


@router.websocket("/terminal")
async def admin_terminal_ws(ws: WebSocket):
    await ws.accept()

    admin = await _verify_admin_ws(ws)
    if not admin:
        await ws.send_json({"type": "error", "message": "需要管理员权限"})
        await ws.close(code=4003)
        return

    try:
        first_msg = await asyncio.wait_for(ws.receive_text(), timeout=30)
        params = json.loads(first_msg)
    except Exception:
        await ws.send_json({"type": "error", "message": "未收到连接参数"})
        await ws.close(code=4000)
        return

    host = params.get("host", "")
    port = int(params.get("port", 22))
    username = params.get("username", "root")
    password = params.get("password")
    private_key = params.get("private_key")

    if not host:
        await ws.send_json({"type": "error", "message": "host 不能为空"})
        await ws.close(code=4000)
        return

    start_time = time.time()
    try:
        import asyncssh
    except ImportError:
        await ws.send_json({"type": "error", "message": "asyncssh 未安装"})
        await ws.close(code=4000)
        return

    try:
        conn_kwargs: dict = {
            "host": host,
            "port": port,
            "username": username,
            "known_hosts": None,
        }
        if private_key:
            conn_kwargs["client_keys"] = [asyncssh.import_private_key(private_key)]
        elif password:
            conn_kwargs["password"] = password
        else:
            await ws.send_json({"type": "error", "message": "需要提供密码或私钥"})
            await ws.close(code=4000)
            return

        conn = await asyncssh.connect(**conn_kwargs)
    except Exception as e:
        await ws.send_json({"type": "error", "message": f"SSH 连接失败: {e}"})
        await ws.close(code=4000)
        return

    try:
        _audit_ssh(admin, host, port, "connected")
        process = await conn.create_process(
            term_type="xterm-256color",
            term_size=(120, 40),
        )
        await ws.send_json({"type": "connected", "message": f"已连接 {host}:{port}"})

        async def _read_ssh():
            try:
                while True:
                    data = await process.stdout.read(4096)
                    if not data:
                        break
                    await ws.send_text(data)
            except Exception:
                pass

        read_task = asyncio.create_task(_read_ssh())

        try:
            while True:
                msg = await ws.receive_text()
                if msg.startswith('{"type":"resize"'):
                    try:
                        resize = json.loads(msg)
                        process.change_terminal_size(
                            resize.get("cols", 120),
                            resize.get("rows", 40),
                        )
                    except Exception:
                        pass
                else:
                    process.stdin.write(msg)
        except WebSocketDisconnect:
            pass
        finally:
            read_task.cancel()
    finally:
        elapsed = int(time.time() - start_time)
        _audit_ssh(admin, host, port, "disconnected", elapsed)
        try:
            conn.close()
        except Exception:
            pass


def _audit_ssh(admin: dict, host: str, port: int, event: str, duration: int = 0):
    """异步记录 SSH 审计日志（fire-and-forget）。"""
    async def _write():
        try:
            from backend.db.database import append_audit_log
            await append_audit_log(
                owner_id=admin.get("user_id", ""),
                tenant_id="default",
                action=f"admin_ssh_{event}",
                resource_type="ssh",
                resource_key=f"{host}:{port}",
                detail={"duration_seconds": duration} if duration else {},
            )
        except Exception:
            pass
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_write())
    except RuntimeError:
        pass
