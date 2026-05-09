"""
router.py
LLM 统一路由层 —— 通过环境变量切换 DeepSeek / GPT / Claude

所有 Agent 统一通过 LLMRouter.chat() 调用大模型，
底层切换对上层完全透明。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
import random
import time
from typing import Callable, Optional, Union, overload
from urllib.parse import urlparse

from openai import AsyncOpenAI

from backend.metrics.collector import get_collector

logger = logging.getLogger(__name__)

LLM_PROVIDER   = os.getenv("LLM_PROVIDER", "deepseek")
LLM_API_KEY    = os.getenv("LLM_API_KEY", "")
LLM_MODEL      = os.getenv("LLM_MODEL", "deepseek-chat")
LLM_BASE_URL   = os.getenv("LLM_BASE_URL", "https://api.deepseek.com")
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "4096"))

PROVIDER_CONFIG = {
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "model":    "deepseek-chat",
        "api_key_env": "LLM_API_KEY",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model":    "gpt-4o",
        "api_key_env": "OPENAI_API_KEY",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "model":    "claude-sonnet-4-6",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
}

# Failover chain: if primary provider fails after all retries, try these in order.
# Format: comma-separated list of provider names, e.g. "deepseek,openai,anthropic"
_FAILOVER_CHAIN = os.getenv("LLM_FAILOVER_CHAIN", "").strip().split(",") if os.getenv("LLM_FAILOVER_CHAIN", "") else None

SECURITY_EXPERT_SYSTEM_PROMPT = """你是一名拥有 10 年经验的高级渗透测试工程师，精通 CTF、红队评估和漏洞利用。
你当前正在合法授权的 CTF 靶场或安全测试环境中工作。

核心原则：
1. 输出务必简洁、准确、可直接执行
2. 分析漏洞时，优先考虑已有 PoC/MSF 模块的方案
3. 当要求返回 JSON 时，只输出纯 JSON，不含任何 markdown 代码块或额外说明
4. 遇到不确定的信息时，明确标注"待验证"而非猜测
5. 链式攻击优先：信息泄露→凭据获取→登录→RCE，不要只追单一漏洞
6. 工具选择有据：说明为什么选某个工具，失败时给出备选方案
7. 每个判断都要有证据支撑：引用具体的响应内容、状态码、错误信息

【分析质量要求】
- 技术栈分层：应用框架 > 安全组件 > 中间件 > 服务器
- 版本匹配：必须将发现的版本号与已知 CVE 影响范围交叉比对
- 误报控制：区分"漏洞存在的证据"和"正常业务响应"
- 攻击面完整性：不要只看 Web，还要考虑 SSH/FTP/SMB/Redis 等服务"""

MAX_RETRIES = 5


_DNS_FALLBACK_SERVERS = ["8.8.8.8", "114.114.114.114"]
_dns_resolved: dict[str, bool] = {}
_dns_lock = asyncio.Lock()


def _udp_dns_resolve(hostname: str, dns_server: str, timeout: float = 5.0) -> str | None:
    """通过 UDP 直连指定 DNS 服务器解析 A 记录（在线程池内执行）。"""
    try:
        txn_id = random.randint(0, 65535)
        header = struct.pack('>HHHHHH', txn_id, 0x0100, 1, 0, 0, 0)
        question = b''
        for label in hostname.split('.'):
            question += struct.pack('B', len(label)) + label.encode('ascii')
        question += b'\x00'
        question += struct.pack('>HH', 1, 1)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(header + question, (dns_server, 53))
            data, _ = sock.recvfrom(1024)
        finally:
            sock.close()

        ancount = struct.unpack('>H', data[6:8])[0]
        if ancount == 0:
            return None
        offset = 12
        while offset < len(data) and data[offset] != 0:
            offset += data[offset] + 1
        offset += 5
        for _ in range(ancount):
            if offset + 2 > len(data):
                break
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1
            if offset + 10 > len(data):
                break
            rtype, _, _, rdlength = struct.unpack('>HHIH', data[offset:offset + 10])
            offset += 10
            if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
                return '.'.join(str(b) for b in data[offset:offset + 4])
            offset += rdlength
    except Exception as e:
        logger.debug(f"[DNS] UDP 解析 {hostname} via {dns_server} 失败: {e}")
    return None


async def _ensure_host_resolvable_async(url: str) -> None:
    """异步 DNS 兜底：系统 DNS 失败后用公共 DNS，在线程池执行，不阻塞事件循环。"""
    hostname = urlparse(url).hostname
    if not hostname or _dns_resolved.get(hostname):
        return

    async with _dns_lock:
        if _dns_resolved.get(hostname):
            return

        try:
            await asyncio.to_thread(socket.getaddrinfo, hostname, 443, socket.AF_INET)
            _dns_resolved[hostname] = True
            return
        except socket.gaierror:
            logger.warning(f"[DNS] 系统解析 {hostname} 失败，尝试公共 DNS 直连解析...")

        for dns_server in _DNS_FALLBACK_SERVERS:
            try:
                ip = await asyncio.to_thread(_udp_dns_resolve, hostname, dns_server)
                if ip:
                    logger.info(f"[DNS] 通过 {dns_server} 解析 {hostname} → {ip}")
                    try:
                        with open('/etc/hosts', 'r') as f:
                            content = f.read()
                        if hostname not in content:
                            with open('/etc/hosts', 'a') as f:
                                f.write(f"{ip}\t{hostname}\n")
                            logger.info(f"[DNS] 已写入 /etc/hosts: {ip} {hostname}")
                    except OSError as e:
                        logger.warning(f"[DNS] 写入 /etc/hosts 失败: {e}")
                    _dns_resolved[hostname] = True
                    return
            except Exception as e:
                logger.debug(f"[DNS] UDP {hostname} via {dns_server}: {e}")

        logger.error(f"[DNS] 所有公共 DNS 均无法解析 {hostname}")
        _dns_resolved[hostname] = True


class LLMRouter:
    """
    LLM 统一调用接口。

    用法：
        llm = LLMRouter()
        response = await llm.chat("分析这个 nmap 输出...", response_format="json")
    """

    def __init__(self):
        import httpx as httpx_client

        primary = LLM_PROVIDER.lower()
        primary_config = PROVIDER_CONFIG.get(primary, PROVIDER_CONFIG["deepseek"])

        base_url = LLM_BASE_URL or primary_config["base_url"]
        model = LLM_MODEL or primary_config["model"]

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_ensure_host_resolvable_async(base_url))
        except RuntimeError:
            pass

        self._model = model
        self._active_provider = primary

        # Build failover chain: primary + backups from LLM_FAILOVER_CHAIN (no duplicates)
        chain = _FAILOVER_CHAIN or []
        self._provider_clients: list = []
        seen = {primary}
        for name in [primary] + [n.strip().lower() for n in chain if n.strip().lower() not in seen]:
            if name not in seen and name in PROVIDER_CONFIG:
                seen.add(name)
            else:
                continue
            cfg = PROVIDER_CONFIG[name]
            key = os.getenv(cfg["api_key_env"], "") or LLM_API_KEY
            url = cfg["base_url"]
            self._provider_clients.append((
                name, cfg["model"],
                AsyncOpenAI(
                    api_key=key, base_url=url, max_retries=0,
                    http_client=httpx_client.AsyncClient(
                        timeout=httpx_client.Timeout(
                            connect=30, read=120, write=30, pool=30,
                        ),
                    ),
                ),
            ))

        if not self._provider_clients:
            self._provider_clients = [(
                primary, model,
                AsyncOpenAI(
                    api_key=LLM_API_KEY, base_url=base_url, max_retries=0,
                    http_client=httpx_client.AsyncClient(
                        timeout=httpx_client.Timeout(
                            connect=30, read=120, write=30, pool=30,
                        ),
                    ),
                ),
            )]

        providers_str = ", ".join(f"{p}/{m}" for p, m, _ in self._provider_clients)
        logger.info(f"[LLMRouter] Providers: {providers_str} (active={self._active_provider}/{self._model})")

    def _get_active_client(self):
        return self._provider_clients[0] if self._provider_clients else (self._active_provider, self._model, None)

    async def _try_failover(self) -> bool:
        """Switch to next provider in failover chain. Returns False if exhausted."""
        if len(self._provider_clients) <= 1:
            return False
        old_provider, old_model, _ = self._provider_clients.pop(0)
        logger.warning(
            f"[LLMRouter] Provider {old_provider}/{old_model} exhausted, failing over. "
            f"Remaining: {len(self._provider_clients)}"
        )
        if self._provider_clients:
            new_name, new_model, _ = self._provider_clients[0]
            self._active_provider = new_name
            self._model = new_model
            logger.info(f"[LLMRouter] Switched to {new_name}/{new_model}")
            return True
        return False

    def _extract_usage(self, response):
        """Safely extract usage from an OpenAI response object."""
        try:
            return getattr(response, 'usage', None)
        except Exception:
            return None

    @staticmethod
    def _extract_reasoning(message) -> str:
        """Extract reasoning_content from DeepSeek response message (if present)."""
        rc = getattr(message, "reasoning_content", None)
        if rc:
            return str(rc)
        raw = getattr(message, "model_extra", None) or {}
        return str(raw.get("reasoning_content", "") or "")

    async def chat(
        self,
        user_message: str,
        system_prompt: Optional[str] = None,
        response_format: str = "text",
        temperature: float = 0.2,
        max_tokens: int = LLM_MAX_TOKENS,
        return_thinking: bool = False,
        phase: str = "",
        caller: str = "",
    ) -> Union[str, tuple[str, str]]:
        """
        发送消息并返回模型回复（带自动重试）。
        """
        start = time.monotonic()
        messages = [
            {
                "role": "system",
                "content": system_prompt or SECURITY_EXPERT_SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": user_message,
            },
        ]

        kwargs: dict = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if response_format == "json":
            kwargs["response_format"] = {"type": "json_object"}

        for attempt in range(MAX_RETRIES):
            try:
                response = await self._provider_clients[0][2].chat.completions.create(**kwargs)
                msg = response.choices[0].message
                content = msg.content or ""
                if not content.strip():
                    reasoning = self._extract_reasoning(msg)
                    if reasoning:
                        logger.debug(f"[LLMRouter] content 为空，回退到 reasoning_content ({len(reasoning)} chars)")
                        content = reasoning
                logger.debug(f"[LLMRouter] 响应长度: {len(content)} chars")
                get_collector().collect_llm_call(
                    phase=phase, method="chat",
                    duration_ms=(time.monotonic() - start) * 1000,
                    usage=getattr(response, "usage", None),
                    status="ok", caller=caller,
                    provider=self._active_provider, model=self._model,
                )
                if return_thinking:
                    return content, self._extract_reasoning(msg)
                return content

            except Exception as e:
                if attempt < MAX_RETRIES - 1:
                    wait = 2 * (attempt + 1)
                    logger.warning(
                        f"[LLMRouter] API 调用失败 (第{attempt + 1}次)，"
                        f"{wait}秒后重试: {e}"
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        f"[LLMRouter] API 调用失败 (已重试{MAX_RETRIES}次): {e}"
                    )
                    get_collector().collect_llm_call(
                        phase=phase, method="chat",
                        duration_ms=(time.monotonic() - start) * 1000,
                        status="error", caller=caller,
                        provider=self._active_provider, model=self._model,
                    )
                    fallback = json.dumps({"error": str(e), "targets": []}) if response_format == "json" else f"LLM 调用失败: {e}"
                    return (fallback, "") if return_thinking else fallback

        get_collector().collect_llm_call(
            phase=phase, method="chat",
            duration_ms=(time.monotonic() - start) * 1000,
            status="error", caller=caller,
            provider=self._active_provider, model=self._model,
        )
        fallback = json.dumps({"error": "unexpected", "targets": []}) if response_format == "json" else "LLM 调用失败: 未知错误"
        return (fallback, "") if return_thinking else fallback

    async def chat_multi_turn(
        self,
        messages: list[dict[str, str]],
        system_prompt: Optional[str] = None,
        response_format: str = "text",
        temperature: float = 0.2,
        max_tokens: int = LLM_MAX_TOKENS,
        return_thinking: bool = False,
        phase: str = "",
        caller: str = "",
    ) -> Union[str, tuple[str, str]]:
        """
        多轮对话接口 —— 传入完整 messages 历史。
        用于 ReAct 循环等需要保持对话上下文的场景。
        """
        start = time.monotonic()
        full_messages = [
            {
                "role": "system",
                "content": system_prompt or SECURITY_EXPERT_SYSTEM_PROMPT,
            },
            *messages,
        ]

        kwargs: dict = {
            "model": self._model,
            "messages": full_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if response_format == "json":
            kwargs["response_format"] = {"type": "json_object"}

        for attempt in range(MAX_RETRIES):
            try:
                response = await self._provider_clients[0][2].chat.completions.create(**kwargs)
                msg = response.choices[0].message
                content = msg.content or ""
                if not content.strip():
                    reasoning = self._extract_reasoning(msg)
                    if reasoning:
                        logger.debug(f"[LLMRouter] 多轮 content 为空，回退到 reasoning_content ({len(reasoning)} chars)")
                        content = reasoning
                logger.debug(
                    f"[LLMRouter] 多轮响应: {len(content)} chars, "
                    f"轮次={len(messages)}条消息"
                )
                get_collector().collect_llm_call(
                    phase=phase, method="multi_turn",
                    duration_ms=(time.monotonic() - start) * 1000,
                    usage=getattr(response, "usage", None),
                    status="ok", caller=caller,
                    provider=self._active_provider, model=self._model,
                )
                if return_thinking:
                    return content, self._extract_reasoning(msg)
                return content
            except Exception as e:
                if attempt < MAX_RETRIES - 1:
                    wait = 2 * (attempt + 1)
                    logger.warning(
                        f"[LLMRouter] 多轮调用失败 (第{attempt + 1}次)，"
                        f"{wait}秒后重试: {e}"
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        f"[LLMRouter] 多轮调用失败 (已重试{MAX_RETRIES}次): {e}"
                    )
                    get_collector().collect_llm_call(
                        phase=phase, method="multi_turn",
                        duration_ms=(time.monotonic() - start) * 1000,
                        status="error", caller=caller,
                        provider=self._active_provider, model=self._model,
                    )
                    fallback = json.dumps({"error": str(e), "action": "conclude_fail"}) if response_format == "json" else f"LLM 调用失败: {e}"
                    return (fallback, "") if return_thinking else fallback

        get_collector().collect_llm_call(
            phase=phase, method="multi_turn",
            duration_ms=(time.monotonic() - start) * 1000,
            status="error", caller=caller,
            provider=self._active_provider, model=self._model,
        )
        fallback = json.dumps({"error": "unexpected", "action": "conclude_fail"}) if response_format == "json" else "LLM 调用失败: 未知错误"
        return (fallback, "") if return_thinking else fallback

    async def chat_multi_turn_stream(
        self,
        messages: list[dict[str, str]],
        *,
        on_content_delta: Optional[Callable] = None,
        on_reasoning_delta: Optional[Callable] = None,
        system_prompt: Optional[str] = None,
        response_format: str = "text",
        temperature: float = 0.2,
        max_tokens: int = LLM_MAX_TOKENS,
        phase: str = "",
        caller: str = "",
    ) -> tuple[str, str]:
        """Streaming multi-turn chat with callbacks. Returns (content, reasoning)."""
        start = time.monotonic()
        if response_format == "json" and on_content_delta is not None:
            logger.debug(
                "[LLMRouter] chat_multi_turn_stream: dropping on_content_delta "
                "for json response_format (raw JSON would leak to UI)"
            )
            on_content_delta = None
        full_messages = [
            {"role": "system", "content": system_prompt or SECURITY_EXPERT_SYSTEM_PROMPT},
            *messages,
        ]
        kwargs: dict = {
            "model": self._model,
            "messages": full_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if response_format == "json":
            kwargs["response_format"] = {"type": "json_object"}

        content_parts: list[str] = []
        reasoning_parts: list[str] = []
        last_usage = None

        try:
            stream = await self._provider_clients[0][2].chat.completions.create(**kwargs)
            async for chunk in stream:
                usage = getattr(chunk, "usage", None)
                if usage:
                    last_usage = usage
                delta = chunk.choices[0].delta if chunk.choices else None
                if not delta:
                    continue
                if delta.content:
                    content_parts.append(delta.content)
                    if on_content_delta:
                        try:
                            await on_content_delta(delta.content)
                        except Exception:
                            pass
                rc = getattr(delta, "reasoning_content", None)
                if not rc:
                    extra = getattr(delta, "model_extra", None) or {}
                    rc = extra.get("reasoning_content")
                if rc:
                    reasoning_parts.append(rc)
                    if on_reasoning_delta:
                        try:
                            await on_reasoning_delta(rc)
                        except Exception:
                            pass
            get_collector().collect_llm_call(
                phase=phase, method="stream",
                duration_ms=(time.monotonic() - start) * 1000,
                usage=last_usage, status="ok", caller=caller,
                provider=self._active_provider, model=self._model,
            )
        except Exception as e:
            logger.error(f"[LLMRouter] multi-turn stream 失败: {e}")
            get_collector().collect_llm_call(
                phase=phase, method="stream",
                duration_ms=(time.monotonic() - start) * 1000,
                status="error", caller=caller,
                provider=self._active_provider, model=self._model,
            )
            fallback = json.dumps({"error": str(e), "action": "conclude_fail"}) if response_format == "json" else f"LLM stream error: {e}"
            return fallback, ""

        return "".join(content_parts), "".join(reasoning_parts)

    async def chat_multi_turn_with_tools(
        self,
        messages: list[dict],
        *,
        tools: list[dict],
        tool_choice: str = "auto",
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = LLM_MAX_TOKENS,
        phase: str = "",
        caller: str = "",
    ) -> tuple[str, list, str]:
        """
        多轮对话 + Function Calling。
        不流式，因为 OpenAI function calling 的 streaming chunk 拼接复杂。
        """
        start = time.monotonic()
        full_messages = [
            {"role": "system", "content": system_prompt or SECURITY_EXPERT_SYSTEM_PROMPT},
            *messages,
        ]
        kwargs: dict = {
            "model": self._model,
            "messages": full_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "tools": tools,
            "tool_choice": tool_choice,
        }

        for attempt in range(MAX_RETRIES):
            try:
                response = await self._provider_clients[0][2].chat.completions.create(**kwargs)
                msg = response.choices[0].message
                content = msg.content or ""
                tool_calls = list(getattr(msg, "tool_calls", None) or [])
                reasoning = self._extract_reasoning(msg)
                if not content.strip() and reasoning:
                    logger.debug(f"[LLMRouter] tools content 为空，回退到 reasoning_content ({len(reasoning)} chars)")
                    content = reasoning
                logger.debug(
                    f"[LLMRouter] tools 响应: content_len={len(content)}, "
                    f"tool_calls={len(tool_calls)}"
                )
                get_collector().collect_llm_call(
                    phase=phase, method="tools",
                    duration_ms=(time.monotonic() - start) * 1000,
                    usage=getattr(response, "usage", None),
                    status="ok", caller=caller,
                    provider=self._active_provider, model=self._model,
                )
                return content, tool_calls, reasoning
            except Exception as e:
                if attempt < MAX_RETRIES - 1:
                    wait = 2 * (attempt + 1)
                    logger.warning(
                        f"[LLMRouter] tools 调用失败 (第{attempt + 1}次)，{wait}秒后重试: {e}"
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(f"[LLMRouter] tools 调用失败 (重试{MAX_RETRIES}次): {e}")
                    get_collector().collect_llm_call(
                        phase=phase, method="tools",
                        duration_ms=(time.monotonic() - start) * 1000,
                        status="error", caller=caller,
                        provider=self._active_provider, model=self._model,
                    )
                    if await self._try_failover():
                        kwargs["model"] = self._model
                        continue
                    return "", [], ""

        get_collector().collect_llm_call(
            phase=phase, method="tools",
            duration_ms=(time.monotonic() - start) * 1000,
            status="error", caller=caller,
            provider=self._active_provider, model=self._model,
        )
        return "", [], ""

    async def chat_stream(
        self,
        user_message: str,
        system_prompt: Optional[str] = None,
        response_format: str = "text",
        temperature: float = 0.2,
        max_tokens: int = LLM_MAX_TOKENS,
    ):
        """
        Streaming version of chat(). Yields (kind, delta) tuples where
        kind is "content" or "reasoning".
        """
        messages = [
            {"role": "system", "content": system_prompt or SECURITY_EXPERT_SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]
        kwargs: dict = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        if response_format == "json":
            kwargs["response_format"] = {"type": "json_object"}

        try:
            stream = await self._provider_clients[0][2].chat.completions.create(**kwargs)
            async for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                if not delta:
                    continue
                if delta.content:
                    yield ("content", delta.content)
                rc = getattr(delta, "reasoning_content", None)
                if not rc:
                    extra = getattr(delta, "model_extra", None) or {}
                    rc = extra.get("reasoning_content")
                if rc:
                    yield ("reasoning", rc)
        except Exception as e:
            logger.error(f"[LLMRouter] stream 失败: {e}")
            yield ("content", f"[LLM stream error: {e}]")

    async def chat_with_stream_callback(
        self,
        user_message: str,
        *,
        on_content_delta: Optional[Callable] = None,
        on_reasoning_delta: Optional[Callable] = None,
        system_prompt: Optional[str] = None,
        response_format: str = "text",
        temperature: float = 0.2,
        max_tokens: int = LLM_MAX_TOKENS,
    ) -> tuple[str, str]:
        """
        Streaming chat that fires callbacks for each delta, then returns
        the full (content, reasoning) strings.
        """
        if response_format == "json" and on_content_delta is not None:
            logger.debug(
                "[LLMRouter] chat_with_stream_callback: dropping on_content_delta "
                "for json response_format"
            )
            on_content_delta = None
        content_parts: list[str] = []
        reasoning_parts: list[str] = []

        async for kind, delta in self.chat_stream(
            user_message,
            system_prompt=system_prompt,
            response_format=response_format,
            temperature=temperature,
            max_tokens=max_tokens,
        ):
            if kind == "content":
                content_parts.append(delta)
                if on_content_delta:
                    try:
                        await on_content_delta(delta)
                    except Exception:
                        pass
            elif kind == "reasoning":
                reasoning_parts.append(delta)
                if on_reasoning_delta:
                    try:
                        await on_reasoning_delta(delta)
                    except Exception:
                        pass

        return "".join(content_parts), "".join(reasoning_parts)

    async def analyze_scan_output(self, raw_output: str, tool_name: str) -> dict:
        """
        让 LLM 解读工具原始输出，提取关键信息。
        用于辅助 Parser 处理非结构化输出。
        """
        prompt = f"""以下是 {tool_name} 的原始输出，请提取关键安全信息，以 JSON 返回：

```
{raw_output[:3000]}
```

返回格式（纯 JSON，不含代码块）：
{{
  "open_ports": [80, 443, ...],
  "services": [{{"port": 80, "service": "http", "version": "..."}}],
  "potential_vulns": ["描述1", "描述2"],
  "os_hint": "linux/windows/unknown",
  "notes": "其他重要发现"
}}"""

        result = await self.chat(prompt, response_format="json")
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "JSON 解析失败", "raw": result}

    async def suggest_next_step(
        self,
        target: str,
        findings_summary: str,
        current_phase: str,
    ) -> str:
        """
        让 LLM 根据当前发现建议下一步操作（用于增强 Agent 决策）。
        """
        prompt = f"""当前渗透测试目标：{target}
当前阶段：{current_phase}
已发现内容：
{findings_summary}

请建议下一步最优行动方案（简洁，不超过 200 字）："""

        return await self.chat(prompt, temperature=0.3)