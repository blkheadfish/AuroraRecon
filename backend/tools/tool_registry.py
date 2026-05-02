"""
tools/tool_registry.py
工具注册表 —— 从 YAML 文件加载工具定义

设计原则:
  - 新增工具只需添加 YAML 条目，不改代码
  - 运行时可通过 register() 动态注册
  - 未在注册表中的工具自动 fallback 到 container 执行
  - 多人扩展时只需改 executor 字段（local/container/remote）
  - YAML 变更后需重启或 trigger uvicorn reload 才能生效

Function Calling:
  - to_openai_tools(category, include_meta) → 生成 OpenAI function calling
    schema，让 LLM 直接返回 tool_calls 而非原始 shell 字符串。
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

DEFINITIONS_DIR = Path(__file__).parent / "definitions"


@dataclass
class ToolDefinition:
    """单个工具的定义"""
    name: str
    executor: str = "container"          # local | container | remote
    command: str = ""                     # 实际执行的命令（默认=name）
    category: str = "general"            # recon | vuln_scan | exploit | post_exploit | general
    timeout: int = 120                    # 默认超时秒数
    description: str = ""
    requires_ports: list[int] = field(default_factory=list)  # 多人时需要动态分配的端口


class ToolRegistry:
    """
    工具注册表。

    用法:
        registry = ToolRegistry()         # 自动从 definitions/ 加载
        tool = registry.get("nmap")       # 查询工具定义
        tools = registry.list_by_category("recon")  # 按分类查询
    """

    def __init__(self, auto_load: bool = True):
        self._tools: dict[str, ToolDefinition] = {}
        if auto_load:
            self._load_from_dir(DEFINITIONS_DIR)

    def _load_from_dir(self, dir_path: Path) -> None:
        """从目录加载所有 YAML 定义文件"""
        if not dir_path.exists():
            logger.warning(f"[ToolRegistry] 定义目录不存在: {dir_path}")
            return

        for yaml_file in sorted(dir_path.glob("*.yaml")):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    items = yaml.safe_load(f)
                if not isinstance(items, list):
                    continue
                for item in items:
                    td = ToolDefinition(
                        name=item["name"],
                        executor=item.get("executor", "container"),
                        command=item.get("command", item["name"]),
                        category=item.get("category", "general"),
                        timeout=item.get("timeout", 120),
                        description=item.get("description", ""),
                        requires_ports=item.get("requires_ports", []),
                    )
                    self._tools[td.name] = td
            except Exception as e:
                logger.warning(f"[ToolRegistry] 加载失败 {yaml_file.name}: {e}")

        logger.info(f"[ToolRegistry] 已加载 {len(self._tools)} 个工具定义")

    def register(self, tool: ToolDefinition) -> None:
        """运行时动态注册工具"""
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolDefinition]:
        """查询工具定义，未找到返回 None"""
        return self._tools.get(name)

    def get_or_default(self, name: str) -> ToolDefinition:
        """查询工具定义，未找到返回默认 container 定义"""
        return self._tools.get(name, ToolDefinition(
            name=name, executor="container", command=name,
        ))

    def list_by_category(self, category: str) -> list[ToolDefinition]:
        return [t for t in self._tools.values() if t.category == category]

    def list_all(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    @property
    def size(self) -> int:
        return len(self._tools)

    def summary(self) -> dict[str, int]:
        """按分类统计工具数量"""
        counts: dict[str, int] = {}
        for t in self._tools.values():
            counts[t.category] = counts.get(t.category, 0) + 1
        return counts

    # ── Function Calling Schema ────────────────────────

    def to_openai_tools(
        self,
        *,
        categories: Optional[list[str]] = None,
        include_meta: bool = True,
        max_tools: int = 64,
    ) -> list[dict]:
        """
        将注册的工具转成 OpenAI function calling schema 列表。

        参数:
          categories: 仅导出指定 category 的工具（None=全部）
          include_meta: 是否附带通用 meta 工具（run_shell / http_request）
          max_tools: 防止 schema 过长导致 LLM 拒绝调用 — 超过则只挑高频常用

        每个工具的参数统一约定：
          - 默认所有工具暴露一个 ``args`` 字符串参数（命令行参数串），
            执行时拼成 ``<command> <args>`` 直接走 ``executor.run_script``。
          - 极少数高频工具（curl）有专用 schema（http_request meta 工具）。

        返回的 list 可直接传给 OpenAI Chat Completions 的 ``tools`` 字段：

            tools = registry.to_openai_tools(categories=["exploit", "recon"])
            response = await client.chat.completions.create(
                model=..., messages=..., tools=tools, tool_choice="auto",
            )
        """
        cat_filter = set(categories) if categories else None
        tools: list[dict] = []

        # 出现频次高的工具优先（避免 schema 超长）
        priority_names = {
            "curl", "wget", "nmap", "gobuster", "ffuf", "sqlmap", "nuclei",
            "hydra", "ncrack", "whatweb", "httpx", "wpscan", "msfconsole",
            "metasploit", "john", "hashcat",
        }

        candidates = list(self._tools.values())
        candidates.sort(
            key=lambda t: (
                0 if t.name in priority_names else 1,
                t.category,
                t.name,
            )
        )

        for tool in candidates:
            if cat_filter and tool.category not in cat_filter:
                continue
            tools.append(self._tool_to_openai_function(tool))
            if len(tools) >= max_tools - (3 if include_meta else 0):
                break

        if include_meta:
            tools.extend(_meta_tool_schemas())

        return tools

    @staticmethod
    def _tool_to_openai_function(tool: ToolDefinition) -> dict:
        """单个 ToolDefinition → OpenAI function schema。"""
        # OpenAI 要求 function name 满足 ^[a-zA-Z0-9_-]+$，长度 ≤ 64
        name = re.sub(r"[^A-Za-z0-9_\-]", "_", tool.name)[:64]
        desc = tool.description or f"{tool.name} command"
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": (
                    f"{desc}\n"
                    f"category={tool.category}, timeout_default={tool.timeout}s"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "args": {
                            "type": "string",
                            "description": (
                                "命令行参数串（不含命令名本身），例如 nmap 工具传 "
                                "'-sV -p 80,443 10.0.0.1'。如果一条参数里有空格请用 "
                                "shell quoting。"
                            ),
                        },
                        "purpose": {
                            "type": "string",
                            "description": "执行目的的简短描述（中文/英文均可）",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": (
                                f"覆盖默认超时秒数（默认 {tool.timeout}s，"
                                f"长耗时工具如 hydra/john 才需要调高）"
                            ),
                        },
                    },
                    "required": ["args"],
                },
            },
        }


def _meta_tool_schemas() -> list[dict]:
    """两个通用 meta 工具：任意 shell 与结构化 http_request。"""
    return [
        {
            "type": "function",
            "function": {
                "name": "run_shell",
                "description": (
                    "执行任意 bash 脚本（多行、管道、重定向都行）。"
                    "当需要复合命令、变量替换、循环时使用——优先使用具体工具，只有它们表达不了时才回落到 run_shell。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "script": {
                            "type": "string",
                            "description": "完整 bash 脚本片段。第一行通常是 set +e 等。",
                        },
                        "purpose": {
                            "type": "string",
                            "description": "执行目的的简短描述",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "覆盖默认超时秒数（默认 60s）",
                        },
                    },
                    "required": ["script"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "http_request",
                "description": (
                    "发起 HTTP/HTTPS 请求（curl 包装）。"
                    "Web 漏洞利用、payload 投递、回显验证的首选工具——比直接写 curl 更稳。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "完整 URL，例如 http://10.0.0.5:8080/api?x=1",
                        },
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
                            "description": "HTTP 方法，默认 GET",
                        },
                        "headers": {
                            "type": "object",
                            "description": "请求头字典，例如 {\"Content-Type\": \"application/json\"}",
                            "additionalProperties": {"type": "string"},
                        },
                        "body": {
                            "type": "string",
                            "description": "请求体（POST/PUT/PATCH 用）",
                        },
                        "follow_redirects": {
                            "type": "boolean",
                            "description": "是否跟随 3xx 重定向（默认 false）",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "请求超时秒数（默认 15）",
                        },
                        "purpose": {
                            "type": "string",
                            "description": "执行目的的简短描述",
                        },
                    },
                    "required": ["url"],
                },
            },
        },
    ]
