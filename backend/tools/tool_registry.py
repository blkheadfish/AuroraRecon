"""
tools/tool_registry.py
工具注册表 —— 从 YAML 文件加载工具定义

设计原则:
  - 新增工具只需添加 YAML 条目，不改代码
  - 运行时可通过 register() 动态注册
  - 未在注册表中的工具自动 fallback 到 container 执行
  - 多人扩展时只需改 executor 字段（local/container/remote）
"""
from __future__ import annotations

import logging
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
