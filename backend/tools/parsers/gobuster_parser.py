"""gobuster_parser.py —— 解析 Gobuster 目录爆破输出"""
from __future__ import annotations
import re


class GobusterParser:
    _LINE_RE = re.compile(r"^(/\S*)\s+\(Status:\s*(\d+)\)", re.MULTILINE)

    def parse(self, output: str) -> list[str]:
        """返回发现的路径列表（仅 2xx / 3xx 状态码）"""
        paths = []
        for match in self._LINE_RE.finditer(output):
            path, status = match.group(1), int(match.group(2))
            if 200 <= status < 400:
                paths.append(path)
        return paths
