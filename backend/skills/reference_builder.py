"""
skills/reference_builder.py
Reference 文件生成工具 — 复用 builder.py 的 URL→LLM 抽取逻辑

用途：
  1. 从漏洞技术文档/博客 URL 抓取内容
  2. 调用 LLM 提取结构化利用知识
  3. 输出为 $skill/references/<vuln_id>.md（Markdown 格式）

与旧 builder.py 的区别：
  - 输出 Markdown 而非 JSON（直接供 _react_freeform 消费）
  - 输出到 skill 的 references/ 目录而非 kb_data/
  - 不再生成向量索引

使用方式：
  python -m backend.skills.reference_builder --skill shiro_rce
  python -m backend.skills.reference_builder --all
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent

LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-v4-flash")


@dataclass
class VulnSource:
    """一个漏洞的知识数据源"""
    vuln_id: str
    name: str
    skill_id: str = ""  # 对应的 skill_id
    urls: list[str] = field(default_factory=list)
    extra_context: str = ""
    fallback_content: str = ""


# 从 builder.py 导入预定义的漏洞数据源
def _load_sources_from_builder() -> list[VulnSource]:
    """从 builder.py 的 VULN_SOURCES 加载数据源定义。"""
    try:
        from backend.knowledge.builder import VULN_SOURCES as BUILDER_SOURCES
        sources = []
        for bs in BUILDER_SOURCES:
            sources.append(VulnSource(
                vuln_id=bs.vuln_id,
                name=bs.name,
                urls=list(bs.urls),
                extra_context=bs.extra_context,
                fallback_content=bs.fallback_content,
            ))
        return sources
    except ImportError:
        logger.warning("无法导入 builder.py，使用空数据源列表")
        return []


async def _fetch_url(client, url: str) -> str:
    """抓取单个 URL，返回文本内容"""
    try:
        resp = await client.get(url, follow_redirects=True, timeout=30)
        if resp.status_code == 200:
            text = resp.text.strip()
            logger.info(f"  ✅ {url} ({len(text)} chars)")
            return text
        else:
            logger.warning(f"  ❌ {url} -> HTTP {resp.status_code}")
            return ""
    except Exception as e:
        logger.warning(f"  ❌ {url} -> {e}")
        return ""


async def _fetch_all_sources(source: VulnSource) -> str:
    """抓取漏洞的所有数据源，合并为一个文本。"""
    import httpx

    parts = []

    if source.urls:
        async with httpx.AsyncClient(
            headers={"User-Agent": "Mozilla/5.0 PentestAI-RefBuilder/1.0"},
            verify=False,
        ) as client:
            for url in source.urls:
                text = await _fetch_url(client, url)
                if text:
                    parts.append(f"--- 来源: {url} ---\n{text}")

    if source.extra_context:
        parts.append(f"--- 人工补充信息 ---\n{source.extra_context}")

    combined = "\n\n".join(parts)

    if not combined.strip() and source.fallback_content:
        logger.info(f"  📦 所有URL失败，使用内嵌兜底内容")
        combined = f"--- 内嵌知识 ---\n{source.fallback_content}"
    elif not combined.strip():
        logger.warning(f"[{source.vuln_id}] 无任何内容来源")
        return ""

    if source.fallback_content and parts:
        combined += f"\n\n--- 补充信息（来自内嵌知识）---\n{source.fallback_content}"

    return combined


EXTRACT_PROMPT = """你是一名资深渗透测试工程师，请从以下漏洞资料中提取利用知识，输出为 Markdown 格式。

漏洞名称: {vuln_name}

原始资料:
{raw_content}

请输出结构化的 Markdown（不要用代码块包裹）：

## 漏洞概述
一句话描述漏洞原理和影响。

## 受影响版本
受影响的软件版本范围。

## 检测方法
如何检测漏洞是否存在（具体的请求和预期响应），包含可执行的 curl 命令。

## 利用步骤
### 步骤 1: xxx
- 命令: `可执行的完整命令`
- 预期结果: xxx
- 注意事项: xxx

### 步骤 2: xxx
...

## 验证命令
一条最简的验证命令。

## 常见 Payload 变体
列出不同的 payload 变体和绕过方式。

## 修复建议
如何修复此漏洞。

## 参考链接
原始 URL 列表。

【关键要求】:
1. 命令必须完整可执行，目标地址用 {{TARGET}} 占位
2. 提取资料中所有现成的 curl/PoC 命令
3. 对于需要目标回连的漏洞（JNDI/反弹shell），标注注意事项和替代方案
4. 尽可能多地提取有效 payload 变体"""


async def _extract_markdown(source: VulnSource, raw_content: str) -> Optional[str]:
    """调用 LLM 从原始内容提取 Markdown 格式的利用知识。"""
    if not raw_content.strip():
        logger.warning(f"[{source.vuln_id}] 无内容可提取")
        return None

    if not LLM_API_KEY:
        logger.error("LLM_API_KEY 未设置！")
        return None

    if len(raw_content) > 12000:
        raw_content = raw_content[:12000] + "\n\n... [内容过长已截断] ..."

    prompt = EXTRACT_PROMPT.format(
        vuln_name=source.name,
        raw_content=raw_content,
    )

    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(
            api_key=LLM_API_KEY,
            base_url=LLM_BASE_URL,
        )

        response = await client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "你是一名渗透测试知识库构建助手。从漏洞资料中提取利用知识，输出 Markdown。",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=4096,
        )

        content = response.choices[0].message.content or ""
        logger.info(f"  ✅ LLM提取成功: {len(content)} chars")
        return content

    except Exception as e:
        logger.error(f"  ❌ LLM调用失败: {e}")
        return None


def _find_skill_dir(skill_id: str) -> Optional[Path]:
    """查找 skill 对应的目录。"""
    for skill_yaml in SKILLS_DIR.rglob("skill.yaml"):
        try:
            import yaml
            with open(skill_yaml, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if raw and raw.get("skill_id") == skill_id:
                return skill_yaml.parent
        except Exception:
            continue
    return None


def _save_reference(skill_dir: Path, vuln_id: str, markdown: str) -> Path:
    """保存 reference 到 skill 的 references/ 目录。"""
    refs_dir = skill_dir / "references"
    refs_dir.mkdir(parents=True, exist_ok=True)
    filepath = refs_dir / f"{vuln_id}.md"
    filepath.write_text(markdown, encoding="utf-8")
    return filepath


async def build_one(source: VulnSource) -> bool:
    """为单个漏洞生成 reference 文件。"""
    logger.info(f"\n{'='*60}")
    logger.info(f"构建: {source.vuln_id} ({source.name})")
    logger.info(f"{'='*60}")

    # 查找 skill 目录
    skill_id = source.skill_id or source.vuln_id
    skill_dir = _find_skill_dir(skill_id)
    if not skill_dir:
        logger.error(f"❌ 未找到 skill 目录: {skill_id}")
        logger.info("   提示: 先确认 skill.yaml 的 skill_id 与 vuln_id 的映射关系")
        return False

    logger.info(f"📁 Skill 目录: {skill_dir}")

    # 抓取数据源
    logger.info("📥 抓取数据源...")
    raw_content = await _fetch_all_sources(source)
    if not raw_content:
        logger.error(f"❌ {source.vuln_id}: 无数据源内容")
        return False

    # LLM 提取
    logger.info("🤖 LLM 提取利用知识...")
    markdown = await _extract_markdown(source, raw_content)
    if not markdown:
        logger.error(f"❌ {source.vuln_id}: LLM提取失败")
        return False

    # 保存
    filepath = _save_reference(skill_dir, source.vuln_id, markdown)
    logger.info(f"💾 已保存: {filepath}")
    return True


async def build_all(sources: Optional[list[VulnSource]] = None) -> dict[str, bool]:
    """构建所有 reference 文件。"""
    sources = sources or _load_sources_from_builder()
    if not sources:
        logger.error("无数据源！请确保 builder.py 可导入")
        return {}

    results: dict[str, bool] = {}
    logger.info(f"🚀 开始构建 references: {len(sources)} 个漏洞")

    for source in sources:
        ok = await build_one(source)
        results[source.vuln_id] = ok
        if ok:
            await asyncio.sleep(1)

    success = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    logger.info(f"\n✅ 构建完成: {success} 成功, {failed} 失败")

    return results


async def build_single(vuln_id: str) -> bool:
    """构建单个指定的 reference。"""
    sources = _load_sources_from_builder()
    source = next((s for s in sources if s.vuln_id == vuln_id), None)
    if not source:
        logger.error(f"未找到数据源: {vuln_id}")
        return False
    return await build_one(source)


def migrate_kb_json_to_references() -> dict[str, bool]:
    """
    一次性迁移脚本：将 kb_data/*.json 转为对应 skill 的 references/*.md。

    映射逻辑：
      - 读取 JSON 中的 dispatch_skill 字段确定目标 skill
      - 从 JSON 各字段组装 Markdown
      - 写入 $skill/references/<vuln_id>.md
    """
    kb_data_dir = Path(__file__).parent.parent / "knowledge" / "kb_data"
    if not kb_data_dir.is_dir():
        logger.warning(f"kb_data 目录不存在: {kb_data_dir}")
        return {}

    import json
    results: dict[str, bool] = {}

    for json_path in sorted(kb_data_dir.glob("*.json")):
        vuln_id = json_path.stem
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"读取 JSON 失败 {json_path}: {e}")
            results[vuln_id] = False
            continue

        skill_id = data.get("dispatch_skill") or data.get("vuln_id", vuln_id)
        skill_dir = _find_skill_dir(skill_id)
        if not skill_dir:
            logger.warning(f"未找到 skill: {skill_id} (vuln_id={vuln_id}), 跳过")
            results[vuln_id] = False
            continue

        # 组装 Markdown
        md = _json_to_markdown(data)
        filepath = _save_reference(skill_dir, vuln_id, md)
        logger.info(f"迁移: {vuln_id} → {filepath}")
        results[vuln_id] = True

    success = sum(1 for v in results.values() if v)
    logger.info(f"迁移完成: {success}/{len(results)} 成功")
    return results


def _json_to_markdown(data: dict) -> str:
    """将 KB JSON 条目转为 Markdown。"""
    lines = []

    desc = data.get("description", "")
    if desc:
        lines.append(f"## 漏洞概述\n{desc}\n")

    versions = data.get("affected_versions", "")
    if versions:
        lines.append(f"## 受影响版本\n{versions}\n")

    detection = data.get("detection_method", "")
    if detection:
        lines.append(f"## 检测方法\n{detection}\n")

    steps = data.get("exploit_steps", [])
    if steps:
        lines.append("## 利用步骤\n")
        for s in steps:
            if isinstance(s, dict):
                step_no = s.get("step", "")
                desc_s = s.get("description", "")
                cmd = s.get("command", "")
                expected = s.get("expected_result", "")
                notes = s.get("notes", "")
                lines.append(f"### 步骤 {step_no}: {desc_s}")
                if cmd:
                    lines.append(f"- 命令: `{cmd}`")
                if expected:
                    lines.append(f"- 预期结果: {expected}")
                if notes:
                    lines.append(f"- 注意事项: {notes}")
                lines.append("")

    verify = data.get("verification_command", "")
    if verify:
        lines.append(f"## 验证命令\n`{verify}`\n")
        sign = data.get("verification_success_sign", "")
        if sign:
            lines.append(f"成功标志: {sign}\n")

    callback = data.get("requires_callback")
    if callback:
        note = data.get("callback_note", "需要目标回连攻击机")
        lines.append(f"## 回连注意\n⚠️ {note}\n")

    tags = data.get("tags", [])
    if tags:
        lines.append(f"## 标签\n{', '.join(tags)}\n")

    cves = data.get("cves", [])
    if cves:
        lines.append(f"## CVE\n{', '.join(cves)}\n")

    remediation = data.get("remediation", "")
    if remediation:
        lines.append(f"## 修复建议\n{remediation}\n")

    return "\n".join(lines)


def list_skills_without_references() -> list[str]:
    """列出所有没有 references/ 目录的 skill。"""
    missing = []
    for skill_yaml in SKILLS_DIR.rglob("skill.yaml"):
        skill_dir = skill_yaml.parent
        refs_dir = skill_dir / "references"
        if not refs_dir.is_dir() or not list(refs_dir.glob("*.md")):
            try:
                import yaml
                with open(skill_yaml, "r", encoding="utf-8") as f:
                    raw = yaml.safe_load(f)
                skill_id = raw.get("skill_id", skill_yaml.parent.name)
                missing.append(skill_id)
            except Exception:
                missing.append(skill_yaml.parent.name)
    return sorted(missing)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="PentestAI Skill Reference 构建器",
    )
    parser.add_argument(
        "--skill", "-s", type=str, default=None,
        help="为指定的 vuln_id 构建 reference",
    )
    parser.add_argument(
        "--all", "-a", action="store_true",
        help="构建所有 reference",
    )
    parser.add_argument(
        "--migrate", "-m", action="store_true",
        help="从 kb_data/*.json 迁移到 references/*.md",
    )
    parser.add_argument(
        "--list-missing", "-l", action="store_true",
        help="列出所有缺少 references 的 skill",
    )
    args = parser.parse_args()

    if args.list_missing:
        missing = list_skills_without_references()
        print(f"\n缺少 references 的 Skill ({len(missing)} 个):\n")
        for sid in missing:
            print(f"  - {sid}")
        return

    if args.migrate:
        migrate_kb_json_to_references()
        return

    if not LLM_API_KEY:
        print("❌ 请设置 LLM_API_KEY 环境变量")
        sys.exit(1)

    if args.skill:
        asyncio.run(build_single(args.skill))
    elif args.all:
        asyncio.run(build_all())
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
