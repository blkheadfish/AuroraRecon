from __future__ import annotations

import asyncio
import json
from pathlib import Path

from backend.db.database import init_db, upsert_tenant_asset


ROOT = Path(__file__).resolve().parents[2]
SKILLS_DIR = ROOT / "backend" / "skills"
KB_DIR = ROOT / "backend" / "knowledge" / "kb_data"


async def migrate_global_templates() -> None:
    await init_db()

    # Global skill templates
    for yaml_file in SKILLS_DIR.rglob("*.yaml"):
        skill_id = yaml_file.stem
        content = yaml_file.read_text(encoding="utf-8")
        await upsert_tenant_asset(
            asset_type="skill",
            asset_key=skill_id,
            layer="global_template",
            owner_id="",
            tenant_id="default",
            content=json.dumps({"skill_id": skill_id, "yaml": content}, ensure_ascii=False),
        )

    # Global KB raw templates
    if KB_DIR.exists():
        for kb_file in KB_DIR.glob("*.json"):
            vuln_id = kb_file.stem
            content = kb_file.read_text(encoding="utf-8")
            await upsert_tenant_asset(
                asset_type="knowledge_raw",
                asset_key=vuln_id,
                layer="global_template",
                owner_id="",
                tenant_id="default",
                content=json.dumps({"vuln_id": vuln_id, "json": content}, ensure_ascii=False),
            )

    # Global prompt template
    default_prompts = [
        {"id": "vuln", "name": "漏洞分析 Prompt", "version": "v1.4", "active": True, "content": "你是漏洞分析助手，请严格基于证据输出。"},
        {"id": "exploit", "name": "利用决策 Prompt", "version": "v1.7", "active": True, "content": "你是利用决策助手，优先输出可审计 payload。"},
        {"id": "report", "name": "报告生成 Prompt", "version": "v1.2", "active": True, "content": "你是安全报告助手，输出结构化修复建议。"},
    ]
    await upsert_tenant_asset(
        asset_type="prompt",
        asset_key="prompt.manage.v1",
        layer="global_template",
        owner_id="",
        tenant_id="default",
        content=json.dumps({"prompts": default_prompts}, ensure_ascii=False),
    )


if __name__ == "__main__":
    asyncio.run(migrate_global_templates())
    print("Bigbang asset migration completed.")
