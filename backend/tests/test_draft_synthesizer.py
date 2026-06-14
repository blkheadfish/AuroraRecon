"""Skill 草案沉淀单元测试。

验证：
  1. generate_draft_yaml 从成功 exploit 生成结构正确的 YAML；
  2. 草案文件名用 .skill.yaml.draft 双保险后缀；
  3. 草案写入 .drafts/ 目录；
  4. list_drafts / get_draft / promote_draft / delete_draft 流程；
  5. loader 不加载 .drafts/ 目录（_SKIP_DIRS 含 .drafts）；
  6. 空或无命令的 result 不生成草案。
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from backend.agents.models import VulnFinding, ExploitResult, CommandExecutionRecord
from backend.skills.draft_synthesizer import (
    generate_draft_yaml,
    write_draft,
    list_drafts,
    get_draft,
    promote_draft,
    delete_draft,
    DRAFTS_DIR,
    SKILLS_DIR,
)
from backend.skills.loader import _SKIP_DIRS, _should_skip_path


def _make_finding(
    name: str = "Test SQLi",
    cve: str = "CVE-2024-0001",
    vuln_id: str = "f-001",
    port: int = 80,
) -> VulnFinding:
    return VulnFinding(
        vuln_id=vuln_id,
        name=name,
        description="A test SQL injection vulnerability",
        cve=cve,
        port=port,
        severity="high",
    )


def _make_result(evidence: str = "uid=33(www-data)", commands: list | None = None) -> ExploitResult:
    cmds = commands if commands is not None else ["curl -X POST 'http://target/login' -d 'user=admin&pass=test'"]
    return ExploitResult(
        vuln_id="f-001",
        success=True,
        evidence=evidence,
        commands_run=cmds,
    )


class TestDraftGeneration:
    def test_generate_draft_produces_valid_yaml(self):
        finding = _make_finding()
        result = _make_result()
        yaml_str = generate_draft_yaml(finding, result, [], "task-123")

        assert yaml_str
        assert "skill_id:" in yaml_str
        assert "draft_" in yaml_str
        assert "status: draft" in yaml_str
        assert "source_task_id: task-123" in yaml_str
        assert "generated_at:" in yaml_str
        assert "exploit_paths:" in yaml_str

    def test_generate_draft_contains_steps_from_commands(self):
        finding = _make_finding()
        result = _make_result(
            commands=["curl http://x", "echo 'test'"],
        )
        yaml_str = generate_draft_yaml(finding, result, [], "task-abc")
        assert "step_1" in yaml_str
        assert "curl http://x" in yaml_str

    def test_empty_commands_returns_empty_string(self):
        finding = _make_finding()
        result = _make_result(commands=[])
        yaml_str = generate_draft_yaml(finding, result, [], "task-x")
        assert yaml_str == ""

    def test_generate_draft_infers_category(self):
        finding = _make_finding(name="SMBrce exploit", port=445)
        result = _make_result()
        yaml_str = generate_draft_yaml(finding, result, [], "task-1")
        assert "category: network" in yaml_str or "category: web_rce" in yaml_str


class TestWriteDraft:
    def test_write_and_list_drafts(self):
        finding = _make_finding()
        result = _make_result()
        yaml_str = generate_draft_yaml(finding, result, [], "task-write-test")
        assert yaml_str

        filepath = write_draft(yaml_str, "test_draft_write")
        assert filepath.exists()
        assert filepath.suffix == ".draft"
        assert ".skill.yaml" in filepath.name

        drafts = list_drafts()
        assert any(d["filename"] == filepath.name for d in drafts)

        # cleanup
        filepath.unlink()

    def test_get_draft_returns_correct_draft(self):
        finding = _make_finding()
        result = _make_result()
        yaml_str = generate_draft_yaml(finding, result, [], "task-get-test")
        skill_id = yaml_str.split("skill_id: ")[1].split("\n")[0].strip()

        filepath = write_draft(yaml_str, skill_id)
        draft = get_draft(skill_id)
        assert draft is not None
        assert draft["skill_id"] == skill_id

        filepath.unlink()

    def test_promote_moves_to_formal_dir(self):
        finding = _make_finding()
        result = _make_result()
        yaml_str = generate_draft_yaml(finding, result, [], "task-promote")
        skill_id = yaml_str.split("skill_id: ")[1].split("\n")[0].strip()

        filepath = write_draft(yaml_str, skill_id)
        dest = promote_draft(skill_id)
        assert dest is not None
        assert dest.exists()
        assert not filepath.exists()  # draft deleted

        # cleanup promoted skill
        import shutil
        if dest.parent.exists():
            shutil.rmtree(dest.parent, ignore_errors=True)

    def test_delete_draft_removes_file(self):
        finding = _make_finding()
        result = _make_result()
        yaml_str = generate_draft_yaml(finding, result, [], "task-delete")
        skill_id = yaml_str.split("skill_id: ")[1].split("\n")[0].strip()

        filepath = write_draft(yaml_str, skill_id)
        assert filepath.exists()
        assert delete_draft(skill_id)
        assert not filepath.exists()

    def test_delete_nonexistent_returns_false(self):
        assert delete_draft("nonexistent_draft_id") is False


class TestLoaderSkip:
    def test_drafts_directory_is_skipped_by_loader(self):
        assert ".drafts" in _SKIP_DIRS

    def test_should_skip_path_detects_drafts(self):
        draft_path = Path("/some/skills/.drafts/test.skill.yaml.draft")
        assert _should_skip_path(draft_path) is True

    def test_should_skip_path_does_not_skip_normal_skills(self):
        normal_path = Path("/some/skills/web_rce/lfi_rfi/skill.yaml")
        assert _should_skip_path(normal_path) is False


class TestDraftFilenameSafety:
    def test_draft_file_uses_dot_draft_suffix(self):
        finding = _make_finding()
        result = _make_result()
        yaml_str = generate_draft_yaml(finding, result, [], "task-suffix")
        skill_id = yaml_str.split("skill_id: ")[1].split("\n")[0].strip()

        filepath = write_draft(yaml_str, skill_id)
        assert filepath.name.endswith(".skill.yaml.draft")
        filepath.unlink()
