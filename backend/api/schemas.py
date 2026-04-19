"""
schemas.py —— 所有 API 请求/响应 Pydantic 模型
"""
from __future__ import annotations

import re
from typing import Literal, Optional

from pydantic import BaseModel, field_validator
from backend.agents.models import WorkflowMode, parse_target


# ── 任务相关 ──────────────────────────────────────────────

class CreateTaskRequest(BaseModel):
    """
    创建任务请求。

    workflow_mode 决定一组默认值(审批策略 / 证据门槛 / 风险预算 / 轮次
    上限 / Skill 匹配阈值);用户可以同时在 `auto_approve` / `success_gate_level`
    / `risk_budget` / `max_react_rounds` / `max_explore_rounds` 等字段上
    显式覆盖,缺省(None)则使用 mode 默认值。这些参数均为 per-task,
    不会写回全局环境变量。
    """

    target: str
    scope_note: str = "CTF/授权靶场测试"
    extra_hint: str = ""
    user_prompt: str = ""
    workflow_mode: WorkflowMode = "pentest_engineer"

    # 以下字段为可选覆盖项,不传则沿用 workflow_mode 的默认值
    auto_approve: Optional[bool] = None
    success_gate_level: Optional[Literal["strict", "medium", "lenient"]] = None
    risk_budget: Optional[int] = None
    max_react_rounds: Optional[int] = None
    max_explore_rounds: Optional[int] = None
    skill_min_score: Optional[int] = None
    skill_weak_boost: Optional[int] = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        raw = v.strip()
        if not raw:
            raise ValueError("目标地址不能为空")

        if re.search(r'[;\|`$&<>(){}\[\]!]', raw):
            raise ValueError("目标地址包含非法字符")

        parsed = parse_target(raw)

        if not parsed.host:
            raise ValueError("无法解析目标主机地址")

        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            raise ValueError(f"端口号超出范围: {parsed.port}")

        if parsed.scheme and parsed.scheme not in ("http", "https"):
            raise ValueError(f"不支持的协议: {parsed.scheme}")

        host = parsed.host
        ipv4_match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', host)
        if ipv4_match:
            octets = [int(g) for g in ipv4_match.groups()]
            if not all(0 <= o <= 255 for o in octets):
                raise ValueError(f"无效的 IPv4 地址: {host}")
        elif host != "localhost":
            if not re.match(
                r'^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?'
                r'(\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$',
                host,
            ):
                raise ValueError(f"无效的主机名: {host}")

        return raw


class TaskSummary(BaseModel):
    task_id: str
    target: str
    status: str
    current_phase: str
    findings_count: int
    got_shell: bool
    report_path: str
    privilege_level: str = ""
    created_at: str = ""
    updated_at: str = ""
    workflow_mode: str = "pentest_engineer"
    auto_approve: bool = False


class TaskDetail(TaskSummary):
    target_os: str = "unknown"
    scope_note: str = ""
    error_msg: str = ""
    open_ports: list = []
    os_info: dict = {}
    web_paths: list = []
    path_contents: list = []
    subdomains: list = []
    findings: list = []
    exploit_results: list = []
    post_findings: dict = {}
    report_md: str = ""
    phase_log: list = []
    # per-task 运行时参数(用于回显与调试,不允许中途修改)
    success_gate_level: str = "strict"
    risk_budget: int = 3
    max_react_rounds: int = 25
    max_explore_rounds: int = 15


class TaskStats(BaseModel):
    total: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    pending: int = 0
    shells_obtained: int = 0
    root_reached: int = 0
    total_findings: int = 0


# ── 认证相关 ──────────────────────────────────────────────

class AuthRegisterRequest(BaseModel):
    username: str
    password: str
    nickname: str = ""

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) < 2 or len(v) > 64:
            raise ValueError("用户名长度 2-64 字符")
        if not re.match(r"^[A-Za-z0-9_\-]+$", v):
            raise ValueError("用户名仅允许字母/数字/_/-")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("密码至少 6 位")
        return v


class AuthLoginRequest(BaseModel):
    username: str
    password: str


class AuthUpdateMeRequest(BaseModel):
    nickname: str = ""
    avatar_url: str = ""
    oss_url: str = ""
    old_password: str = ""
    new_password: str = ""


# ── 审批相关 ──────────────────────────────────────────────

class ApproveRequest(BaseModel):
    approved: bool = True


# ── 设置相关 ──────────────────────────────────────────────

class ProfileUpdateRequest(BaseModel):
    nickname: str
    avatar: str = ""


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str


# ── Skill 相关 ────────────────────────────────────────────

class SkillRawUpdateRequest(BaseModel):
    yaml: str


# ── Knowledge 相关 ────────────────────────────────────────

class KnowledgeSourceCreateRequest(BaseModel):
    vuln_id: str
    name: str
    urls: list[str]
    extra_context: str = ""
    fallback_content: str = ""

    @field_validator("vuln_id")
    @classmethod
    def validate_vuln_id(cls, v: str) -> str:
        vv = v.strip().lower()
        if not re.match(r"^[a-z0-9][a-z0-9_\-]{1,63}$", vv):
            raise ValueError("vuln_id 仅允许小写字母/数字/_/-，长度 2-64")
        return vv

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        vv = v.strip()
        if not vv:
            raise ValueError("name 不能为空")
        return vv[:120]


class KnowledgeBuildRequest(BaseModel):
    vuln_id: str | None = None


class KnowledgeSourceSaveRequest(BaseModel):
    name: str = ""
    urls: list[str] = []
    extra_context: str = ""
    fallback_content: str = ""


class KnowledgeSourceUrlRequest(BaseModel):
    url: str


class KnowledgeRawRequest(BaseModel):
    json_content: str


# ── Chat 相关 ─────────────────────────────────────────────

class ChatMessageRequest(BaseModel):
    text: str
