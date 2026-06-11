"""
schemas.py —— 所有 API 请求/响应 Pydantic 模型
"""
from __future__ import annotations

import re
from typing import Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator
from backend.agents.models import WorkflowMode, parse_target



class CreateTaskRequest(BaseModel):
    """
    创建任务请求。

    支持两种模式：
    1. 传统模式：直接传 target (IP/域名/CIDR)，兼容旧接口
    2. 自然语言模式：传 raw_prompt，系统自动解析意图
       - target 可选（raw_prompt 提供时可为空）
       - authorization_token 提供后跳过安全卡口

    workflow_mode 决定一组默认值(审批策略 / 证据门槛 / 风险预算 / 轮次
    上限 / Skill 匹配阈值);用户可以同时在 `auto_approve` / `success_gate_level`
    / `risk_budget` / `max_react_rounds` / `max_explore_rounds` 等字段上
    显式覆盖,缺省(None)则使用 mode 默认值。这些参数均为 per-task,
    不会写回全局环境变量。
    """

    target: str = ""
    raw_prompt: str = ""
    scope_note: str = "CTF/授权靶场测试"
    extra_hint: str = ""
    user_prompt: str = ""
    workflow_mode: WorkflowMode = "pentest_engineer"
    authorization_token: Optional[str] = None
    user_confirmed_risks: list[str] = []

    auto_approve: Optional[bool] = None
    autonomy_level: Optional[Literal["manual", "supervised", "autonomous"]] = None
    success_gate_level: Optional[Literal["strict", "medium", "lenient"]] = None
    risk_budget: Optional[int] = None
    max_react_rounds: Optional[int] = None
    max_explore_rounds: Optional[int] = None
    skill_min_score: Optional[int] = None
    skill_weak_boost: Optional[int] = None

    confirmed_plan: Optional[dict] = None

    parsed_intent_extra: dict | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """校验 target 字段。

        注意：target 可以为空（当 raw_prompt 提供时），此时不做校验。
        空 target 的完整校验在路由层完成（与 raw_prompt 联动）。
        """
        raw = v.strip()
        if not raw:
            return raw

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
    autonomy_level: str = "manual"
    chain_template_id: str = "web"
    chain_template: Optional[dict] = None


class PendingConfirmationResponse(BaseModel):
    """POST /tasks 返回的安全卡口待确认响应。

    当目标为公网 IP、需进一步确认授权等场景时,后端不会立即创建任务,
    而是返回此结构,要求前端展示风险警告并收集用户确认后二次提交。
    二次提交时需在 CreateTaskRequest.user_confirmed_risks 中传入已勾选的
    风险项 ID,后端校验通过后才会正式创建任务。
    """
    status: Literal["pending_confirmation"] = "pending_confirmation"
    task_id: str = ""
    target: str
    warnings: list[str] = Field(default_factory=list)
    required_confirmations: list[str] = Field(default_factory=list)
    parsed_intent: dict = Field(default_factory=dict)
    message: str = ""


TaskCreateResponse = Union[TaskSummary, PendingConfirmationResponse]


class TaskDetail(TaskSummary):
    target_os: str = "unknown"
    scope_note: str = ""
    error_msg: str = ""
    authorized_scope: list = []
    scope_violations: list = []
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
    parsed_intent: dict = Field(default_factory=dict)
    pentest_plan: dict = Field(default_factory=dict)
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



class ApproveRequest(BaseModel):
    approved: bool = True


class CheckpointDecisionRequest(BaseModel):
    """Plan 模式确认框的用户响应。

    action:
      - ``approve`` 直接按 Agent 推荐继续
      - ``reject``  跳过该决策,后续节点应当尊重
      - ``modify``  保留当前阶段但带上用户 prompt 重做(由 Agent 节点决定如何使用)
      - ``skip``    不做选择,等价于让任务继续按默认值跑
    selected_option / user_prompt 仅作为软引导写入 state,Agent 节点自己决定
    如何消费,便于前端逐步演进。
    """

    action: Literal["approve", "reject", "modify", "skip"] = "approve"
    selected_option: str = ""
    user_prompt: str = ""
    note: str = ""
    next_action: str = ""



class ProfileUpdateRequest(BaseModel):
    nickname: str
    avatar: str = ""


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str



class AdminUpdateRoleRequest(BaseModel):
    role: Literal["admin", "user"]


class AdminResetPasswordRequest(BaseModel):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("密码至少 6 位")
        return v



class SkillRawUpdateRequest(BaseModel):
    yaml: str



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



class ChatMessageRequest(BaseModel):
    text: str
    from_event_id: str | None = None
    from_event_ts: str | None = None



class ParseIntentRequest(BaseModel):
    """前端在用户输入自然语言任务描述时调用,
    由 LLM 解析出结构化的 target / 工作流偏好 / 关注漏洞等信息。
    """

    user_prompt: str
    workflow_mode: WorkflowMode = "pentest_engineer"

    @field_validator("user_prompt")
    @classmethod
    def validate_user_prompt(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("user_prompt 不能为空")
        return v[:2000]


class ParseIntentResponse(BaseModel):
    """LLM 解析的结构化结果。

    fallback=True 表示 LLM 调用失败,字段是基于本地正则兜底解析得到。
    target 为空字符串表示没有从 prompt 中识别到合法目标。
    """

    target: str = ""
    suggested_workflow_mode: str = ""
    priority_vulns: list[str] = []
    scope_note: str = ""
    extra_hint: str = ""
    summary: str = ""
    intents: list[str] = []
    confidence: float = 0.0
    fallback: bool = False
    error: str = ""



class PlanStep(BaseModel):
    """单个策略步骤"""
    tool: str = ""
    skill: str = ""
    purpose: str = ""
    command_hint: str = ""
    expected_output: str = ""
    trigger_condition: str = ""
    expected_impact: str = ""
    fallback: str = ""
    depends_on: str = ""
    enabled: bool = True


class PlanPhase(BaseModel):
    """策略中的单个阶段"""
    phase: str = ""
    description: str = ""
    steps: list[PlanStep] = []


class PentestPlan(BaseModel):
    """完整的渗透策略"""
    target_understanding: str = ""
    phases: list[PlanPhase] = []
    unsupported_hints: list[str] = []
    risk_notes: list[str] = []


class PlanRequest(BaseModel):
    """策略生成请求"""
    user_prompt: str

    @field_validator("user_prompt")
    @classmethod
    def validate_user_prompt(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("user_prompt 不能为空")
        return v[:2000]


class PlanResponse(BaseModel):
    """策略生成响应"""
    plan_id: str = ""
    plan: PentestPlan = Field(default_factory=PentestPlan)
    available_tools_count: int = 0
    available_skills_count: int = 0


class ConfirmPlanRequest(BaseModel):
    """用户确认/修改后的策略提交"""
    plan_id: str
    plan: PentestPlan
    user_note: str = ""
    target: str = ""
    workflow_mode: WorkflowMode = "pentest_engineer"
