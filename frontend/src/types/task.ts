export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

export type WorkflowMode = 'pentest_engineer' | 'ctf_expert'

export interface PortInfo {
  port: number
  protocol?: string
  state?: string
  service?: string
  version?: string
  banner?: string
}

export type VerificationStatus = 'confirmed' | 'likely' | 'suspected' | 'unverified' | 'rejected'

export interface Finding {
  vuln_id: string
  name: string
  description?: string
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | string
  target?: string
  port?: number
  tool?: string
  cve?: string
  evidence?: string
  exploitable?: boolean
  confidence?: number
  verification_status?: VerificationStatus
  verification_reasons?: string[]
  evidence_snippets?: { kind?: string; text?: string; source?: string }[]
}

export interface ChainTemplateInfo {
  id: string
  pipeline_steps: { key: string; label: string }[]
}

export interface TaskSummary {
  task_id: string
  target: string
  status: TaskStatus
  current_phase?: string
  findings_count?: number
  got_shell?: boolean
  report_path?: string | null
  created_at?: string
  updated_at?: string
  chain_template_id?: string
  chain_template?: ChainTemplateInfo
  workflow_mode?: WorkflowMode | string
  auto_approve?: boolean
}

/** POST /tasks 安全卡口待确认响应 */
export interface PendingConfirmationResponse {
  status: 'pending_confirmation'
  task_id: string
  target: string
  warnings: string[]
  required_confirmations: string[]
  parsed_intent: Record<string, unknown>
  message: string
}

/** POST /tasks 的联合响应类型 */
export type TaskCreateResponse = TaskSummary | PendingConfirmationResponse

export interface AttackGraphNode {
  id: string
  type: 'host' | 'service' | 'finding' | 'credential' | 'foothold' | 'loot' | 'objective' | 'path'
  label?: string
  facts?: Record<string, unknown>
  discovered_at?: string
  discovered_by?: string
}

export interface AttackGraphEdge {
  src: string
  dst: string
  relation: 'enables' | 'leads_to' | 'exposes' | 'consumes' | 'discovers'
  note?: string
}

export interface AttackGraphPayload {
  nodes: AttackGraphNode[]
  edges: AttackGraphEdge[]
}

export interface TaskDetail extends TaskSummary {
  findings?: Finding[]
  // 后端默认返回轻量快照: phase_log 留空, phase_log_tail 仅含最近 N 条,
  // phase_log_total 表示真实总条数。完整日志走分页 /tasks/{id}/logs。
  phase_log?: string[]
  phase_log_tail?: string[]
  phase_log_total?: number
  decision_events?: DecisionEvent[]
  decision_events_tail?: DecisionEvent[]
  decision_events_total?: number
  exploit_results?: ExploitResult[]
  tool_records?: CommandExecutionRecord[]
  tool_records_count?: number
  report_available?: boolean
  open_ports?: PortInfo[]
  os_info?: Record<string, string>
  web_paths?: string[]
  web_paths_inventory?: {
    path: string
    status: number
    confidence: number
    hints: string[]
    source_tools: string[]
  }[]
  path_contents?: {
    path?: string
    status?: number
    title?: string
    hints?: string[]
    tech_clues?: string[]
    keywords?: string[]
    server?: string
    powered_by?: string
    content_snippet?: string
    content_truncated?: boolean
  }[]
  subdomains?: string[]
  scope_note?: string
  authorized_scope?: string[]
  scope_violations?: { command: string; targets: string[]; ts: string }[]
  extra_hint?: string
  user_prompt?: string
  parsed_intent?: Record<string, unknown>
  pentest_plan?: Record<string, unknown>
  privilege_level?: string
  // per-task 运行时参数(回显用,不允许中途改)
  success_gate_level?: 'strict' | 'medium' | 'lenient' | string
  risk_budget?: number
  max_react_rounds?: number
  max_explore_rounds?: number
  skill_min_score?: number
  skill_weak_boost?: number
  foothold_status?: string
  chain_visited?: string[]
  secondary_elided?: boolean
  attack_next_steps?: { stage?: string; action?: string; priority?: number }[]
  privesc_attempt_count?: number
  max_privesc_rounds?: number
  chain_summary?: string
  pending_checkpoint?: CheckpointPayload | null
  checkpoint_history?: CheckpointPayload[]
  pending_user_prompt?: string
  attack_graph?: AttackGraphPayload
  chain_template?: ChainTemplateInfo
  prior_intel?: PriorIntelPayload
}

export interface PriorCredentialHint {
  service: string
  username: string
  has_secret: boolean
  source: string
}

export interface PriorIntelPayload {
  known_services: {
    host: string
    port: number
    service: string
    version: string
    banner: string
  }[]
  known_fingerprints: Record<string, string>
  known_findings: {
    vuln_id: string
    name: string
    severity: string
    cve: string
  }[]
  credential_hints: PriorCredentialHint[]
  source_task_count: number
  source_task_ids: string[]
}

export interface TaskLogsPage {
  logs: string[]
  offset: number
  limit: number
  total: number
  next_seq: number
  has_more: boolean
}

export interface CommandExecutionRecord {
  id?: string
  phase?: string
  tool?: string
  display_tool?: string
  backend?: string
  runtime_command?: string
  round?: number
  command: string
  purpose?: string
  timestamp?: string
  stdout?: string
  stderr?: string
  exit_code?: number
  elapsed?: number
  truncated?: boolean
  total_len?: number
}

export interface ExploitResult {
  vuln_id: string
  success: boolean
  shell_type?: string
  evidence?: string
  commands_run?: string[]
  command_results?: CommandExecutionRecord[]
  command_records?: CommandExecutionRecord[]
  session_info?: Record<string, unknown>
}

export interface CheckpointOption {
  id: string
  label: string
  tone?: 'primary' | 'success' | 'warning' | 'danger' | 'info' | string
  action?: 'approve' | 'reject' | 'modify' | 'skip' | string
  wants_prompt?: boolean
  hint?: string
}

export interface CheckpointPayload {
  checkpoint_id: string
  checkpoint_type: string
  phase?: string
  status?: 'pending' | 'resolved' | string
  created_at?: string
  resolved_at?: string
  thinking?: string
  summary?: string
  recommendation?: string
  risk?: string
  requires_input?: boolean
  default_action?: 'approve' | 'reject' | 'modify' | 'skip' | string
  options?: CheckpointOption[]
  context?: Record<string, unknown>
  response?: {
    action: string
    selected_option?: string
    user_prompt?: string
    note?: string
  }
}

export interface DecisionEvent {
  id: string
  timestamp?: string
  phase?: string
  action?: string
  tool?: string
  /**
   * 展示用工具名(由 executor 层算好), 前端 helper 优先用它而不是 ``tool``,
   * 避免把 ``/bin/bash`` 这类 shell 包装直接渲染到工具链节点。
   */
  display_tool?: string
  backend?: string
  poc_or_vuln?: string
  command?: string
  runtime_command?: string
  stdout?: string
  stderr?: string
  exit_code?: number | null
  elapsed_ms?: number | null
  purpose?: string
  round?: number | null
  truncated?: boolean
  total_len?: number
  message?: string
  tone?: 'primary' | 'success' | 'warning' | 'danger' | 'info' | string
  raw?: string
  // Plan 风格 checkpoint 事件(action === 'checkpoint_request' / 'checkpoint_resolved')
  checkpoint_id?: string
  checkpoint_type?: string
  thinking?: string
  summary?: string
  recommendation?: string
  risk?: string
  options?: CheckpointOption[]
  requires_input?: boolean
  default_action?: string
  context?: Record<string, unknown>
  response?: CheckpointPayload['response']
  replay?: boolean
  // Operator Replanner 事件(action === 'operator_replan')附带的结构化战术
  // 计划, 由后端 ``backend.agents.operator_replanner.plan_to_decision_event``
  // 注入。前端 ``TaskChat.vue`` 据此渲染高亮重规划卡片。
  operator_plan?: OperatorPlanPayload
  // Agent 推理事件(action === 'thought')可附带的 LLM 思考链(reasoning_content)
  reasoning?: string
  expected?: string
  plan?: string[]
  vuln_name?: string
  // 节点 yield-to-operator 事件(action === 'node_yielded_to_operator')附带的 phase
  branch_id?: string
  // 审批卡片附带的利用目标上下文
  exploitable_count?: number
  top_targets?: ApprovalTarget[]
  risk?: string
}

export interface OperatorPlanFocusTarget {
  type: string
  value: string
}

export interface OperatorPlanPayload {
  plan_id: string
  created_at: string
  user_request?: string
  source_phase?: string
  intent_summary?: string
  rationale?: string
  next_phase?: string | null
  target_phases?: string[]
  skip_phases?: string[]
  rerun_current?: boolean
  focus_targets?: OperatorPlanFocusTarget[]
  preferred_tools?: string[]
  avoided_tools?: string[]
  keyword_hints?: string[]
  extra_constraints?: Record<string, unknown>
  needs_human_approval?: boolean
  consumed_by?: string[]
  derived_replan_signals?: Record<string, number>
}

// Plan Mode: 策略预览相关类型
export interface PlanStep {
  tool: string
  skill: string
  purpose: string
  command_hint: string
  expected_output: string
  trigger_condition: string
  expected_impact: string
  fallback: string
  depends_on: string
  enabled: boolean
}

export interface PlanPhase {
  phase: string
  description: string
  steps: PlanStep[]
}

export interface PentestPlan {
  target_understanding: string
  phases: PlanPhase[]
  unsupported_hints: string[]
  risk_notes: string[]
}

export interface PlanResponse {
  plan_id: string
  plan: PentestPlan
  available_tools_count: number
  available_skills_count: number
}

export interface TaskStats {
  total: number
  running: number
  completed: number
  failed: number
  cancelled: number
  total_findings: number
  shells_obtained: number
}

export interface HealthInfo {
  status: 'ok' | 'error' | string
  version: string
  database: 'connected' | 'disconnected' | string
  redis: 'connected' | 'disconnected' | string
  active_tasks: number
  timestamp: string
}

export interface ReportData {
  path?: string
  markdown?: string
}

export interface ToolCatalogItem {
  name: string
  category: string
  executor: string
  timeout: number
}

export interface ToolInvocationTopItem {
  tool: string
  calls: number
  completed_calls: number
  success_rate: number
  avg_elapsed_ms: number
  backends: Record<string, number>
}

export interface MetricsOverview {
  generated_at: string
  window_hours: number
  system_overview: {
    api_status: string
    database: string
    redis: string
    msf: string
    version: string
    total_tasks: number
    running_tasks: number
    completed_tasks: number
    failed_tasks: number
    active_task_ids: number
  }
  tool_overview: {
    total_tools: number
    by_category: Record<string, number>
    by_executor: Record<string, number>
    tools: ToolCatalogItem[]
  }
  tool_invocation_overview: {
    total_calls: number
    completed_calls: number
    success_calls: number
    failed_calls: number
    success_rate: number
    avg_elapsed_ms: number
    by_backend: Record<string, number>
    top_tools: ToolInvocationTopItem[]
  }
}

export interface WsPhaseUpdateEvent {
  type: 'phase_update'
  phase: string
  status?: TaskStatus
  findings_count?: number
  got_shell?: boolean
  logs?: string[]
}

export interface WsLogEvent {
  type: 'log'
  data: string
  /**
   * 后端 phase_log 数组下标(append 后立即取的索引)。前端用它推进
   * `lastLogSeq`,保证 WS 重连只补缺失增量,而不会从默认 tail 再吃一遍。
   */
  seq?: number
}

export interface WsDoneEvent {
  type: 'done'
  status?: TaskStatus
}

export interface WsApprovalRequiredEvent {
  type: 'approval_required'
  reason?: string
}

export interface WsHeartbeatEvent {
  type: 'heartbeat'
}

export interface WsDecisionEvent {
  type: 'decision_event'
  data: DecisionEvent
}

export interface WsHistoryMetaEvent {
  type: 'history_meta'
  phase_log_total: number
  phase_log_start: number
  phase_log_replayed: number
}

export interface WsHistoryLogsEvent {
  type: 'history_logs'
  data: string[]
  start_seq?: number
  next_seq?: number
  total?: number
}

// ── 任务分支(Claude/Kimi 风格 branch tree) ─────────────────

export type BranchStatus = 'running' | 'paused' | 'completed' | 'failed'

export interface TaskBranch {
  branch_id: string
  task_id: string
  parent_branch_id?: string | null
  fork_event_id?: string | null
  fork_phase: string
  fork_round?: number | null
  thread_id: string
  status: BranchStatus
  label: string
  initiating_prompt: string
  is_root: boolean
  created_at: string
  updated_at: string
}

export interface BranchTreeItem extends TaskBranch {
  sibling_index: number
  sibling_total: number
  is_active: boolean
  children: string[]
}

export interface BranchTreePayload {
  branches: BranchTreeItem[]
  active_branch_id: string
  max_branches_per_task: number
}

export interface WsBranchForkedEvent {
  type: 'branch_forked'
  branch: TaskBranch
  parent: TaskBranch
}

export interface WsBranchSwitchedEvent {
  type: 'branch_switched'
  branch: TaskBranch
}

export interface WsBranchStatusChangedEvent {
  type: 'branch_status_changed'
  branch: TaskBranch
}

// ── 协议 v2 WS 事件 (envelope 风格, 直接对应 Redis Stream body) ──

/** 首包: 服务端告知协议版本 / 回放条数 / 后端模式 */
export interface WsHelloV2 {
  type: 'hello'
  protocol_version: number
  task_id: string
  replay_count: number
  after_id: string
  stream_redis_backed: boolean
}

/** 历史回放: 包含一批 envelope, 前端按 event.id 去重后批量注入 store */
export interface WsHistoryV2 {
  type: 'history'
  events: Record<string, unknown>[]
  first_id: string
  last_id: string
}

/** 单条日志 */
export interface WsLogV2 {
  type: 'log'
  id: string
  task_id: string
  branch_id: string
  ts: string
  v: number
  payload: { line: string; seq: number }
}

/** 决策事件 (tool_start / tool_result / thought / checkpoint_* / llm_delta / ...) */
export interface WsDecisionEventV2 {
  type: 'decision_event'
  id: string
  task_id: string
  branch_id: string
  ts: string
  v: number
  payload: Record<string, unknown>
}

/** 阶段更新 */
export interface WsPhaseUpdateV2 {
  type: 'phase_update'
  id: string
  task_id: string
  branch_id: string
  ts: string
  v: number
  payload: {
    phase: string
    status: string
    logs: string[]
    log_seq_last: number
    branch_id: string
    findings_count: number
    got_shell: boolean
    privilege_level?: string
    foothold_status?: string
    chain_visited?: string[]
    secondary_elided?: boolean
    attack_next_steps?: { stage?: string; action?: string; priority?: number }[]
    privesc_attempt_count?: number
  }
}

/** 审批卡片中展示的单个漏洞目标 */
export interface ApprovalTarget {
  name: string
  severity: string
  vuln_id: string
  cve?: string
  port?: number
  description?: string
}

/** 审批卡片上下文（前端视图层派生） */
export interface ApprovalCardContext {
  phase: string
  phaseLabel: string
  risk: string
  riskType: 'danger' | 'warning' | 'info' | ''
  summary: string
  targets: ApprovalTarget[]
  recommendation: string
  exploitableCount: number
}

/** 等待审批 */
export interface WsApprovalRequiredV2 {
  type: 'approval_required'
  id: string
  task_id: string
  branch_id: string
  ts: string
  v: number
  payload: {
    phase: string
    status: string
    server_iso: string
    logs: string[]
    findings_count: number
    got_shell: boolean
    exploitable_count?: number
    top_targets?: ApprovalTarget[]
    risk?: string
  }
}

/** 任务结束 */
export interface WsDoneV2 {
  type: 'done'
  id: string
  task_id: string
  branch_id: string
  ts: string
  v: number
  payload: {
    status: string
    findings_count: number
    got_shell: boolean
  }
}

/** 分支分叉 */
export interface WsBranchForkedV2 {
  type: 'branch_forked'
  id: string
  task_id: string
  branch_id: string
  ts: string
  v: number
  payload: {
    branch: TaskBranch
    parent: TaskBranch
  }
}

/** 分支切换 */
export interface WsBranchSwitchedV2 {
  type: 'branch_switched'
  id: string
  task_id: string
  branch_id: string
  ts: string
  v: number
  payload: {
    branch: TaskBranch
  }
}

/** 分支状态变更 */
export interface WsBranchStatusChangedV2 {
  type: 'branch_status_changed'
  id: string
  task_id: string
  branch_id: string
  ts: string
  v: number
  payload: {
    branch: TaskBranch
  }
}

/** 鉴权/任务校验错误 */
export interface WsErrorV2 {
  type: 'error'
  code: string
  message: string
}

/** 服务端心跳 */
export interface WsHeartbeatV2 {
  type: 'heartbeat'
}

/** 服务端 pong */
export interface WsPongV2 {
  type: 'pong'
}

/** 内部事件: 重连成功后触发 store 拉快照 */
export interface WsInternalReconnected {
  type: '_reconnected'
}

export type WsTaskEvent =
  | WsPhaseUpdateEvent
  | WsLogEvent
  | WsDoneEvent
  | WsApprovalRequiredEvent
  | WsHeartbeatEvent
  | WsDecisionEvent
  | WsHistoryMetaEvent
  | WsHistoryLogsEvent
  | WsBranchForkedEvent
  | WsBranchSwitchedEvent
  | WsBranchStatusChangedEvent
  | WsHelloV2
  | WsHistoryV2
  | WsLogV2
  | WsDecisionEventV2
  | WsPhaseUpdateV2
  | WsApprovalRequiredV2
  | WsDoneV2
  | WsBranchForkedV2
  | WsBranchSwitchedV2
  | WsBranchStatusChangedV2
  | WsErrorV2
  | WsHeartbeatV2
  | WsPongV2
  | WsInternalReconnected
  | Record<string, unknown>
