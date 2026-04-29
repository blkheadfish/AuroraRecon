export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed'

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
  workflow_mode?: WorkflowMode | string
  auto_approve?: boolean
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
  extra_hint?: string
  user_prompt?: string
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
}

export interface TaskStats {
  total: number
  running: number
  completed: number
  failed: number
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
  | Record<string, unknown>
