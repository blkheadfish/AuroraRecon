export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface PortInfo {
  port: number
  protocol?: string
  state?: string
  service?: string
  version?: string
  banner?: string
}

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
}

export interface TaskDetail extends TaskSummary {
  findings?: Finding[]
  phase_log?: string[]
  decision_events?: DecisionEvent[]
  exploit_results?: ExploitResult[]
  tool_records?: CommandExecutionRecord[]
  open_ports?: PortInfo[]
  os_info?: Record<string, string>
  web_paths?: string[]
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
  }[]
  subdomains?: string[]
  scope_note?: string
  extra_hint?: string
  user_prompt?: string
  workflow_mode?: string
  privilege_level?: string
  foothold_status?: string
  chain_visited?: string[]
  secondary_elided?: boolean
  attack_next_steps?: { stage?: string; action?: string; priority?: number }[]
  privesc_attempt_count?: number
  max_privesc_rounds?: number
  chain_summary?: string
}

export interface CommandExecutionRecord {
  id?: string
  phase?: string
  tool?: string
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

export interface DecisionEvent {
  id: string
  timestamp?: string
  phase?: string
  action?: string
  tool?: string
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

export type WsTaskEvent =
  | WsPhaseUpdateEvent
  | WsLogEvent
  | WsDoneEvent
  | WsApprovalRequiredEvent
  | WsHeartbeatEvent
  | WsDecisionEvent
  | Record<string, unknown>
