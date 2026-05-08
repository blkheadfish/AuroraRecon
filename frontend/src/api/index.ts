import axios from 'axios'
import type { AxiosInstance } from 'axios'
import type {
  BranchTreePayload,
  HealthInfo,
  MetricsOverview,
  PendingConfirmationResponse,
  PentestPlan,
  PlanResponse,
  ReportData,
  TaskBranch,
  TaskCreateResponse,
  TaskDetail,
  TaskLogsPage,
  TaskStats,
  TaskSummary,
  WsTaskEvent,
} from '@/types/task'
import type {
  PasswordChangePayload,
  ProfileUpdatePayload,
  SettingsPayload,
  UserProfile,
} from '@/types/settings'

// 默认走同源 `/api`（开发由 vite proxy 代理到后端，生产由 nginx 转发）。
// 跨机部署且不方便反代时，构建时设置 VITE_API_BASE=http://<backend-host>:<port>
// 即可让前端直连后端（需后端 CORS 放行，或者前端同机反代）。
const BASE = (import.meta.env?.VITE_API_BASE as string | undefined)?.trim() || '/api'
const TOKEN_KEY = 'auth.token'

// 后端很多接口会触发 LLM 调用或 Docker 拉镜像，15s 在跨机内网部署下经常不够。
// 统一默认 60s，少数已知重型接口（例如 /knowledge/build）在下方单独显式拔高。
const DEFAULT_TIMEOUT_MS = Number(import.meta.env?.VITE_API_TIMEOUT_MS) || 60000

const http: AxiosInstance = axios.create({
  baseURL: BASE,
  timeout: DEFAULT_TIMEOUT_MS,
})

http.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) {
    config.headers = config.headers || {}
    config.headers['Authorization'] = `Bearer ${token}`
  }
  return config
})

http.interceptors.response.use(
  (res) => res.data,
  (err) => {
    if (err?.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      localStorage.removeItem('auth.user')
      const path = window.location.pathname
      if (path !== '/login' && path !== '/register' && path !== '/start') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(err)
  },
)

function getWsBase(): string {
  // 优先使用构建时指定的 VITE_WS_BASE（跨机部署场景），否则回落到同源。
  const envWs = (import.meta.env?.VITE_WS_BASE as string | undefined)?.trim()
  if (envWs) return envWs.replace(/\/$/, '')
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${location.host}`
}

export const api = {
  authLogin: (username: string, password: string): Promise<{ token: string; user: any }> =>
    http.post('/auth/login', { username, password }),
  authRegister: (username: string, password: string, nickname?: string): Promise<{ token: string; user: any }> =>
    http.post('/auth/register', { username, password, nickname: nickname || '' }),
  authMe: (): Promise<any> => http.get('/auth/me'),
  authUpdateMe: (data: { nickname?: string; avatar_url?: string; oss_url?: string; old_password?: string; new_password?: string }): Promise<{ status: string; user: any }> =>
    http.put('/auth/me', data),

  healthCheck: (): Promise<HealthInfo> => http.get('/health'),
  // AI辅助生成：DeepSeek-V4-Pro,2026-05-03
  parseTaskIntent: (payload: {
    userPrompt: string
    workflowMode?: 'pentest_engineer' | 'ctf_expert'
  }): Promise<{
    target: string
    suggested_workflow_mode: string
    priority_vulns: string[]
    scope_note: string
    extra_hint: string
    summary: string
    intents: string[]
    confidence: number
    fallback: boolean
    error: string
  }> =>
    http.post(
      '/tasks/parse-intent',
      {
        user_prompt: payload.userPrompt,
        workflow_mode: payload.workflowMode ?? 'pentest_engineer',
      },
      { timeout: 30000 },
    ),

  // Plan Mode: 在创建任务前生成渗透策略预览，不执行任何工具
  // AI辅助生成：DeepSeek-V4-Pro,2026-05-03
  generatePlan: (payload: {
    userPrompt: string
  }): Promise<PlanResponse> =>
    http.post('/tasks/plan', { user_prompt: payload.userPrompt }, { timeout: 180000 }),

  createTask: (payload: {
    target: string
    rawPrompt?: string
    note?: string
    extraHint?: string
    userPrompt?: string
    workflowMode?: 'pentest_engineer' | 'ctf_expert'
    autoApprove?: boolean | null
    successGateLevel?: 'strict' | 'medium' | 'lenient' | null
    riskBudget?: number | null
    maxReactRounds?: number | null
    maxExploreRounds?: number | null
    skillMinScore?: number | null
    skillWeakBoost?: number | null
    userConfirmedRisks?: string[]
    confirmedPlan?: Record<string, unknown> | null
    // ★ 新增：前端缓存 parse-intent 完整响应，回传给后端
    parsedIntentExtra?: Record<string, unknown> | null
  }): Promise<TaskCreateResponse> =>
    http.post('/tasks', {
      target:                payload.target,
      raw_prompt:            payload.rawPrompt ?? '',
      scope_note:            payload.note ?? 'CTF/授权靶场测试',
      extra_hint:            payload.extraHint ?? '',
      user_prompt:           payload.userPrompt ?? '',
      workflow_mode:         payload.workflowMode ?? 'pentest_engineer',
      auto_approve:          payload.autoApprove ?? null,
      success_gate_level:    payload.successGateLevel ?? null,
      risk_budget:           payload.riskBudget ?? null,
      max_react_rounds:      payload.maxReactRounds ?? null,
      max_explore_rounds:    payload.maxExploreRounds ?? null,
      skill_min_score:       payload.skillMinScore ?? null,
      skill_weak_boost:      payload.skillWeakBoost ?? null,
      user_confirmed_risks:  payload.userConfirmedRisks ?? [],
      confirmed_plan:        payload.confirmedPlan ?? null,
      // ★ 新增：透传 parse-intent 完整表达式回后端
      parsed_intent_extra:   payload.parsedIntentExtra ?? null,
    }),
  // 默认走轻量快照(phase_log_tail/decision_events_tail),完整 state 用 getTaskFull
  getTask: (id: string): Promise<TaskDetail> => http.get(`/tasks/${id}`),
  // 「原始数据」Tab 显式拉完整 to_detail(),按需触发,首屏不再付出该代价
  getTaskFull: (id: string): Promise<TaskDetail> =>
    http.get(`/tasks/${id}`, { params: { full: true } }),
  listTasks: (): Promise<TaskSummary[]> => http.get('/tasks'),
  getStats: (): Promise<TaskStats> => http.get('/tasks/stats'),
  getLogs: (
    id: string,
    params?: { offset?: number; limit?: number; tail?: number; after_seq?: number },
  ): Promise<TaskLogsPage> =>
    http.get(`/tasks/${id}/logs`, { params: params || {} }),
  // 协议 v2: 历史事件分页 (后端 XRANGE 包装), 用于 IndexedDB 翻页 / 主动补差量
  getEvents: (
    id: string,
    params?: { after_id?: string; count?: number },
  ): Promise<{
    events: Array<Record<string, unknown>>
    count: number
    first_id: string
    last_id: string
    has_more: boolean
  }> => http.get(`/tasks/${id}/events`, { params: params || {} }),
  getReport: (id: string): Promise<ReportData> => http.get(`/tasks/${id}/report`),
  cancelTask: (id: string): Promise<{ ok: boolean }> => http.post(`/tasks/${id}/cancel`),
  deleteTask: (id: string): Promise<{ ok: boolean }> => http.delete(`/tasks/${id}`),
  approveTask: (id: string, approved = true): Promise<{ ok: boolean }> =>
    http.post(`/tasks/${id}/approve`, { approved }),
  respondCheckpoint: (
    id: string,
    payload: {
      action: 'approve' | 'reject' | 'modify' | 'skip'
      selected_option?: string
      user_prompt?: string
      note?: string
      next_action?: string
    },
  ): Promise<{ status: string; approved: boolean; action: string }> =>
    http.post(`/tasks/${id}/checkpoint/respond`, {
      action: payload.action,
      selected_option: payload.selected_option ?? '',
      user_prompt: payload.user_prompt ?? '',
      note: payload.note ?? '',
      next_action: payload.next_action ?? '',
    }),

  getSettings: (): Promise<SettingsPayload> => http.get('/settings'),
  saveSettings: (data: SettingsPayload): Promise<{ ok: boolean }> => http.post('/settings', data),
  testLLM: (): Promise<{ ok: boolean }> => http.post('/settings/test-llm'),
  getProfile: (): Promise<UserProfile> => http.get('/profile'),
  updateProfile: (data: ProfileUpdatePayload): Promise<{ status: string; profile: UserProfile }> =>
    http.put('/profile', data),
  changePassword: (data: PasswordChangePayload): Promise<{ status: string }> =>
    http.post('/profile/change-password', data),
  getMetricsOverview: async (windowHours = 24): Promise<MetricsOverview> => {
    // 只保留一次调用；之前的两段 axios.get 回退逻辑没有带 Authorization，
    // 跨机部署时只会稳定吃到 401 / 超时，反而把这次请求拖满 15s 才报错。
    const params = { window_hours: windowHours }
    return http.get('/metrics/overview', { params })
  },
  getSkills: (): Promise<{
    skills: Array<{
      skill_id: string
      name: string
      category: string
      paths_count: number
      probes_count: number
      source: string
      enabled?: boolean
    }>
    total: number
  }> => http.get('/skills'),
  getSkillRaw: (skillId: string): Promise<{ skill_id: string; source: string; yaml: string }> =>
    http.get(`/skills/${skillId}/raw`),
  saveSkillRaw: (skillId: string, yamlContent: string): Promise<{ status: string; skill_id: string }> =>
    http.put(`/skills/${skillId}/raw`, { yaml: yamlContent }),
  reloadSkills: (): Promise<{ status: string; total: number }> =>
    http.post('/skills/reload'),

  getKnowledgeEntries: (): Promise<{
    entries: Array<{
      vuln_id: string
      description: string
      category: string
      cves: string[]
      tags: string[]
      default_port: number | null
    }>
    total: number
  }> => http.get('/knowledge/entries'),
  getKnowledgeRaw: (vulnId: string): Promise<{ vuln_id: string; source: string; json: string }> =>
    http.get(`/knowledge/${vulnId}/raw`),
  saveKnowledgeRaw: (vulnId: string, jsonContent: string): Promise<{ status: string; vuln_id: string }> =>
    http.put(`/knowledge/${vulnId}/raw`, { json_content: jsonContent }),
  reloadKnowledge: (): Promise<{ status: string; total: number }> =>
    http.post('/knowledge/reload'),
  getPrompts: (): Promise<{ prompts: Array<{ id: string; name: string; version: string; active: boolean; content: string }>; source: string }> =>
    http.get('/prompts'),
  savePrompts: (prompts: Array<{ id: string; name: string; version: string; active: boolean; content: string }>): Promise<{ status: string; count: number }> =>
    http.post('/prompts', { prompts }),

  getKnowledgeSource: (vulnId: string): Promise<{
    vuln_id: string
    name: string
    urls: string[]
    extra_context: string
    fallback_content: string
    is_custom: boolean
    built: boolean
  }> => http.get(`/knowledge/${vulnId}/sources`),

  saveKnowledgeSource: (vulnId: string, payload: {
    name?: string
    urls?: string[]
    extra_context?: string
    fallback_content?: string
  }): Promise<{ status: string; source: { vuln_id: string } }> =>
    http.put(`/knowledge/${vulnId}/sources`, payload),

  addKnowledgeSourceUrl: (vulnId: string, url: string): Promise<{ status: string; url: string; urls: string[] }> =>
    http.post(`/knowledge/${vulnId}/sources/url`, { url }),

  removeKnowledgeSourceUrl: (vulnId: string, url: string): Promise<{ status: string; url: string; urls: string[] }> =>
    http.delete(`/knowledge/${vulnId}/sources/url`, { data: { url } }),

  createKnowledgeSource: (payload: {
    vuln_id: string
    name: string
    urls: string[]
    extra_context?: string
    fallback_content?: string
  }): Promise<{ status: string; source: { vuln_id: string } }> =>
    http.post('/knowledge/sources/new', payload),

  buildKnowledge: (vulnId?: string): Promise<{
    status: string
    mode: 'single' | 'all'
    total?: number
    success: number
    failed: number
    vuln_id?: string
    results?: Record<string, boolean>
  }> => http.post('/knowledge/build', vulnId ? { vuln_id: vulnId } : {}, { timeout: 600000 }),

  sendChat: (
    taskId: string,
    text: string,
    options?: { fromEventId?: string; fromEventTs?: string },
  ): Promise<{
    status: string
    message: { role: string; text: string; timestamp: string }
    task_status?: string
    fork_active?: boolean
    branch?: TaskBranch | null
  }> =>
    http.post(`/tasks/${taskId}/chat`, {
      text,
      // 仅在用户从历史气泡选择"在此分叉"时才回传, 让 BranchManager
      // 走 ``find_checkpoint_at_or_before`` 找具体 checkpoint。
      from_event_id: options?.fromEventId,
      from_event_ts: options?.fromEventTs,
    }),
  getChatHistory: (taskId: string): Promise<{ messages: Array<{ role: string; text: string; timestamp: string }> }> =>
    http.get(`/tasks/${taskId}/chat`),

  // ── 任务分支 (Claude/Kimi 风格 branch tree) ─────────────────
  listBranches: (taskId: string): Promise<BranchTreePayload> =>
    http.get(`/tasks/${taskId}/branches`),
  activateBranch: (taskId: string, branchId: string): Promise<{ status: string; branch: TaskBranch }> =>
    http.post(`/tasks/${taskId}/branches/${branchId}/activate`),
  resumeBranch: (taskId: string, branchId: string): Promise<{ status: string; branch: TaskBranch }> =>
    http.post(`/tasks/${taskId}/branches/${branchId}/resume`),
  pauseBranch: (taskId: string, branchId: string): Promise<{ status: string; branch: TaskBranch }> =>
    http.post(`/tasks/${taskId}/branches/${branchId}/pause`),

  listMembers: (): Promise<Array<{ user_id: string; email: string; role: string }>> =>
    http.get('/team/members'),
  inviteMember: (email: string, role: string): Promise<{ ok: boolean }> =>
    http.post('/team/members', { email, role }),
  removeMember: (userId: string): Promise<{ ok: boolean }> =>
    http.delete(`/team/members/${userId}`),

  assignTask: (taskId: string, userId: string): Promise<{ ok: boolean }> =>
    http.post(`/tasks/${taskId}/assign`, { user_id: userId }),

  getComments: (taskId: string): Promise<Array<{ id: string; text: string; created_at: string }>> =>
    http.get(`/tasks/${taskId}/comments`),
  addComment: (taskId: string, text: string): Promise<{ ok: boolean }> =>
    http.post(`/tasks/${taskId}/comments`, { text }),

  // ── 管理员端点（role === 'admin' 才能调用） ────────────────
  adminListUsers: (): Promise<{
    users: Array<{
      id: string
      username: string
      nickname: string
      avatar_url: string
      oss_url: string
      role: string
      created_at: string
    }>
    total: number
  }> => http.get('/admin/users'),

  adminUpdateUserRole: (
    userId: string,
    role: 'admin' | 'user',
  ): Promise<{ status: string; user: { id: string; username: string; role: string } }> =>
    http.patch(`/admin/users/${userId}/role`, { role }),

  adminResetPassword: (
    userId: string,
    newPassword: string,
  ): Promise<{ status: string }> =>
    http.post(`/admin/users/${userId}/reset-password`, { new_password: newPassword }),

  adminDeleteUser: (userId: string): Promise<{ status: string }> =>
    http.delete(`/admin/users/${userId}`),

  adminGetLlmRuntime: (): Promise<{
    llm: { provider: string; model: string; base_url: string; has_key: boolean }
    embedding: { enabled: boolean; model: string; base_url: string; has_key: boolean }
    note: string
  }> => http.get('/admin/llm-runtime'),

  adminListAuditLogs: (params?: {
    page?: number
    page_size?: number
    action?: string
    owner_id?: string
  }): Promise<{
    items: Array<{
      id: string
      owner_id: string
      tenant_id: string
      action: string
      resource_type: string
      resource_key: string
      detail: Record<string, unknown>
      created_at: string
    }>
    total: number
    page: number
    page_size: number
  }> => http.get('/admin/audit-logs', { params }),

  adminSetSkillEnabled: (
    skillId: string,
    enabled: boolean,
  ): Promise<{ status: string; resource_type: string; resource_key: string; enabled: boolean }> =>
    http.patch(`/admin/skills/${skillId}/enabled`, { enabled }),

  adminSetToolEnabled: (
    toolName: string,
    enabled: boolean,
  ): Promise<{ status: string; resource_type: string; resource_key: string; enabled: boolean }> =>
    http.patch(`/admin/tools/${toolName}/enabled`, { enabled }),

  adminListOverrides: (resourceType?: string): Promise<{
    items: Array<{ id: string; resource_type: string; resource_key: string; enabled: boolean; detail_json?: string; updated_at: string }>
    total: number
  }> => http.get('/admin/overrides', { params: resourceType ? { resource_type: resourceType } : {} }),

  adminListTasks: (): Promise<Array<TaskSummary & { owner_id?: string }>> =>
    http.get('/tasks', { params: { all: true } }),

  adminGetSystemMetrics: (): Promise<{
    host: {
      cpu_percent: number
      cpu_count: number
      memory: { total_gb: number; used_gb: number; percent: number }
      disk: Array<{ mountpoint: string; total_gb: number; used_gb: number; percent: number }>
      uptime_seconds: number
      error?: string
    }
    docker: {
      containers: Array<{
        name: string
        status: string
        image?: string
        cpu_percent: number
        memory_mb: number
        memory_limit_mb: number
      }>
      total_running: number
      total_stopped: number
      error?: string
    }
  }> => http.get('/admin/system-metrics', { timeout: 15000 }),

  adminSetToolTimeout: (
    toolName: string,
    timeout: number,
  ): Promise<{ status: string; tool: string; timeout: number }> =>
    http.patch(`/admin/tools/${toolName}/timeout`, { timeout }),

  adminDockerAction: (
    containerName: string,
    action: 'restart' | 'stop' | 'start',
  ): Promise<{ status: string; container: string; action: string }> =>
    http.post(`/admin/docker/${containerName}/${action}`),

  adminSaveKnowledgeRawGlobal: (
    vulnId: string,
    jsonContent: string,
  ): Promise<{ status: string; vuln_id: string; source: string; scope: string }> =>
    http.put(`/admin/knowledge/${vulnId}/raw`, { json_content: jsonContent }),

  buildAdminTerminalWsUrl: (): string => {
    const base = getWsBase()
    const token = localStorage.getItem(TOKEN_KEY) ?? ''
    return `${base}/admin/terminal${token ? `?token=${encodeURIComponent(token)}` : ''}`
  },
}

export interface WsConnection {
  close: () => void
  readonly readyState: number
}

export interface WsConnectOptions {
  /**
   * 协议 v2: Redis Stream id (string), 用于增量重连。
   * 服务端对 ``after_id`` 之后的事件做 XRANGE / XREAD 回放。
   */
  afterId?: string
  /**
   * 首次连接希望回放的最近 N 条 (服务端上限 5000)。
   */
  logTail?: number
}

export function createWsConnection(
  taskId: string,
  onMessage?: (data: WsTaskEvent) => void,
  onClose?: () => void,
  options?: WsConnectOptions,
): WsConnection {
  const wsBase = getWsBase()

  function _buildUrl(): string {
    const token = localStorage.getItem(TOKEN_KEY) ?? ''
    const queryParts: string[] = []
    if (token) queryParts.push(`token=${encodeURIComponent(token)}`)
    if (options?.afterId) {
      queryParts.push(`after_id=${encodeURIComponent(options.afterId)}`)
    }
    if (typeof options?.logTail === 'number' && options.logTail >= 0) {
      queryParts.push(`log_tail=${options.logTail}`)
    }
    return `${wsBase}/ws/${taskId}${queryParts.length ? `?${queryParts.join('&')}` : ''}`
  }

  // 协议 v2 推荐节奏: 服务端每 25s 没业务事件时主动发 ``heartbeat``,
  // 客户端 ping 间隔与之对齐 (略宽), pong 等待到 8s 容忍弱网抖动。
  const PING_INTERVAL = 25000
  const PONG_TIMEOUT = 8000

  let ws: WebSocket | null = null
  let heartbeatTimer: number | undefined
  let pongTimer: number | undefined
  let awaitingPong = false
  let destroyed = false
  // 1008 鉴权失败 + 自动 token refresh + 立即重连一次的状态机
  let authRetryAttempted = false
  // onclose 后的"温和首次重试" (覆盖 NAT 抖动 / 服务重启间隙) — 命中过一次后
  // 后续重连交给上层 wsManager 的指数退避来管。
  let softRetryUsed = false

  function clearTimers() {
    if (heartbeatTimer) window.clearInterval(heartbeatTimer)
    if (pongTimer) window.clearTimeout(pongTimer)
    heartbeatTimer = undefined
    pongTimer = undefined
    awaitingPong = false
  }

  // 协议 v2 鉴权失败时尝试刷新 token 一次
  async function _tryRefreshToken(): Promise<boolean> {
    try {
      // /auth/me 是最轻量的鉴权探测; 后端会在 token 即将过期时颁发新的。
      // 没有 refresh 接口的部署里, 至少能感知到 "token 过期" 触发用户重登。
      const res = await api.authMe()
      // authMe 返回的 user 不带新 token, 这里仅确认 token 仍可用; 真正的
      // refresh 在后端将来加了 /auth/refresh 后再补。
      return Boolean(res)
    } catch {
      return false
    }
  }

  function connect() {
    if (destroyed) return
    const url = _buildUrl()
    ws = new WebSocket(url)

    ws.onopen = () => {
      heartbeatTimer = window.setInterval(() => {
        if (ws?.readyState === WebSocket.OPEN) {
          ws.send('ping')
          awaitingPong = true
          pongTimer = window.setTimeout(() => {
            if (awaitingPong && !destroyed) {
              ws?.close()
            }
          }, PONG_TIMEOUT)
        }
      }, PING_INTERVAL)
    }

    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data) as WsTaskEvent
        const t = (data as { type?: string }).type
        if (t === 'heartbeat' || t === 'pong') {
          awaitingPong = false
          if (pongTimer) { window.clearTimeout(pongTimer); pongTimer = undefined }
          return
        }
        // 收到任何业务帧, 都视为对端活着 -> 清掉 pong 等待
        awaitingPong = false
        if (pongTimer) { window.clearTimeout(pongTimer); pongTimer = undefined }
        onMessage?.(data)
      } catch {
        if (typeof e.data === 'string' && e.data.trim() === 'pong') {
          awaitingPong = false
          if (pongTimer) { window.clearTimeout(pongTimer); pongTimer = undefined }
        }
      }
    }

    ws.onclose = (ev: CloseEvent) => {
      clearTimers()
      if (destroyed) return
      // 1008 = policy violation, 后端在 token 过期 / 鉴权失败时使用
      if (ev.code === 1008 && !authRetryAttempted) {
        authRetryAttempted = true
        _tryRefreshToken().then((ok) => {
          if (destroyed) return
          if (ok) {
            // token 仍可用 → 立即重连
            connect()
          } else {
            // token 真的过期 → 交给 axios 401 拦截器处理 (会跳登录页)
            onClose?.()
          }
        })
        return
      }
      // 第一次掉线快速温和重试一次 (覆盖 NAT 抖动 / load balancer 漂移),
      // 之后的重连节奏交给 wsManager 的退避策略。
      if (!softRetryUsed) {
        softRetryUsed = true
        window.setTimeout(() => {
          if (!destroyed) connect()
        }, 500)
        return
      }
      onClose?.()
    }

    ws.onerror = () => {
      ws?.close()
    }
  }

  connect()

  return {
    close() {
      destroyed = true
      clearTimers()
      ws?.close()
    },
    get readyState() {
      return ws?.readyState ?? WebSocket.CLOSED
    },
  }
}

export default http
