import axios from 'axios'
import type { AxiosInstance } from 'axios'
import type {
  HealthInfo,
  MetricsOverview,
  ReportData,
  TaskDetail,
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

const BASE = '/api'
const TOKEN_KEY = 'auth.token'

const http: AxiosInstance = axios.create({
  baseURL: BASE,
  timeout: 15000,
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
  createTask: (payload: {
    target: string
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
  }): Promise<TaskSummary> =>
    http.post('/tasks', {
      target:              payload.target,
      scope_note:          payload.note ?? 'CTF/授权靶场测试',
      extra_hint:          payload.extraHint ?? '',
      user_prompt:         payload.userPrompt ?? '',
      workflow_mode:       payload.workflowMode ?? 'pentest_engineer',
      auto_approve:        payload.autoApprove ?? null,
      success_gate_level:  payload.successGateLevel ?? null,
      risk_budget:         payload.riskBudget ?? null,
      max_react_rounds:    payload.maxReactRounds ?? null,
      max_explore_rounds:  payload.maxExploreRounds ?? null,
      skill_min_score:     payload.skillMinScore ?? null,
      skill_weak_boost:    payload.skillWeakBoost ?? null,
    }),
  getTask: (id: string): Promise<TaskDetail> => http.get(`/tasks/${id}`),
  listTasks: (): Promise<TaskSummary[]> => http.get('/tasks'),
  getStats: (): Promise<TaskStats> => http.get('/tasks/stats'),
  getLogs: (id: string): Promise<{ logs: string[] }> => http.get(`/tasks/${id}/logs`),
  getReport: (id: string): Promise<ReportData> => http.get(`/tasks/${id}/report`),
  cancelTask: (id: string): Promise<{ ok: boolean }> => http.post(`/tasks/${id}/cancel`),
  deleteTask: (id: string): Promise<{ ok: boolean }> => http.delete(`/tasks/${id}`),
  approveTask: (id: string, approved = true): Promise<{ ok: boolean }> =>
    http.post(`/tasks/${id}/approve`, { approved }),

  getSettings: (): Promise<SettingsPayload> => http.get('/settings'),
  saveSettings: (data: SettingsPayload): Promise<{ ok: boolean }> => http.post('/settings', data),
  testLLM: (): Promise<{ ok: boolean }> => http.post('/settings/test-llm'),
  getProfile: (): Promise<UserProfile> => http.get('/profile'),
  updateProfile: (data: ProfileUpdatePayload): Promise<{ status: string; profile: UserProfile }> =>
    http.put('/profile', data),
  changePassword: (data: PasswordChangePayload): Promise<{ status: string }> =>
    http.post('/profile/change-password', data),
  getMetricsOverview: async (windowHours = 24): Promise<MetricsOverview> => {
    const params = { window_hours: windowHours }
    try {
      return await http.get('/metrics/overview', { params })
    } catch (e) {
      const status = e?.response?.status ?? null
      if (status !== 404) throw e
    }

    try {
      const res = await axios.get<MetricsOverview>('/metrics/overview', { params, timeout: 15000 })
      return res.data
    } catch (e) {
      const status = e?.response?.status ?? null
      if (status !== 404) throw e
    }

    const res = await axios.get<MetricsOverview>('/api/metrics/overview', { params, timeout: 15000 })
    return res.data
  },
  getSkills: (): Promise<{
    skills: Array<{
      skill_id: string
      name: string
      category: string
      paths_count: number
      probes_count: number
      source: string
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

  sendChat: (taskId: string, text: string): Promise<{ status: string; message: { role: string; text: string; timestamp: string } }> =>
    http.post(`/tasks/${taskId}/chat`, { text }),
  getChatHistory: (taskId: string): Promise<{ messages: Array<{ role: string; text: string; timestamp: string }> }> =>
    http.get(`/tasks/${taskId}/chat`),

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
}

export interface WsConnection {
  close: () => void
  readonly readyState: number
}

export function createWsConnection(
  taskId: string,
  onMessage?: (data: WsTaskEvent) => void,
  onClose?: () => void,
): WsConnection {
  const wsBase = getWsBase()
  const token = localStorage.getItem(TOKEN_KEY) ?? ''
  const url = `${wsBase}/ws/${taskId}${token ? `?token=${encodeURIComponent(token)}` : ''}`

  const PING_INTERVAL = 15000
  const PONG_TIMEOUT = 5000

  let ws: WebSocket | null = null
  let heartbeatTimer: number | undefined
  let pongTimer: number | undefined
  let awaitingPong = false
  let destroyed = false

  function clearTimers() {
    if (heartbeatTimer) window.clearInterval(heartbeatTimer)
    if (pongTimer) window.clearTimeout(pongTimer)
    heartbeatTimer = undefined
    pongTimer = undefined
    awaitingPong = false
  }

  function connect() {
    if (destroyed) return
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
        onMessage?.(data)
      } catch {
        // Ignore non-JSON frames; treat raw text as possible pong
        if (typeof e.data === 'string' && e.data.trim() === 'pong') {
          awaitingPong = false
          if (pongTimer) { window.clearTimeout(pongTimer); pongTimer = undefined }
        }
      }
    }

    ws.onclose = () => {
      clearTimers()
      if (!destroyed) {
        onClose?.()
      }
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
