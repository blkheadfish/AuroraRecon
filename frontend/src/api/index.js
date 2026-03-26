import axios from 'axios'

// ── HTTP 基础配置 ────────────────────────────────────────
const BASE = '/api'

const http = axios.create({
	baseURL: BASE,
	timeout: 15000,
})

http.interceptors.response.use(
	res => res.data,
	err => Promise.reject(err)
)

// ── WebSocket URL 自动检测（修复：不再硬编码 IP）─────────
// 开发模式：Vite 的 ws proxy 会转发 /ws/* → 后端
// 生产模式：走 Nginx ws 反代
function getWsBase() {
	const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
	// 开发模式 Vite dev server 支持 ws proxy，直接用同 host/port
	return `${proto}//${location.host}`
}

// ── REST API ────────────────────────────────────────────
export const api = {
	healthCheck:    ()              => http.get('/health'),
	createTask:     (target, note) => http.post('/tasks', { target, scope_note: note }),
	getTask:        (id)           => http.get(`/tasks/${id}`),
	listTasks:      ()             => http.get('/tasks'),
	getStats:       ()             => http.get('/tasks/stats'),
	getLogs:        (id)           => http.get(`/tasks/${id}/logs`),
	getReport:      (id)           => http.get(`/tasks/${id}/report`),
	cancelTask:     (id)           => http.post(`/tasks/${id}/cancel`),
	deleteTask:     (id)           => http.delete(`/tasks/${id}`),

	// 人工审批（配合 LangGraph interrupt_before）
	approveTask:    (id, approved = true) =>
		http.post(`/tasks/${id}/approve`, { approved }),

	// 设置相关
	getSettings:    ()             => http.get('/settings'),
	saveSettings:   (data)         => http.post('/settings', data),
	testLLM:        ()             => http.post('/settings/test-llm'),

	// ── 团队协作预留接口（阶段二实现）──────────────────────
	// 用户管理
	listMembers:    ()             => http.get('/team/members'),
	inviteMember:   (email, role)  => http.post('/team/members', { email, role }),
	removeMember:   (userId)       => http.delete(`/team/members/${userId}`),

	// 任务分配
	assignTask:     (taskId, userId) =>
		http.post(`/tasks/${taskId}/assign`, { user_id: userId }),

	// 协作评论
	getComments:    (taskId)       => http.get(`/tasks/${taskId}/comments`),
	addComment:     (taskId, text) => http.post(`/tasks/${taskId}/comments`, { text }),
}

// ── WebSocket 连接工厂 ──────────────────────────────────
export function createWsConnection(taskId, onMessage, onClose) {
	const wsBase = getWsBase()
	const url = `${wsBase}/ws/${taskId}`

	let ws = null
	let heartbeatTimer = null
	let reconnectTimer = null
	let destroyed = false

	function connect() {
		if (destroyed) return
		ws = new WebSocket(url)

		ws.onopen = () => {
			// 每 25s 发一次 ping，防止代理层因空闲超时断连
			heartbeatTimer = setInterval(() => {
				if (ws?.readyState === WebSocket.OPEN) ws.send('ping')
			}, 25000)
		}

		ws.onmessage = (e) => {
			try {
				const data = JSON.parse(e.data)
				if (data.type === 'heartbeat') return
				onMessage?.(data)
			} catch { /* 忽略非 JSON 消息 */ }
		}

		ws.onclose = () => {
			clearInterval(heartbeatTimer)
			if (!destroyed) onClose?.()
		}

		ws.onerror = () => {
			ws?.close()
		}
	}

	connect()

	return {
		close() {
			destroyed = true
			clearInterval(heartbeatTimer)
			clearTimeout(reconnectTimer)
			ws?.close()
		},
		get readyState() {
			return ws?.readyState ?? WebSocket.CLOSED
		},
	}
}

export default http