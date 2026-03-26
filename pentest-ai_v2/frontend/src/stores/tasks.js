import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, createWsConnection } from '@/api'

export const useTasksStore = defineStore('tasks', () => {
	const tasks    = ref([])
	const loading  = ref(false)
	// wsMap: taskId → { ws, seenLogs: Set }
	const wsMap    = ref({})

	// ── 任务列表操作 ─────────────────────────────────────

	async function fetchTasks() {
		loading.value = true
		try {
			tasks.value = await api.listTasks()
		} finally {
			loading.value = false
		}
	}

	async function createTask(target, scopeNote) {
		const task = await api.createTask(target, scopeNote)
		tasks.value.unshift(task)
		return task
	}

	function updateTask(updated) {
		const idx = tasks.value.findIndex(t => t.task_id === updated.task_id)
		if (idx >= 0) {
			tasks.value[idx] = { ...tasks.value[idx], ...updated }
		} else {
			tasks.value.unshift(updated)
		}
	}

	function removeTask(taskId) {
		tasks.value = tasks.value.filter(t => t.task_id !== taskId)
		unsubscribeTask(taskId)
	}

	// ── WebSocket 订阅 ───────────────────────────────────

	/**
	 * 订阅任务实时更新。
	 *
	 * onUpdate(data) 会收到以下事件类型：
	 *   - { type: 'log',          data: '...'    }  单条日志（去重后）
	 *   - { type: 'phase_update', phase, status, findings_count, got_shell, logs: [...] }
	 *   - { type: 'done',         status }
	 *   - { type: 'approval_required' }             人工审批门触发
	 *
	 * 返回 unsubscribe 函数。
	 */
	function subscribeTask(taskId, onUpdate) {
		if (wsMap.value[taskId]) return () => unsubscribeTask(taskId)

		// seenLogs: 用 Set 去重，防止 phase_update 推最近 5 条导致重复累积
		const seenLogs = new Set()
		let retries = 0
		const maxRetries = 8

		function connect() {
			const entry = createWsConnection(
				taskId,
				// onMessage
				(data) => {
					retries = 0

					if (data.type === 'phase_update') {
						// 更新 store 中的任务摘要
						updateTask({
							task_id:        taskId,
							current_phase:  data.phase,
							status:         data.status || 'running',
							findings_count: data.findings_count,
							got_shell:      data.got_shell,
						})

						// 推送新日志（去重）
						const newLogs = (data.logs || []).filter(l => !seenLogs.has(l))
						newLogs.forEach(l => seenLogs.add(l))
						if (newLogs.length) {
							onUpdate?.({ ...data, logs: newLogs })
						} else {
							// phase / status 更新但无新日志，仍通知组件刷新进度
							onUpdate?.({ ...data, logs: [] })
						}
						return
					}

					if (data.type === 'log') {
						if (!seenLogs.has(data.data)) {
							seenLogs.add(data.data)
							onUpdate?.(data)
						}
						return
					}

					if (data.type === 'approval_required') {
						updateTask({ task_id: taskId, current_phase: 'awaiting_approval' })
					}

					onUpdate?.(data)
				},
				// onClose → 自动重连（指数退避）
				() => {
					if (!wsMap.value[taskId]) return  // 已手动 unsubscribe
					if (retries < maxRetries) {
						retries++
						const delay = Math.min(1000 * 2 ** retries, 30000)
						setTimeout(connect, delay)
					} else {
						// 重连耗尽，拉一次最终状态
						api.getTask(taskId).then(updateTask).catch(() => {})
					}
				}
			)
			wsMap.value[taskId] = { ws: entry, seenLogs }
		}

		connect()
		return () => unsubscribeTask(taskId)
	}

	function unsubscribeTask(taskId) {
		wsMap.value[taskId]?.ws?.close()
		delete wsMap.value[taskId]
	}

	return {
		tasks, loading,
		fetchTasks, createTask, updateTask, removeTask,
		subscribeTask, unsubscribeTask,
	}
})