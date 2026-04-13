import { defineStore } from 'pinia'
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { subscribeTaskEvents } from '@/services/wsManager'
import { useTaskListStore } from '@/stores/taskList'
import type { DecisionEvent, TaskDetail, WsTaskEvent } from '@/types/task'

type ApprovalState = 'idle' | 'submitting' | 'submitted' | 'error'

interface TaskLiveState {
  task: TaskDetail | null
  logs: string[]
  logSet: Set<string>
  events: WsTaskEvent[]
  decisionEvents: DecisionEvent[]
  decisionEventIds: Set<string>
  approvalState: ApprovalState
  approvalNonce: string
  approvalSubmittedAt: number
  lastWsUpdate: number
  unsub?: () => void
}

export const useTaskLiveStore = defineStore('taskLive', () => {
  const taskStateMap = ref<Record<string, TaskLiveState>>({})
  const taskListStore = useTaskListStore()

  const APPROVAL_PROTECTION_MS = 5000

  function ensureState(taskId: string): TaskLiveState {
    if (!taskStateMap.value[taskId]) {
      taskStateMap.value[taskId] = {
        task: null,
        logs: [],
        logSet: new Set<string>(),
        events: [],
        decisionEvents: [],
        decisionEventIds: new Set<string>(),
        approvalState: 'idle',
        approvalNonce: '',
        approvalSubmittedAt: 0,
        lastWsUpdate: 0,
      }
    }
    return taskStateMap.value[taskId]
  }

  function pushLog(state: TaskLiveState, line: string) {
    if (!line || state.logSet.has(line)) return
    state.logSet.add(line)
    state.logs.push(line)
  }

  function mergeDecisionEvents(state: TaskLiveState, incoming: DecisionEvent[] = []) {
    if (!Array.isArray(incoming) || !incoming.length) return
    for (const event of incoming) {
      const id = String(event?.id || '')
      if (!id || state.decisionEventIds.has(id)) continue
      state.decisionEventIds.add(id)
      state.decisionEvents.push(event)
    }
    state.decisionEvents.sort((a, b) => String(a?.timestamp || '').localeCompare(String(b?.timestamp || '')))
  }

  async function refreshTask(taskId: string) {
    const full = await api.getTask(taskId)
    const state = ensureState(taskId)
    mergeDecisionEvents(state, full.decision_events || [])

    const apiTime = full.updated_at ?? ''
    const localTime = state.task?.updated_at ?? ''
    const wsRecent = Date.now() - state.lastWsUpdate < 4000

    if (!state.task || (!wsRecent && apiTime >= localTime)) {
      state.task = { ...full, decision_events: state.decisionEvents.slice() }
    } else {
      state.task = {
        ...state.task,
        findings: full.findings ?? state.task.findings,
        report_path: full.report_path ?? state.task.report_path,
        decision_events: state.decisionEvents.slice(),
      }
    }

    for (const line of (full.phase_log || [])) {
      pushLog(state, line)
    }
    taskListStore.upsertTask(full)
    return full
  }

  async function attach(taskId: string) {
    const state = ensureState(taskId)
    if (state.unsub) return

    state.unsub = subscribeTaskEvents(taskId, (event) => {
      state.events.push(event)
      if ((event as { type?: string }).type === 'log') {
        const line = String((event as { data?: string }).data || '')
        pushLog(state, line)
      }
      if ((event as { type?: string }).type === 'decision_event') {
        const payload = (event as { data?: DecisionEvent }).data
        if (payload && typeof payload === 'object') {
          mergeDecisionEvents(state, [payload])
          if (state.task) {
            state.task = {
              ...state.task,
              decision_events: state.decisionEvents.slice(),
            }
          }
        }
      }
      if ((event as { type?: string }).type === 'phase_update') {
        state.lastWsUpdate = Date.now()
        const patch = event as {
          phase?: string
          status?: string
          findings_count?: number
          got_shell?: boolean
          logs?: string[]
          privilege_level?: string
          foothold_status?: string
          chain_visited?: string[]
          secondary_elided?: boolean
          attack_next_steps?: { stage?: string; action?: string; priority?: number }[]
          privesc_attempt_count?: number
        }
        taskListStore.upsertTask({
          task_id: taskId,
          current_phase: patch.phase,
          status: patch.status as TaskDetail['status'],
          findings_count: patch.findings_count,
          got_shell: patch.got_shell,
        })
        if (state.task && patch.phase) {
          const prevPhase = state.task.current_phase
          state.task = {
            ...state.task,
            current_phase: patch.phase,
            status: (patch.status as TaskDetail['status']) ?? state.task.status,
            got_shell: patch.got_shell ?? state.task.got_shell,
            privilege_level: patch.privilege_level ?? state.task.privilege_level,
            foothold_status: patch.foothold_status ?? state.task.foothold_status,
            chain_visited: patch.chain_visited ?? state.task.chain_visited,
            secondary_elided: patch.secondary_elided ?? state.task.secondary_elided,
            attack_next_steps: patch.attack_next_steps ?? state.task.attack_next_steps,
            privesc_attempt_count: patch.privesc_attempt_count ?? state.task.privesc_attempt_count,
          }
          if (prevPhase === 'awaiting_approval' && patch.phase !== 'awaiting_approval') {
            state.approvalState = 'idle'
          }
        }
        if (patch.logs?.length) {
          for (const line of patch.logs) {
            pushLog(state, line)
          }
        }
      }
      if ((event as { type?: string }).type === 'approval_required') {
        state.lastWsUpdate = Date.now()
        const incomingNonce = (event as { nonce?: string }).nonce || `ar-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
        taskListStore.upsertTask({ task_id: taskId, current_phase: 'awaiting_approval', status: 'running' })
        if (state.task) {
          state.task = { ...state.task, current_phase: 'awaiting_approval' }
        }

        const withinProtection = Date.now() - state.approvalSubmittedAt < APPROVAL_PROTECTION_MS
        if (state.approvalState === 'submitted' && !withinProtection) {
          state.approvalNonce = incomingNonce
          state.approvalState = 'idle'
        } else if (state.approvalState === 'idle') {
          state.approvalNonce = incomingNonce
        }

        const approvalEvent: DecisionEvent = {
          id: `approval-req-${taskId}-${incomingNonce}`,
          timestamp: new Date().toLocaleTimeString(),
          phase: 'awaiting_approval',
          action: 'approval_required',
          message: '系统检测到可利用路径，等待人工审批。',
          tone: 'warning',
        } as DecisionEvent
        mergeDecisionEvents(state, [approvalEvent])
        if (state.task) {
          state.task = { ...state.task, decision_events: state.decisionEvents.slice() }
        }
      }
      if ((event as { type?: string }).type === 'done') {
        refreshTask(taskId).catch(() => {})
      }
    })
  }

  function detach(taskId: string) {
    const state = taskStateMap.value[taskId]
    if (!state) return
    state.unsub?.()
    delete state.unsub
  }

  function clear(taskId: string) {
    detach(taskId)
    delete taskStateMap.value[taskId]
  }

  function getLiveState(taskId: string): TaskLiveState {
    return ensureState(taskId)
  }

  async function submitApproval(taskId: string, approved: boolean) {
    const s = ensureState(taskId)
    if (s.approvalState !== 'idle') return
    s.approvalState = 'submitting'
    try {
      await api.approveTask(taskId, approved)
      s.approvalState = 'submitted'
      s.approvalSubmittedAt = Date.now()
      ElMessage.success(approved ? '已批准继续利用' : '已拒绝利用阶段')
    } catch (e: unknown) {
      const detail = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      const msg = detail || (e as Error)?.message || '审批失败'
      if (detail && /已在执行/.test(detail)) {
        s.approvalState = 'submitted'
        s.approvalSubmittedAt = Date.now()
        ElMessage.info('审批已在执行中')
      } else {
        s.approvalState = 'error'
        ElMessage.error(msg)
        setTimeout(() => { s.approvalState = 'idle' }, 3000)
      }
    }
  }

  return {
    taskStateMap,
    ensureState,
    refreshTask,
    attach,
    detach,
    clear,
    getLiveState,
    submitApproval,
  }
})
