import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api'
import { subscribeTaskEvents } from '@/services/wsManager'
import { useTaskListStore } from '@/stores/taskList'
import type { DecisionEvent, TaskDetail, WsTaskEvent } from '@/types/task'

interface TaskLiveState {
  task: TaskDetail | null
  logs: string[]
  logSet: Set<string>
  events: WsTaskEvent[]
  decisionEvents: DecisionEvent[]
  decisionEventIds: Set<string>
  unsub?: () => void
}

export const useTaskLiveStore = defineStore('taskLive', () => {
  const taskStateMap = ref<Record<string, TaskLiveState>>({})
  const taskListStore = useTaskListStore()

  function ensureState(taskId: string): TaskLiveState {
    if (!taskStateMap.value[taskId]) {
      taskStateMap.value[taskId] = {
        task: null,
        logs: [],
        logSet: new Set<string>(),
        events: [],
        decisionEvents: [],
        decisionEventIds: new Set<string>(),
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
    state.task = {
      ...full,
      decision_events: state.decisionEvents.slice(),
    }
    const freshLogs = full.phase_log || []
    for (const line of freshLogs) {
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
        }
        if (patch.logs?.length) {
          for (const line of patch.logs) {
            pushLog(state, line)
          }
        }
      }
      if ((event as { type?: string }).type === 'approval_required') {
        taskListStore.upsertTask({ task_id: taskId, current_phase: 'awaiting_approval', status: 'running' })
        if (state.task) {
          state.task = { ...state.task, current_phase: 'awaiting_approval' }
        }
        const approvalEvent: DecisionEvent = {
          id: `approval-req-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          phase: 'awaiting_approval',
          action: 'approval_required',
          message: '系统检测到可利用路径，等待人工审批。',
          tone: 'warning',
          findings_count: (event as { findings_count?: number }).findings_count,
          exploitable_count: (event as { exploitable_count?: number }).exploitable_count,
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

  return {
    taskStateMap,
    ensureState,
    refreshTask,
    attach,
    detach,
    clear,
    getLiveState,
  }
})
