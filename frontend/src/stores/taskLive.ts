import { defineStore } from 'pinia'
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { subscribeTaskEvents } from '@/services/wsManager'
import { loadEvents } from '@/services/eventStore'
import { useTaskListStore } from '@/stores/taskList'
import type {
  ApprovalTarget,
  BranchTreeItem,
  CheckpointPayload,
  DecisionEvent,
  TaskBranch,
  TaskDetail,
} from '@/types/task'

type ApprovalState = 'idle' | 'submitting' | 'submitted' | 'error'
type CheckpointState = 'idle' | 'submitting' | 'submitted' | 'error'

// ── 有界缓存阈值 ───────────────────────────────────────
const MAX_LOG_BUFFER = 1000
const MAX_DECISION_EVENTS = 1000
const MAX_TOOL_STREAM_LINES = 200

// ── Token 流式刷新：全局 rAF 循环，每帧 flush，视觉与显示器刷新对齐 ──
// key = "${taskId}::${streamId}", 避免同任务多流碰撞
const DELTA_BATCH_MS = 16
const _deltaBufs: Record<string, { taskId: string; sid: string; phase: string; kind: string; text: string }> = {}
let _deltaRafId: number | null = null

function _flushDeltas() {
  _deltaRafId = null
  const now = Date.now()
  const stateMap = taskStateMap.value
  for (const [key, buf] of Object.entries(_deltaBufs)) {
    if (!buf.text) continue
    const state = stateMap[buf.taskId]
    if (!state) { delete _deltaBufs[key]; continue }
    const sid = buf.sid
    if (!state.llmStreams[sid]) {
      state.llmStreams[sid] = { streamId: sid, phase: buf.phase, kind: buf.kind, text: '', updatedAt: now }
    }
    state.llmStreams[sid].text += buf.text
    state.llmStreams[sid].updatedAt = now
    delete _deltaBufs[key]
  }
}

function _scheduleDeltaFlush() {
  if (_deltaRafId !== null) return
  _deltaRafId = requestAnimationFrame(() => _flushDeltas())
}

interface LlmStreamBubble {
  streamId: string
  phase: string
  kind: string
  text: string
  updatedAt: number
}

interface TaskLiveState {
  task: TaskDetail | null
  taskUpdatedAt: number
  logs: string[]
  logSet: Set<string>
  logTotal: number
  logEarliestSeq: number
  decisionEvents: DecisionEvent[]
  decisionEventIds: Set<string>
  /** 已收到的最大 event.id（Redis Stream ID 字典序单调），用于增量追加时免排序。 */
  lastDecisionEventId: string
  llmStreams: Record<string, LlmStreamBubble>
  toolStreams: Record<string, string[]>
  approvalState: ApprovalState
  approvalNonce: string
  approvalSubmittedAt: number
  lastWsUpdate: number
  pendingCheckpoint: CheckpointPayload | null
  checkpointHistory: CheckpointPayload[]
  checkpointState: CheckpointState
  branches: BranchTreeItem[]
  activeBranchId: string
  maxBranchesPerTask: number
  branchFlashAt: number
  unsub?: () => void
  _everAttached: boolean
  /** phase_update 节流：100ms 内多次 patch 合并为一次 state.task 更新 */
  _phasePatchPending?: Record<string, unknown>
  _phasePatchTimer?: number | null
}

export const useTaskLiveStore = defineStore('taskLive', () => {
  const taskStateMap = ref<Record<string, TaskLiveState>>({})
  const taskListStore = useTaskListStore()

  const APPROVAL_PROTECTION_MS = 5000

  function ensureState(taskId: string): TaskLiveState {
    if (!taskStateMap.value[taskId]) {
      taskStateMap.value[taskId] = {
        task: null,
        taskUpdatedAt: 0,
        logs: [],
        logSet: new Set<string>(),
        logTotal: 0,
        logEarliestSeq: 0,
        decisionEvents: [],
        decisionEventIds: new Set<string>(),
        lastDecisionEventId: '',
        llmStreams: {},
        toolStreams: {},
        approvalState: 'idle',
        approvalNonce: '',
        approvalSubmittedAt: 0,
        lastWsUpdate: 0,
        pendingCheckpoint: null,
        checkpointHistory: [],
        checkpointState: 'idle',
        branches: [],
        activeBranchId: '',
        maxBranchesPerTask: 12,
        branchFlashAt: 0,
        _everAttached: false,
        _phasePatchPending: undefined,
        _phasePatchTimer: null,
      }
    }
    return taskStateMap.value[taskId]
  }

  // ── 分支树工具 ────────────────────────────────────────
  function computeSiblingTotals(items: BranchTreeItem[]): BranchTreeItem[] {
    const groups = new Map<string, BranchTreeItem[]>()
    for (const it of items) {
      const key = `${it.parent_branch_id ?? ''}::${it.fork_event_id ?? ''}`
      if (!groups.has(key)) groups.set(key, [])
      groups.get(key)!.push(it)
    }
    for (const arr of groups.values()) {
      arr.sort((a, b) => (a.created_at || '').localeCompare(b.created_at || ''))
      arr.forEach((it, idx) => {
        it.sibling_index = idx + 1
        it.sibling_total = arr.length
      })
    }
    return items
  }

  function upsertBranch(state: TaskLiveState, raw: TaskBranch | BranchTreeItem) {
    if (!raw?.branch_id) return
    const idx = state.branches.findIndex((b) => b.branch_id === raw.branch_id)
    const baseItem: BranchTreeItem = {
      branch_id: raw.branch_id,
      task_id: raw.task_id,
      parent_branch_id: raw.parent_branch_id ?? null,
      fork_event_id: raw.fork_event_id ?? null,
      fork_phase: raw.fork_phase || '',
      fork_round: raw.fork_round ?? null,
      thread_id: raw.thread_id || '',
      status: raw.status,
      label: raw.label || '',
      initiating_prompt: raw.initiating_prompt || '',
      is_root: Boolean(raw.is_root),
      created_at: raw.created_at || '',
      updated_at: raw.updated_at || '',
      sibling_index: (raw as BranchTreeItem).sibling_index ?? 1,
      sibling_total: (raw as BranchTreeItem).sibling_total ?? 1,
      is_active: Boolean((raw as BranchTreeItem).is_active),
      children: (raw as BranchTreeItem).children ?? [],
    }
    if (idx >= 0) {
      state.branches.splice(idx, 1, { ...state.branches[idx], ...baseItem })
    } else {
      state.branches.push(baseItem)
    }
    computeSiblingTotals(state.branches)
  }

  function setActiveBranch(state: TaskLiveState, branchId: string) {
    if (!branchId) return
    state.activeBranchId = branchId
    for (const b of state.branches) {
      b.is_active = b.branch_id === branchId
    }
  }

  async function refreshBranches(taskId: string) {
    const state = ensureState(taskId)
    try {
      const tree = await api.listBranches(taskId)
      state.branches = computeSiblingTotals([...(tree.branches || [])])
      state.activeBranchId = tree.active_branch_id || state.activeBranchId
      state.maxBranchesPerTask = tree.max_branches_per_task || state.maxBranchesPerTask
      for (const b of state.branches) {
        b.is_active = b.branch_id === state.activeBranchId
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.debug('[taskLive] refreshBranches failed', e)
    }
  }

  async function activateBranch(taskId: string, branchId: string) {
    const state = ensureState(taskId)
    try {
      const res = await api.activateBranch(taskId, branchId)
      upsertBranch(state, res.branch)
      setActiveBranch(state, branchId)
      try { await refreshTask(taskId) } catch { /* 静默失败, ws 后续会补齐 */ }
      ElMessage.success('已切换分支')
    } catch (e) {
      ElMessage.error('切换分支失败')
      throw e
    }
  }

  async function resumeBranch(taskId: string, branchId: string) {
    const state = ensureState(taskId)
    try {
      const res = await api.resumeBranch(taskId, branchId)
      upsertBranch(state, res.branch)
      setActiveBranch(state, branchId)
      try { await refreshTask(taskId) } catch { /* idem */ }
      ElMessage.success('已恢复分支运行')
    } catch (e) {
      ElMessage.error('恢复分支失败')
      throw e
    }
  }

  async function pauseBranch(taskId: string, branchId: string) {
    const state = ensureState(taskId)
    try {
      const res = await api.pauseBranch(taskId, branchId)
      upsertBranch(state, res.branch)
    } catch (e) {
      ElMessage.error('暂停分支失败')
      throw e
    }
  }

  // ── checkpoint helpers ─────────────────────────────────
  function decisionEventToCheckpoint(event: DecisionEvent): CheckpointPayload | null {
    const cpId = String((event as { checkpoint_id?: string }).checkpoint_id || '')
    if (!cpId) return null
    return {
      checkpoint_id: cpId,
      checkpoint_type: String((event as { checkpoint_type?: string }).checkpoint_type || 'generic'),
      phase: event.phase || '',
      status: 'pending',
      created_at: event.timestamp || new Date().toISOString(),
      thinking: (event as { thinking?: string }).thinking || '',
      summary: (event as { summary?: string }).summary || event.message || '',
      recommendation: (event as { recommendation?: string }).recommendation || '',
      risk: (event as { risk?: string }).risk || '',
      requires_input: Boolean((event as { requires_input?: boolean }).requires_input),
      default_action:
        ((event as { default_action?: string }).default_action as CheckpointPayload['default_action']) ||
        'approve',
      options: ((event as { options?: CheckpointPayload['options'] }).options) || [],
      context: ((event as { context?: Record<string, unknown> }).context) || {},
    }
  }

  function archiveCheckpoint(state: TaskLiveState, archived: CheckpointPayload) {
    if (!archived?.checkpoint_id) return
    const idx = state.checkpointHistory.findIndex(
      (h) => h.checkpoint_id === archived.checkpoint_id,
    )
    if (idx >= 0) {
      state.checkpointHistory.splice(idx, 1, archived)
    } else {
      state.checkpointHistory.push(archived)
    }
    if (state.checkpointHistory.length > 50) {
      state.checkpointHistory.splice(0, state.checkpointHistory.length - 50)
    }
  }

  function applyCheckpointRequest(state: TaskLiveState, event: DecisionEvent) {
    const ckpt = decisionEventToCheckpoint(event)
    if (!ckpt) return
    const archived = state.checkpointHistory.find(
      (h) => h.checkpoint_id === ckpt.checkpoint_id && h.status === 'resolved',
    )
    if (archived) return
    state.pendingCheckpoint = ckpt
    if (state.checkpointState === 'submitting' || state.checkpointState === 'submitted') {
      state.checkpointState = 'idle'
    }
  }

  function applyCheckpointResolved(state: TaskLiveState, event: DecisionEvent) {
    const cpId = String((event as { checkpoint_id?: string }).checkpoint_id || '')
    if (!cpId) return
    const base =
      state.pendingCheckpoint && state.pendingCheckpoint.checkpoint_id === cpId
        ? state.pendingCheckpoint
        : state.checkpointHistory.find((h) => h.checkpoint_id === cpId)
    const archived: CheckpointPayload = {
      checkpoint_id: cpId,
      checkpoint_type:
        String((event as { checkpoint_type?: string }).checkpoint_type || base?.checkpoint_type || 'generic'),
      phase: event.phase || base?.phase || '',
      status: 'resolved',
      created_at: base?.created_at || '',
      resolved_at: event.timestamp || new Date().toISOString(),
      thinking: base?.thinking || '',
      summary: base?.summary || '',
      recommendation: base?.recommendation || '',
      risk: base?.risk || '',
      requires_input: base?.requires_input,
      default_action: base?.default_action,
      options: base?.options || [],
      context: base?.context || {},
      response: ((event as { response?: CheckpointPayload['response'] }).response) || base?.response,
    }
    archiveCheckpoint(state, archived)
    if (state.pendingCheckpoint?.checkpoint_id === cpId) {
      state.pendingCheckpoint = null
    }
    if (state.checkpointState === 'submitting') {
      state.checkpointState = 'submitted'
    }
  }

  function syncCheckpointFromSnapshot(
    state: TaskLiveState,
    pending: CheckpointPayload | null | undefined,
    history: CheckpointPayload[] | undefined,
  ) {
    if (Array.isArray(history)) {
      for (const item of history) {
        if (!item?.checkpoint_id) continue
        archiveCheckpoint(state, item)
      }
    }
    if (pending && pending.checkpoint_id) {
      const archived = state.checkpointHistory.find(
        (h) => h.checkpoint_id === pending.checkpoint_id && h.status === 'resolved',
      )
      if (!archived) {
        state.pendingCheckpoint = { ...pending, status: 'pending' }
      } else {
        state.pendingCheckpoint = null
      }
    } else if (state.pendingCheckpoint) {
      state.pendingCheckpoint = null
    }
  }

  function pushLog(state: TaskLiveState, line: string) {
    if (!line || state.logSet.has(line)) return
    state.logSet.add(line)
    state.logs.push(line)
    if (state.logs.length > MAX_LOG_BUFFER) {
      const drop = state.logs.length - MAX_LOG_BUFFER
      const evicted = state.logs.splice(0, drop)
      for (const l of evicted) state.logSet.delete(l)
    }
  }

  // ── 协议 v2: 增量单调追加 (Redis Stream ID 天然字典序递增) ──
  function mergeDecisionEvents(state: TaskLiveState, incoming: DecisionEvent[] = [], _preSorted = false) {
    if (!Array.isArray(incoming) || !incoming.length) return
    const newEvents: DecisionEvent[] = []
    let allMonotonic = true
    for (const event of incoming) {
      const id = String(event?.id || '')
      if (!id || state.decisionEventIds.has(id)) continue
      state.decisionEventIds.add(id)
      newEvents.push(event)
      if (id > state.lastDecisionEventId) {
        state.lastDecisionEventId = id
      } else {
        allMonotonic = false
      }
    }
    if (!newEvents.length) return
    if (allMonotonic && state.decisionEvents.length > 0) {
      //  fast path: 所有新事件 ID 都大于已有最大值，直接 push，O(k)
      state.decisionEvents.push(...newEvents)
    } else {
      // slow path: 存在乱序或空数组初始化，合入后一次性排序
      state.decisionEvents.push(...newEvents)
      state.decisionEvents.sort((a, b) => {
        const aid = String(a?.id || '')
        const bid = String(b?.id || '')
        return aid < bid ? -1 : aid > bid ? 1 : 0
      })
      const last = state.decisionEvents[state.decisionEvents.length - 1]
      state.lastDecisionEventId = String(last?.id || '')
    }
    if (state.decisionEvents.length > MAX_DECISION_EVENTS) {
      const drop = state.decisionEvents.length - MAX_DECISION_EVENTS
      const evicted = state.decisionEvents.splice(0, drop)
      for (const ev of evicted) state.decisionEventIds.delete(String(ev?.id || ''))
    }
  }

  function pushToolStreamLine(state: TaskLiveState, sid: string, line: string) {
    if (!state.toolStreams[sid]) state.toolStreams[sid] = []
    const arr = state.toolStreams[sid]
    arr.push(line)
    if (arr.length > MAX_TOOL_STREAM_LINES) {
      arr.splice(0, arr.length - MAX_TOOL_STREAM_LINES)
    }
  }

  async function refreshTask(taskId: string) {
    const full = await api.getTask(taskId)
    const state = ensureState(taskId)
    mergeDecisionEvents(state, full.decision_events_tail || full.decision_events || [])

    // 安全网: 快照 tail 只回填最近 120 条，若事件总数更大则从 REST /events
    // 补差量，避免页面刷新后 IndexedDB 冷启动 + WS 首帧未到达时出现空白时间线。
    // 从 Stream 头部开始拉 (after_id 为空)，mergeDecisionEvents 会自动按 id 去重。
    const expectedTotal = full.decision_events_total ?? 0
    if (state.decisionEvents.length < expectedTotal && expectedTotal > 0) {
      try {
        const page = await api.getEvents(taskId, { count: 1000 })
        if (page.events?.length) {
          const dEvents: DecisionEvent[] = []
          for (const ev of page.events) {
            const p = (ev.payload || {}) as Record<string, unknown>
            dEvents.push({
              id: String((ev as any).id || ''),
              timestamp: String((ev as any).ts || (ev as any).timestamp || ''),
              ...p,
            } as DecisionEvent)
          }
          if (dEvents.length) mergeDecisionEvents(state, dEvents)
        }
      } catch {
        // 非关键路径
      }
    }

    syncCheckpointFromSnapshot(
      state,
      (full.pending_checkpoint as CheckpointPayload | null | undefined) ?? null,
      (full.checkpoint_history as CheckpointPayload[] | undefined) ?? [],
    )

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
        report_available: full.report_available ?? state.task.report_available,
        phase_log_total: full.phase_log_total ?? state.task.phase_log_total,
        decision_events_total: full.decision_events_total ?? state.task.decision_events_total,
        decision_events: state.decisionEvents.slice(),
        pending_checkpoint: full.pending_checkpoint ?? state.task.pending_checkpoint,
        checkpoint_history: full.checkpoint_history ?? state.task.checkpoint_history,
        pending_user_prompt: full.pending_user_prompt ?? state.task.pending_user_prompt,
        pentest_plan: full.pentest_plan ?? state.task.pentest_plan,
        parsed_intent: full.parsed_intent ?? state.task.parsed_intent,
        attack_graph: full.attack_graph ?? state.task.attack_graph,
      }
    }

    const tail = (full.phase_log_tail && full.phase_log_tail.length)
      ? full.phase_log_tail
      : (full.phase_log || [])
    for (const line of tail) {
      pushLog(state, line)
    }
    if (typeof full.phase_log_total === 'number') {
      state.logTotal = full.phase_log_total
      const tailLen = tail.length
      const minEarliest = Math.max(0, full.phase_log_total - tailLen)
      state.logEarliestSeq = state.logEarliestSeq
        ? Math.min(state.logEarliestSeq, minEarliest)
        : minEarliest
    }
    taskListStore.upsertTask(full)
    state.taskUpdatedAt = Date.now()
    return full
  }

  async function loadEarlierLogs(taskId: string, count = 500): Promise<number> {
    const state = ensureState(taskId)
    if (state.logEarliestSeq <= 0) return 0
    const end = state.logEarliestSeq
    const start = Math.max(0, end - count)
    if (end <= start) return 0
    try {
      const page = await api.getLogs(taskId, { offset: start, limit: end - start })
      const logs = Array.isArray(page.logs) ? page.logs : []
      for (let i = logs.length - 1; i >= 0; i--) {
        const line = logs[i]
        if (!line || state.logSet.has(line)) continue
        state.logSet.add(line)
        state.logs.unshift(line)
      }
      if (state.logs.length > MAX_LOG_BUFFER) {
        const drop = state.logs.length - MAX_LOG_BUFFER
        const evicted = state.logs.splice(state.logs.length - drop, drop)
        for (const l of evicted) state.logSet.delete(l)
      }
      state.logEarliestSeq = page.offset
      if (typeof page.total === 'number') state.logTotal = page.total
      return logs.length
    } catch {
      return 0
    }
  }

  // ── phase_update 实际应用（被节流器调用）────────────────
  function _applyPhaseUpdate(state: TaskLiveState, taskId: string, p: Record<string, unknown>) {
    const patch = {
      phase: String(p.phase || ''),
      status: String(p.status || ''),
      findings_count: Number(p.findings_count || 0),
      got_shell: Boolean(p.got_shell),
      privilege_level: String(p.privilege_level || ''),
      foothold_status: String(p.foothold_status || ''),
      chain_visited: (p.chain_visited || []) as string[],
      secondary_elided: Boolean(p.secondary_elided),
      attack_next_steps: (p.attack_next_steps || []) as { stage?: string; action?: string; priority?: number }[],
      privesc_attempt_count: Number(p.privesc_attempt_count || 0),
      branch_id: String(p.branch_id || ''),
      attack_graph: p.attack_graph as TaskDetail['attack_graph'] | undefined,
      chain_template: p.chain_template as TaskDetail['chain_template'] | undefined,
    }

    const updateBid = patch.branch_id
    const sameBranch = !updateBid || !state.activeBranchId || updateBid === state.activeBranchId
    if (!sameBranch) return

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
        attack_graph: (patch.attack_graph as TaskDetail['attack_graph']) ?? state.task.attack_graph,
        chain_template: (patch.chain_template as TaskDetail['chain_template']) ?? state.task.chain_template,
      }
      if (prevPhase !== 'awaiting_approval' && patch.phase === 'awaiting_approval') {
        state.approvalState = 'idle'
      }
      if (prevPhase === 'awaiting_approval' && patch.phase !== 'awaiting_approval') {
        state.approvalState = 'idle'
        const removed = new Set<string>()
        state.decisionEvents = state.decisionEvents.filter((ev) => {
          if (ev.action === 'approval_required' || ev.action === 'approval') {
            removed.add(String(ev.id || ''))
            state.decisionEventIds.delete(String(ev.id || ''))
            return false
          }
          return true
        })
        if (removed.size > 0 && state.task) {
          state.task = { ...state.task, decision_events: state.decisionEvents.slice() }
        }
      }
    }
  }

  // ── 协议 v2: 统一事件入口 applyEvent ──────────────────
  function applyEvent(state: TaskLiveState, taskId: string, raw: Record<string, unknown>) {
    const eventType = String(raw.type || '')

    // ── 历史回放 (v2 history 帧) ──────────────────────
    if (eventType === 'history') {
      const events = (raw.events || []) as Record<string, unknown>[]
      const dEvents: DecisionEvent[] = []
      for (const ev of events) {
        const et = String(ev.type || '')
        if (et === 'log') {
          const p = (ev.payload || {}) as { line?: string; seq?: number }
          if (p.line) pushLog(state, p.line)
          if (typeof p.seq === 'number') {
            state.logTotal = Math.max(state.logTotal, p.seq + 1)
          }
        } else if (et === 'decision_event') {
          const p = (ev.payload || {}) as Record<string, unknown>
          const de = { id: String(ev.id || ''), timestamp: String(ev.ts || ''), ...p } as DecisionEvent
          dEvents.push(de)
          const action = String(p.action || '')
          if (action === 'checkpoint_request') applyCheckpointRequest(state, de)
          if (action === 'checkpoint_resolved') applyCheckpointResolved(state, de)
        }
      }
      if (dEvents.length) {
        mergeDecisionEvents(state, dEvents)
        if (state.task) {
          state.task = {
            ...state.task,
            decision_events: state.decisionEvents.slice(),
            pending_checkpoint: state.pendingCheckpoint,
            checkpoint_history: state.checkpointHistory.slice(),
          }
        }
      }
      return
    }

    // ── 单条日志 (v2 log envelope) ────────────────────
    if (eventType === 'log') {
      state.lastWsUpdate = Date.now()
      const p = (raw.payload || {}) as { line?: string; seq?: number }
      if (p.line) pushLog(state, p.line)
      if (typeof p.seq === 'number') {
        state.logTotal = Math.max(state.logTotal, p.seq + 1)
      } else {
        state.logTotal = state.logTotal + 1
      }
      return
    }

    // ── 决策事件 (v2 decision_event envelope) ─────────
    if (eventType === 'decision_event') {
      state.lastWsUpdate = Date.now()
      const p = (raw.payload || {}) as Record<string, unknown>
      const de = {
        id: String(raw.id || ''),
        timestamp: String(raw.ts || ''),
        branch_id: String(raw.branch_id || ''),
        ...p,
      } as DecisionEvent

      const action = String(p.action || '')

      if (action === 'llm_delta') {
        const sid = (p.stream_id as string) || 'default'
        const delta = (p.delta as string) || ''
        if (!delta) return
        const phase = (p.phase as string) || ''
        const kind = (p.kind as string) || 'content'
        // 批处理：合并 80ms 窗口内的 delta，减少 Vue 重渲染次数
        const bufKey = `${taskId}::${sid}`
        if (!_deltaBufs[bufKey]) {
          _deltaBufs[bufKey] = { taskId, sid, phase, kind, text: '' }
        }
        _deltaBufs[bufKey].text += delta
        _deltaBufs[bufKey].phase = phase || _deltaBufs[bufKey].phase
        _deltaBufs[bufKey].kind = kind || _deltaBufs[bufKey].kind
        // 首次创建 stream bubble 时同步初始化，避免 UI 闪现空 bubble
        if (!state.llmStreams[sid]) {
          state.llmStreams[sid] = { streamId: sid, phase, kind, text: '', updatedAt: Date.now() }
        }
        _scheduleDeltaFlush()
      } else if (action === 'tool_stream') {
        const sid = (p.stream_id as string) || 'default'
        const line = (p.line as string) || ''
        // 后端窗口合并后 line 可能是多行 \n 连接, 拆开保持每行一条渲染
        for (const ln of line.split('\n')) pushToolStreamLine(state, sid, ln)
      } else {
        mergeDecisionEvents(state, [de])
        if (action === 'checkpoint_request') {
          applyCheckpointRequest(state, de)
        } else if (action === 'checkpoint_resolved') {
          applyCheckpointResolved(state, de)
        }
      }
      return
    }

    // ── 阶段更新 (v2 phase_update envelope) ───────────
    if (eventType === 'phase_update') {
      state.lastWsUpdate = Date.now()
      const p = (raw.payload || {}) as Record<string, unknown>
      const logs = (p.logs || []) as string[]
      if (logs.length) {
        for (const line of logs) pushLog(state, line)
      }
      // 节流: 100ms 内多次 phase_update 合并为一次昂贵的 state.task 更新
      if (!state._phasePatchPending) state._phasePatchPending = {}
      Object.assign(state._phasePatchPending, p)
      delete state._phasePatchPending.logs
      if (!state._phasePatchTimer) {
        state._phasePatchTimer = window.setTimeout(() => {
          state._phasePatchTimer = null
          const patch = state._phasePatchPending
          state._phasePatchPending = undefined
          if (patch) _applyPhaseUpdate(state, taskId, patch)
        }, 100)
      }
      return
    }

    // ── 攻击图增量更新 (v2 attack_graph envelope) ─────
    // phase_update 不再携带 attack_graph, 改为仅在图节点/边变化时单独推送。
    if (eventType === 'attack_graph') {
      const p = (raw.payload || {}) as TaskDetail['attack_graph']
      if (state.task && p) {
        state.task = { ...state.task, attack_graph: p }
      }
      return
    }

    // ── 等待审批 (v2 approval_required envelope) ──────
    if (eventType === 'approval_required') {
      state.lastWsUpdate = Date.now()
      const incomingNonce = `ar-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
      taskListStore.upsertTask({ task_id: taskId, current_phase: 'awaiting_approval', status: 'running' })
      if (state.task) {
        state.task = { ...state.task, current_phase: 'awaiting_approval' }
      }

      const withinProtection = state.approvalNonce && incomingNonce === state.approvalNonce
        && Date.now() - state.approvalSubmittedAt < APPROVAL_PROTECTION_MS
      if (state.approvalState === 'submitted' && withinProtection) {
        // same nonce still in protection window, ignore duplicate
      } else if (state.approvalState === 'submitted' && !withinProtection) {
        state.approvalNonce = incomingNonce
        state.approvalState = 'idle'
      } else {
        state.approvalNonce = incomingNonce
        state.approvalState = 'idle'
      }

      const p = (raw.payload || {}) as Record<string, unknown>
      const serverIso = String(p.server_iso || '')
      const exploitableCount = Number(p.exploitable_count ?? 0)
      const topTargets = (p.top_targets as ApprovalTarget[]) || []
      const risk = String(p.risk || '')
      const targetsSummary = topTargets.slice(0, 3)
        .map((t) => `${t.severity?.toUpperCase?.() || '?'} | ${t.name}${t.cve ? ` (${t.cve})` : ''}`)
        .join('\n')
      const message = exploitableCount > 0
        ? `系统已识别 ${exploitableCount} 个可利用漏洞，等待你的授权再开始利用。` + (targetsSummary ? `\n\n待利用目标:\n${targetsSummary}` : '')
        : '系统检测到可利用路径，等待人工审批。'
      const approvalEvent: DecisionEvent = {
        id: String(raw.id || `approval-req-${taskId}-${incomingNonce}`),
        timestamp: serverIso || String(raw.ts || new Date().toISOString()),
        phase: 'awaiting_approval',
        action: 'approval_required',
        message,
        tone: 'warning',
        exploitable_count: exploitableCount,
        top_targets: topTargets,
        risk,
      } as DecisionEvent
      mergeDecisionEvents(state, [approvalEvent])
      if (state.task) {
        state.task = { ...state.task, decision_events: state.decisionEvents.slice() }
      }
      return
    }

    // ── 任务结束 (v2 done envelope) ────────────────────
    if (eventType === 'done') {
      refreshTask(taskId).catch(() => {})
      return
    }

    // ── 分支事件 (v2) ─────────────────────────────────
    if (eventType === 'branch_forked') {
      const p = (raw.payload || {}) as Record<string, unknown>
      if (p.parent) upsertBranch(state, { ...(p.parent as TaskBranch), status: 'paused' })
      if (p.branch) {
        upsertBranch(state, p.branch as TaskBranch)
        setActiveBranch(state, (p.branch as TaskBranch).branch_id)
        state.branchFlashAt = Date.now()
      }
      return
    }
    if (eventType === 'branch_switched') {
      const p = (raw.payload || {}) as Record<string, unknown>
      if (p.branch) {
        upsertBranch(state, p.branch as TaskBranch)
        setActiveBranch(state, (p.branch as TaskBranch).branch_id)
      }
      return
    }
    if (eventType === 'branch_status_changed') {
      const p = (raw.payload || {}) as Record<string, unknown>
      if (p.branch) upsertBranch(state, p.branch as TaskBranch)
      return
    }

    // ── 重连内部事件 ──────────────────────────────────
    if (eventType === '_reconnected') {
      refreshTask(taskId).catch(() => {})
      return
    }
  }

  // ── attach / detach ──────────────────────────────────
  async function attach(taskId: string) {
    const state = ensureState(taskId)
    if (state.unsub) return

    // 判断 state 是否已温热（之前 attach 过，从另一视图切换过来）
    const isWarm = state._everAttached

    if (!isWarm) {
      // 冷启动：从 IndexedDB 预热历史事件，避免 WS 首包到之前时间线空白
      try {
        const cached = await loadEvents(taskId, 2000)
        if (cached.length) {
          const dEvents: DecisionEvent[] = []
          for (const ev of cached) {
            const et = String(ev.type || '')
            if (et === 'log') {
              const p = (ev.payload || {}) as { line?: string; seq?: number }
              if (p.line) pushLog(state, p.line)
              if (typeof p.seq === 'number') state.logTotal = Math.max(state.logTotal, p.seq + 1)
            } else if (et === 'decision_event') {
              const p = (ev.payload || {}) as Record<string, unknown>
              dEvents.push({
                id: String(ev.id || ''),
                timestamp: String(ev.ts || ''),
                ...p,
              } as DecisionEvent)
            }
          }
          if (dEvents.length) mergeDecisionEvents(state, dEvents, true)
        }
      } catch {
        // IndexedDB 不可用，跳过预热
      }
      // 冷启动时拉任务快照；温热时由视图层 onMounted 的 refreshTask 负责
      refreshTask(taskId).catch(() => {})
    }

    state.unsub = subscribeTaskEvents(taskId, (event) => {
      applyEvent(state, taskId, event)
    })

    // 冷启动时拉完整 branch tree；温热时复用已有数据
    if (!isWarm) {
      refreshBranches(taskId).catch(() => {})
    }

    state._everAttached = true
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

  async function submitCheckpoint(
    taskId: string,
    payload: {
      action: 'approve' | 'reject' | 'modify' | 'skip'
      selected_option?: string
      user_prompt?: string
      note?: string
      next_action?: string
    },
  ) {
    const s = ensureState(taskId)
    if (s.checkpointState === 'submitting') return
    s.checkpointState = 'submitting'
    try {
      await api.respondCheckpoint(taskId, payload)
      s.checkpointState = 'submitted'
      s.approvalSubmittedAt = Date.now()
      const tip = (
        payload.action === 'approve' ? '已批准并继续' :
        payload.action === 'reject'  ? '已拒绝当前节点' :
        payload.action === 'modify'  ? '已提交意见,Agent 将参考用户提示继续' :
                                       '已提交,Agent 将按默认策略继续'
      )
      ElMessage.success(tip)
    } catch (e: unknown) {
      const detail = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      const msg = detail || (e as Error)?.message || '提交确认失败'
      if (detail && /已在执行/.test(detail)) {
        s.checkpointState = 'submitted'
        s.approvalSubmittedAt = Date.now()
        ElMessage.info('确认已在执行中')
      } else {
        s.checkpointState = 'error'
        ElMessage.error(msg)
        setTimeout(() => { s.checkpointState = 'idle' }, 3000)
      }
    }
  }

  return {
    taskStateMap,
    ensureState,
    refreshTask,
    loadEarlierLogs,
    attach,
    detach,
    clear,
    getLiveState,
    submitApproval,
    submitCheckpoint,
    refreshBranches,
    activateBranch,
    resumeBranch,
    pauseBranch,
  }
})
