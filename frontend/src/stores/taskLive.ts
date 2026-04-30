import { defineStore } from 'pinia'
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { subscribeTaskEvents } from '@/services/wsManager'
import { useTaskListStore } from '@/stores/taskList'
import type {
  BranchTreeItem,
  CheckpointPayload,
  DecisionEvent,
  TaskBranch,
  TaskDetail,
} from '@/types/task'

type ApprovalState = 'idle' | 'submitting' | 'submitted' | 'error'
type CheckpointState = 'idle' | 'submitting' | 'submitted' | 'error'

// ── 有界缓存阈值 ───────────────────────────────────────
// 长任务运行起来日志/工具流/决策事件都会无限堆积,直接 push 进响应式
// 数组会让前端内存与 DOM 越跑越慢直到卡死。统一在 store 层做 LRU 裁剪,
// 由前端组件按需再缩成「可见 tail」交给 DOM。
const MAX_LOG_BUFFER = 3000
const MAX_DECISION_EVENTS = 1000
const MAX_TOOL_STREAM_LINES = 500

interface LlmStreamBubble {
  streamId: string
  phase: string
  kind: string
  text: string
  updatedAt: number
}

interface TaskLiveState {
  task: TaskDetail | null
  logs: string[]
  logSet: Set<string>
  /** 已知 server 端 phase_log 总条数,用于增量拉取/分页加载更早历史。 */
  logTotal: number
  /** 已加载历史的最早 index(0 表示已经从头加载)。 */
  logEarliestSeq: number
  decisionEvents: DecisionEvent[]
  decisionEventIds: Set<string>
  llmStreams: Record<string, LlmStreamBubble>
  toolStreams: Record<string, string[]>
  approvalState: ApprovalState
  approvalNonce: string
  approvalSubmittedAt: number
  lastWsUpdate: number
  /** 当前 pending 的 Plan 风格 checkpoint(若有),来自后端 decision_event。 */
  pendingCheckpoint: CheckpointPayload | null
  /** 已 resolve 的 checkpoint 历史(最新的在末尾),用于审计与时间线展示。 */
  checkpointHistory: CheckpointPayload[]
  /** 当前 checkpoint 的提交状态,避免重复点击。 */
  checkpointState: CheckpointState
  /** 任务分支树(Claude/Kimi 风格); branches[*].sibling_total 渲染 <n/m>。 */
  branches: BranchTreeItem[]
  /** 当前活动分支 id; 时间线/输入框 / 分支徽标都靠它高亮。 */
  activeBranchId: string
  /** 后端配置的单任务分支上限,用于在 UI 提前禁用 fork。 */
  maxBranchesPerTask: number
  /** 最近一次 fork 时间(毫秒), 用于发送动画。 */
  branchFlashAt: number
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
        logTotal: 0,
        logEarliestSeq: 0,
        decisionEvents: [],
        decisionEventIds: new Set<string>(),
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
      }
    }
    return taskStateMap.value[taskId]
  }

  // ── 分支树工具 ────────────────────────────────────────
  /**
   * 在不重算后端 sibling_total 的前提下尽量保留 BranchTreeItem 的视图字段。
   * 如果是 ws 推送过来的全新 TaskBranch (没有 sibling_index/total),
   * 我们用启发式: 同 (parent, fork_event_id) 计 sibling 数。
   */
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
      // 保持 is_active 对齐
      for (const b of state.branches) {
        b.is_active = b.branch_id === state.activeBranchId
      }
    } catch (e) {
      // 老任务后端可能返回 404 / 500, 这里静默回退即可
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
      // Claude 风格分支切换: 切换到目标分支后强制重新拉一次后端快照,
      // 让 ``decision_events_tail`` 把目标分支视角的最近事件补齐, 避免
      // 仅靠 store 里旧分支的累积导致 TaskChat 看不到目标分支的历史。
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
    // 已 resolve 过的 checkpoint 不应再次激活(replay 场景)
    const archived = state.checkpointHistory.find(
      (h) => h.checkpoint_id === ckpt.checkpoint_id && h.status === 'resolved',
    )
    if (archived) return
    state.pendingCheckpoint = ckpt
    if (state.checkpointState === 'submitting' || state.checkpointState === 'submitted') {
      // 新 checkpoint 进入,重置交互态
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
      // 后端权威:有 pending 就强制采用快照里的 pending(可能是首次刷新加载)
      const archived = state.checkpointHistory.find(
        (h) => h.checkpoint_id === pending.checkpoint_id && h.status === 'resolved',
      )
      if (!archived) {
        state.pendingCheckpoint = { ...pending, status: 'pending' }
      } else {
        state.pendingCheckpoint = null
      }
    } else if (state.pendingCheckpoint) {
      // 后端没有 pending, 但本地仍有 → 说明已被消费, 清掉
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
      for (const line of evicted) state.logSet.delete(line)
    }
  }

  // 比较器: 主 key = timestamp 字典序; tie-breaker = id 中的递增 idx
  // (id 形如 "de-{idx}-{HHMMSSffffff}", idx 是后端 push 时的真实顺序)
  function _decisionEventIdx(id: string): number {
    const m = String(id || '').match(/^de-(\d+)-/)
    return m ? Number(m[1]) : 0
  }
  // 把任意时间戳字符串(ISO / "HH:MM:SS" / 本地化字符串)归一化成毫秒 epoch,
  // 用于排序。不能直接对原始字符串做 localeCompare —— 后端给的 ISO 形如
  // ``2026-04-30T11:33:53`` 以字符 '2' 开头, 而前端 ``toLocaleTimeString``
  // 短格式 ``11:33:53`` 以字符 '1' 开头, 字典序会把短格式时间戳排到任何
  // ISO 时间戳之前, 直接导致同一时刻产生的 approval_required 卡片被错误排到
  // 历史最早处 → 滚出 MAX_DECISION_EVENTS 窗口 → 用户根本看不到审批按钮。
  function _toEpoch(ts: string): number {
    if (!ts) return 0
    // ISO 或可被 Date 解析的串走 Date.parse
    const direct = Date.parse(ts)
    if (!Number.isNaN(direct)) return direct
    // 仅 "HH:MM:SS(.fraction)" 这种短格式: 拼今天的日期再 parse
    const short = ts.match(/^(\d{1,2}):(\d{2}):(\d{2})(\.\d+)?$/)
    if (short) {
      const now = new Date()
      const built = new Date(
        now.getFullYear(), now.getMonth(), now.getDate(),
        Number(short[1]), Number(short[2]), Number(short[3]),
        short[4] ? Math.round(Number(short[4]) * 1000) : 0,
      )
      return built.getTime()
    }
    // 兜底: 把字符串转 0, 让 tie-breaker (id idx) 接管, 不会产生跨字符前缀
    // 的诡异排序。
    return 0
  }
  function _compareDecisionEvents(a: DecisionEvent, b: DecisionEvent): number {
    const ea = _toEpoch(String(a?.timestamp || ''))
    const eb = _toEpoch(String(b?.timestamp || ''))
    if (ea !== eb) return ea - eb
    return _decisionEventIdx(String(a?.id || '')) - _decisionEventIdx(String(b?.id || ''))
  }

  function mergeDecisionEvents(state: TaskLiveState, incoming: DecisionEvent[] = []) {
    if (!Array.isArray(incoming) || !incoming.length) return
    for (const event of incoming) {
      const id = String(event?.id || '')
      if (!id || state.decisionEventIds.has(id)) continue
      state.decisionEventIds.add(id)
      state.decisionEvents.push(event)
    }
    // 用副本 sort + splice 重建,避免 Vue3 reactive 对原地 sort 触发依赖更新
    // 不可靠的问题(实测在 Pinia + computed 链路下偶发 rail 渲染顺序不刷新)。
    const sorted = state.decisionEvents.slice().sort(_compareDecisionEvents)
    state.decisionEvents.splice(0, state.decisionEvents.length, ...sorted)
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
    // 后端默认返回轻量快照: phase_log 留空, phase_log_tail/phase_log_total
    // 描述完整大小, decision_events 等价于 decision_events_tail。
    const full = await api.getTask(taskId)
    const state = ensureState(taskId)
    mergeDecisionEvents(state, full.decision_events_tail || full.decision_events || [])
    // 同步 Plan 风格 checkpoint(刷新/重连后用于回填确认卡片)
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
      }
    }

    // 兼容: 老接口返回 phase_log,新接口返回 phase_log_tail
    const tail = (full.phase_log_tail && full.phase_log_tail.length)
      ? full.phase_log_tail
      : (full.phase_log || [])
    for (const line of tail) {
      pushLog(state, line)
    }
    if (typeof full.phase_log_total === 'number') {
      state.logTotal = full.phase_log_total
      const tailLen = tail.length
      // tail 来自最近 tail_len 条,因此最早可见 index 至少是 total - tailLen
      const minEarliest = Math.max(0, full.phase_log_total - tailLen)
      state.logEarliestSeq = state.logEarliestSeq
        ? Math.min(state.logEarliestSeq, minEarliest)
        : minEarliest
    }
    taskListStore.upsertTask(full)
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
      // 旧日志 prepend: 用 unshift 保持时间顺序,同时维持 dedup set
      for (let i = logs.length - 1; i >= 0; i--) {
        const line = logs[i]
        if (!line || state.logSet.has(line)) continue
        state.logSet.add(line)
        state.logs.unshift(line)
      }
      if (state.logs.length > MAX_LOG_BUFFER) {
        const drop = state.logs.length - MAX_LOG_BUFFER
        const evicted = state.logs.splice(state.logs.length - drop, drop)
        for (const line of evicted) state.logSet.delete(line)
      }
      state.logEarliestSeq = page.offset
      if (typeof page.total === 'number') state.logTotal = page.total
      return logs.length
    } catch {
      return 0
    }
  }

  async function attach(taskId: string) {
    const state = ensureState(taskId)
    if (state.unsub) return

    state.unsub = subscribeTaskEvents(taskId, (event) => {
      const eventType = (event as { type?: string }).type

      if (eventType === 'history_meta') {
        const total = Number((event as { phase_log_total?: number }).phase_log_total || 0)
        if (total > 0) state.logTotal = total
        return
      }
      if (eventType === 'history_logs') {
        const lines = (event as { data?: string[] }).data || []
        for (const line of lines) pushLog(state, line)
        const meta = event as { start_seq?: number; total?: number }
        if (typeof meta.start_seq === 'number') {
          state.logEarliestSeq = state.logEarliestSeq
            ? Math.min(state.logEarliestSeq, meta.start_seq)
            : meta.start_seq
        }
        if (typeof meta.total === 'number') state.logTotal = meta.total
        return
      }
      if (eventType === 'history_events') {
        const events = (event as { data?: DecisionEvent[] }).data || []
        mergeDecisionEvents(state, events)
        // 重连/首连时回放历史 checkpoint 事件,保证刷新后卡片仍能恢复。
        // 顺序处理:先 request 把 pendingCheckpoint 填上,再用 resolved 覆盖。
        for (const e of events) {
          if (e?.action === 'checkpoint_request') applyCheckpointRequest(state, e)
        }
        for (const e of events) {
          if (e?.action === 'checkpoint_resolved') applyCheckpointResolved(state, e)
        }
        if (state.task) {
          state.task = {
            ...state.task,
            decision_events: state.decisionEvents.slice(),
            pending_checkpoint: state.pendingCheckpoint,
            checkpoint_history: state.checkpointHistory.slice(),
          }
        }
        return
      }
      if (eventType === 'log') {
        const line = String((event as { data?: string }).data || '')
        const seq = (event as { seq?: number }).seq
        pushLog(state, line)
        if (typeof seq === 'number' && Number.isFinite(seq)) {
          // seq = append 后的 phase_log 下标,因此总数至少是 seq+1
          state.logTotal = Math.max(state.logTotal, seq + 1)
        } else {
          state.logTotal = state.logTotal + 1
        }
        return
      }
      if (eventType === 'decision_event') {
        const payload = (event as { data?: Record<string, unknown> }).data
        if (payload && typeof payload === 'object') {
          const action = payload.action as string | undefined

          if (action === 'llm_delta') {
            const sid = (payload.stream_id as string) || 'default'
            const delta = (payload.delta as string) || ''
            const phase = (payload.phase as string) || ''
            const kind = (payload.kind as string) || 'content'
            if (!state.llmStreams[sid]) {
              state.llmStreams[sid] = { streamId: sid, phase, kind, text: '', updatedAt: Date.now() }
            }
            state.llmStreams[sid].text += delta
            state.llmStreams[sid].updatedAt = Date.now()
          } else if (action === 'tool_stream') {
            const sid = (payload.stream_id as string) || 'default'
            const line = (payload.line as string) || ''
            pushToolStreamLine(state, sid, line)
          } else {
            const decisionEvent = payload as unknown as DecisionEvent
            mergeDecisionEvents(state, [decisionEvent])
            // Plan 风格 checkpoint 协议:实时把 pending_checkpoint 同步进 store,
            // 任务详情页的 DecisionCheckpointCard 直接订阅 state.pendingCheckpoint。
            if (action === 'checkpoint_request') {
              applyCheckpointRequest(state, decisionEvent)
            } else if (action === 'checkpoint_resolved') {
              applyCheckpointResolved(state, decisionEvent)
            }
            if (state.task) {
              state.task = {
                ...state.task,
                decision_events: state.decisionEvents.slice(),
                pending_checkpoint: state.pendingCheckpoint,
                checkpoint_history: state.checkpointHistory.slice(),
              }
            }
          }
        }
        return
      }
      if (eventType === 'phase_update') {
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
          branch_id?: string
        }
        // 当 phase_update 携带 branch_id 且不是当前 active 分支时, 不更新
        // ``state.task`` 的 phase / status (避免把老分支的 phase 推到
        // 当前视图)。logs 仍然 push 到 buffer, 但走 branch_id 注入路径让
        // TaskChat 自己过滤展示。
        const updateBid = String(patch.branch_id || '')
        const sameBranch = !updateBid || !state.activeBranchId || updateBid === state.activeBranchId
        if (!sameBranch) {
          if (patch.logs?.length) {
            for (const line of patch.logs) pushLog(state, line)
          }
          return
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
          for (const line of patch.logs) pushLog(state, line)
        }
        return
      }
      if (eventType === 'approval_required') {
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

        // 时间戳必须是 ISO 才能跟后端 phase_log 派生事件一起正确排序;
        // 之前用 toLocaleTimeString() 形如 "11:33:53" 字典序会把这个气泡
        // 排到所有 ISO 时间戳之前, 直接落出消息窗口让按钮"消失"。
        // 优先用后端给的 server_iso (见 task_runner.py 推 WS 时的字段),
        // 没有就回退到本地 ISO。
        const serverIso = (event as { server_iso?: string }).server_iso
        const approvalEvent: DecisionEvent = {
          id: `approval-req-${taskId}-${incomingNonce}`,
          timestamp: serverIso || new Date().toISOString(),
          phase: 'awaiting_approval',
          action: 'approval_required',
          message: '系统检测到可利用路径，等待人工审批。',
          tone: 'warning',
        } as DecisionEvent
        mergeDecisionEvents(state, [approvalEvent])
        if (state.task) {
          state.task = { ...state.task, decision_events: state.decisionEvents.slice() }
        }
        return
      }
      if (eventType === 'done') {
        refreshTask(taskId).catch(() => {})
        return
      }
      if (eventType === 'branch_forked') {
        const ev = event as { branch?: TaskBranch; parent?: TaskBranch }
        if (ev.parent) upsertBranch(state, { ...ev.parent, status: 'paused' })
        if (ev.branch) {
          upsertBranch(state, ev.branch)
          setActiveBranch(state, ev.branch.branch_id)
          state.branchFlashAt = Date.now()
        }
        return
      }
      if (eventType === 'branch_switched') {
        const ev = event as { branch?: TaskBranch }
        if (ev.branch) {
          upsertBranch(state, ev.branch)
          setActiveBranch(state, ev.branch.branch_id)
        }
        return
      }
      if (eventType === 'branch_status_changed') {
        const ev = event as { branch?: TaskBranch }
        if (ev.branch) upsertBranch(state, ev.branch)
        return
      }
    })

    // 拉一份完整 branch tree, ws 之后的事件再做增量补丁。
    refreshBranches(taskId).catch(() => {})
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
    },
  ) {
    const s = ensureState(taskId)
    if (s.checkpointState === 'submitting') return
    s.checkpointState = 'submitting'
    try {
      await api.respondCheckpoint(taskId, payload)
      // 后续真正的 resolved 状态由 ws 推送的 checkpoint_resolved 事件统一收尾,
      // 这里只标记本地按钮 loading 收回,避免界面残留。
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
