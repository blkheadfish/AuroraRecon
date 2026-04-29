import { api, createWsConnection, type WsConnection } from '@/api'
import type { WsTaskEvent } from '@/types/task'

type Listener = (event: WsTaskEvent) => void

interface ChannelState {
  conn: WsConnection
  listeners: Set<Listener>
  seenLogs: Set<string>
  seenLogsOrder: string[]
  seenDecisionIds: Set<string>
  retries: number
  reconnectTimer: number | null
  firstMessageAfterReconnect: boolean
  /** 已收到的最后一条 phase_log 的 server 端 index,用于重连增量回放。 */
  lastLogSeq: number
}

const channels = new Map<string, ChannelState>()
const MAX_RETRIES = 30
// 去重 Set 上限。长任务里 dedup set 无界增长会和实际日志一起把内存吃满,
// 切到 LRU 风格后 set 永远保持 O(1) 大小,代价只是非常老的重复行可能漏判。
const SEEN_LOGS_CAP = 4000

// ── lastLogSeq sessionStorage 持久化 ────────────────────────
// Pinia 是纯内存 store, 浏览器 F5 刷新后所有 store 状态都重置, 包括
// channel.lastLogSeq → 重连时只能用默认 ``log_tail=200`` 拉一段历史,
// 长任务下 200 条根本对不上用户上次看到的位置。这里把每个 task 的
// lastLogSeq 同步进 sessionStorage, 刷新后能用 ``after_log_seq=K``
// 精准请求增量, 既不重发已看过的日志也不漏。tab 关闭后 session 自动
// 清理, 不会污染长期存储。
const LOG_SEQ_KEY_PREFIX = 'ws_seq_'

function loadSavedLogSeq(taskId: string): number {
  try {
    const raw = sessionStorage.getItem(LOG_SEQ_KEY_PREFIX + taskId)
    if (!raw) return 0
    const n = Number.parseInt(raw, 10)
    return Number.isFinite(n) && n > 0 ? n : 0
  } catch {
    return 0
  }
}

function persistLogSeq(taskId: string, seq: number) {
  if (!Number.isFinite(seq) || seq <= 0) return
  try {
    sessionStorage.setItem(LOG_SEQ_KEY_PREFIX + taskId, String(seq))
  } catch {
    /* 配额 / 隐私模式 sessionStorage 不可用时静默忽略 */
  }
}

function bumpLogSeq(taskId: string, channel: ChannelState, candidate: number) {
  if (!Number.isFinite(candidate)) return
  if (candidate > channel.lastLogSeq) {
    channel.lastLogSeq = candidate
    persistLogSeq(taskId, candidate)
  }
}

function noteSeenLog(channel: ChannelState, line: string) {
  if (!line || channel.seenLogs.has(line)) return
  channel.seenLogs.add(line)
  channel.seenLogsOrder.push(line)
  if (channel.seenLogsOrder.length > SEEN_LOGS_CAP) {
    const evict = channel.seenLogsOrder.shift()
    if (evict !== undefined) channel.seenLogs.delete(evict)
  }
}

function dedupeLogs(taskId: string, channel: ChannelState, event: WsTaskEvent): WsTaskEvent {
  if ((event as { type?: string }).type === 'phase_update') {
    const logs = ((event as { logs?: string[] }).logs || []).filter((line) => !channel.seenLogs.has(line))
    logs.forEach((line) => noteSeenLog(channel, line))
    return { ...(event as object), logs } as WsTaskEvent
  }
  if ((event as { type?: string }).type === 'log') {
    const line = String((event as { data?: string }).data || '')
    const seq = (event as { seq?: number }).seq
    // 推进 lastLogSeq,这样断线重连/刷新时 ?after_log_seq=N 只会补差值,
    // 不会再让后端把最近 200 行 history_logs 整段重发。
    if (typeof seq === 'number' && Number.isFinite(seq)) {
      bumpLogSeq(taskId, channel, seq + 1)
    }
    if (line && !channel.seenLogs.has(line)) {
      noteSeenLog(channel, line)
      return event
    }
    return { type: 'heartbeat' }
  }
  if ((event as { type?: string }).type === 'history_logs') {
    const data = (event as { data?: string[] }).data || []
    const filtered = data.filter((line) => !channel.seenLogs.has(line))
    filtered.forEach((line) => noteSeenLog(channel, line))
    const meta = event as { start_seq?: number; next_seq?: number; total?: number }
    if (typeof meta.next_seq === 'number') {
      bumpLogSeq(taskId, channel, meta.next_seq)
    }
    return { ...(event as object), data: filtered } as WsTaskEvent
  }
  if ((event as { type?: string }).type === 'history_meta') {
    // 仅作元信息广播,不要在这里推进 lastLogSeq。连接可能在 meta 后、
    // history_logs 前断开,过早推进会导致下次重连跳过未收到的日志。
    return event
  }
  if ((event as { type?: string }).type === 'decision_event') {
    const data = (event as { data?: { id?: string } }).data
    const id = String(data?.id || '')
    if (id) {
      if (channel.seenDecisionIds.has(id)) {
        return { type: 'heartbeat' }
      }
      channel.seenDecisionIds.add(id)
    }
  }
  return event
}

function broadcast(taskId: string, event: WsTaskEvent) {
  const channel = channels.get(taskId)
  if (!channel) return
  for (const listener of channel.listeners) {
    listener(event)
  }
}

function clearReconnectTimer(state: ChannelState) {
  if (state.reconnectTimer !== null) {
    window.clearTimeout(state.reconnectTimer)
    state.reconnectTimer = null
  }
}

function connect(taskId: string) {
  const channel = channels.get(taskId)
  if (!channel) return

  channel.firstMessageAfterReconnect = channel.retries > 0

  // 重连时只请求 server 还没回放过的部分(after_log_seq),避免每次掉线
  // 都重新接收上 MB 历史日志。首次连接(lastLogSeq==0)走默认 tail。
  const wsOptions = channel.lastLogSeq > 0
    ? { afterLogSeq: channel.lastLogSeq }
    : undefined

  channel.conn = createWsConnection(
    taskId,
    (rawEvent) => {
      if (channel.firstMessageAfterReconnect) {
        channel.firstMessageAfterReconnect = false
        channel.retries = 0
        api.getTask(taskId)
          .then((task) => {
            broadcast(taskId, {
              type: 'phase_update',
              phase: task.current_phase || 'unknown',
              status: task.status,
              findings_count: task.findings_count,
              got_shell: task.got_shell,
              logs: [],
            })
            if (task.current_phase === 'awaiting_approval') {
              broadcast(taskId, { type: 'approval_required' })
            }
          })
          .catch(() => {})
      }
      const event = dedupeLogs(taskId, channel, rawEvent)
      const t = (event as { type?: string }).type
      if (t === 'heartbeat' || t === 'pong') return
      broadcast(taskId, event)
    },
    () => {
      const latest = channels.get(taskId)
      if (!latest) return
      if (latest.retries >= MAX_RETRIES) {
        api.getTask(taskId)
          .then((task) => {
            broadcast(taskId, {
              type: 'phase_update',
              phase: task.current_phase || 'unknown',
              status: task.status,
              findings_count: task.findings_count,
              got_shell: task.got_shell,
              logs: [],
            })
            if (task.current_phase === 'awaiting_approval') {
              broadcast(taskId, { type: 'approval_required' })
            }
          })
          .catch(() => {})
        return
      }
      latest.retries += 1
      const base = Math.min(1000 * 2 ** latest.retries, 30000)
      const jitter = Math.floor(Math.random() * Math.min(base * 0.3, 3000))
      const delay = base + jitter
      clearReconnectTimer(latest)
      latest.reconnectTimer = window.setTimeout(() => connect(taskId), delay)
    },
    wsOptions,
  )
}

export function subscribeTaskEvents(taskId: string, listener: Listener): () => void {
  let channel = channels.get(taskId)
  if (!channel) {
    // 首次为该 task 建 channel 时, 从 sessionStorage 恢复上次见到的最大 seq,
    // 这样 connect() 走 wsOptions.afterLogSeq 直接进入"只补增量"路径,
    // 而不是默认拉最近 200 条 history_logs (跨刷新时往往全是已见过的)。
    const savedSeq = loadSavedLogSeq(taskId)
    channel = {
      conn: {
        close: () => {},
        get readyState() {
          return WebSocket.CLOSED
        },
      },
      listeners: new Set<Listener>(),
      seenLogs: new Set<string>(),
      seenLogsOrder: [],
      seenDecisionIds: new Set<string>(),
      retries: 0,
      reconnectTimer: null,
      firstMessageAfterReconnect: false,
      lastLogSeq: savedSeq,
    }
    channels.set(taskId, channel)
    connect(taskId)
  }

  channel.listeners.add(listener)

  return () => {
    const current = channels.get(taskId)
    if (!current) return
    current.listeners.delete(listener)
    if (current.listeners.size === 0) {
      clearReconnectTimer(current)
      current.conn.close()
      channels.delete(taskId)
    }
  }
}

export function closeAllTaskEventChannels() {
  for (const [, channel] of channels) {
    clearReconnectTimer(channel)
    channel.conn.close()
  }
  channels.clear()
}
