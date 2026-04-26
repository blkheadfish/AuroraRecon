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

function noteSeenLog(channel: ChannelState, line: string) {
  if (!line || channel.seenLogs.has(line)) return
  channel.seenLogs.add(line)
  channel.seenLogsOrder.push(line)
  if (channel.seenLogsOrder.length > SEEN_LOGS_CAP) {
    const evict = channel.seenLogsOrder.shift()
    if (evict !== undefined) channel.seenLogs.delete(evict)
  }
}

function dedupeLogs(channel: ChannelState, event: WsTaskEvent): WsTaskEvent {
  if ((event as { type?: string }).type === 'phase_update') {
    const logs = ((event as { logs?: string[] }).logs || []).filter((line) => !channel.seenLogs.has(line))
    logs.forEach((line) => noteSeenLog(channel, line))
    return { ...(event as object), logs } as WsTaskEvent
  }
  if ((event as { type?: string }).type === 'log') {
    const line = String((event as { data?: string }).data || '')
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
      channel.lastLogSeq = Math.max(channel.lastLogSeq, meta.next_seq)
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
      const event = dedupeLogs(channel, rawEvent)
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
      lastLogSeq: 0,
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
