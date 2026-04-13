import { api, createWsConnection, type WsConnection } from '@/api'
import type { WsTaskEvent } from '@/types/task'

type Listener = (event: WsTaskEvent) => void

interface ChannelState {
  conn: WsConnection
  listeners: Set<Listener>
  seenLogs: Set<string>
  seenDecisionIds: Set<string>
  retries: number
  reconnectTimer: number | null
  firstMessageAfterReconnect: boolean
}

const channels = new Map<string, ChannelState>()
const MAX_RETRIES = 30

function dedupeLogs(event: WsTaskEvent, seenLogs: Set<string>): WsTaskEvent {
  if ((event as { type?: string }).type === 'phase_update') {
    const logs = ((event as { logs?: string[] }).logs || []).filter((line) => !seenLogs.has(line))
    logs.forEach((line) => seenLogs.add(line))
    return { ...(event as object), logs } as WsTaskEvent
  }
  if ((event as { type?: string }).type === 'log') {
    const line = String((event as { data?: string }).data || '')
    if (line && !seenLogs.has(line)) {
      seenLogs.add(line)
      return event
    }
    return { type: 'heartbeat' }
  }
  if ((event as { type?: string }).type === 'decision_event') {
    const data = (event as { data?: { id?: string } }).data
    const id = String(data?.id || '')
    if (id) {
      const channel = [...channels.values()].find((ch) => ch.seenLogs === seenLogs)
      if (channel) {
        if (channel.seenDecisionIds.has(id)) {
          return { type: 'heartbeat' }
        }
        channel.seenDecisionIds.add(id)
      }
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
      const event = dedupeLogs(rawEvent, channel.seenLogs)
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
      seenDecisionIds: new Set<string>(),
      retries: 0,
      reconnectTimer: null,
      firstMessageAfterReconnect: false,
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
