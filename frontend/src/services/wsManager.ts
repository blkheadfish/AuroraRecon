/**
 * wsManager.ts —— WebSocket 实时事件通道 (协议 v2, Redis Stream)
 *
 * 职责:
 *   1. 管理 ``task_id → WebSocket`` 一对一的连接生命周期
 *   2. 连接时携带 ``after_id=<lastEventId>`` 让服务端 XRANGE 只补差量
 *   3. 所有通过 WS 到达的 envelope 按 ``event.id`` 去重后广播给 listener
 *   4. 断线后自动重连: 早期退避激进(500/1k/2k/4k), 后期稳在 30s
 *   5. 持久化 ``lastEventId`` 到 IndexedDB (eventStore), F5 刷新无损
 */

import { createWsConnection, type WsConnection, type WsConnectOptions } from '@/api'
import { getLastEventId, appendEvents } from '@/services/eventStore'
import type { EventEnvelope } from '@/services/eventStore'

type Listener = (event: Record<string, unknown>) => void

interface ChannelState {
  conn: WsConnection
  listeners: Set<Listener>
  /** 已收到的最后一条 event.id, 用于重连时传 ``after_id``。 */
  lastEventId: string
  /** 已收到的事件 id 集合 (按 event.id 去重, 替代 v1 的 seenLogs/seenDecisionIds)。 */
  seenEventIds: Set<string>
  retries: number
  reconnectTimer: number | null
  /** 重连后第一条业务帧到达时复位 retries 并补拉一次任务快照。 */
  firstMessageAfterReconnect: boolean
  /** IndexedDB 批量写入缓冲: 200ms 内的 event 合并成一笔事务。 */
  writeBuffer: EventEnvelope[]
  writeTimer: number | null
}

const channels = new Map<string, ChannelState>()

/** WS 消息 Micro-batch: 同一帧内收到的多条事件合并为一次广播，减少 Vue DOM 重排。 */
const _frameBuffers = new Map<string, Record<string, unknown>[]>()
let _frameRafId: number | null = null

/** 低频兜底 flush 间隔: 隐藏态下 rAF 暂停, 防止帧缓冲无界增长。 */
const SAFETY_FLUSH_MS = 250
let _safetyFlushTimer: number | null = null

/**
 * 派发并清空当前所有 task 的帧缓冲 (复用 rAF 回调的派发逻辑)。
 * flush 后立即清空 _frameBuffers, 因此前台 rAF 主路径与可见性 / 兜底
 * 触发之间不会重复派发同一批事件。
 */
function flushFrameBuffers() {
  if (_frameBuffers.size === 0) return
  const buffers = new Map(_frameBuffers)
  _frameBuffers.clear()
  for (const [tid, events] of buffers) {
    for (const ev of events) {
      broadcast(tid, ev)
    }
  }
}

function _onVisibilityChange() {
  // 切回前台: 立即派发隐藏期间堆积的帧, 避免 rAF 恢复时一次性突发卡顿。
  if (typeof document !== 'undefined' && !document.hidden) {
    flushFrameBuffers()
  }
}

/** 注册可见性 flush + 低频兜底定时器 (幂等, 模块初始化与首个订阅时调用)。 */
function _installBackgroundFlush() {
  if (typeof document === 'undefined' || _safetyFlushTimer !== null) return
  document.addEventListener('visibilitychange', _onVisibilityChange)
  _safetyFlushTimer = window.setInterval(flushFrameBuffers, SAFETY_FLUSH_MS)
}

function _enqueueFrame(taskId: string, event: Record<string, unknown>) {
  if (!_frameBuffers.has(taskId)) {
    _frameBuffers.set(taskId, [])
  }
  _frameBuffers.get(taskId)!.push(event)
  if (_frameRafId === null) {
    _frameRafId = requestAnimationFrame(() => {
      _frameRafId = null
      flushFrameBuffers()
    })
  }
}

_installBackgroundFlush()

/**
 * 激进退避数组: 前 4 次必须 < 5s, 覆盖 NAT 抖动 / LB 漂移;
 * 之后稳定在 30s, 避免对服务端造成脉冲式重连压力。
 */
const BACKOFF_MS = [500, 1000, 2000, 4000, 8000, 15000, 30000, 30000]
const MAX_RETRIES = 30

/** IndexedDB 批量写入缓冲延迟: 合并 200ms 内的业务事件为一笔事务。 */
const WRITE_FLUSH_MS = 200

/** 去重 Set 上限: 单任务 5w 事件, Set 占用约 ~2MB, 控在可接受范围。 */
const SEEN_IDS_CAP = 50000

function _noteSeenId(channel: ChannelState, id: string) {
  if (!id) return
  channel.seenEventIds.add(id)
  // LRU 裁剪: 超过上限按插入序踢最早的那一半, 确保新事件不会因 set 满被误判重复
  if (channel.seenEventIds.size > SEEN_IDS_CAP) {
    const toDrop = SEEN_IDS_CAP / 2
    let i = 0
    for (const key of channel.seenEventIds) {
      if (i >= toDrop) break
      channel.seenEventIds.delete(key)
      i++
    }
  }
}

function _bumpLastEventId(channel: ChannelState, id: string) {
  if (!id) return
  // Stream ID 字典序天然单调; 直接字符串比较即可判"更新"
  if (id > channel.lastEventId) {
    channel.lastEventId = id
  }
}

function broadcast(taskId: string, event: Record<string, unknown>) {
  const channel = channels.get(taskId)
  if (!channel) return
  for (const listener of channel.listeners) {
    listener(event)
  }
}

function _flushWrites(taskId: string) {
  const channel = channels.get(taskId)
  if (!channel || !channel.writeBuffer.length) return
  const batch = channel.writeBuffer.splice(0)
  if (channel.writeTimer !== null) {
    window.clearTimeout(channel.writeTimer)
    channel.writeTimer = null
  }
  appendEvents(taskId, batch).catch(() => {})
}

function _scheduleWrite(channel: ChannelState, taskId: string) {
  if (channel.writeTimer !== null) return
  channel.writeTimer = window.setTimeout(() => _flushWrites(taskId), WRITE_FLUSH_MS)
}

function clearReconnectTimer(state: ChannelState) {
  if (state.reconnectTimer !== null) {
    window.clearTimeout(state.reconnectTimer)
    state.reconnectTimer = null
  }
}

async function connect(taskId: string) {
  const channel = channels.get(taskId)
  if (!channel) return

  channel.firstMessageAfterReconnect = channel.retries > 0

  // 协议 v2: WS 连接携带 after_id, 服务端只补差量
  const wsOptions: WsConnectOptions = {}
  if (channel.lastEventId) {
    wsOptions.afterId = channel.lastEventId
  }

  channel.conn = createWsConnection(
    taskId,
    (rawEvent) => {
      const ev = rawEvent as Record<string, unknown>
      const t = String(ev.type || '')

      // ── 控制帧 ──────────────────────────────
      if (t === 'heartbeat' || t === 'pong') return

      // 协议 v2 hello 帧: 服务端告知协议版本 / 回放条数 / 后端模式
      if (t === 'hello') {
        // 仅作可观测, 前端不阻塞
        return
      }

      if (t === 'error') {
        _enqueueFrame(taskId, ev)
        return
      }

      // ── 历史回放帧 ──────────────────────────
      if (t === 'history') {
        const events = (ev.events || []) as EventEnvelope[]
        const filtered: EventEnvelope[] = []
        for (const e of events) {
          const eid = String(e.id || '')
          if (!eid || channel.seenEventIds.has(eid)) continue
          _noteSeenId(channel, eid)
          _bumpLastEventId(channel, eid)
          filtered.push(e)
        }
        if (filtered.length) {
          // 将历史事件批量持久化到 IndexedDB
          appendEvents(taskId, filtered).catch(() => {})
          // 广播: 前端用 history envelope 一次性注入 store
          _enqueueFrame(taskId, { type: 'history', events: filtered })
        }
        return
      }

      // ── 业务事件 ────────────────────────────
      const eid = String(ev.id || '')

      // 重连后第一条业务帧 → 复位重试计数器 + 拉一次任务快照
      if (channel.firstMessageAfterReconnect) {
        channel.firstMessageAfterReconnect = false
        channel.retries = 0
        _enqueueFrame(taskId, { type: '_reconnected' })
      }

      // 去重: 按 event.id
      if (eid && channel.seenEventIds.has(eid)) return
      if (eid) {
        _noteSeenId(channel, eid)
        _bumpLastEventId(channel, eid)
      }

      // 持久化到 IndexedDB (缓冲批量写入, 200ms 合并一事务)
      if (eid) {
        channel.writeBuffer.push(ev as unknown as EventEnvelope)
        _scheduleWrite(channel, taskId)
      }

      _enqueueFrame(taskId, ev)
    },
    () => {
      // ── onclose 回调 ───────────────────────
      const latest = channels.get(taskId)
      if (!latest) return
      if (latest.retries >= MAX_RETRIES) {
        // 超过最大重试次数, 放弃重连
        return
      }
      latest.retries += 1
      const idx = Math.min(latest.retries - 1, BACKOFF_MS.length - 1)
      const base = BACKOFF_MS[idx]
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
      lastEventId: '',
      seenEventIds: new Set<string>(),
      retries: 0,
      reconnectTimer: null,
      firstMessageAfterReconnect: false,
      writeBuffer: [],
      writeTimer: null,
    }
    channels.set(taskId, channel)
    _installBackgroundFlush()

    // 立即连接 (首次无 afterId → 服务端返回最近 tail); 同时异步从
    // IndexedDB 恢复 lastEventId, 仅用于后续断线重连的增量回放。
    connect(taskId)
    getLastEventId(taskId).then((savedId) => {
      const cur = channels.get(taskId)
      if (cur && savedId && savedId > cur.lastEventId) {
        cur.lastEventId = savedId
      }
    })
  } else {
    // 已有 channel, 直接加入 listener
  }

  channel.listeners.add(listener)

  return () => {
    const current = channels.get(taskId)
    if (!current) return
    current.listeners.delete(listener)
    if (current.listeners.size === 0) {
      clearReconnectTimer(current)
      if (current.writeTimer !== null) {
        window.clearTimeout(current.writeTimer)
        current.writeTimer = null
      }
      // 销毁前 flush 残留缓冲
      if (current.writeBuffer.length) {
        appendEvents(taskId, current.writeBuffer.splice(0)).catch(() => {})
      }
      current.conn.close()
      channels.delete(taskId)
      _frameBuffers.delete(taskId)
    }
  }
}

export function closeAllTaskEventChannels() {
  for (const [, channel] of channels) {
    clearReconnectTimer(channel)
    channel.conn.close()
  }
  channels.clear()
  if (_frameRafId !== null) {
    cancelAnimationFrame(_frameRafId)
    _frameRafId = null
  }
  _frameBuffers.clear()
  if (typeof document !== 'undefined') {
    document.removeEventListener('visibilitychange', _onVisibilityChange)
  }
  if (_safetyFlushTimer !== null) {
    window.clearInterval(_safetyFlushTimer)
    _safetyFlushTimer = null
  }
}
