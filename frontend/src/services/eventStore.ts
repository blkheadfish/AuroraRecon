/**
 * eventStore.ts —— IndexedDB 缓存层 (协议 v2)
 *
 * 功能:
 *   1. 在 ``ws:close`` 与下次 ``attach()`` 之间持久化最后看到的 event id +
 *      最近 N 条 envelope, 让 F5 刷新能用 ``after_id=<lastId>`` 走"只补差量"
 *      路径 (后端 Redis Stream XRANGE), 用户视觉无中断。
 *   2. 进入页面时一次性 ``loadEvents`` 预热 store (避免在 WS 首包没到之前
 *      时间线一片空白, 体感很差)。
 *   3. 自动裁剪: 单 task 最多保存 5000 条 envelope, 超过则丢最旧;
 *      lastEventId 单独 key 即时落盘。
 *
 * 容错:
 *   - IndexedDB 不可用 (隐私模式 / 配额已满 / Safari 私模) → 退到内存
 *     Map fallback, lastEventId 退到 ``sessionStorage``。功能降级但不崩。
 *   - 异步 API 失败均吞掉, 调用方拿到空数据/空 ID, 走"全量回放"路径。
 */

const DB_NAME = 'pentest_events'
const DB_VERSION = 1
const STORE_LAST_ID = 'last_event_id'
const STORE_EVENTS = 'events'

const MAX_EVENTS_PER_TASK = 5000
const SS_LAST_ID_PREFIX = 'evstore_last_id:'

let _dbPromise: Promise<IDBDatabase> | null = null

// 内存 fallback
const _memEvents = new Map<string, EventEnvelope[]>()
const _memLastId = new Map<string, string>()

export interface EventEnvelope {
  id: string
  task_id?: string
  branch_id?: string
  ts?: string
  type: string
  v?: number
  payload?: Record<string, unknown>
  [k: string]: unknown
}

function _openDb(): Promise<IDBDatabase> {
  if (_dbPromise) return _dbPromise
  _dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('indexedDB unavailable'))
      return
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE_LAST_ID)) {
        db.createObjectStore(STORE_LAST_ID) // key = task_id, value = lastEventId
      }
      if (!db.objectStoreNames.contains(STORE_EVENTS)) {
        // primary key 用 [task_id, id] (id 是 Redis Stream ID, 字典序单调),
        // 这样 loadEvents 用 IDBKeyRange.bound 直接拿一段即可。
        const store = db.createObjectStore(STORE_EVENTS, { keyPath: ['task_id', 'id'] })
        store.createIndex('by_task', 'task_id', { unique: false })
      }
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error || new Error('indexedDB open failed'))
  }).catch((err) => {
    // eslint-disable-next-line no-console
    console.warn('[eventStore] IndexedDB unavailable, falling back to memory:', err)
    _dbPromise = null
    throw err
  })
  return _dbPromise
}

/** 取上次保存的 lastEventId; 没有就返回空串。 */
export async function getLastEventId(taskId: string): Promise<string> {
  if (!taskId) return ''
  // 优先 IndexedDB
  try {
    const db = await _openDb()
    const id = await new Promise<string>((resolve, reject) => {
      const tx = db.transaction(STORE_LAST_ID, 'readonly')
      const store = tx.objectStore(STORE_LAST_ID)
      const req = store.get(taskId)
      req.onsuccess = () => resolve(String(req.result || ''))
      req.onerror = () => reject(req.error)
    })
    if (id) return id
  } catch {
    // fallthrough to memory + sessionStorage
  }
  if (_memLastId.has(taskId)) return _memLastId.get(taskId) || ''
  try {
    return sessionStorage.getItem(SS_LAST_ID_PREFIX + taskId) || ''
  } catch {
    return ''
  }
}

async function _setLastEventId(taskId: string, eventId: string): Promise<void> {
  if (!taskId || !eventId) return
  _memLastId.set(taskId, eventId)
  try {
    sessionStorage.setItem(SS_LAST_ID_PREFIX + taskId, eventId)
  } catch {
    /* ignored */
  }
  try {
    const db = await _openDb()
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_LAST_ID, 'readwrite')
      const store = tx.objectStore(STORE_LAST_ID)
      const req = store.put(eventId, taskId)
      req.onsuccess = () => resolve()
      req.onerror = () => reject(req.error)
    })
  } catch {
    /* IndexedDB failure -> sessionStorage already covered */
  }
}

/** 增量追加事件并自动裁剪老数据, 同步推进 lastEventId。 */
export async function appendEvents(
  taskId: string,
  events: EventEnvelope[],
): Promise<void> {
  if (!taskId || !Array.isArray(events) || events.length === 0) return
  const filtered = events
    .filter((ev) => ev && typeof ev.id === 'string' && ev.id)
    .map((ev) => ({ ...ev, task_id: taskId }))
  if (!filtered.length) return
  const lastId = filtered[filtered.length - 1].id

  // memory cache 同步更新
  const mem = _memEvents.get(taskId) || []
  const seen = new Set(mem.map((ev) => ev.id))
  for (const ev of filtered) {
    if (!seen.has(ev.id)) {
      seen.add(ev.id)
      mem.push(ev)
    }
  }
  if (mem.length > MAX_EVENTS_PER_TASK) {
    mem.splice(0, mem.length - MAX_EVENTS_PER_TASK)
  }
  _memEvents.set(taskId, mem)

  await _setLastEventId(taskId, lastId)

  try {
    const db = await _openDb()
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_EVENTS, 'readwrite')
      const store = tx.objectStore(STORE_EVENTS)
      let pending = filtered.length
      let errored = false
      tx.oncomplete = () => resolve()
      tx.onerror = () => {
        if (!errored) {
          errored = true
          reject(tx.error)
        }
      }
      tx.onabort = tx.onerror
      for (const ev of filtered) {
        store.put(ev)
        pending -= 1
        if (pending === 0) {
          // 完成所有 put 后再做一次 trim
          break
        }
      }
    })
    // 裁剪: 用 cursor 数当前 task 的总数, 多于阈值则按 id 升序删最旧的
    await _trimEvents(db, taskId)
  } catch {
    /* IndexedDB failure -> memory only, fine */
  }
}

async function _trimEvents(db: IDBDatabase, taskId: string): Promise<void> {
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_EVENTS, 'readwrite')
      const store = tx.objectStore(STORE_EVENTS)
      const idx = store.index('by_task')
      const range = IDBKeyRange.only(taskId)
      const countReq = idx.count(range)
      countReq.onsuccess = () => {
        const total = Number(countReq.result || 0)
        if (total <= MAX_EVENTS_PER_TASK) {
          resolve()
          return
        }
        const toDrop = total - MAX_EVENTS_PER_TASK
        const cursorReq = idx.openCursor(range, 'next')
        let dropped = 0
        cursorReq.onsuccess = () => {
          const cursor = cursorReq.result
          if (!cursor || dropped >= toDrop) {
            resolve()
            return
          }
          cursor.delete()
          dropped += 1
          cursor.continue()
        }
        cursorReq.onerror = () => reject(cursorReq.error)
      }
      countReq.onerror = () => reject(countReq.error)
    })
  } catch {
    /* ignore */
  }
}

/** 加载某 task 缓存里的事件 (按 id 升序), 返回最多 ``limit`` 条。 */
export async function loadEvents(
  taskId: string,
  limit: number = 2000,
): Promise<EventEnvelope[]> {
  if (!taskId) return []
  const cap = Math.max(1, Math.min(limit, MAX_EVENTS_PER_TASK))
  try {
    const db = await _openDb()
    return await new Promise<EventEnvelope[]>((resolve, reject) => {
      const tx = db.transaction(STORE_EVENTS, 'readonly')
      const store = tx.objectStore(STORE_EVENTS)
      const idx = store.index('by_task')
      const range = IDBKeyRange.only(taskId)
      const req = idx.getAll(range, cap)
      req.onsuccess = () => {
        // keyPath=[task_id, id], by_task 索引返回结果已按 id 字典序排列, 无需二次排序
        resolve((req.result || []) as EventEnvelope[])
      }
      req.onerror = () => reject(req.error)
    })
  } catch {
    const mem = _memEvents.get(taskId) || []
    return mem.slice(-cap)
  }
}

/** 用户主动清理 (删除任务 / 切换 owner 时)。 */
export async function dropTaskEvents(taskId: string): Promise<void> {
  if (!taskId) return
  _memEvents.delete(taskId)
  _memLastId.delete(taskId)
  try {
    sessionStorage.removeItem(SS_LAST_ID_PREFIX + taskId)
  } catch {
    /* ignore */
  }
  try {
    const db = await _openDb()
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction([STORE_EVENTS, STORE_LAST_ID], 'readwrite')
      const evStore = tx.objectStore(STORE_EVENTS)
      const lastStore = tx.objectStore(STORE_LAST_ID)
      const idx = evStore.index('by_task')
      const range = IDBKeyRange.only(taskId)
      const cursorReq = idx.openCursor(range)
      cursorReq.onsuccess = () => {
        const cursor = cursorReq.result
        if (!cursor) return
        cursor.delete()
        cursor.continue()
      }
      lastStore.delete(taskId)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error)
      tx.onabort = tx.onerror
    })
  } catch {
    /* ignore */
  }
}
