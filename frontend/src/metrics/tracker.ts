type MetricPayload = Record<string, unknown>

export interface MetricEvent {
  name: string
  ts: number
  payload: MetricPayload
}

const KEY = 'pentest.metrics.events'
const MAX_EVENTS = 300

function loadEvents(): MetricEvent[] {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function saveEvents(events: MetricEvent[]) {
  localStorage.setItem(KEY, JSON.stringify(events.slice(-MAX_EVENTS)))
}

export function trackEvent(name: string, payload: MetricPayload = {}) {
  const events = loadEvents()
  events.push({
    name,
    ts: Date.now(),
    payload,
  })
  saveEvents(events)
}

export function getMetricEvents(): MetricEvent[] {
  return loadEvents()
}

export function getMetricCounters() {
  const events = loadEvents()
  const counter: Record<string, number> = {}
  for (const event of events) {
    counter[event.name] = (counter[event.name] || 0) + 1
  }
  return counter
}

export function clearMetricEvents() {
  localStorage.removeItem(KEY)
}
