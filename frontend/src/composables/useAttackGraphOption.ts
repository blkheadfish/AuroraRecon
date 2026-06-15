import { ref, watch, onBeforeUnmount } from 'vue'
import type { AttackGraphNode, AttackGraphEdge } from '@/types/task'

interface AugmentedNode extends AttackGraphNode {
  _origin?: string
  _pinned?: boolean
  _x?: number
  _y?: number
}

interface AugmentedEdge extends AttackGraphEdge {
  _origin?: string
}

export interface NodeTypeMeta {
  color: string
  symbol: string
  size: number
  label: string
}

export interface RelationMeta {
  color: string
  type: 'solid' | 'dashed' | 'dotted'
  width: number
  curveness: number
  label: string
}

export interface SeverityMeta {
  color: string
  label: string
  sizeBoost: number
  glow: number
}

export const DEFAULT_NODE_STYLE: NodeTypeMeta = { color: '#888', symbol: 'circle', size: 36, label: '?' }

export const NODE_TYPE_META: Record<string, NodeTypeMeta> = {
  host:             { color: 'var(--accent-blue)',   symbol: 'rect',       size: 40, label: '主机' },
  service:          { color: 'var(--text-secondary)', symbol: 'roundRect', size: 28, label: '服务' },
  web_endpoint:     { color: 'var(--accent-blue)',   symbol: 'circle',     size: 26, label: '端点' },
  finding:          { color: 'var(--accent-red)',     symbol: 'diamond',   size: 34, label: '漏洞' },
  credential:       { color: 'var(--accent-yellow)',  symbol: 'pin',       size: 30, label: '凭据' },
  session:          { color: 'var(--accent-green)',   symbol: 'triangle',  size: 36, label: '会话' },
  loot:             { color: 'var(--accent-purple)',  symbol: 'rect',      size: 28, label: '战利品' },
  objective:        { color: 'var(--accent-red)',     symbol: 'path://',   size: 56, label: '目标' },
  pivot_point:      { color: 'var(--accent-purple)',  symbol: 'diamond',   size: 30, label: '跳板' },
  domain_user:      { color: 'var(--accent-purple)',  symbol: 'circle',    size: 28, label: '域用户' },
  group:            { color: 'var(--accent-purple)',  symbol: 'roundRect', size: 28, label: '组' },
  computer:         { color: 'var(--accent-purple)',  symbol: 'rect',      size: 28, label: '计算机' },
  share:            { color: 'var(--accent-purple)',  symbol: 'roundRect', size: 26, label: '共享' },
  ticket:           { color: 'var(--accent-purple)',  symbol: 'pin',       size: 26, label: '票据' },
  spn:              { color: 'var(--accent-purple)',  symbol: 'diamond',   size: 26, label: 'SPN' },
  cloud_identity:   { color: 'var(--accent-blue)',    symbol: 'circle',    size: 28, label: '云身份' },
  iam_role:         { color: 'var(--accent-blue)',    symbol: 'diamond',   size: 28, label: 'IAM角色' },
  bucket:           { color: 'var(--accent-blue)',    symbol: 'rect',      size: 28, label: 'Bucket' },
}

export const RELATION_META: Record<string, RelationMeta> = {
  runs_on:        { color: 'var(--border)',         type: 'solid',  width: 1,   curveness: 0.12, label: '运行在' },
  exposes:        { color: 'var(--border)',         type: 'solid',  width: 1,   curveness: 0.12, label: '暴露' },
  vulnerable_to:  { color: 'var(--accent-red)',     type: 'dashed', width: 1.5, curveness: 0.12, label: '易受' },
  yields:         { color: 'var(--accent-green)',   type: 'solid',  width: 1.5, curveness: 0.12, label: '产出' },
  enables:        { color: 'var(--accent-blue)',    type: 'solid',  width: 1.5, curveness: 0.12, label: '使能' },
  leads_to:       { color: 'var(--accent-blue)',    type: 'solid',  width: 1.5, curveness: 0.12, label: '导致' },
  pivots_to:      { color: 'var(--accent-purple)',  type: 'solid',  width: 2,   curveness: 0.12, label: '跳转至' },
  has_session_on: { color: 'var(--accent-purple)',  type: 'solid',  width: 2,   curveness: 0.12, label: '会话' },
  requires:       { color: 'var(--text-muted)',     type: 'dotted', width: 1,   curveness: 0.12, label: '需要' },
  member_of:      { color: 'var(--accent-purple)',  type: 'dashed', width: 1.5, curveness: 0.12, label: '成员' },
  admin_of:       { color: 'var(--accent-purple)',  type: 'dashed', width: 1.5, curveness: 0.12, label: '管理员' },
  kerberoastable: { color: 'var(--accent-purple)',  type: 'dashed', width: 1.5, curveness: 0.12, label: 'Kerberoastable' },
  assumes:        { color: 'var(--accent-blue)',    type: 'dashed', width: 1.5, curveness: 0.12, label: '扮演' },
  can_read:       { color: 'var(--accent-blue)',    type: 'dashed', width: 1.5, curveness: 0.12, label: '可读' },
  can_write:      { color: 'var(--accent-blue)',    type: 'dashed', width: 1.5, curveness: 0.12, label: '可写' },
  discovers:      { color: 'var(--accent-purple)',  type: 'dashed', width: 1.5, curveness: 0.12, label: '发现' },
  consumes:       { color: 'var(--accent-purple)',  type: 'solid',  width: 1.5, curveness: 0.12, label: '消费' },
}

export const SEVERITY_META: Record<string, SeverityMeta> = {
  critical: { color: 'var(--accent-red)',    label: '严重', sizeBoost: 14, glow: 18 },
  high:     { color: 'var(--accent-orange)', label: '高危', sizeBoost: 10, glow: 14 },
  medium:   { color: 'var(--accent-yellow)', label: '中危', sizeBoost: 6,  glow: 8  },
  low:      { color: 'var(--accent-blue)',   label: '低危', sizeBoost: 2,  glow: 0  },
  info:     { color: 'var(--text-muted)',    label: '信息', sizeBoost: 0,  glow: 0  },
}

const NODE_TYPE_ORDER = [
  'host', 'service', 'web_endpoint', 'finding', 'credential', 'session',
  'loot', 'objective', 'pivot_point',
  'domain_user', 'group', 'computer', 'share', 'ticket', 'spn',
  'cloud_identity', 'iam_role', 'bucket',
]

export const typeLabel = (t: string): string =>
  (NODE_TYPE_META[t] || DEFAULT_NODE_STYLE).label

export const typeTag = (t: string): string => {
  switch (t) {
    case 'host':         return ''
    case 'service':      return 'success'
    case 'web_endpoint': return 'success'
    case 'finding':      return 'danger'
    case 'credential':   return 'warning'
    case 'foothold':     return 'info'
    case 'session':      return 'info'
    case 'loot':         return 'info'
    case 'objective':    return 'success'
    case 'pivot_point':  return 'warning'
    default:             return ''
  }
}

function escapeHtml(s: unknown): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function truncateLabel(s: string): string {
  if (!s) return ''
  return s.length > 28 ? s.slice(0, 26) + '\u2026' : s
}

export interface KillChainPath {
  edgeIds: Set<string>
  nodes: Set<string>
}

function resolveCssVar(name: string, fallback: string): string {
  if (typeof document === 'undefined') return fallback
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback
}

function resolveColor(token: string, fallback: string): string {
  if (token.startsWith('var(')) {
    const name = token.slice(4, -1)
    return resolveCssVar(name, fallback)
  }
  return token
}

export const NODE_TYPE_COUNT_KEYS = NODE_TYPE_ORDER

export function buildEchartsNodes(
  mergedNodes: AugmentedNode[],
  selectedNodeId: string,
  frontendNodeIds: Set<string>,
  ownedNodeIds: Set<string>,
  objectiveReachedIds: Set<string>,
  highValueNodeIds: Set<string>,
  killChainNodeIds: Set<string>,
  degrade: boolean,
  textColor: string,
) {
  return mergedNodes.map((n) => {
    const meta = NODE_TYPE_META[n.type] || DEFAULT_NODE_STYLE
    let color = resolveColor(meta.color, '#888')
    let size = meta.size
    let glow = 0
    let severity = ''

    if (n.type === 'finding') {
      severity = String(n.facts?.severity || 'info').toLowerCase()
      const sevMeta = SEVERITY_META[severity] || SEVERITY_META.info
      color = resolveColor(sevMeta.color, '#888')
      size += sevMeta.sizeBoost
      glow = sevMeta.glow
    }

    const exploitable = Boolean(n.facts?.exploitable)
    const isSynth = n._origin === 'synth'
    const isPrior = n.facts?.source === 'prior' || n.facts?.from_history === true
    const isTargetSelected = selectedNodeId && n.id === selectedNodeId
    const isFrontier = frontendNodeIds.has(n.id)
    const isOwned = ownedNodeIds.has(n.id)
    const isObjectiveReached = objectiveReachedIds.has(n.id)
    const isHighValue = highValueNodeIds.has(n.id)
    const inKillChain = killChainNodeIds.has(n.id)

    let borderColor = 'transparent'
    let borderWidth = 0
    let borderType: string = 'solid'
    let shadowBlur = glow
    let shadowColor = 'transparent'

    if (isTargetSelected) {
      borderColor = resolveColor('var(--accent-red)', '#e06979')
      borderWidth = 3
      shadowBlur = Math.max(glow, 18)
      shadowColor = resolveColor('var(--accent-red)', '#e06979')
    } else if (isObjectiveReached) {
      borderColor = resolveColor('var(--accent-yellow)', '#d9a84e')
      borderWidth = 2
      shadowBlur = isTargetSelected ? 30 : (degrade ? 0 : 30)
      shadowColor = degrade ? 'transparent' : 'rgba(217,168,78,.6)'
    } else if (isOwned) {
      borderColor = resolveColor('var(--accent-green)', '#56c9a4')
      borderWidth = 2
    } else if (isFrontier && !degrade) {
      borderColor = resolveColor('var(--accent-blue)', '#58b8e0')
      borderWidth = 1
      shadowBlur = Math.max(shadowBlur, 20)
      shadowColor = 'rgba(88,184,224,.45)'
    } else if (exploitable) {
      borderColor = '#ffc857'
      borderWidth = 2
    } else if (isPrior) {
      borderColor = '#c9a74e'
      borderWidth = 2
      borderType = 'dashed'
    } else if (isSynth) {
      borderColor = 'rgba(255,255,255,0.18)'
      borderWidth = 1
      borderType = isHighValue ? 'dashed' : 'solid'
    } else if (isHighValue) {
      borderType = 'dashed'
      borderWidth = 1
    }

    const showLabel = degrade
      ? (n.type === 'host' || n.type === 'objective' || n.type === 'credential')
      : true

    const labelColor = inKillChain
      ? resolveCssVar('--accent-red', '#e06979')
      : textColor

    return {
      id: n.id,
      name: (isPrior ? '\u23f3 ' : '') + (n.label || n.id),
      symbol: meta.symbol,
      symbolSize: size + (isTargetSelected ? 8 : 0),
      category: n.type,
      x: n._pinned ? n._x : undefined,
      y: n._pinned ? n._y : undefined,
      fixed: n._pinned || false,
      itemStyle: {
        color,
        borderColor,
        borderWidth,
        borderType,
        shadowBlur: degrade ? 0 : shadowBlur,
        shadowColor,
        opacity: isSynth && !inKillChain ? 0.88 : 1,
      },
      label: {
        show: showLabel,
        position: 'bottom',
        fontSize: 11,
        fontFamily: 'JetBrains Mono',
        formatter: (p: { name: string }) => truncateLabel(p.name),
        color: labelColor,
      },
      _raw: {
        ...n,
        _severity: severity,
        _evidence: n.facts?.evidence || '',
        _isPrior: isPrior,
        _isFrontier: isFrontier,
        _isOwned: isOwned,
        _isObjectiveReached: isObjectiveReached,
      },
    }
  })
}

export function buildEchartsEdges(
  mergedEdges: AugmentedEdge[],
  killChainEdgeIds: Set<string>,
  degrade: boolean,
) {
  return mergedEdges.map((e) => {
    const meta = RELATION_META[e.relation] || RELATION_META.leads_to
    const isSynth = e._origin === 'synth'
    const inKillChain = killChainEdgeIds.has(`${e.src}|${e.dst}|${e.relation}`)
    const isNonKillChain = !inKillChain && !killChainEdgeIds.has(`${e.src}|${e.dst}|${e.relation}`)

    return {
      source: e.src,
      target: e.dst,
      lineStyle: {
        color: resolveColor(meta.color, '#888'),
        type: isSynth && !inKillChain ? 'dashed' : meta.type,
        width: inKillChain ? 3 : meta.width,
        opacity: inKillChain ? 1 : (isNonKillChain ? 0.45 : 0.75),
        curveness: meta.curveness,
        shadowBlur: inKillChain && !degrade ? 8 : 0,
        shadowColor: inKillChain ? resolveCssVar('--accent-red', '#e06979') : 'transparent',
      },
      label: { show: false },
      _raw: e,
    }
  })
}

export function buildCategories(textColor: string) {
  return NODE_TYPE_COUNT_KEYS.map((k) => ({
    name: k,
    itemStyle: { color: resolveColor(NODE_TYPE_META[k]?.color || '#888', '#888') },
  })).filter((c) => NODE_TYPE_META[c.name])
}

export function computeNodeTypeStats(nodes: AugmentedNode[]): { type: string; count: number }[] {
  const counts: Record<string, number> = {}
  for (const n of nodes) {
    counts[n.type] = (counts[n.type] || 0) + 1
  }
  return NODE_TYPE_COUNT_KEYS
    .filter((k) => counts[k])
    .map((type) => ({ type, count: counts[type] }))
}

export function computeSeverityStats(nodes: AugmentedNode[]): { key: string; count: number }[] {
  const counts: Record<string, number> = {}
  for (const n of nodes) {
    if (n.type !== 'finding') continue
    const k = String(n.facts?.severity || 'info').toLowerCase()
    counts[k] = (counts[k] || 0) + 1
  }
  return ['critical', 'high', 'medium', 'low', 'info']
    .filter((k) => counts[k])
    .map((key) => ({ key, count: counts[key] }))
}

export function buildTooltipFormatter(
  textColor: string,
  mutedColor: string,
  accentColor: string,
  nodeTypeMeta: Record<string, NodeTypeMeta>,
  relationMeta: Record<string, RelationMeta>,
  severityMeta: Record<string, SeverityMeta>,
) {
  return (p: { dataType?: string; data?: any }) => {
    if (p.dataType === 'node') {
      const r = p.data._raw
      const sev = r._severity
      const sevTag = sev
        ? `<span style="display:inline-block;padding:0 6px;border-radius:3px;background:${resolveColor(severityMeta[sev]?.color || '#666', '#666')};color:#fff;font-size:10px;margin-left:4px">${severityMeta[sev]?.label || sev}</span>`
        : ''
      const exp = r.facts?.exploitable
        ? `<span style="display:inline-block;padding:0 6px;border-radius:3px;background:#ffc857;color:#1d2128;font-size:10px;margin-left:4px">可利用</span>`
        : ''
      const cve = r.facts?.cve
        ? `<div style="font-size:11px;margin-top:4px;color:${accentColor}">${escapeHtml(r.facts.cve)}</div>`
        : ''
      const tgt = r.facts?.target
        ? `<div style="font-size:11px;margin-top:2px;color:#9ab4c0">target: ${escapeHtml(String(r.facts.target))}</div>`
        : ''
      const priorNote = r._isPrior
        ? `<div style="font-size:10px;margin-top:4px;padding:2px 6px;border-radius:3px;background:rgba(201,167,78,0.15);color:#c9a74e;display:inline-block">\u23f3 历史推断，待验证</div>`
        : ''
      const frontierNote = r._isFrontier
        ? `<div style="font-size:10px;margin-top:2px;color:${accentColor};opacity:0.8">\u25cf 可利用前沿</div>`
        : ''
      const ownedNote = r._isOwned
        ? `<div style="font-size:10px;margin-top:2px;color:#56c9a4">\u2713 已攻陷</div>`
        : ''
      const evidence = r._evidence && r._evidence.length < 200
        ? `<div style="font-size:11px;margin-top:6px;padding:6px 8px;border-left:2px solid ${accentColor};background:rgba(88,184,224,0.06);color:${mutedColor}">${escapeHtml(r._evidence)}</div>`
        : ''
      return `
        <div style="font-weight:600;margin-bottom:4px">${escapeHtml(r.label || r.id)}${sevTag}${exp}</div>
        <div style="font-size:11px;color:${mutedColor}">${typeLabel(r.type)} \u00b7 ${escapeHtml(r.id)}</div>
        ${cve}${tgt}${priorNote}${frontierNote}${ownedNote}
        ${evidence}
        <div style="font-size:11px;margin-top:4px;color:${mutedColor}">来源: ${escapeHtml(r.discovered_by || '\u2014')}</div>
      `
    }
    if (p.dataType === 'edge') {
      const r = p.data._raw
      const meta = RELATION_META[r.relation] || {}
      return `
        <div style="font-family:JetBrains Mono,monospace;font-size:11px"><code>${escapeHtml(r.src)}</code></div>
        <div style="margin:2px 0;color:${resolveColor(meta.color || '#aaa', '#aaa')}">\u2014 ${meta.label || r.relation} \u2192</div>
        <div style="font-family:JetBrains Mono,monospace;font-size:11px"><code>${escapeHtml(r.dst)}</code></div>
        ${r.note ? `<div style="font-size:11px;color:${mutedColor};margin-top:4px">${escapeHtml(r.note)}</div>` : ''}
      `
    }
    return ''
  }
}

export function useNodePinning(
  chartRef: { value: any },
  onPin: (nodeId: string, x: number, y: number) => void,
) {
  const pinned = new Set<string>()

  function onFinished() {
    const chart = chartRef.value
    if (!chart) return
    try {
      const model = chart.getModel?.() || chart._model
      if (!model) return
      const series = model.getSeries?.() || []
      for (const s of series) {
        const graph = s?.getGraph?.()
        if (!graph) continue
        const data = s.getData?.()
        if (!data) continue
        data.each((idx: number) => {
          const node = graph.getNodeByIndex?.(idx)
          if (!node) return
          const id = data.getId?.(idx)
          if (!id || pinned.has(id)) return
          const pos = node.getLayout?.()
          if (pos && isFinite(pos.x) && isFinite(pos.y)) {
            pinned.add(id)
            onPin(id, pos.x, pos.y)
          }
        })
      }
    } catch { /* ignore chart API differences */ }
  }

  function reset() {
    pinned.clear()
  }

  return { onFinished, reset, pinned }
}

export function usePulseTimer(
  onTick: () => void,
  enabledRef: { value: boolean },
  intervalMs: number = 700,
) {
  let timer: ReturnType<typeof setInterval> | null = null

  function start() {
    stop()
    timer = setInterval(() => {
      if (!enabledRef.value) return
      onTick()
    }, intervalMs)
  }

  function stop() {
    if (timer !== null) {
      clearInterval(timer)
      timer = null
    }
  }

  onBeforeUnmount(stop)

  return { start, stop }
}
