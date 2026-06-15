<template>
  <div class="attack-graph-view">
    <!-- ── 顶部统计 / 操作栏 ───────────────────────────────── -->
    <div class="graph-toolbar">
      <div class="graph-stats">
        <el-tag size="small" effect="plain" type="info">
          节点 {{ mergedNodes.length }} / 边 {{ mergedEdges.length }}
        </el-tag>
        <el-tag
          v-for="t in nodeTypeStats"
          :key="t.type"
          size="small"
          effect="plain"
          :type="typeTag(t.type)"
          class="type-stat"
          :class="{ 'is-disabled': hiddenTypes.has(t.type) }"
          @click="toggleType(t.type)"
        >
          <span class="type-stat-icon" :style="{ background: resolveMetaColor((NODE_TYPE_META[t.type] || DEFAULT_NODE_STYLE).color) }" />
          {{ typeLabel(t.type) }} &middot; {{ t.count }}
        </el-tag>
        <el-tag
          v-if="severityStats.length"
          v-for="s in severityStats"
          :key="`sev-${s.key}`"
          size="small"
          effect="dark"
          :color="resolveMetaColor(SEVERITY_META[s.key]?.color)"
          class="sev-stat"
        >
          {{ SEVERITY_META[s.key]?.label || s.key }} &middot; {{ s.count }}
        </el-tag>
      </div>
      <div class="graph-actions">
        <el-input
          v-model="searchText"
          size="small"
          clearable
          placeholder="搜索节点 (label / id)"
          class="graph-search"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>
        <el-tooltip content="只看可利用 / 已确认的节点" placement="top">
          <el-switch
            v-model="exploitableOnly"
            size="small"
            inline-prompt
            active-text="高危"
            inactive-text="全部"
          />
        </el-tooltip>
        <el-radio-group v-model="layoutMode" size="small">
          <el-radio-button value="force">力导向</el-radio-button>
          <el-radio-button value="circular">环形</el-radio-button>
          <el-radio-button value="layered">分层</el-radio-button>
        </el-radio-group>
        <el-button size="small" plain @click="resetView">
          <el-icon><Refresh /></el-icon>
          重置
        </el-button>
      </div>
    </div>

    <!-- ── 主画布 / 空状态 ─────────────────────────────────── -->
    <div v-if="!mergedNodes.length" class="graph-empty">
      <div class="graph-empty-inner">
        <div class="empty-icon-wrap">
          <el-icon class="empty-icon"><Share /></el-icon>
        </div>
        <p class="empty-text">{{ emptyText }}</p>
        <el-button size="small" plain @click="$emit('refresh')" v-if="hasRefreshHandler">
          重新拉取数据
        </el-button>
      </div>
    </div>
    <div v-else ref="canvasWrapRef" class="graph-canvas-wrap">
      <VChart
        v-if="chartReady"
        ref="chartRef"
        :option="debouncedOption"
        :update-options="{ notMerge: false, lazyUpdate: true }"
        autoresize
        class="graph-canvas"
        @click="onNodeClick"
        @finished="onChartFinished"
      />
      <!-- 自定义图例面板 -->
      <div v-if="!degrade" class="graph-legend-panel">
        <div
          v-for="t in nodeTypeStats"
          :key="t.type"
          class="legend-row"
          :class="{ 'is-disabled': hiddenTypes.has(t.type) }"
          @click="toggleType(t.type)"
        >
          <span class="legend-icon" :style="{ background: resolveMetaColor((NODE_TYPE_META[t.type] || DEFAULT_NODE_STYLE).color) }" />
          <span class="legend-label">{{ typeLabel(t.type) }}</span>
          <span class="legend-count">&times;{{ t.count }}</span>
        </div>
      </div>
    </div>

    <!-- ── Kill-chain 路径文字 ──────────────────────────────── -->
    <div v-if="killChainPathText" class="kill-chain-caption">
      <el-icon><Link /></el-icon>
      <span>{{ killChainPathText }}</span>
    </div>

    <!-- ── 节点详情抽屉 ─────────────────────────────────────── -->
    <el-drawer
      v-model="drawerOpen"
      direction="rtl"
      size="420px"
      :title="drawerTitle"
      :with-header="true"
    >
      <div v-if="selected" class="node-detail">
        <div class="detail-row">
          <span class="detail-label">类型</span>
          <el-tag size="small" :type="typeTag(selected.type)">
            {{ typeLabel(selected.type) }}
          </el-tag>
          <el-tag
            v-if="selected._severity"
            size="small"
            effect="dark"
            :color="resolveMetaColor(SEVERITY_META[selected._severity]?.color)"
            class="detail-sev"
          >
            {{ SEVERITY_META[selected._severity]?.label || selected._severity }}
          </el-tag>
          <el-tag
            v-if="selected.facts?.exploitable"
            size="small"
            type="danger"
            effect="dark"
          >可利用</el-tag>
        </div>
        <div class="detail-row">
          <span class="detail-label">ID</span>
          <code class="detail-code">{{ selected.id }}</code>
        </div>
        <div class="detail-row">
          <span class="detail-label">名称</span>
          <span class="detail-value">{{ selected.label || '—' }}</span>
        </div>
        <div class="detail-row" v-if="selected.facts?.cve">
          <span class="detail-label">CVE</span>
          <a
            class="cve-link"
            :href="`https://nvd.nist.gov/vuln/detail/${selected.facts.cve}`"
            target="_blank"
            rel="noopener"
          >{{ selected.facts.cve }}</a>
        </div>
        <div class="detail-row">
          <span class="detail-label">发现来源</span>
          <span class="detail-value">{{ selected.discovered_by || '—' }}</span>
        </div>
        <div class="detail-row" v-if="selected.facts?.source === 'prior' || selected.facts?.from_history === true">
          <span class="detail-label">可信度</span>
          <el-tag size="small" type="warning" effect="plain">⏳ 历史推断，待验证</el-tag>
        </div>
        <div class="detail-row">
          <span class="detail-label">发现时间</span>
          <span class="detail-value mono">{{ formatTs(selected.discovered_at) }}</span>
        </div>

        <div class="detail-section" v-if="selected._evidence">
          <div class="detail-section-title">证据 / PoC</div>
          <pre class="detail-evidence">{{ selected._evidence }}</pre>
        </div>

        <div class="detail-section">
          <div class="detail-section-title">关联事实</div>
          <pre class="detail-facts">{{ pretty(selected.facts) }}</pre>
        </div>

        <div class="detail-section" v-if="relatedEdges.length">
          <div class="detail-section-title">关联边 ({{ relatedEdges.length }})</div>
          <ul class="edge-list">
            <li v-for="(e, idx) in relatedEdges" :key="idx">
              <code>{{ e.src }}</code>
              <span class="rel">— {{ (RELATION_META[e.relation] || {}).label || e.relation }} →</span>
              <code>{{ e.dst }}</code>
              <span v-if="e.note" class="note">{{ e.note }}</span>
            </li>
          </ul>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onBeforeUnmount, ref, watch, getCurrentInstance } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { GraphChart, LinesChart } from 'echarts/charts'
import {
  TitleComponent, TooltipComponent, LegendComponent,
} from 'echarts/components'
import { Search, Refresh, Share, Link } from '@element-plus/icons-vue'
import { useChartTheme } from '@/composables/useChartTheme'
import { useTaskLiveStore } from '@/stores/taskLive'
import {
  NODE_TYPE_META, DEFAULT_NODE_STYLE, RELATION_META, SEVERITY_META,
  typeLabel, typeTag, NODE_TYPE_COUNT_KEYS,
  buildEchartsNodes, buildEchartsEdges, buildCategories,
  computeNodeTypeStats, computeSeverityStats, buildTooltipFormatter,
  useNodePinning, usePulseTimer,
} from '@/composables/useAttackGraphOption'

use([CanvasRenderer, GraphChart, LinesChart, TitleComponent, TooltipComponent, LegendComponent])

const props = defineProps({
  graph: {
    type: Object,
    default: () => ({ nodes: [], edges: [] }),
  },
  task: {
    type: Object,
    default: null,
  },
  selectedNodeId: {
    type: String,
    default: '',
  },
})

defineEmits(['refresh', 'select'])

const chartTheme = useChartTheme()
const taskLiveStore = useTaskLiveStore()
const taskId = computed(() => props.task?.id || props.task?.task_id || '')
const taskWorldGraph = computed(() => {
  if (!taskId.value) return { nodes: {}, edges: [] }
  const state = taskLiveStore.getLiveState(taskId.value)
  return state?.worldGraph || { nodes: {}, edges: [] }
})
const chartRef = ref<any>(null)
const layoutMode = ref('force')
const drawerOpen = ref(false)
const selected = ref<any>(null)
const searchText = ref('')
const exploitableOnly = ref(false)
const hiddenTypes = ref(new Set<string>())

const hasRefreshHandler = computed(() => {
  const inst = getCurrentInstance()
  return Boolean(inst?.vnode?.props?.onRefresh)
})

// ── 性能降级与动画偏好 ─────────────────────────────
const prefersReducedMotion = ref(false)
const degrade = computed(() => mergedNodes.value.length > 120)

// ── 节点状态追踪 ────────────────────────────────────
const frontendNodeIds = ref(new Set<string>())
const ownedNodeIds = ref(new Set<string>())
const objectiveReachedIds = ref(new Set<string>())
const highValueNodeIds = ref(new Set<string>())
const pulseGeneration = ref(0)

function resolveMetaColor(token: string | undefined): string {
  if (!token) return '#888'
  if (token.startsWith('var(')) {
    const name = token.slice(4, -1)
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#888'
  }
  return token
}

// ── 世界模型监听（从 store 提取状态标注） ──────────
watch(
  () => taskWorldGraph.value,
  (wg) => {
    const frontier = new Set<string>()
    const owned = new Set<string>()
    const objective = new Set<string>()
    const highValue = new Set<string>()

    for (const [id, node] of Object.entries(wg?.nodes || {})) {
      const attrs = (node as any).attrs || {}
      if (attrs.frontier === true || attrs._frontier === true) frontier.add(id)
      if (attrs.owned === true || attrs._owned === true) owned.add(id)
      if (attrs.objective_reached === true || attrs._objective_reached === true) objective.add(id)
      if (attrs.high_value === true || attrs._high_value === true) highValue.add(id)
    }

    frontendNodeIds.value = frontier
    ownedNodeIds.value = owned
    objectiveReachedIds.value = objective
    highValueNodeIds.value = highValue
  },
)

// ── Kill-chain 路径计算 ────────────────────────────
const killChainPath = computed(() => {
  const wg = taskWorldGraph.value
  if (!wg || !wg.nodes || !wg.edges) return { edgeIds: new Set<string>(), nodes: new Set<string>() }

  const chainNodeIds = new Set<string>()
  const chainEdgeIds = new Set<string>()

  for (const [id, node] of Object.entries(wg.nodes)) {
    const attrs = (node as any).attrs || {}
    if (attrs._on_kill_chain === true || attrs._on_path === true || attrs.kill_chain === true) {
      chainNodeIds.add(id)
    }
  }
  for (const e of wg.edges) {
    const attrs = (e as any).attrs || {}
    if (attrs._on_kill_chain === true || attrs._on_path === true || attrs.kill_chain === true) {
      chainEdgeIds.add(`${e.src}|${e.dst}|${e.relation}`)
    }
  }

  if (chainNodeIds.size > 0 || chainEdgeIds.size > 0) {
    return { edgeIds: chainEdgeIds, nodes: chainNodeIds }
  }

  const objectiveNodes = new Set<string>()
  for (const [id, node] of Object.entries(wg.nodes)) {
    const attrs = (node as any).attrs || {}
    if (attrs.objective_reached === true || attrs._objective_reached === true || node.type === 'objective') {
      objectiveNodes.add(id)
    }
  }

  if (objectiveNodes.size > 0) {
    for (const e of wg.edges) {
      if (objectiveNodes.has(e.dst)) {
        chainNodeIds.add(e.src)
        chainNodeIds.add(e.dst)
        chainEdgeIds.add(`${e.src}|${e.dst}|${e.relation}`)
      }
    }
  }

  return { edgeIds: chainEdgeIds, nodes: chainNodeIds }
})

const killChainPathText = computed(() => {
  const kc = killChainPath.value
  if (kc.nodes.size === 0) return ''
  const wg = taskWorldGraph.value
  const nodeLabels: string[] = []
  for (const id of kc.nodes) {
    const node = wg?.nodes?.[id]
    if (node) nodeLabels.push(node.label || node.type)
  }
  if (nodeLabels.length === 0) return ''
  let gaps = 0
  for (const [, node] of Object.entries(wg?.nodes || {})) {
    if (!kc.nodes.has(node.id) && ((node as any).attrs?.high_value || node.type === 'credential')) {
      gaps++
    }
  }
  const gapStr = gaps > 0 ? ` (缺 ${gaps} 个凭据)` : ''
  return `\u{1f6e3}\ufe0f 已规划路径: ${nodeLabels.join(' \u2192 ')}${gapStr}`
})

// ── 辅助：与后端保持一致的 ID 命名 ─────────────────
function _hostId(host: string) { return host ? `host:${host}` : '' }
function _svcId(host: string, port: number | string) { return host && port ? `svc:${host}:${port}` : '' }
function _findingId(vid: string) { return vid ? `finding:${vid}` : '' }
function _credId(cred: any) {
  const user = cred?.user || cred?.username || ''
  const src  = cred?.source || ''
  const val  = cred?.value || cred?.password || ''
  const raw  = `${user}|${src}|${val}`
  let h = 0x811c9dc5
  for (let i = 0; i < raw.length; i++) {
    h ^= raw.charCodeAt(i)
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0
  }
  return `cred:${h.toString(16)}`
}
function _lootId(loot: any, idx: number) {
  const key = (typeof loot === 'string' ? loot : (loot?.path || loot?.name || `idx${idx}`))
  return `loot:${key}`
}
function _hostFromTarget(target: string) {
  if (!target) return ''
  try {
    if (target.includes('://')) {
      return new URL(target).hostname
    }
  } catch { /* fall through */ }
  return String(target).split(':')[0]
}

// ── 合成图：以后端 graph 为权威，task.* 兜底补齐 ───
const composedGraph = computed(() => {
  const nodeMap = new Map<string, any>()
  const edgeSet = new Set<string>()
  const edges: any[] = []

  for (const n of (props.graph?.nodes || [])) {
    if (!n?.id) continue
    nodeMap.set(n.id, { ...n, _origin: 'backend' })
  }
  for (const e of (props.graph?.edges || [])) {
    if (!e?.src || !e?.dst) continue
    const key = `${e.src}|${e.dst}|${e.relation || 'leads_to'}`
    if (edgeSet.has(key)) continue
    edgeSet.add(key)
    edges.push({ ...e, _origin: 'backend' })
  }

  const upsert = (id: string, type: string, label: string, facts: any, discoveredBy: string) => {
    if (!id) return
    if (nodeMap.has(id)) return
    nodeMap.set(id, {
      id,
      type,
      label: label || id,
      facts: facts || {},
      discovered_by: discoveredBy || 'frontend_synth',
      discovered_at: '',
      _origin: 'synth',
    })
  }
  const addEdge = (src: string, dst: string, relation: string, note: string) => {
    if (!src || !dst || src === dst) return
    const key = `${src}|${dst}|${relation || 'leads_to'}`
    if (edgeSet.has(key)) return
    edgeSet.add(key)
    edges.push({ src, dst, relation: relation || 'leads_to', note: note || '', _origin: 'synth' })
  }

  const t = props.task
  if (t) {
    const host = _hostFromTarget(t.target_host || t.target)
    if (host) upsert(_hostId(host), 'host', host, { from: 'task.target' }, 'task_summary')

    const ports = Array.isArray(t.open_ports) ? t.open_ports : []
    for (const p of ports) {
      if (!p?.port) continue
      const svcId = _svcId(host, p.port)
      if (!svcId) continue
      upsert(svcId, 'service',
        `${p.service || 'svc'}:${p.port}`,
        { port: p.port, service: p.service || '', version: p.version || '', banner: p.banner || '' },
        'task_summary',
      )
      addEdge(_hostId(host), svcId, 'exposes')
    }

    const findings = Array.isArray(t.findings) ? t.findings : []
    for (const f of findings) {
      if (!f?.vuln_id) continue
      const fid = _findingId(f.vuln_id)
      upsert(fid, 'finding', f.name || f.vuln_id, {
        severity: f.severity || 'info',
        cve: f.cve || '',
        exploitable: Boolean(f.exploitable),
        confidence: f.confidence,
        verification_status: f.verification_status || '',
        tool: f.tool || '',
        target: f.target || '',
        port: f.port || 0,
        evidence: f.evidence || '',
        description: f.description || '',
      }, f.tool || 'finding_synth')

      const fHost = _hostFromTarget(f.target) || host
      if (f.port && fHost) {
        const svcId = _svcId(fHost, f.port)
        upsert(svcId, 'service', `svc:${f.port}`, { port: f.port }, 'finding_synth')
        upsert(_hostId(fHost), 'host', fHost, {}, 'finding_synth')
        addEdge(_hostId(fHost), svcId, 'exposes')
        addEdge(svcId, fid, 'enables')
      } else if (fHost) {
        upsert(_hostId(fHost), 'host', fHost, {}, 'finding_synth')
        addEdge(_hostId(fHost), fid, 'enables')
      }
    }

    const creds = Array.isArray(t.credential_store) ? t.credential_store : []
    for (const c of creds) {
      if (!c) continue
      const cid = _credId(c)
      const userPart = c.user || c.username || '?'
      const srcPart = c.source || '?'
      upsert(cid, 'credential', `${userPart}@${srcPart}`, c, 'credential_store')
      if (host) addEdge(_hostId(host), cid, 'discovers')
    }

    if (t.got_shell || t.foothold_status === 'established' || t.foothold_status === 'verified') {
      const fhId = `foothold:${host || 'unknown'}`
      upsert(fhId, 'foothold',
        host ? `Shell @ ${host}` : 'Shell',
        { status: t.foothold_status || 'established', privilege_level: t.privilege_level || 'unknown' },
        'foothold_tracker',
      )
      if (host) addEdge(_hostId(host), fhId, 'leads_to')
      for (const f of findings) {
        if (f?.exploitable && f?.vuln_id) {
          addEdge(_findingId(f.vuln_id), fhId, 'leads_to')
        }
      }
    }

    const loots = Array.isArray(t.loot_store) ? t.loot_store : []
    loots.forEach((l: any, i: number) => {
      const lid = _lootId(l, i)
      const label = typeof l === 'string' ? l : (l?.path || l?.name || `loot-${i}`)
      upsert(lid, 'loot', label, typeof l === 'object' ? l : { value: l }, 'loot_store')
      if (host) addEdge(`foothold:${host}`, lid, 'consumes')
    })

    const obj = t.objective_status
    if (obj && (obj.flag_found || obj.objective_reached || obj.status === 'reached')) {
      const oid = `objective:${host || 'task'}`
      upsert(oid, 'objective', obj.flag || obj.objective || '目标达成', obj, 'objective_collector')
      if (host) addEdge(`foothold:${host}`, oid, 'leads_to')
    }
  }

  return { nodes: Array.from(nodeMap.values()), edges }
})

// ── 显示过滤 ─────────────────────────────────────────
const filteredGraph = computed(() => {
  const allNodes = composedGraph.value.nodes
  const allEdges = composedGraph.value.edges
  const q = searchText.value.trim().toLowerCase()
  const visibleIds = new Set<string>()

  for (const n of allNodes) {
    if (hiddenTypes.value.has(n.type)) continue
    if (exploitableOnly.value) {
      const sev = n.facts?.severity
      const ok =
        n.type === 'host' || n.type === 'foothold' || n.type === 'objective' ||
        (n.type === 'finding' && (n.facts?.exploitable || sev === 'critical' || sev === 'high')) ||
        n.type === 'credential' || n.type === 'loot'
      if (!ok) continue
    }
    if (q) {
      const hay = `${n.id} ${n.label || ''} ${n.facts?.cve || ''} ${n.facts?.target || ''}`.toLowerCase()
      if (!hay.includes(q)) continue
    }
    visibleIds.add(n.id)
  }

  const nodes = allNodes.filter((n) => visibleIds.has(n.id))
  const edges = allEdges.filter((e) => visibleIds.has(e.src) && visibleIds.has(e.dst))
  return { nodes, edges }
})

const mergedNodes = computed(() => filteredGraph.value.nodes)
const mergedEdges = computed(() => filteredGraph.value.edges)

const emptyText = computed(() => {
  const totalRaw = composedGraph.value.nodes.length
  if (totalRaw === 0) return '等待侦察数据…'
  if (searchText.value || exploitableOnly.value || hiddenTypes.value.size) return '当前过滤条件下没有匹配节点，调整筛选试试'
  return '无可视化数据'
})

// ── 节点 / 边 → ECharts 数据 ──────────────────────────
const textColor = computed(() => chartTheme.textColor())
const mutedColor = computed(() => chartTheme.mutedTextColor())
const accentColor = computed(() => chartTheme.colors().cyan)

const echartsNodes = computed(() => {
  return buildEchartsNodes(
    mergedNodes.value,
    props.selectedNodeId,
    frontendNodeIds.value,
    ownedNodeIds.value,
    objectiveReachedIds.value,
    highValueNodeIds.value,
    killChainPath.value.nodes,
    degrade.value,
    textColor.value,
  )
})

const echartsLinks = computed(() => {
  return buildEchartsEdges(
    mergedEdges.value,
    killChainPath.value.edgeIds,
    degrade.value,
  )
})

const categories = computed(() => {
  return NODE_TYPE_COUNT_KEYS
    .filter((k) => NODE_TYPE_META[k])
    .map((k) => ({
      name: k,
      itemStyle: { color: resolveMetaColor(NODE_TYPE_META[k]?.color) },
    }))
})

const nodeTypeStats = computed(() => computeNodeTypeStats(composedGraph.value.nodes))
const severityStats = computed(() => computeSeverityStats(composedGraph.value.nodes))

// ── Kill-chain 流动线坐标 ─────────────────────────────
const killChainLineCoords = ref<number[][][]>([])

function updateKillChainCoords() {
  const chart = chartRef.value
  if (!chart) return
  const kc = killChainPath.value
  if (kc.edgeIds.size === 0) { killChainLineCoords.value = []; return }

  try {
    const option = chart.getOption?.()
    const series = option?.series?.[0]
    const graphNodes = series?.data || []
    const graphLinks = series?.links || series?.edges || []

    const nodePosMap: Record<string, [number, number]> = {}
    for (const n of graphNodes) {
      if (n.x !== undefined && n.y !== undefined) {
        nodePosMap[n.id || n.name] = [n.x, n.y]
      }
    }

    const coords: number[][][] = []
    for (const link of graphLinks) {
      const key = `${link.source || ''}|${link.target || ''}|${link._raw?.relation || ''}`
      if (!kc.edgeIds.has(key)) continue
      const srcPos = nodePosMap[link.source]
      const dstPos = nodePosMap[link.target]
      if (srcPos && dstPos) {
        coords.push([srcPos, dstPos])
      }
    }
    killChainLineCoords.value = coords
  } catch { /* ignore */ }
}

// ── ECharts option ───────────────────────────────────
const rawOption = computed(() => {
  const tip = chartTheme.tooltipStyle()
  const tooltipFormatter = buildTooltipFormatter(
    textColor.value, mutedColor.value, accentColor.value,
    NODE_TYPE_META, RELATION_META, SEVERITY_META,
  )

  const series: any[] = [{
    type: 'graph',
    layout: layoutMode.value === 'circular' ? 'circular' : layoutMode.value === 'layered' ? 'force' : 'force',
    force: layoutMode.value !== 'circular' ? {
      repulsion: 240,
      edgeLength: [70, 150],
      gravity: 0.06,
      friction: 0.16,
      layoutAnimation: true,
    } : undefined,
    circular: layoutMode.value === 'circular' ? { rotateLabel: true } : undefined,
    roam: true,
    draggable: true,
    focusNodeAdjacency: true,
    edgeSymbol: ['none', 'arrow'],
    edgeSymbolSize: [0, 8],
    nodes: echartsNodes.value,
    links: echartsLinks.value,
    categories: categories.value,
    emphasis: {
      focus: 'adjacency',
      scale: true,
      lineStyle: { width: 4 },
      itemStyle: { borderColor: accentColor.value, borderWidth: 2, shadowBlur: 16 },
      label: { fontSize: 12, fontWeight: 'bold' },
    },
    lineStyle: { opacity: 0.7 },
    animationDurationUpdate: 600,
    animationEasingUpdate: 'cubicOut',
  }]

  if (killChainLineCoords.value.length > 0 && !degrade.value && !prefersReducedMotion.value) {
    series.push({
      type: 'lines',
      coordinateSystem: 'none',
      polyline: false,
      effect: {
        show: true,
        period: 4,
        trailLength: 0.4,
        symbol: 'arrow',
        symbolSize: 6,
        color: resolveMetaColor('var(--accent-red)'),
      },
      lineStyle: { width: 0, opacity: 0 },
      data: killChainLineCoords.value.map((c) => ({ coords: c })),
    })
  }

  return {
    backgroundColor: 'transparent',
    tooltip: {
      ...tip,
      enterable: true,
      formatter: tooltipFormatter,
    },
    legend: [
      {
        data: categories.value
          .filter((c) => nodeTypeStats.value.some((s) => s.type === c.name))
          .map((c) => ({ name: c.name, itemStyle: c.itemStyle })),
        textStyle: { color: textColor.value, fontSize: 11 },
        formatter: (name: string) => typeLabel(name),
        bottom: 4,
        type: 'scroll',
      },
    ],
    series,
  }
})

// ── Debounced option ──────────────────────────────────
const debouncedOption = ref<any>(null)
let _debounceTimer: ReturnType<typeof setTimeout> | null = null

watch(rawOption, (newOpt) => {
  if (_debounceTimer) clearTimeout(_debounceTimer)
  _debounceTimer = setTimeout(() => {
    debouncedOption.value = newOpt
  }, 250)
}, { immediate: true })

// ── 分层布局 fallback ────────────────────────────────
watch(layoutMode, (mode) => {
  if (mode === 'layered') {
    nextTick(() => {
      const chart = chartRef.value
      if (!chart) return
      try {
        const nodes = mergedNodes.value
        const phaseOrder: Record<string, number> = {
          host: 0, service: 0, web_endpoint: 0,
          finding: 1, credential: 1,
          session: 2, foothold: 2,
          loot: 3, objective: 3, pivot_point: 2,
        }
        const phaseOrderKeys = Object.keys(phaseOrder)
        const maxPhase = Math.max(...Object.values(phaseOrder), 3)

        chart.setOption({
          series: [{
            nodes: nodes.map((n, i) => {
              const phase = phaseOrder[n.type] ?? 1
              return {
                id: n.id,
                x: (phase / maxPhase) * 600 + 50,
                y: (i % Math.max(1, Math.floor(nodes.length / (maxPhase + 1)))) * 80 + 60,
                fixed: true,
              }
            }),
          }],
        }, { notMerge: true })
      } catch { /* ignore */ }
    })
  }
})

// ── 节点钉位 ──────────────────────────────────────────
const pinning = useNodePinning(chartRef, (nodeId: string, x: number, y: number) => {
  const node = composedGraph.value.nodes.find((n) => n.id === nodeId)
  if (node) {
    node._pinned = true
    node._x = x
    node._y = y
  }
})

function onChartFinished() {
  pinning.onFinished()
  updateKillChainCoords()
}

// ── 脉冲定时器（frontier / owned 呼吸）───────────────
const pulseEnabled = computed(() => !degrade.value && !prefersReducedMotion.value)
const pulseTimer = usePulseTimer(() => {
  pulseGeneration.value += 1
  const chart = chartRef.value
  if (!chart) return
  const fIds = frontendNodeIds.value
  const oIds = ownedNodeIds.value
  if (fIds.size === 0 && oIds.size === 0) return

  try {
    const frontierNodes: any[] = []
    const ownedNodes: any[] = []
    for (const node of echartsNodes.value) {
      if (frontendNodeIds.value.has(node.id)) frontierNodes.push({ id: node.id, itemStyle: { shadowBlur: pulseGeneration.value % 2 === 0 ? 24 : 12 } })
      if (ownedNodeIds.value.has(node.id)) ownedNodes.push({ id: node.id, itemStyle: { shadowBlur: pulseGeneration.value % 2 === 0 ? 16 : 8, shadowColor: 'rgba(86,201,164,.5)' } })
    }
    if (frontierNodes.length > 0 || ownedNodes.length > 0) {
      chart.setOption({ series: [{ nodes: [...frontierNodes, ...ownedNodes] }] }, { notMerge: false })
    }
  } catch { /* ignore */ }
}, pulseEnabled)

const relatedEdges = computed(() => {
  if (!selected.value) return []
  const id = selected.value.id
  return composedGraph.value.edges.filter((e: any) => e.src === id || e.dst === id)
})

const drawerTitle = computed(() => {
  if (!selected.value) return '节点详情'
  return `${typeLabel(selected.value.type)}: ${selected.value.label || selected.value.id}`
})

function toggleType(t: string) {
  const next = new Set(hiddenTypes.value)
  if (next.has(t)) next.delete(t)
  else next.add(t)
  hiddenTypes.value = next
}

function onNodeClick(p: any) {
  if (p?.dataType === 'node' && p.data?._raw) {
    selected.value = p.data._raw
    drawerOpen.value = true
  }
}

function resetView() {
  hiddenTypes.value = new Set()
  searchText.value = ''
  exploitableOnly.value = false
  pinning.reset()
  if (chartRef.value && typeof chartRef.value.dispatchAction === 'function') {
    chartRef.value.dispatchAction({ type: 'restore' })
  }
}

function formatTs(ts: string) {
  if (!ts) return '—'
  try {
    const d = new Date(ts)
    if (isNaN(d.getTime())) return ts
    return d.toLocaleString()
  } catch { return ts }
}

function pretty(obj: any) {
  if (!obj || (typeof obj === 'object' && Object.keys(obj).length === 0)) return '(无)'
  try { return JSON.stringify(obj, null, 2) } catch { return String(obj) }
}

watch(() => composedGraph.value.nodes.length, () => {
  if (selected.value && !composedGraph.value.nodes.find((n: any) => n.id === selected.value.id)) {
    drawerOpen.value = false
    selected.value = null
  }
})

// ── 延迟挂载 ECharts ─────────────────────────────────
const canvasWrapRef = ref<any>(null)
const chartReady = ref(false)
let _ro: ResizeObserver | null = null

function _tryMountChart() {
  nextTick(() => {
    const el = canvasWrapRef.value
    if (!el) return
    const rect = el.getBoundingClientRect()
    if (rect.width > 0 && rect.height > 0) {
      chartReady.value = true
      return
    }
    if (_ro) _ro.disconnect()
    _ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect
      if (width > 0 && height > 0) {
        chartReady.value = true
        _ro!.disconnect()
      }
    })
    _ro.observe(el)
  })
}

watch([() => mergedNodes.value.length, canvasWrapRef], ([len]) => {
  if (len > 0) _tryMountChart()
})

onMounted(() => {
  if (mergedNodes.value.length > 0) _tryMountChart()

  try {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    prefersReducedMotion.value = mq.matches
    mq.addEventListener('change', (e) => { prefersReducedMotion.value = e.matches })
  } catch { /* ignore */ }

  pulseTimer.start()
})

onBeforeUnmount(() => {
  if (_ro) _ro.disconnect()
  if (_debounceTimer) clearTimeout(_debounceTimer)
})
</script>

<style scoped>
.attack-graph-view {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 540px;
}

.graph-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
  padding: 4px 0;
}

.graph-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}

.type-stat {
  font-variant-numeric: tabular-nums;
  cursor: pointer;
  user-select: none;
  transition: opacity var(--t-fast) var(--ease-out), transform var(--t-fast) var(--ease-out);
  display: inline-flex !important;
  align-items: center;
  gap: 5px;
}
.type-stat:hover { transform: translateY(-1px); }
.type-stat.is-disabled {
  opacity: 0.36;
  text-decoration: line-through;
}

.type-stat-icon {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
}

.sev-stat {
  font-variant-numeric: tabular-nums;
  border: none !important;
  color: #fff !important;
}

.graph-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}

.graph-search {
  width: 200px;
}

/* ── 空状态 ───────────────────────────────────────────── */
.graph-empty {
  min-height: 380px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.graph-empty-inner {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 16px;
}

.empty-icon-wrap {
  width: 80px;
  height: 80px;
  border-radius: 50%;
  background: color-mix(in srgb, var(--text-muted) 10%, transparent);
  display: flex;
  align-items: center;
  justify-content: center;
}

.empty-icon {
  font-size: 36px;
  color: var(--text-muted);
  opacity: 0.45;
}

.empty-text {
  color: var(--text-secondary);
  font-size: 13px;
  margin: 0;
}

/* ── 主画布 ──────────────────────────────────────────── */
.graph-canvas-wrap {
  flex: 1;
  min-height: 540px;
  border-radius: 8px;
  background:
    radial-gradient(circle at 50% 50%, rgba(56,139,253,.06), transparent 60%),
    linear-gradient(var(--start-grid-line) 1px, transparent 1px) 0 0/32px 32px,
    linear-gradient(90deg, var(--start-grid-line) 1px, transparent 1px) 0 0/32px 32px,
    var(--bg-base);
  border: 1px solid var(--border);
  position: relative;
  overflow: hidden;
}

.graph-canvas {
  width: 100%;
  height: 540px;
}

/* ── 自定义图例面板 ──────────────────────────────────── */
.graph-legend-panel {
  position: absolute;
  top: 12px;
  right: 12px;
  background: rgba(22,27,34,.72);
  border: 1px solid var(--start-panel-border);
  backdrop-filter: blur(8px);
  border-radius: 8px;
  padding: 8px 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  z-index: 10;
  min-width: 130px;
}

.legend-row {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  user-select: none;
  transition: opacity var(--t-fast) var(--ease-out);
  padding: 2px 0;
}
.legend-row:hover {
  opacity: 0.8;
}
.legend-row.is-disabled {
  opacity: 0.36;
  text-decoration: line-through;
}

.legend-icon {
  width: 10px;
  height: 10px;
  border-radius: 2px;
  display: inline-block;
  flex-shrink: 0;
}

.legend-label {
  font-size: 11px;
  color: var(--text-secondary);
  font-family: var(--font-mono);
}

.legend-count {
  font-size: 10px;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  margin-left: auto;
}

/* ── Kill-chain 路径说明 ─────────────────────────────── */
.kill-chain-caption {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  background: color-mix(in srgb, var(--accent-red) 10%, var(--bg-surface));
  border: 1px solid color-mix(in srgb, var(--accent-red) 25%, var(--border));
  border-radius: var(--radius-md);
  font-size: 12px;
  color: var(--text-primary);
  font-family: var(--font-mono);
}

.kill-chain-caption .el-icon {
  color: var(--accent-red);
}

/* ── 抽屉详情 ───────────────────────────────────────── */
.node-detail {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 6px 4px;
}

.detail-row {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}

.detail-label {
  width: 72px;
  flex-shrink: 0;
  color: var(--text-muted);
  font-size: 12px;
}

.detail-value {
  font-size: 13px;
  color: var(--text-primary);
}

.detail-value.mono,
.detail-code {
  font-family: var(--font-mono);
  font-size: 12px;
  background: color-mix(in srgb, var(--accent-blue) 8%, transparent);
  padding: 1px 6px;
  border-radius: 3px;
  word-break: break-all;
}

.detail-sev {
  border: none !important;
  color: #fff !important;
}

.cve-link {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--accent-blue);
  text-decoration: none;
}
.cve-link:hover { text-decoration: underline; }

.detail-section {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.detail-section-title {
  font-size: 12px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.4px;
}

.detail-evidence,
.detail-facts {
  background: rgba(0, 0, 0, 0.2);
  padding: 10px 12px;
  border-radius: 6px;
  font-size: 11.5px;
  font-family: var(--font-mono);
  max-height: 240px;
  overflow: auto;
  margin: 0;
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-all;
}

.detail-evidence {
  border-left: 3px solid var(--accent-red);
}

.edge-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.edge-list li {
  font-size: 12px;
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 4px;
  padding: 6px 8px;
  background: color-mix(in srgb, var(--accent-blue) 5%, transparent);
  border-radius: 4px;
}

.edge-list code {
  font-family: var(--font-mono);
  font-size: 11px;
  word-break: break-all;
}

.rel {
  color: var(--text-muted);
  font-size: 11px;
}

.note {
  width: 100%;
  color: var(--text-muted);
  font-size: 11px;
  font-style: italic;
}

/* ── prefers-reduced-motion ──────────────────────────── */
@media (prefers-reduced-motion: reduce) {
  .graph-canvas-wrap {
    background: var(--bg-base) !important;
  }

  .type-stat {
    transition: none;
  }

  .graph-legend-panel {
    backdrop-filter: none;
  }
}
</style>
