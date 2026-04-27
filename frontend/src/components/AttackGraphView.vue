<template>
  <div class="attack-graph-view">
    <div class="graph-toolbar">
      <div class="graph-stats">
        <el-tag size="small" effect="plain" type="info">
          节点 {{ nodes.length }} / 边 {{ edges.length }}
        </el-tag>
        <el-tag
          v-for="t in nodeTypeStats"
          :key="t.type"
          size="small"
          effect="plain"
          :type="typeTag(t.type)"
          class="type-stat"
        >
          {{ typeLabel(t.type) }} · {{ t.count }}
        </el-tag>
      </div>
      <div class="graph-actions">
        <el-radio-group v-model="layoutMode" size="small">
          <el-radio-button label="force">力导向</el-radio-button>
          <el-radio-button label="circular">环形</el-radio-button>
        </el-radio-group>
        <el-button size="small" plain @click="resetView">重置视图</el-button>
      </div>
    </div>

    <div v-if="!nodes.length" class="graph-empty">
      <el-empty description="尚未捕获攻击图节点（运行中节点出现新事实后会自动绘制）" />
    </div>
    <div v-else class="graph-canvas-wrap">
      <VChart
        ref="chartRef"
        :option="option"
        :update-options="{ notMerge: false }"
        autoresize
        class="graph-canvas"
        @click="onNodeClick"
      />
    </div>

    <el-drawer
      v-model="drawerOpen"
      direction="rtl"
      size="380px"
      :title="drawerTitle"
      :with-header="true"
    >
      <div v-if="selected" class="node-detail">
        <div class="detail-row">
          <span class="detail-label">类型</span>
          <el-tag size="small" :type="typeTag(selected.type)">
            {{ typeLabel(selected.type) }}
          </el-tag>
        </div>
        <div class="detail-row">
          <span class="detail-label">ID</span>
          <code class="detail-code">{{ selected.id }}</code>
        </div>
        <div class="detail-row">
          <span class="detail-label">发现来源</span>
          <span class="detail-value">{{ selected.discovered_by || '—' }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">发现时间</span>
          <span class="detail-value mono">{{ formatTs(selected.discovered_at) }}</span>
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
              <span class="rel">— {{ e.relation }} →</span>
              <code>{{ e.dst }}</code>
              <span v-if="e.note" class="note">{{ e.note }}</span>
            </li>
          </ul>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
/**
 * AttackGraphView — 渲染后端 state.attack_graph (nodes/edges) 为力导向图。
 *
 * 节点类型与 backend/agents/models.py:AttackNodeType 保持一致：
 *   host / service / finding / credential / foothold / loot / objective / path
 * 边关系：enables / leads_to / exposes / consumes / discovers
 *
 * 数据由 TaskDetail.vue 通过 props 注入（来自 GET /tasks/{id} 的 attack_graph 字段）。
 */
import { computed, ref, watch } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { GraphChart } from 'echarts/charts'
import {
  TitleComponent, TooltipComponent, LegendComponent,
} from 'echarts/components'
import { useChartTheme } from '@/composables/useChartTheme'

use([CanvasRenderer, GraphChart, TitleComponent, TooltipComponent, LegendComponent])

const props = defineProps({
  graph: {
    type: Object,
    default: () => ({ nodes: [], edges: [] }),
  },
})

const chartTheme = useChartTheme()
const chartRef = ref(null)
const layoutMode = ref('force')
const drawerOpen = ref(false)
const selected = ref(null)

const nodes = computed(() => props.graph?.nodes || [])
const edges = computed(() => props.graph?.edges || [])

const NODE_TYPE_META = {
  host:        { color: '#58b8c9', symbol: 'circle',     size: 56, label: '主机' },
  service:     { color: '#4a9ea8', symbol: 'roundRect',  size: 46, label: '服务' },
  finding:     { color: '#c36672', symbol: 'diamond',    size: 50, label: '漏洞' },
  credential:  { color: '#a68753', symbol: 'triangle',   size: 42, label: '凭据' },
  foothold:    { color: '#7773ad', symbol: 'pin',        size: 50, label: '立足点' },
  loot:        { color: '#8878a8', symbol: 'rect',       size: 38, label: '战利品' },
  objective:   { color: '#2e9472', symbol: 'star',       size: 56, label: '目标' },
  path:        { color: '#6889a0', symbol: 'circle',     size: 32, label: '路径' },
}

const RELATION_META = {
  enables:    { color: '#c36672', dashed: false, label: '使能' },
  leads_to:   { color: '#58b8c9', dashed: false, label: '导致' },
  exposes:    { color: '#4a9ea8', dashed: true,  label: '暴露' },
  consumes:   { color: '#a68753', dashed: false, label: '消费' },
  discovers:  { color: '#7773ad', dashed: true,  label: '发现' },
}

function typeLabel(t) {
  return NODE_TYPE_META[t]?.label || t
}

function typeTag(t) {
  switch (t) {
    case 'host':       return ''
    case 'service':    return 'success'
    case 'finding':    return 'danger'
    case 'credential': return 'warning'
    case 'foothold':   return 'info'
    case 'loot':       return 'info'
    case 'objective':  return 'success'
    default:           return ''
  }
}

const nodeTypeStats = computed(() => {
  const counts = {}
  for (const n of nodes.value) {
    counts[n.type] = (counts[n.type] || 0) + 1
  }
  return Object.entries(counts).map(([type, count]) => ({ type, count }))
})

const echartsNodes = computed(() =>
  nodes.value.map((n) => {
    const meta = NODE_TYPE_META[n.type] || NODE_TYPE_META.path
    return {
      id: n.id,
      name: n.label || n.id,
      symbol: meta.symbol,
      symbolSize: meta.size,
      category: n.type,
      itemStyle: { color: meta.color },
      label: {
        show: true,
        position: 'right',
        fontSize: 11,
        formatter: (p) => truncateLabel(p.name),
        color: chartTheme.textColor(),
      },
      // 原始数据回带，方便 tooltip & drawer
      _raw: n,
    }
  }),
)

const echartsLinks = computed(() =>
  edges.value.map((e) => {
    const meta = RELATION_META[e.relation] || RELATION_META.leads_to
    return {
      source: e.src,
      target: e.dst,
      lineStyle: {
        color: meta.color,
        type: meta.dashed ? 'dashed' : 'solid',
        width: 1.2,
        opacity: 0.7,
        curveness: 0.12,
      },
      label: {
        show: false,
      },
      _raw: e,
    }
  }),
)

const categories = computed(() =>
  Object.keys(NODE_TYPE_META).map((k) => ({
    name: k,
    itemStyle: { color: NODE_TYPE_META[k].color },
  })),
)

const option = computed(() => {
  const tip = chartTheme.tooltipStyle()
  return {
    backgroundColor: 'transparent',
    tooltip: {
      ...tip,
      formatter: (p) => {
        if (p.dataType === 'node') {
          const r = p.data._raw
          return `
            <div style="font-weight:600;margin-bottom:4px">${escapeHtml(r.label || r.id)}</div>
            <div style="font-size:11px;color:#888">${typeLabel(r.type)} · ${escapeHtml(r.id)}</div>
            <div style="font-size:11px;margin-top:4px;color:#aaa">${escapeHtml(r.discovered_by || '—')}</div>
          `
        }
        if (p.dataType === 'edge') {
          const r = p.data._raw
          const meta = RELATION_META[r.relation] || {}
          return `
            <div><code>${escapeHtml(r.src)}</code></div>
            <div style="margin:2px 0;color:${meta.color || '#aaa'}">— ${meta.label || r.relation} →</div>
            <div><code>${escapeHtml(r.dst)}</code></div>
            ${r.note ? `<div style="font-size:11px;color:#888;margin-top:4px">${escapeHtml(r.note)}</div>` : ''}
          `
        }
        return ''
      },
    },
    legend: [
      {
        data: categories.value.map((c) => ({ name: c.name, itemStyle: c.itemStyle })),
        textStyle: { color: chartTheme.textColor(), fontSize: 11 },
        formatter: (name) => typeLabel(name),
        bottom: 4,
        type: 'scroll',
      },
    ],
    series: [
      {
        type: 'graph',
        layout: layoutMode.value === 'circular' ? 'circular' : 'force',
        force: layoutMode.value === 'force' ? {
          repulsion: 220,
          edgeLength: [60, 140],
          gravity: 0.04,
          friction: 0.6,
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
          lineStyle: { width: 2.5 },
          itemStyle: { borderColor: chartTheme.colors().cyan, borderWidth: 2 },
        },
        lineStyle: { opacity: 0.7 },
      },
    ],
  }
})

const relatedEdges = computed(() => {
  if (!selected.value) return []
  const id = selected.value.id
  return edges.value.filter((e) => e.src === id || e.dst === id)
})

const drawerTitle = computed(() => {
  if (!selected.value) return '节点详情'
  return `${typeLabel(selected.value.type)}: ${selected.value.label || selected.value.id}`
})

function onNodeClick(p) {
  if (p?.dataType === 'node' && p.data?._raw) {
    selected.value = p.data._raw
    drawerOpen.value = true
  }
}

function resetView() {
  if (chartRef.value && typeof chartRef.value.dispatchAction === 'function') {
    chartRef.value.dispatchAction({ type: 'restore' })
  }
}

function truncateLabel(s) {
  if (!s) return ''
  return s.length > 28 ? s.slice(0, 26) + '…' : s
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function formatTs(ts) {
  if (!ts) return '—'
  try {
    const d = new Date(ts)
    if (isNaN(d.getTime())) return ts
    return d.toLocaleString()
  } catch {
    return ts
  }
}

function pretty(obj) {
  if (!obj || (typeof obj === 'object' && Object.keys(obj).length === 0)) {
    return '(无)'
  }
  try {
    return JSON.stringify(obj, null, 2)
  } catch {
    return String(obj)
  }
}

watch(() => props.graph, () => {
  // 数据刷新后, 若当前抽屉锁定的节点已被淘汰则关闭
  if (selected.value && !nodes.value.find((n) => n.id === selected.value.id)) {
    drawerOpen.value = false
    selected.value = null
  }
}, { deep: true })
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
}

.graph-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}

.graph-empty {
  min-height: 380px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.graph-canvas-wrap {
  flex: 1;
  min-height: 540px;
  border-radius: 8px;
  background: var(--bg-soft, rgba(13, 17, 23, 0.55));
  border: 1px solid var(--border-color, rgba(88, 184, 201, 0.12));
  position: relative;
  overflow: hidden;
}

.graph-canvas {
  width: 100%;
  height: 540px;
}

.node-detail {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 6px 4px;
}

.detail-row {
  display: flex;
  gap: 8px;
  align-items: baseline;
}

.detail-label {
  width: 72px;
  flex-shrink: 0;
  color: var(--text-muted, #8b949e);
  font-size: 12px;
}

.detail-value {
  font-size: 13px;
  color: var(--text-primary, #d0d6dc);
}

.detail-value.mono,
.detail-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  background: rgba(88, 184, 201, 0.08);
  padding: 1px 6px;
  border-radius: 3px;
  word-break: break-all;
}

.detail-section {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.detail-section-title {
  font-size: 12px;
  color: var(--text-muted, #8b949e);
  text-transform: uppercase;
  letter-spacing: 0.4px;
}

.detail-facts {
  background: rgba(0, 0, 0, 0.18);
  padding: 10px 12px;
  border-radius: 6px;
  font-size: 11.5px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  max-height: 280px;
  overflow: auto;
  margin: 0;
  color: var(--text-secondary, #9ab4c0);
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
  background: rgba(88, 184, 201, 0.05);
  border-radius: 4px;
}

.edge-list code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  word-break: break-all;
}

.rel {
  color: var(--text-muted, #8b949e);
  font-size: 11px;
}

.note {
  width: 100%;
  color: var(--text-muted, #8b949e);
  font-size: 11px;
  font-style: italic;
}
</style>
