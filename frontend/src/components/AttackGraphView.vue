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
          <span class="type-stat-icon" :style="{ background: (NODE_TYPE_META[t.type] || DEFAULT_NODE_STYLE).color }" />
          {{ typeLabel(t.type) }} · {{ t.count }}
        </el-tag>
        <el-tag
          v-if="severityStats.length"
          v-for="s in severityStats"
          :key="`sev-${s.key}`"
          size="small"
          effect="dark"
          :color="SEVERITY_META[s.key]?.color"
          class="sev-stat"
        >
          {{ SEVERITY_META[s.key]?.label || s.key }} · {{ s.count }}
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
        </el-radio-group>
        <el-button size="small" plain @click="resetView">
          <el-icon><Refresh /></el-icon>
          重置
        </el-button>
      </div>
    </div>

    <!-- ── 主画布 / 空状态 ─────────────────────────────────── -->
    <div v-if="!mergedNodes.length" class="graph-empty">
      <el-empty :description="emptyText">
        <template #image>
          <el-icon class="empty-icon"><Share /></el-icon>
        </template>
        <el-button size="small" plain @click="$emit('refresh')" v-if="hasRefreshHandler">
          重新拉取数据
        </el-button>
      </el-empty>
    </div>
    <div v-else ref="canvasWrapRef" class="graph-canvas-wrap">
      <VChart
        v-if="chartReady"
        ref="chartRef"
        :option="option"
        :update-options="{ notMerge: false, lazyUpdate: true }"
        autoresize
        class="graph-canvas"
        @click="onNodeClick"
      />
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
            :color="SEVERITY_META[selected._severity]?.color"
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
              <span class="rel">— {{ RELATION_META[e.relation]?.label || e.relation }} →</span>
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
 * ── 重要：前端兜底合成 ──────────────────────────────────────────
 * 后端只在 `node_vuln_scan` 末尾调用 `attach_finding_to_graph`,
 * 而 exploit / post_foothold / 二次利用 / 信息泄露解析等阶段追加的
 * findings 不会进入 attack_graph（凭据 / loot / shell 同样存在盲区）。
 *
 * 因此组件接收完整 `task` 对象后，会按后端 ID 命名约定
 * (`host:`, `svc:`, `finding:`, `cred:`, `loot:`, `foothold:`,
 *  `objective:`) 把 task.findings / open_ports / credential_store /
 * loot_store / foothold_status / target 中缺失的节点合成补齐，
 * 并自动连边（host→service→finding→cred→foothold→loot→objective），
 * 同名节点天然以后端权威数据为准（先放后端、再 upsert 合成）。
 */
import { computed, nextTick, onMounted, onUnmounted, ref, watch, getCurrentInstance } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { GraphChart } from 'echarts/charts'
import {
  TitleComponent, TooltipComponent, LegendComponent,
} from 'echarts/components'
import { Search, Refresh, Share } from '@element-plus/icons-vue'
import { useChartTheme } from '@/composables/useChartTheme'

use([CanvasRenderer, GraphChart, TitleComponent, TooltipComponent, LegendComponent])

const props = defineProps({
  /** 后端权威 attack_graph (nodes/edges)。 */
  graph: {
    type: Object,
    default: () => ({ nodes: [], edges: [] }),
  },
  /**
   * 完整任务对象 (TaskDetail). 用于在后端 attack_graph 未及时同步时
   * 从 findings / open_ports / credential_store 等字段合成节点兜底。
   * 不传则降级为只渲染 props.graph (向后兼容)。
   */
  task: {
    type: Object,
    default: null,
  },
  /** W2-T1: 当前选中的前沿节点 id, 高亮该节点。 */
  selectedNodeId: {
    type: String,
    default: '',
  },
})

defineEmits(['refresh'])

const chartTheme = useChartTheme()
const chartRef = ref(null)
const layoutMode = ref('force')
const drawerOpen = ref(false)
const selected = ref(null)
const searchText = ref('')
const exploitableOnly = ref(false)
const hiddenTypes = ref(new Set())

const hasRefreshHandler = computed(() => {
  // 检查父组件是否监听了 refresh 事件
  const inst = getCurrentInstance()
  return Boolean(inst?.vnode?.props?.onRefresh)
})

// ── 节点 / 关系视觉规范 ────────────────────────────────────
// C7.3 扩展点: WS3 可往 NODE_TYPE_META / RELATION_META 追加 AD/云类型
// 样式而无需改渲染主体。未知 type 走 DEFAULT_NODE_STYLE 兜底。
const DEFAULT_NODE_STYLE = { color: '#888', symbol: 'circle', size: 36, label: '?' }

const nodeTypeStyle = NODE_TYPE_META

const NODE_TYPE_META = {
  host:        { color: '#58b8e0', symbol: 'circle',     size: 60, label: '主机' },
  service:     { color: '#4ec9b0', symbol: 'roundRect',  size: 48, label: '服务' },
  web_endpoint:{ color: '#3fb980', symbol: 'roundRect',  size: 44, label: '端点' },
  finding:     { color: '#e06979', symbol: 'diamond',    size: 50, label: '漏洞' },
  credential:  { color: '#d9a84e', symbol: 'triangle',   size: 44, label: '凭据' },
  foothold:    { color: '#aea0d6', symbol: 'pin',        size: 54, label: '立足点' },
  session:     { color: '#b08fd4', symbol: 'pin',        size: 50, label: '会话' },
  loot:        { color: '#7b8fd4', symbol: 'rect',       size: 40, label: '战利品' },
  objective:   { color: '#2d9d76', symbol: 'star',       size: 60, label: '目标' },
  path:        { color: '#9198a9', symbol: 'circle',     size: 32, label: '路径' },
  pivot_point: { color: '#e0a050', symbol: 'diamond',    size: 46, label: '跳板' },
}

const RELATION_META = {
  enables:       { color: '#e06979', dashed: false, label: '使能',      curveness: 0.10 },
  leads_to:      { color: '#58b8e0', dashed: false, label: '导致',      curveness: 0.18 },
  exposes:       { color: '#4ec9b0', dashed: true,  label: '暴露',      curveness: 0.08 },
  consumes:      { color: '#d9a84e', dashed: false, label: '消费',      curveness: 0.14 },
  discovers:     { color: '#aea0d6', dashed: true,  label: '发现',      curveness: 0.20 },
  runs_on:       { color: '#58b8e0', dashed: false, label: '运行在',    curveness: 0.10 },
  vulnerable_to: { color: '#e06979', dashed: false, label: '易受',      curveness: 0.12 },
  yields:        { color: '#d9a84e', dashed: false, label: '产出',      curveness: 0.14 },
  pivots_to:     { color: '#aea0d6', dashed: false, label: '跳转至',    curveness: 0.16 },
  requires:      { color: '#9198a9', dashed: true,  label: '需要',      curveness: 0.18 },
}

const SEVERITY_META = {
  critical: { color: '#cb2431', label: '严重', sizeBoost: 12, glow: 16 },
  high:     { color: '#e06979', label: '高危', sizeBoost: 8,  glow: 12 },
  medium:   { color: '#d9a84e', label: '中危', sizeBoost: 4,  glow: 6  },
  low:      { color: '#7b8fd4', label: '低危', sizeBoost: 0,  glow: 0  },
  info:     { color: '#9198a9', label: '信息', sizeBoost: 0,  glow: 0  },
}

function typeLabel(t) { return (NODE_TYPE_META[t] || DEFAULT_NODE_STYLE).label }

function typeTag(t) {
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

// ── 辅助：与后端保持一致的 ID 命名 ─────────────────────────
function _hostId(host) { return host ? `host:${host}` : '' }
function _svcId(host, port) { return host && port ? `svc:${host}:${port}` : '' }
function _findingId(vid) { return vid ? `finding:${vid}` : '' }
function _credId(cred) {
  // 与后端 _ag_credential_id 同形：user|source|value 拼接做指纹
  const user = cred?.user || cred?.username || ''
  const src  = cred?.source || ''
  const val  = cred?.value || cred?.password || ''
  const raw  = `${user}|${src}|${val}`
  // 简单 fnv1a，足以前端去重
  let h = 0x811c9dc5
  for (let i = 0; i < raw.length; i++) {
    h ^= raw.charCodeAt(i)
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0
  }
  return `cred:${h.toString(16)}`
}
function _lootId(loot, idx) {
  const key = (typeof loot === 'string' ? loot : (loot?.path || loot?.name || `idx${idx}`))
  return `loot:${key}`
}

function _hostFromTarget(target) {
  if (!target) return ''
  try {
    if (target.includes('://')) {
      return new URL(target).hostname
    }
  } catch { /* fall through */ }
  return String(target).split(':')[0]
}

// ── 合成图：以后端 graph 为权威，task.* 兜底补齐 ───────────
const _ORDER = ['host', 'service', 'finding', 'credential', 'foothold', 'loot', 'objective', 'path']

const composedGraph = computed(() => {
  const nodeMap = new Map() // id -> node
  const edgeSet = new Set() // 去重 key: src|dst|relation
  const edges = []

  // 1. 后端权威节点 / 边先入
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

  const upsert = (id, type, label, facts, discoveredBy) => {
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
  const addEdge = (src, dst, relation, note) => {
    if (!src || !dst || src === dst) return
    const key = `${src}|${dst}|${relation || 'leads_to'}`
    if (edgeSet.has(key)) return
    edgeSet.add(key)
    edges.push({ src, dst, relation: relation || 'leads_to', note: note || '', _origin: 'synth' })
  }

  // 2. 从 task 兜底合成
  const t = props.task
  if (t) {
    // 主机
    const host = _hostFromTarget(t.target_host || t.target)
    if (host) upsert(_hostId(host), 'host', host, { from: 'task.target' }, 'task_summary')

    // 服务（端口）
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

    // 漏洞 finding -> service / host
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

      // 连边：service / host -> finding
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

    // 凭据
    const creds = Array.isArray(t.credential_store) ? t.credential_store : []
    for (const c of creds) {
      if (!c) continue
      const cid = _credId(c)
      const userPart = c.user || c.username || '?'
      const srcPart = c.source || '?'
      upsert(cid, 'credential', `${userPart}@${srcPart}`, c, 'credential_store')
      // 凭据如果有命中的 finding（按 source 反查）尝试连边；保守起见只指向 host
      if (host) addEdge(_hostId(host), cid, 'discovers')
    }

    // Foothold（如果拿到 shell）
    if (t.got_shell || t.foothold_status === 'established' || t.foothold_status === 'verified') {
      const fhId = `foothold:${host || 'unknown'}`
      upsert(fhId, 'foothold',
        host ? `Shell @ ${host}` : 'Shell',
        {
          status: t.foothold_status || 'established',
          privilege_level: t.privilege_level || 'unknown',
        },
        'foothold_tracker',
      )
      if (host) addEdge(_hostId(host), fhId, 'leads_to')
      // 把所有可利用的 finding 连到 foothold
      for (const f of findings) {
        if (f?.exploitable && f?.vuln_id) {
          addEdge(_findingId(f.vuln_id), fhId, 'leads_to')
        }
      }
    }

    // Loot
    const loots = Array.isArray(t.loot_store) ? t.loot_store : []
    loots.forEach((l, i) => {
      const lid = _lootId(l, i)
      const label = typeof l === 'string'
        ? l
        : (l?.path || l?.name || `loot-${i}`)
      upsert(lid, 'loot', label, typeof l === 'object' ? l : { value: l }, 'loot_store')
      if (host) addEdge(`foothold:${host}`, lid, 'consumes')
    })

    // 目标完成
    const obj = t.objective_status
    if (obj && (obj.flag_found || obj.objective_reached || obj.status === 'reached')) {
      const oid = `objective:${host || 'task'}`
      upsert(oid, 'objective', obj.flag || obj.objective || '目标达成', obj, 'objective_collector')
      if (host) addEdge(`foothold:${host}`, oid, 'leads_to')
    }
  }

  return {
    nodes: Array.from(nodeMap.values()),
    edges,
  }
})

// ── 显示过滤（搜索 / 类型隐藏 / 仅高危） ─────────────────
const filteredGraph = computed(() => {
  const allNodes = composedGraph.value.nodes
  const allEdges = composedGraph.value.edges
  const q = searchText.value.trim().toLowerCase()
  const visibleIds = new Set()

  for (const n of allNodes) {
    if (hiddenTypes.value.has(n.type)) continue
    if (exploitableOnly.value) {
      const sev = n.facts?.severity
      const ok =
        n.type === 'host' ||
        n.type === 'foothold' ||
        n.type === 'objective' ||
        (n.type === 'finding' && (n.facts?.exploitable || sev === 'critical' || sev === 'high')) ||
        (n.type === 'credential') ||
        (n.type === 'loot')
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
  if (totalRaw === 0) {
    return '尚未捕获攻击图节点（运行中节点出现新事实后会自动绘制）'
  }
  if (searchText.value || exploitableOnly.value || hiddenTypes.value.size) {
    return '当前过滤条件下没有匹配节点，调整筛选试试'
  }
  return '无可视化数据'
})

// ── 节点 / 边 → ECharts 数据 ──────────────────────────────
const echartsNodes = computed(() => {
  return mergedNodes.value.map((n) => {
    const meta = NODE_TYPE_META[n.type] || DEFAULT_NODE_STYLE
    let color = meta.color
    let size = meta.size
    let glow = 0
    let severity = ''

    if (n.type === 'finding') {
      severity = String(n.facts?.severity || 'info').toLowerCase()
      const sevMeta = SEVERITY_META[severity] || SEVERITY_META.info
      color = sevMeta.color
      size += sevMeta.sizeBoost
      glow = sevMeta.glow
    }

    const exploitable = Boolean(n.facts?.exploitable)
    const isSynth = n._origin === 'synth'
    const isPrior = n.facts?.source === 'prior' || n.facts?.from_history === true
    const isTargetSelected = props.selectedNodeId && n.id === props.selectedNodeId

    return {
      id: n.id,
      name: (isPrior ? '⏳ ' : '') + (n.label || n.id),
      symbol: meta.symbol,
      symbolSize: size + (isTargetSelected ? 8 : 0),
      category: n.type,
      itemStyle: {
        color,
        borderColor: isTargetSelected ? '#e06979' : (exploitable ? '#ffc857' : (isPrior ? '#c9a74e' : (isSynth ? 'rgba(255,255,255,0.18)' : 'transparent'))),
        borderWidth: isTargetSelected ? 3 : (exploitable ? 2 : (isPrior ? 2 : (isSynth ? 1 : 0))),
        borderType: (isPrior || (isSynth && !exploitable && !isTargetSelected)) ? 'dashed' : 'solid',
        shadowBlur: isTargetSelected ? Math.max(glow, 18) : glow,
        shadowColor: isTargetSelected ? '#e06979' : (glow ? color : 'transparent'),
        opacity: isSynth ? 0.92 : 1,
      },
      label: {
        show: true,
        position: 'right',
        fontSize: 11,
        formatter: (p) => truncateLabel(p.name),
        color: chartTheme.textColor(),
      },
      _raw: { ...n, _severity: severity, _evidence: n.facts?.evidence || '', _isPrior: isPrior },
    }
  })
})

const echartsLinks = computed(() => {
  return mergedEdges.value.map((e) => {
    const meta = RELATION_META[e.relation] || RELATION_META.leads_to
    const isSynth = e._origin === 'synth'
    return {
      source: e.src,
      target: e.dst,
      lineStyle: {
        color: meta.color,
        type: meta.dashed || isSynth ? 'dashed' : 'solid',
        width: 1.4,
        opacity: isSynth ? 0.45 : 0.75,
        curveness: meta.curveness ?? 0.12,
      },
      label: { show: false },
      _raw: e,
    }
  })
})

const categories = computed(() =>
  _ORDER.map((k) => ({
    name: k,
    itemStyle: { color: NODE_TYPE_META[k].color },
  })),
)

const nodeTypeStats = computed(() => {
  const counts = {}
  for (const n of composedGraph.value.nodes) {
    counts[n.type] = (counts[n.type] || 0) + 1
  }
  return _ORDER
    .filter((k) => counts[k])
    .map((type) => ({ type, count: counts[type] }))
})

const severityStats = computed(() => {
  const counts = {}
  for (const n of composedGraph.value.nodes) {
    if (n.type !== 'finding') continue
    const k = String(n.facts?.severity || 'info').toLowerCase()
    counts[k] = (counts[k] || 0) + 1
  }
  return ['critical', 'high', 'medium', 'low', 'info']
    .filter((k) => counts[k])
    .map((key) => ({ key, count: counts[key] }))
})

const option = computed(() => {
  const tip = chartTheme.tooltipStyle()
  return {
    backgroundColor: 'transparent',
    tooltip: {
      ...tip,
      formatter: (p) => {
        if (p.dataType === 'node') {
          const r = p.data._raw
          const sev = r._severity
          const sevTag = sev
            ? `<span style="display:inline-block;padding:0 6px;border-radius:3px;background:${SEVERITY_META[sev]?.color || '#666'};color:#fff;font-size:10px;margin-left:4px">${SEVERITY_META[sev]?.label || sev}</span>`
            : ''
          const exp = r.facts?.exploitable
            ? `<span style="display:inline-block;padding:0 6px;border-radius:3px;background:#ffc857;color:#1d2128;font-size:10px;margin-left:4px">可利用</span>`
            : ''
          const cve = r.facts?.cve
            ? `<div style="font-size:11px;margin-top:4px;color:#58b8e0">${escapeHtml(r.facts.cve)}</div>`
            : ''
          const tgt = r.facts?.target
            ? `<div style="font-size:11px;margin-top:2px;color:#9ab4c0">target: ${escapeHtml(String(r.facts.target))}</div>`
            : ''
          const priorNote = r._isPrior
            ? `<div style="font-size:10px;margin-top:4px;padding:2px 6px;border-radius:3px;background:rgba(201,167,78,0.15);color:#c9a74e;display:inline-block">⏳ 历史推断，待验证</div>`
            : ''
          return `
            <div style="font-weight:600;margin-bottom:4px">${escapeHtml(r.label || r.id)}${sevTag}${exp}</div>
            <div style="font-size:11px;color:#888">${typeLabel(r.type)} · ${escapeHtml(r.id)}</div>
            ${cve}${tgt}${priorNote}
            <div style="font-size:11px;margin-top:4px;color:#aaa">来源: ${escapeHtml(r.discovered_by || '—')}</div>
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
        data: categories.value
          .filter((c) => nodeTypeStats.value.some((s) => s.type === c.name))
          .map((c) => ({ name: c.name, itemStyle: c.itemStyle })),
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
          repulsion: 260,
          edgeLength: [70, 160],
          gravity: 0.05,
          friction: 0.55,
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
          lineStyle: { width: 2.5 },
          itemStyle: { borderColor: chartTheme.colors().cyan, borderWidth: 2 },
          label: { fontSize: 12, fontWeight: 'bold' },
        },
        lineStyle: { opacity: 0.7 },
        animationDurationUpdate: 350,
      },
    ],
  }
})

const relatedEdges = computed(() => {
  if (!selected.value) return []
  const id = selected.value.id
  return composedGraph.value.edges.filter((e) => e.src === id || e.dst === id)
})

const drawerTitle = computed(() => {
  if (!selected.value) return '节点详情'
  return `${typeLabel(selected.value.type)}: ${selected.value.label || selected.value.id}`
})

function toggleType(t) {
  const next = new Set(hiddenTypes.value)
  if (next.has(t)) next.delete(t)
  else next.add(t)
  hiddenTypes.value = next
}

function onNodeClick(p) {
  if (p?.dataType === 'node' && p.data?._raw) {
    selected.value = p.data._raw
    drawerOpen.value = true
  }
}

function resetView() {
  hiddenTypes.value = new Set()
  searchText.value = ''
  exploitableOnly.value = false
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

watch(() => composedGraph.value.nodes.length, () => {
  if (selected.value && !composedGraph.value.nodes.find((n) => n.id === selected.value.id)) {
    drawerOpen.value = false
    selected.value = null
  }
})

// ── 延迟挂载 ECharts (lazy tab) ──────────────────────────
const canvasWrapRef = ref(null)
const chartReady = ref(false)
let _ro = null

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
    _ro = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect
      if (width > 0 && height > 0) {
        chartReady.value = true
        _ro.disconnect()
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
})

onUnmounted(() => {
  if (_ro) _ro.disconnect()
})
</script>

<style scoped>
.attack-graph-view {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 540px;
}

/* ── 顶部工具栏 ──────────────────────────────────────────── */
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
  transition: opacity 0.18s ease, transform 0.12s ease;
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

/* ── 空状态 ───────────────────────────────────────────────── */
.graph-empty {
  min-height: 380px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.empty-icon {
  font-size: 64px;
  color: var(--text-muted, #6e7681);
  opacity: 0.45;
}

/* ── 主画布 ──────────────────────────────────────────────── */
.graph-canvas-wrap {
  flex: 1;
  min-height: 540px;
  border-radius: 8px;
  background:
    radial-gradient(circle at 20% 20%, rgba(88, 184, 224, 0.06) 0%, transparent 60%),
    radial-gradient(circle at 80% 80%, rgba(224, 105, 121, 0.05) 0%, transparent 55%),
    var(--bg-soft, rgba(13, 17, 23, 0.55));
  border: 1px solid var(--border-color, rgba(88, 184, 201, 0.12));
  position: relative;
  overflow: hidden;
}

.graph-canvas {
  width: 100%;
  height: 540px;
}

/* ── 抽屉详情 ───────────────────────────────────────────── */
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

.detail-sev {
  border: none !important;
  color: #fff !important;
}

.cve-link {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  color: var(--accent-blue, #58b8e0);
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
  color: var(--text-muted, #8b949e);
  text-transform: uppercase;
  letter-spacing: 0.4px;
}

.detail-evidence,
.detail-facts {
  background: rgba(0, 0, 0, 0.2);
  padding: 10px 12px;
  border-radius: 6px;
  font-size: 11.5px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  max-height: 240px;
  overflow: auto;
  margin: 0;
  color: var(--text-secondary, #9ab4c0);
  white-space: pre-wrap;
  word-break: break-all;
}

.detail-evidence {
  border-left: 3px solid var(--accent-red, #e06979);
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
