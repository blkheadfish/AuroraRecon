<template>
  <div class="phase-tree">
    <div class="tree-header">
      <div class="tree-title">
        <el-icon><Share /></el-icon>
        <span>阶段决策树</span>
        <el-tag size="small" type="info" effect="plain" class="visit-tag">
          {{ visits.length }} 次访问
        </el-tag>
      </div>
      <div class="tree-legend">
        <span
          v-for="cat in legendItems"
          :key="cat.key"
          class="legend-dot"
        >
          <span class="dot" :style="{ background: cat.color }"></span>
          {{ cat.label }}
        </span>
      </div>
    </div>

    <div v-if="!visits.length" class="tree-empty">
      <el-empty description="尚未产生阶段决策事件" :image-size="64" />
    </div>
    <div v-else class="tree-canvas-wrap">
      <VChart
        :option="option"
        :update-options="{ notMerge: true }"
        autoresize
        class="tree-canvas"
      />
    </div>

    <p class="stats-line" v-if="visits.length">
      路径:
      <span
        v-for="(v, i) in visits"
        :key="i"
        class="path-step"
        :class="{ 'is-revisit': v.visitNo > 1, 'is-current': v.isCurrent }"
      >
        {{ phaseLabel(v.phase) }}<span v-if="v.visitNo > 1" class="badge">×{{ v.visitNo }}</span>
        <span v-if="i < visits.length - 1" class="sep">→</span>
      </span>
    </p>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Share } from '@element-plus/icons-vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { TreeChart } from 'echarts/charts'
import { TitleComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import { useChartTheme } from '@/composables/useChartTheme'

use([CanvasRenderer, TreeChart, TitleComponent, TooltipComponent, LegendComponent])

const props = defineProps({
  events: { type: Array, default: () => [] },
  current: { type: String, default: '' },
  status: { type: String, default: '' },
})

const chartTheme = useChartTheme()

const PHASE_LABELS = {
  init: '初始化',
  recon: '信息侦察',
  surface_enum: '表面枚举',
  intel_harvest: '情报采集',
  vuln_scan: '漏洞扫描',
  exploit_decision: '利用决策',
  awaiting_approval: '人工审批',
  foothold_attempt: '立足点',
  exploit: '漏洞利用',
  secondary_attack: '二次利用',
  post_foothold_enum: '立足后枚举',
  privesc_attempt: '提权',
  objective_collect: '目标收集',
  post_exploit: '后渗透',
  report: '报告生成',
}

function phaseLabel(p) {
  return PHASE_LABELS[p] || p || '—'
}

const PHASE_CATEGORY = {
  init: 'init',
  recon: 'recon',
  surface_enum: 'recon',
  intel_harvest: 'recon',
  vuln_scan: 'scan',
  exploit_decision: 'exploit',
  awaiting_approval: 'approval',
  foothold_attempt: 'exploit',
  exploit: 'exploit',
  secondary_attack: 'exploit',
  post_foothold_enum: 'post',
  privesc_attempt: 'post',
  objective_collect: 'post',
  post_exploit: 'post',
  report: 'report',
}

const CATEGORY_COLORS = computed(() => {
  const c = chartTheme.colors()
  return {
    init:     c.slate,
    recon:    c.cyan,
    scan:     c.teal,
    exploit:  c.ember,
    approval: c.amber,
    post:     c.indigo,
    report:   c.mint,
    other:    c.dim,
  }
})

const legendItems = computed(() => {
  const cc = CATEGORY_COLORS.value
  return [
    { key: 'recon',    label: '侦察',  color: cc.recon },
    { key: 'scan',     label: '扫描',  color: cc.scan },
    { key: 'exploit',  label: '利用',  color: cc.exploit },
    { key: 'approval', label: '审批',  color: cc.approval },
    { key: 'post',     label: '后渗透', color: cc.post },
    { key: 'report',   label: '报告',  color: cc.report },
  ]
})

function categoryOf(phase) {
  return PHASE_CATEGORY[phase] || 'other'
}

function colorFor(phase) {
  return CATEGORY_COLORS.value[categoryOf(phase)] || CATEGORY_COLORS.value.other
}

// ── 从 decision_events 推 visits ────────────────────────────────
const visits = computed(() => {
  const events = Array.isArray(props.events) ? props.events : []
  const list = []
  let last = null
  for (const e of events) {
    const phase = e?.phase
    if (!phase) continue
    if (phase !== last) {
      list.push({
        phase,
        visitNo: 1,
        eventCount: 1,
        firstTs: e.timestamp || '',
        lastTs: e.timestamp || '',
      })
      last = phase
    } else {
      list[list.length - 1].eventCount += 1
      list[list.length - 1].lastTs = e.timestamp || list[list.length - 1].lastTs
    }
  }

  const seen = {}
  for (const v of list) {
    seen[v.phase] = (seen[v.phase] || 0) + 1
    v.visitNo = seen[v.phase]
  }

  if (props.current && list.length) {
    // 标记 visits 中最后一个 == current 的为 isCurrent (运行中显示光晕)
    for (let i = list.length - 1; i >= 0; i--) {
      if (list[i].phase === props.current) {
        list[i].isCurrent = true
        break
      }
    }
    // 如果 current 不在 visits 末尾, 但又是当前阶段, 追加一条占位
    if (!list[list.length - 1].isCurrent && list[list.length - 1].phase !== props.current) {
      const seenN = (seen[props.current] || 0) + 1
      list.push({
        phase: props.current,
        visitNo: seenN,
        eventCount: 0,
        firstTs: '',
        lastTs: '',
        isCurrent: true,
        synthetic: true,
      })
    }
  }
  return list
})

// ── 把 visits 构造为 ECharts tree 数据 ──────────────────────────
// 规则:
//   - 第一个 visit 是根
//   - 第 N (>1) 次进入 X 的 parent = 第 N-1 次进入 X 的 parent (兄弟分支)
//   - 第 1 次进入 X 的 parent = 序列中前一个 visit
const treeData = computed(() => {
  const vs = visits.value
  if (!vs.length) return null

  const nodes = vs.map((v, i) => ({
    idx: i,
    name: phaseLabel(v.phase),
    phase: v.phase,
    visitNo: v.visitNo,
    eventCount: v.eventCount,
    isCurrent: Boolean(v.isCurrent),
    synthetic: Boolean(v.synthetic),
    children: [],
  }))

  // first-visit-of-phase index 缓存
  const firstVisitIdx = {}
  // (phase, visitNo) -> parent idx
  const parentOf = new Array(vs.length).fill(-1)

  for (let i = 0; i < vs.length; i++) {
    const v = vs[i]
    if (v.visitNo === 1) {
      firstVisitIdx[v.phase] = i
      parentOf[i] = i === 0 ? -1 : i - 1
    } else {
      // 找到 visitNo - 1 的同 phase 的 visit
      let prevIdx = -1
      let count = 0
      for (let j = 0; j < i; j++) {
        if (vs[j].phase === v.phase) {
          count += 1
          if (count === v.visitNo - 1) { prevIdx = j; break }
        }
      }
      parentOf[i] = prevIdx >= 0 ? parentOf[prevIdx] : (i - 1)
    }
  }

  let root = null
  for (let i = 0; i < nodes.length; i++) {
    const p = parentOf[i]
    if (p < 0) {
      root = nodes[i]
    } else {
      nodes[p].children.push(nodes[i])
    }
  }
  return root
})

function styleNode(node) {
  const color = colorFor(node.phase)
  const isRevisit = node.visitNo > 1
  return {
    name: node.name + (isRevisit ? ` ×${node.visitNo}` : ''),
    value: {
      phase: node.phase,
      visitNo: node.visitNo,
      eventCount: node.eventCount,
      isCurrent: node.isCurrent,
    },
    itemStyle: {
      color,
      borderColor: node.isCurrent ? chartTheme.colors().mint : color,
      borderWidth: node.isCurrent ? 3 : 1,
      shadowBlur: node.isCurrent ? 18 : 0,
      shadowColor: node.isCurrent ? chartTheme.colors().mint : 'transparent',
      opacity: node.synthetic ? 0.55 : 1,
    },
    lineStyle: isRevisit ? { type: 'dashed', width: 1.4 } : { width: 1.2 },
    label: {
      color: chartTheme.textColor(),
      fontSize: 11,
      fontWeight: node.isCurrent ? 700 : 500,
    },
    symbolSize: node.isCurrent ? 22 : (isRevisit ? 16 : 18),
    children: (node.children || []).map(styleNode),
  }
}

const styledTree = computed(() => {
  const root = treeData.value
  if (!root) return null
  return styleNode(root)
})

const option = computed(() => {
  const tip = chartTheme.tooltipStyle()
  if (!styledTree.value) return { backgroundColor: 'transparent', series: [] }
  return {
    backgroundColor: 'transparent',
    tooltip: {
      ...tip,
      formatter: (p) => {
        const v = p.data?.value || {}
        const parts = [
          `<div style="font-weight:600;margin-bottom:4px">${escapeHtml(p.name)}</div>`,
          `<div style="font-size:11px;color:#8b949e">阶段 · ${escapeHtml(v.phase || '-')}</div>`,
          `<div style="font-size:11px;margin-top:4px">访问次数: 第 ${v.visitNo || 1} 次</div>`,
          `<div style="font-size:11px">事件数: ${v.eventCount ?? 0}</div>`,
        ]
        if (v.isCurrent) {
          parts.push(`<div style="font-size:11px;color:#5cbda3;margin-top:4px">● 当前阶段</div>`)
        }
        return parts.join('')
      },
    },
    series: [
      {
        type: 'tree',
        data: [styledTree.value],
        orient: 'LR',
        layout: 'orthogonal',
        top: '12%',
        bottom: '12%',
        left: '8%',
        right: '12%',
        symbol: 'circle',
        roam: true,
        initialTreeDepth: -1,
        expandAndCollapse: false,
        animationDurationUpdate: 500,
        label: {
          position: 'right',
          verticalAlign: 'middle',
          align: 'left',
          fontSize: 11,
          color: chartTheme.textColor(),
        },
        leaves: {
          label: {
            position: 'right',
            verticalAlign: 'middle',
            align: 'left',
          },
        },
        emphasis: { focus: 'descendant' },
      },
    ],
  }
})

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
</script>

<style scoped>
.phase-tree {
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-base);
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.tree-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
.tree-title {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  font-weight: 700;
  color: var(--text-primary);
}
.tree-title .el-icon {
  color: var(--accent-blue);
}
.visit-tag { margin-left: 4px; }

.tree-legend {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 10px;
}
.legend-dot {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  color: var(--text-muted);
}
.legend-dot .dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
}

.tree-empty {
  min-height: 120px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.tree-canvas-wrap {
  width: 100%;
  height: 280px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--bg-base) 92%, var(--accent-blue) 4%);
  border: 1px solid var(--border);
  overflow: hidden;
}
.tree-canvas {
  width: 100%;
  height: 100%;
}

.stats-line {
  margin: 0;
  font-size: 12px;
  color: var(--text-secondary);
  line-height: 1.7;
  padding-top: 4px;
  border-top: 1px dashed var(--border);
}
.path-step {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-right: 4px;
}
.path-step.is-revisit {
  color: var(--accent-yellow);
}
.path-step.is-current {
  color: var(--accent-green);
  font-weight: 700;
}
.path-step .badge {
  font-size: 10px;
  background: color-mix(in srgb, var(--accent-yellow) 24%, transparent);
  border-radius: 8px;
  padding: 0 5px;
  font-family: var(--font-mono);
}
.path-step .sep {
  color: var(--text-muted);
  margin: 0 4px;
}
</style>
