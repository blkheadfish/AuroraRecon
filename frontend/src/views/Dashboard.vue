<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">系统仪表盘</h1>
        <p class="page-sub">系统概览、工具概览、工具调用概览</p>
      </div>
      <div class="header-actions">
        <el-select v-model="windowHours" size="small" style="width: 130px" @change="refresh">
          <el-option label="最近 1 小时" :value="1" />
          <el-option label="最近 6 小时" :value="6" />
          <el-option label="最近 24 小时" :value="24" />
          <el-option label="最近 72 小时" :value="72" />
        </el-select>
        <el-switch v-model="autoRefresh" active-text="自动刷新" inactive-text="手动" />
        <el-button @click="refresh" :loading="loading">刷新</el-button>
      </div>
    </div>

    <!-- System Overview -->
    <el-card class="panel">
      <template #header>
        <div class="card-header">
          <span>系统概览</span>
          <span class="meta">更新时间 {{ formatTime(metrics.generated_at) }}</span>
        </div>
      </template>
      <div class="system-row">
        <div class="chart-cell">
          <v-chart :option="taskDonutOption" autoresize class="chart" />
        </div>
        <div class="stats-center">
          <div class="status-row">
            <div class="metric-item">
              <div class="label">API 状态</div>
              <el-tag :type="statusTagType(system.api_status)" size="small">{{ system.api_status || '-' }}</el-tag>
            </div>
            <div class="metric-item">
              <div class="label">数据库</div>
              <el-tag :type="statusTagType(system.database)" size="small">{{ system.database || '-' }}</el-tag>
            </div>
            <div class="metric-item">
              <div class="label">Redis</div>
              <el-tag :type="statusTagType(system.redis)" size="small">{{ system.redis || '-' }}</el-tag>
            </div>
            <div class="metric-item">
              <div class="label">MSF</div>
              <el-tag :type="statusTagType(system.msf)" size="small">{{ system.msf || '-' }}</el-tag>
            </div>
          </div>
          <div class="numbers-row">
            <div class="num-card">
              <div class="num-value mono">{{ system.total_tasks || 0 }}</div>
              <div class="num-label">任务总数</div>
            </div>
            <div class="num-card">
              <div class="num-value mono running">{{ system.running_tasks || 0 }}</div>
              <div class="num-label">运行中</div>
            </div>
            <div class="num-card">
              <div class="num-value mono success">{{ system.completed_tasks || 0 }}</div>
              <div class="num-label">已完成</div>
            </div>
            <div class="num-card">
              <div class="num-value mono danger">{{ system.failed_tasks || 0 }}</div>
              <div class="num-label">失败</div>
            </div>
            <div class="num-card">
              <div class="num-value mono shell-color">{{ system.shells_obtained_tasks || 0 }}</div>
              <div class="num-label">获取Shell</div>
            </div>
            <div class="num-card">
              <div class="num-value mono root-color">{{ system.root_reached_tasks || 0 }}</div>
              <div class="num-label">Root提权</div>
            </div>
          </div>
        </div>
        <div class="chart-cell">
          <v-chart :option="successGaugeOption" autoresize class="chart" />
        </div>
      </div>
    </el-card>

    <!-- Main Grid: Tool Overview + Tool Invocation -->
    <div class="main-grid">
      <el-card class="panel">
        <template #header>
          <div class="card-header">
            <span>工具概览</span>
            <span class="meta">已注册工具 {{ toolOverview.total_tools || 0 }}</span>
          </div>
        </template>
        <div class="inline-grid">
          <div class="mini-card">
            <div class="label">总工具数</div>
            <div class="value mono">{{ toolOverview.total_tools || 0 }}</div>
          </div>
          <div class="mini-card">
            <div class="label">分类数</div>
            <div class="value mono">{{ categoryRows.length }}</div>
          </div>
          <div class="mini-card">
            <div class="label">执行器数</div>
            <div class="value mono">{{ executorRows.length }}</div>
          </div>
        </div>
        <div class="chart-container-sm">
          <v-chart :option="categoryPieOption" autoresize class="chart" />
        </div>
        <el-table :data="executorRows" size="small" class="table">
          <el-table-column prop="name" label="执行器" min-width="160" />
          <el-table-column prop="count" label="数量" width="90" />
        </el-table>
      </el-card>

      <el-card class="panel">
        <template #header>
          <div class="card-header">
            <span>工具调用概览</span>
            <span class="meta">时间窗口 {{ metrics.window_hours || 24 }} 小时</span>
          </div>
        </template>
        <div class="inline-grid">
          <div class="mini-card">
            <div class="label">调用总量</div>
            <div class="value mono">{{ invocation.total_calls || 0 }}</div>
          </div>
          <div class="mini-card">
            <div class="label">成功率</div>
            <div class="value mono">{{ invocation.success_rate || 0 }}%</div>
          </div>
          <div class="mini-card">
            <div class="label">平均耗时</div>
            <div class="value mono">{{ formatMs(invocation.avg_elapsed_ms) }}</div>
          </div>
        </div>

        <div class="backend-row">
          <span class="label backend-row-title">执行后端分布</span>
          <el-tooltip
            v-for="item in backendRows"
            :key="item.name"
            :content="backendTip(item.name)"
            placement="top"
          >
            <el-tag size="small" type="info" effect="plain" class="backend-tag">
              <span class="backend-name">{{ item.name }}</span>
              <span class="backend-count mono">{{ item.count }} 次</span>
            </el-tag>
          </el-tooltip>
          <span v-if="!backendRows.length" class="empty-tip">暂无数据</span>
        </div>

        <div class="chart-container-md">
          <v-chart :option="topToolsBarOption" autoresize class="chart" />
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { trackEvent } from '@/metrics/tracker'
import { useChartTheme } from '@/composables/useChartTheme'

import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart, GaugeChart } from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
} from 'echarts/components'

use([
  CanvasRenderer, PieChart, BarChart, GaugeChart,
  TitleComponent, TooltipComponent, LegendComponent, GridComponent,
])

const chartTheme = useChartTheme()
const C = computed(() => chartTheme.colors())
const PALETTE = computed(() => chartTheme.palette())
const TIP_STYLE = computed(() => chartTheme.tooltipStyle())

const autoRefresh = ref(true)
const loading = ref(false)
const windowHours = ref(24)
const metricsEndpointMissing = ref(false)
const metricsMissingToastShown = ref(false)
const metrics = ref({
  generated_at: '',
  window_hours: 24,
  system_overview: {},
  tool_overview: {
    total_tools: 0,
    by_category: {},
    by_executor: {},
    tools: [],
  },
  tool_invocation_overview: {
    total_calls: 0,
    completed_calls: 0,
    success_calls: 0,
    failed_calls: 0,
    success_rate: 0,
    avg_elapsed_ms: 0,
    by_backend: {},
    top_tools: [],
  },
})
let timer = null

const system = computed(() => metrics.value.system_overview || {})
const toolOverview = computed(() => metrics.value.tool_overview || {})
const invocation = computed(() => metrics.value.tool_invocation_overview || {})

const categoryRows = computed(() =>
  Object.entries(toolOverview.value.by_category || {}).map(([name, count]) => ({ name, count })),
)

const executorRows = computed(() =>
  Object.entries(toolOverview.value.by_executor || {}).map(([name, count]) => ({ name, count })),
)

const backendRows = computed(() =>
  Object.entries(invocation.value.by_backend || {})
    .map(([name, count]) => ({ name, count: Number(count || 0) }))
    .sort((a, b) => b.count - a.count),
)

// ── Chart Options ──

const taskDonutOption = computed(() => {
  const c = C.value
  const tip = TIP_STYLE.value
  const running = Number(system.value.running_tasks || 0)
  const completed = Number(system.value.completed_tasks || 0)
  const failed = Number(system.value.failed_tasks || 0)
  const total = running + completed + failed
  const labelColor = chartTheme.textColor()
  const mutedColor = chartTheme.mutedTextColor()
  const bg = chartTheme.bgBase()

  return {
    tooltip: { trigger: 'item', ...tip },
    legend: {
      bottom: 4,
      itemWidth: 10,
      itemHeight: 10,
      textStyle: { color: labelColor, fontSize: 11 },
    },
    series: [{
      type: 'pie',
      radius: ['48%', '72%'],
      center: ['50%', '45%'],
      avoidLabelOverlap: true,
      itemStyle: { borderRadius: 4, borderColor: bg, borderWidth: 2 },
      label: {
        show: true,
        position: 'center',
        formatter: `{big|${total}}\n{sub|任务总数}`,
        rich: {
          big: { fontSize: 22, fontWeight: 700, color: labelColor, fontFamily: 'JetBrains Mono, monospace', lineHeight: 28 },
          sub: { fontSize: 11, color: mutedColor, lineHeight: 18 },
        },
      },
      emphasis: {
        label: { show: true, fontSize: 12 },
        itemStyle: { shadowBlur: 16, shadowColor: 'rgba(88,184,201,0.25)' },
      },
      data: [
        { value: running, name: '运行中', itemStyle: { color: c.cyan } },
        { value: completed, name: '已完成', itemStyle: { color: c.mint } },
        { value: failed, name: '失败', itemStyle: { color: c.ember } },
      ].filter(d => d.value > 0),
    }],
  }
})

const successGaugeOption = computed(() => {
  const c = C.value
  const rate = Number(invocation.value.success_rate || 0)
  const gaugeColor = rate >= 85 ? c.cyan : rate >= 60 ? c.teal : c.ember
  const mutedColor = chartTheme.mutedTextColor()
  return {
    series: [{
      type: 'gauge',
      startAngle: 200,
      endAngle: -20,
      radius: '88%',
      center: ['50%', '55%'],
      min: 0,
      max: 100,
      splitNumber: 5,
      itemStyle: { color: gaugeColor },
      progress: { show: true, width: 14, roundCap: true },
      pointer: { show: false },
      axisLine: {
        lineStyle: {
          width: 14,
          color: [[1, 'rgba(88,184,201,0.08)']],
        },
      },
      axisTick: { show: false },
      splitLine: { show: false },
      axisLabel: { show: false },
      title: {
        show: true,
        offsetCenter: [0, '68%'],
        color: mutedColor,
        fontSize: 11,
      },
      detail: {
        valueAnimation: true,
        offsetCenter: [0, '20%'],
        fontSize: 22,
        fontWeight: 700,
        fontFamily: 'JetBrains Mono, monospace',
        formatter: '{value}%',
        color: gaugeColor,
      },
      data: [{ value: rate, name: '工具调用成功率' }],
    }],
  }
})

const topToolsBarOption = computed(() => {
  const c = C.value
  const tip = TIP_STYLE.value
  const labelColor = chartTheme.textColor()
  const mutedColor = chartTheme.mutedTextColor()
  const tools = (invocation.value.top_tools || []).slice(0, 8).reverse()
  if (!tools.length) {
    return { title: { text: '暂无调用数据', left: 'center', top: 'center', textStyle: { color: mutedColor, fontSize: 12, fontWeight: 400 } } }
  }
  return {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      ...tip,
      formatter: (params) => {
        const p = params[0]
        const tool = tools[p.dataIndex]
        return `<b style="color:${labelColor}">${tool.tool}</b><br/>调用: ${tool.calls} 次<br/>成功率: ${tool.success_rate}%<br/>平均耗时: ${Math.round(tool.avg_elapsed_ms)} ms`
      },
    },
    grid: { left: 8, right: 24, top: 8, bottom: 8, containLabel: true },
    xAxis: {
      type: 'value',
      axisLabel: { color: mutedColor, fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(88,184,201,0.06)' } },
    },
    yAxis: {
      type: 'category',
      data: tools.map(t => t.tool),
      axisLabel: { color: labelColor, fontSize: 11, width: 100, overflow: 'truncate' },
      axisLine: { show: false },
      axisTick: { show: false },
    },
    series: [{
      type: 'bar',
      barWidth: 14,
      data: tools.map(t => ({
        value: t.calls,
        itemStyle: {
          color: t.success_rate >= 80 ? c.cyan : t.success_rate >= 50 ? c.teal : c.ember,
          borderRadius: [0, 4, 4, 0],
        },
      })),
    }],
  }
})

const categoryPieOption = computed(() => {
  const tip = TIP_STYLE.value
  const pal = PALETTE.value
  const labelColor = chartTheme.textColor()
  const mutedColor = chartTheme.mutedTextColor()
  const bg = chartTheme.bgBase()
  const entries = categoryRows.value
  if (!entries.length) {
    return { title: { text: '暂无工具数据', left: 'center', top: 'center', textStyle: { color: mutedColor, fontSize: 12, fontWeight: 400 } } }
  }
  return {
    tooltip: { trigger: 'item', ...tip },
    legend: {
      orient: 'vertical',
      right: 8,
      top: 'center',
      itemWidth: 10,
      itemHeight: 10,
      textStyle: { color: labelColor, fontSize: 11 },
    },
    series: [{
      type: 'pie',
      radius: ['36%', '66%'],
      center: ['35%', '50%'],
      itemStyle: { borderRadius: 4, borderColor: bg, borderWidth: 2 },
      label: { show: false },
      emphasis: {
        itemStyle: { shadowBlur: 16, shadowColor: 'rgba(88,184,201,0.20)' },
      },
      data: entries.map((e, i) => ({
        value: e.count,
        name: e.name,
        itemStyle: { color: pal[i % pal.length] },
      })),
    }],
  }
})

// ── Helpers ──

function backendTip(name) {
  const key = String(name || '').toLowerCase()
  if (key === 'container-run') return 'container-run: 以运行容器任务方式调用工具，常用于完整扫描流程。'
  if (key === 'container-exec') return 'container-exec: 在现有容器中执行命令，常用于短命令探测与补充校验。'
  return `${name}: 按执行后端统计的工具调用次数。`
}

function statusTagType(status) {
  if (status === 'ok' || status === 'connected') return 'success'
  if (status === 'unavailable') return 'warning'
  return 'info'
}

function formatTime(raw) {
  if (!raw) return '--:--:--'
  const t = new Date(raw)
  if (Number.isNaN(t.getTime())) return '--:--:--'
  return t.toLocaleTimeString()
}

function formatMs(value) {
  const num = Number(value || 0)
  if (!Number.isFinite(num)) return '0 ms'
  return `${Math.round(num)} ms`
}

async function refresh(trigger = 'manual') {
  if (metricsEndpointMissing.value && trigger === 'auto') return
  loading.value = true
  try {
    metrics.value = await api.getMetricsOverview(windowHours.value)
    metricsEndpointMissing.value = false
    metricsMissingToastShown.value = false
  } catch (e) {
    const status = e?.response?.status ?? null
    if (status === 404) {
      metricsEndpointMissing.value = true
      autoRefresh.value = false
      if (!metricsMissingToastShown.value) {
        metricsMissingToastShown.value = true
        ElMessage.warning('后端未提供可用的 Metrics Overview 接口，已停止自动刷新。重启后端后可手动刷新重试。')
      }
    } else {
      ElMessage.error(e?.response?.data?.detail || e.message || '读取仪表盘数据失败')
    }
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  trackEvent('dashboard.open')
  await refresh('init')
  timer = window.setInterval(() => {
    if (autoRefresh.value) refresh('auto')
  }, 5000)
})

onUnmounted(() => {
  if (timer) window.clearInterval(timer)
})
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }
.page-title { font-size: 24px; color: var(--text-primary); font-weight: 700; }
.page-sub { margin-top: 4px; font-size: 13px; color: var(--text-secondary); }
.header-actions { display: flex; gap: 10px; align-items: center; }

.panel { border-radius: var(--radius-lg) !important; margin-bottom: 12px; }
.card-header { display: flex; justify-content: space-between; align-items: center; font-weight: 600; }
.meta { font-size: 12px; color: var(--text-muted); font-weight: 500; }

/* ── System Overview Row ── */
.system-row {
  display: flex;
  gap: 16px;
  align-items: stretch;
}

.chart-cell {
  width: 220px;
  min-width: 180px;
  min-height: 200px;
  flex-shrink: 0;
}

.chart-cell .chart {
  width: 100%;
  height: 100%;
  min-height: 200px;
}

.stats-center {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-width: 0;
}

.status-row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.status-row .metric-item {
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-base);
  padding: 8px 12px;
  flex: 1;
  min-width: 100px;
}

.numbers-row {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 8px;
}

.num-card {
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-base);
  padding: 10px 8px;
  text-align: center;
}

.num-value {
  font-size: 22px;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.2;
}

.num-label {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 2px;
}

/* ── Shared ── */
.label { color: var(--text-secondary); font-size: 12px; }
.value { margin-top: 4px; color: var(--text-primary); font-weight: 700; font-size: 20px; }
.mono { font-family: var(--font-mono); }
.running { color: #58b8c9; }
.success { color: #5cbda3; }
.danger { color: #a86070; }
.shell-color { color: #7680b8; }
.root-color { color: #9c8a62; }

/* ── Main Grid ── */
.main-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }

.inline-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin-bottom: 10px;
}

.mini-card {
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-base);
  padding: 10px 12px;
}

.table { margin-top: 8px; }

.chart-container-sm {
  min-height: 220px;
  margin-bottom: 8px;
}

.chart-container-sm .chart {
  width: 100%;
  height: 220px;
}

.chart-container-md {
  min-height: 260px;
  margin-top: 8px;
}

.chart-container-md .chart {
  width: 100%;
  height: 260px;
}

/* ── Backend Row ── */
.backend-row {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 8px;
  flex-wrap: wrap;
  padding: 8px 10px;
  border: 1px dashed color-mix(in srgb, var(--border) 70%, var(--accent-blue));
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--bg-base) 82%, transparent);
}

.backend-row-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-secondary);
}

:deep(.backend-tag.el-tag) {
  margin-right: 0;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border-color: color-mix(in srgb, var(--border) 72%, var(--accent-blue));
  background: color-mix(in srgb, var(--bg-surface) 88%, transparent);
}

.backend-name { color: var(--text-secondary); }
.backend-count { color: var(--text-primary); font-weight: 700; }
.empty-tip { color: var(--text-muted); font-size: 12px; }
</style>
