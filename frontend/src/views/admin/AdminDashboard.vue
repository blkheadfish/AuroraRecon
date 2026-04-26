<template>
  <div class="admin-dashboard">
    <div class="section-header">
      <div>
        <h2 class="section-title">仪表盘</h2>
        <p class="section-sub">系统概览 · 任务运行态势 · 宿主机 & 容器资源监控</p>
      </div>
      <div class="header-actions">
        <el-select v-model="windowHours" size="small" style="width: 130px" @change="refresh">
          <el-option label="最近 1 小时" :value="1" />
          <el-option label="最近 6 小时" :value="6" />
          <el-option label="最近 24 小时" :value="24" />
          <el-option label="最近 72 小时" :value="72" />
        </el-select>
        <el-switch v-model="autoRefresh" active-text="自动" inactive-text="手动" />
        <el-button :loading="loading" :icon="Refresh" @click="refresh" size="small">刷新</el-button>
      </div>
    </div>

    <el-alert
      v-if="liveFetchError"
      type="error"
      show-icon
      :closable="false"
      :title="`实时指标采集失败：${liveFetchError}`"
      description="前端将保留上一次可用数据。常见原因：后端采集超时（Docker 容器过多或 daemon 响应慢）、管理员 Token 失效、docker.sock 未挂载、psutil / docker-py 未安装。"
      style="margin-bottom: 14px"
    />

    <!-- Health + Stat Cards Row -->
    <div class="health-row">
      <div class="health-lamp" :class="sysOverview.api_status === 'ok' ? 'ok' : 'err'">
        <span class="lamp-dot" /><span class="lamp-label">API</span>
      </div>
      <div class="health-lamp" :class="sysOverview.database === 'connected' ? 'ok' : 'err'">
        <span class="lamp-dot" /><span class="lamp-label">Database</span>
      </div>
      <div class="health-lamp" :class="sysOverview.redis === 'connected' ? 'ok' : 'err'">
        <span class="lamp-dot" /><span class="lamp-label">Redis</span>
      </div>
      <div class="health-lamp" :class="sysOverview.msf === 'connected' ? 'ok' : 'err'">
        <span class="lamp-dot" /><span class="lamp-label">MSF</span>
      </div>
      <span class="updated-at">更新于 {{ formatTime(metrics.generated_at) }}</span>
    </div>

    <div class="stat-grid">
      <div class="stat-card"><span class="stat-value">{{ userStats.total }}</span><span class="stat-desc">用户总数</span></div>
      <div class="stat-card admin-accent"><span class="stat-value">{{ userStats.admins }}</span><span class="stat-desc">管理员</span></div>
      <div class="stat-card"><span class="stat-value">{{ sysOverview.total_tasks ?? '—' }}</span><span class="stat-desc">任务总数</span></div>
      <div class="stat-card running"><span class="stat-value">{{ sysOverview.running_tasks ?? '—' }}</span><span class="stat-desc">运行中</span></div>
      <div class="stat-card completed"><span class="stat-value">{{ sysOverview.completed_tasks ?? '—' }}</span><span class="stat-desc">已完成</span></div>
      <div class="stat-card failed"><span class="stat-value">{{ sysOverview.failed_tasks ?? '—' }}</span><span class="stat-desc">失败</span></div>
    </div>

    <!-- ECharts Panels -->
    <div class="chart-row">
      <el-card class="chart-card" shadow="never">
        <template #header><span class="panel-head">任务分布</span></template>
        <v-chart :option="taskDonutOption" :loading="chartLoading" :loading-options="chartLoadingOpts" autoresize class="chart" />
      </el-card>
      <el-card class="chart-card" shadow="never">
        <template #header><span class="panel-head">工具调用成功率</span></template>
        <v-chart :option="successGaugeOption" :loading="chartLoading" :loading-options="chartLoadingOpts" autoresize class="chart" />
      </el-card>
      <el-card class="chart-card chart-card-wide" shadow="never">
        <template #header><span class="panel-head">工具调用 Top 8</span></template>
        <v-chart :option="topToolsBarOption" :loading="chartLoading" :loading-options="chartLoadingOpts" autoresize class="chart" />
      </el-card>
    </div>

    <!-- Guard stats row -->
    <el-card class="panel-card" shadow="never">
      <template #header><span class="panel-head">Guard 拦截摘要</span></template>
      <div class="guard-stats">
        <div class="guard-row"><span class="guard-label">重复探测拦截</span><span class="guard-value">{{ guardOverview.reprobe_intercept_count ?? 0 }}</span></div>
        <div class="guard-row"><span class="guard-label">重复失败命令拦截</span><span class="guard-value">{{ guardOverview.repeat_failed_command_intercept_count ?? 0 }}</span></div>
        <div class="guard-row"><span class="guard-label">LLM 预检拒绝</span><span class="guard-value">{{ guardOverview.llm_preflight_reject_count ?? 0 }}</span></div>
      </div>
    </el-card>

    <!-- ── 系统资源监控 ── -->
    <div class="section-divider">
      <span>系统资源监控</span>
      <span class="divider-sub">每 5 秒轮询 · 保留最近 60 个采样点</span>
    </div>

    <el-alert
      v-if="metricsLive.host.error"
      type="warning"
      show-icon
      :closable="false"
      :title="`宿主机指标采集失败：${metricsLive.host.error}`"
      description="通常是 psutil 未安装或容器未挂载 /proc、/sys。请执行 docker compose build api --no-cache 重建镜像。"
      style="margin-bottom: 12px"
    />

    <div class="resource-row">
      <el-card class="resource-card" shadow="never">
        <template #header>
          <span class="panel-head">宿主机 CPU</span>
          <span class="cpu-now">{{ hostCpuNow }}% · {{ metricsLive.host.cpu_count || 0 }} 核</span>
        </template>
        <v-chart :option="cpuLineOption" :loading="!hasFirstSample" :loading-options="chartLoadingOpts" autoresize class="chart-small" />
      </el-card>

      <el-card class="resource-card" shadow="never">
        <template #header>
          <span class="panel-head">宿主机内存</span>
          <span class="cpu-now">{{ memUsedGb }} / {{ memTotalGb }} GB</span>
        </template>
        <v-chart :option="memGaugeOption" :loading="!hasFirstSample" :loading-options="chartLoadingOpts" autoresize class="chart-small" />
      </el-card>

      <el-card class="resource-card" shadow="never">
        <template #header>
          <span class="panel-head">
            {{ metricsLive.host.source === 'container' ? '容器磁盘' : '宿主机磁盘' }}
          </span>
          <span class="source-tag" :class="metricsLive.host.source === 'host' ? 'host' : 'container'">
            {{ metricsLive.host.source === 'host' ? 'host' : 'container' }}
          </span>
          <span class="cpu-now">{{ metricsLive.host.disk?.length || 0 }} 分区</span>
        </template>
        <div class="disk-list">
          <SkeletonBlock v-if="!hasFirstSample" :rows="3" :height="22" />
          <template v-else>
            <div v-for="d in metricsLive.host.disk || []" :key="d.mountpoint" class="disk-row">
              <div class="disk-head">
                <code class="disk-mount">{{ d.mountpoint }}</code>
                <span class="disk-used">{{ d.used_gb }} / {{ d.total_gb }} GB</span>
              </div>
              <el-progress :percentage="d.percent" :stroke-width="6" :show-text="false"
                :color="d.percent >= 90 ? '#e67e80' : d.percent >= 70 ? '#e69875' : '#83c092'" />
            </div>
            <div v-if="!(metricsLive.host.disk || []).length" class="empty-muted">
              未采集到磁盘分区（容器模式下常见）
            </div>
          </template>
        </div>
      </el-card>
    </div>

    <!-- Docker Containers -->
    <el-card class="panel-card" shadow="never">
      <template #header>
        <span class="panel-head">Docker 容器</span>
        <span class="docker-summary">
          <el-tag type="success" size="small" effect="plain">运行中 {{ metricsLive.docker.total_running }}</el-tag>
          <el-tag type="info" size="small" effect="plain">已停止 {{ metricsLive.docker.total_stopped }}</el-tag>
        </span>
      </template>

      <el-alert
        v-if="metricsLive.docker.error"
        type="error"
        show-icon
        :closable="false"
        :title="`Docker 采集失败：${metricsLive.docker.error}`"
        description="常见原因：镜像过旧（未执行 docker compose build api --no-cache）、api 容器未挂载 /var/run/docker.sock、docker 守护进程未启动、或项目根 docker/ 目录遮蔽了 docker-py 依赖。"
        style="margin-bottom: 12px"
      />
      <el-alert
        v-else-if="metricsLive.docker.warning"
        type="warning"
        show-icon
        :closable="true"
        :title="metricsLive.docker.warning"
        style="margin-bottom: 12px"
      />

      <SkeletonBlock v-if="!hasFirstSample" :rows="5" :height="28" />

      <el-table
        v-else
        :data="metricsLive.docker.containers || []"
        size="small"
        empty-text="未检测到容器"
      >
        <el-table-column prop="name" label="容器名" min-width="220">
          <template #default="{ row }">
            <code class="ct-name">{{ row.name }}</code>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'running' ? 'success' : 'info'" size="small" effect="plain">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="CPU" width="140">
          <template #default="{ row }">
            <div class="ct-metric">
              <span class="ct-val">{{ (row.cpu_percent ?? 0).toFixed(1) }}%</span>
              <el-progress :percentage="Math.min(100, row.cpu_percent || 0)" :stroke-width="4" :show-text="false" />
            </div>
          </template>
        </el-table-column>
        <el-table-column label="内存" min-width="200">
          <template #default="{ row }">
            <div class="ct-metric">
              <span class="ct-val">{{ formatMem(row.memory_mb) }} / {{ formatMem(row.memory_limit_mb) }}</span>
              <el-progress
                :percentage="row.memory_limit_mb ? Math.min(100, (row.memory_mb / row.memory_limit_mb) * 100) : 0"
                :stroke-width="4" :show-text="false" />
            </div>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="220" align="right">
          <template #default="{ row }">
            <el-tag v-if="isCoreContainer(row.name)" size="small" type="warning" effect="plain" title="核心容器已受保护，避免意外终止服务">
              核心 · 受保护
            </el-tag>
            <template v-else>
              <el-button v-if="row.status === 'running'" size="small" text @click="dockerAction(row.name, 'restart')">重启</el-button>
              <el-button v-if="row.status === 'running'" size="small" text type="warning" @click="dockerAction(row.name, 'stop')">停止</el-button>
              <el-button v-else size="small" text type="success" @click="dockerAction(row.name, 'start')">启动</el-button>
            </template>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '@/api'
import { useChartTheme } from '@/composables/useChartTheme'
import SkeletonBlock from '@/components/SkeletonBlock.vue'

import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart, GaugeChart, LineChart } from 'echarts/charts'
import {
  TitleComponent, TooltipComponent, LegendComponent, GridComponent,
} from 'echarts/components'

use([
  CanvasRenderer, PieChart, BarChart, GaugeChart, LineChart,
  TitleComponent, TooltipComponent, LegendComponent, GridComponent,
])

const chartTheme = useChartTheme()
const C = computed(() => chartTheme.colors())
const TIP_STYLE = computed(() => chartTheme.tooltipStyle())

const autoRefresh = ref(true)
const loading = ref(false)
const windowHours = ref(24)

const metrics = ref({
  generated_at: '',
  system_overview: {},
  guard_overview: {},
  tool_invocation_overview: { top_tools: [], success_rate: 0 },
})

const metricsLive = ref({
  host: { cpu_percent: 0, cpu_count: 0, memory: { total_gb: 0, used_gb: 0, percent: 0 }, disk: [], source: 'container', error: '' },
  docker: { containers: [], total_running: 0, total_stopped: 0, error: '', warning: '' },
})
const hasFirstSample = ref(false)
const liveFetchError = ref('')
let _livePending = false

const CORE_CONTAINERS = new Set([
  'pentest_api', 'pentest_frontend', 'pentest_redis', 'pentest_postgres',
  'pentest_reverse_proxy', 'pentest_nginx', 'pentest_toolbox',
])
function isCoreContainer(name) {
  if (!name) return false
  const n = String(name).replace(/^\//, '').toLowerCase()
  return CORE_CONTAINERS.has(n)
}

const cpuSeries = ref([]) // {ts, v}[]
const MAX_SAMPLES = 60

const userStats = ref({ total: 0, admins: 0 })

const sysOverview = computed(() => metrics.value.system_overview || {})
const guardOverview = computed(() => metrics.value.guard_overview || {})
const invocation = computed(() => metrics.value.tool_invocation_overview || {})

const chartLoading = computed(() => !metrics.value.generated_at)
const chartLoadingOpts = computed(() => ({
  text: '采样中…',
  color: chartTheme.colors().cyan,
  textColor: chartTheme.mutedTextColor(),
  maskColor: 'rgba(0, 0, 0, 0)',
  zlevel: 0,
  fontSize: 12,
  fontWeight: 500,
  lineWidth: 3,
  spinnerRadius: 12,
}))

const hostCpuNow = computed(() => (metricsLive.value.host.cpu_percent ?? 0).toFixed(1))
const memUsedGb = computed(() => metricsLive.value.host.memory?.used_gb ?? 0)
const memTotalGb = computed(() => metricsLive.value.host.memory?.total_gb ?? 0)

// ── ECharts options ──

const taskDonutOption = computed(() => {
  const c = C.value
  const tip = TIP_STYLE.value
  const running = Number(sysOverview.value.running_tasks || 0)
  const completed = Number(sysOverview.value.completed_tasks || 0)
  const failed = Number(sysOverview.value.failed_tasks || 0)
  const total = running + completed + failed
  const labelColor = chartTheme.textColor()
  const mutedColor = chartTheme.mutedTextColor()
  const bg = chartTheme.bgBase()
  return {
    tooltip: { trigger: 'item', ...tip },
    legend: { bottom: 4, itemWidth: 10, itemHeight: 10, textStyle: { color: labelColor, fontSize: 11 } },
    series: [{
      type: 'pie', radius: ['48%', '72%'], center: ['50%', '45%'],
      itemStyle: { borderRadius: 4, borderColor: bg, borderWidth: 2 },
      label: {
        show: true, position: 'center',
        formatter: `{big|${total}}\n{sub|任务总数}`,
        rich: {
          big: { fontSize: 22, fontWeight: 700, color: labelColor, fontFamily: 'JetBrains Mono, monospace', lineHeight: 28 },
          sub: { fontSize: 11, color: mutedColor, lineHeight: 18 },
        },
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
      type: 'gauge', startAngle: 200, endAngle: -20,
      radius: '88%', center: ['50%', '55%'],
      min: 0, max: 100,
      itemStyle: { color: gaugeColor },
      progress: { show: true, width: 14, roundCap: true },
      pointer: { show: false },
      axisLine: { lineStyle: { width: 14, color: [[1, 'rgba(88,184,201,0.08)']] } },
      axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false },
      title: { show: true, offsetCenter: [0, '68%'], color: mutedColor, fontSize: 11 },
      detail: {
        valueAnimation: true, offsetCenter: [0, '20%'],
        fontSize: 22, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace',
        formatter: '{value}%', color: gaugeColor,
      },
      data: [{ value: rate, name: '成功率' }],
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
    return { title: { text: '暂无调用数据', left: 'center', top: 'center', textStyle: { color: mutedColor, fontSize: 12 } } }
  }
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, ...tip,
      formatter: (params) => {
        const p = params[0]; const tool = tools[p.dataIndex]
        return `<b style="color:${labelColor}">${tool.tool}</b><br/>调用: ${tool.calls} 次<br/>成功率: ${tool.success_rate}%`
      },
    },
    grid: { left: 8, right: 24, top: 8, bottom: 8, containLabel: true },
    xAxis: { type: 'value', axisLabel: { color: mutedColor, fontSize: 10 },
      axisLine: { show: false }, splitLine: { lineStyle: { color: 'rgba(88,184,201,0.06)' } } },
    yAxis: { type: 'category', data: tools.map(t => t.tool),
      axisLabel: { color: labelColor, fontSize: 11, width: 100, overflow: 'truncate' },
      axisLine: { show: false }, axisTick: { show: false } },
    series: [{
      type: 'bar', barWidth: 14,
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

const cpuLineOption = computed(() => {
  const c = C.value
  const tip = TIP_STYLE.value
  const mutedColor = chartTheme.mutedTextColor()
  const data = cpuSeries.value
  return {
    tooltip: { trigger: 'axis', ...tip,
      formatter: (params) => `${params[0].axisValueLabel}<br/>CPU: ${params[0].value}%` },
    grid: { left: 8, right: 10, top: 8, bottom: 6, containLabel: true },
    xAxis: {
      type: 'category', data: data.map(d => d.ts),
      axisLabel: { color: mutedColor, fontSize: 10, hideOverlap: true },
      axisLine: { lineStyle: { color: 'rgba(88,184,201,0.15)' } }, axisTick: { show: false },
    },
    yAxis: {
      type: 'value', min: 0, max: 100,
      axisLabel: { color: mutedColor, fontSize: 10, formatter: '{value}%' },
      splitLine: { lineStyle: { color: 'rgba(88,184,201,0.06)' } },
    },
    series: [{
      type: 'line', smooth: true, symbol: 'none',
      data: data.map(d => d.v),
      lineStyle: { color: c.cyan, width: 2 },
      areaStyle: { color: 'rgba(88,184,201,0.18)' },
    }],
  }
})

const memGaugeOption = computed(() => {
  const c = C.value
  const pct = Number(metricsLive.value.host.memory?.percent || 0)
  const color = pct >= 85 ? c.ember : pct >= 60 ? c.teal : c.cyan
  const muted = chartTheme.mutedTextColor()
  return {
    series: [{
      type: 'gauge', startAngle: 200, endAngle: -20,
      radius: '88%', center: ['50%', '55%'],
      min: 0, max: 100,
      itemStyle: { color },
      progress: { show: true, width: 14, roundCap: true },
      pointer: { show: false },
      axisLine: { lineStyle: { width: 14, color: [[1, 'rgba(88,184,201,0.08)']] } },
      axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false },
      title: { show: true, offsetCenter: [0, '68%'], color: muted, fontSize: 11 },
      detail: {
        valueAnimation: true, offsetCenter: [0, '20%'],
        fontSize: 22, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace',
        formatter: '{value}%', color,
      },
      data: [{ value: pct.toFixed(1), name: '内存使用率' }],
    }],
  }
})

// ── Actions ──

async function loadOverview() {
  const [metricsRes, usersRes] = await Promise.all([
    api.getMetricsOverview(windowHours.value).catch(() => null),
    api.adminListUsers().catch(() => ({ users: [] })),
  ])
  if (metricsRes) metrics.value = metricsRes
  const users = usersRes?.users || []
  userStats.value = {
    total: users.length,
    admins: users.filter(u => u.role === 'admin').length,
  }
}

async function loadLiveMetrics() {
  if (_livePending) return
  _livePending = true
  try {
    const res = await api.adminGetSystemMetrics()
    metricsLive.value = {
      host: { cpu_percent: 0, cpu_count: 0, memory: {}, disk: [], source: 'container', error: '', ...(res?.host || {}) },
      docker: { containers: [], total_running: 0, total_stopped: 0, error: '', warning: '', ...(res?.docker || {}) },
    }
    liveFetchError.value = ''
    hasFirstSample.value = true
    const ts = new Date().toLocaleTimeString([], { hour12: false })
    cpuSeries.value.push({ ts, v: Number((res?.host?.cpu_percent ?? 0).toFixed(1)) })
    if (cpuSeries.value.length > MAX_SAMPLES) cpuSeries.value.shift()
  } catch (e) {
    liveFetchError.value = e?.response?.data?.detail || e?.message || '实时指标采集失败'
    hasFirstSample.value = true
  } finally {
    _livePending = false
  }
}

async function refresh() {
  loading.value = true
  try {
    await Promise.all([loadOverview(), loadLiveMetrics()])
  } catch (e) {
    ElMessage.error(e?.message || '刷新失败')
  } finally {
    loading.value = false
  }
}

async function dockerAction(name, action) {
  if (isCoreContainer(name)) {
    ElMessage.warning(`${name} 为核心容器，已在前端阻止 ${action} 操作。`)
    return
  }
  try {
    await ElMessageBox.confirm(
      `确认对容器 ${name} 执行 ${action}？`,
      '确认操作', { type: 'warning' },
    )
  } catch { return }
  try {
    await api.adminDockerAction(name, action)
    ElMessage.success(`已${action === 'restart' ? '重启' : action === 'stop' ? '停止' : '启动'}容器 ${name}`)
    await loadLiveMetrics()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '操作失败')
  }
}

function formatMem(mb) {
  const n = Number(mb || 0)
  if (n >= 1024) return `${(n / 1024).toFixed(1)} GB`
  return `${n.toFixed(0)} MB`
}
function formatTime(raw) {
  if (!raw) return '--:--:--'
  const t = new Date(raw)
  if (Number.isNaN(t.getTime())) return '--:--:--'
  return t.toLocaleTimeString()
}

let overviewTimer = null
let liveTimer = null

onMounted(() => {
  refresh()
  overviewTimer = setInterval(() => {
    if (autoRefresh.value) loadOverview()
  }, 30000)
  liveTimer = setInterval(() => {
    if (autoRefresh.value) loadLiveMetrics()
  }, 5000)
})

onUnmounted(() => {
  if (overviewTimer) clearInterval(overviewTimer)
  if (liveTimer) clearInterval(liveTimer)
})
</script>

<style scoped>
.section-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 20px;
  gap: 12px;
  flex-wrap: wrap;
}
.section-title {
  font-size: 20px;
  font-weight: 700;
  color: var(--text-primary);
  margin: 0 0 4px;
}
.section-sub {
  font-size: 13px;
  color: var(--text-secondary);
  margin: 0;
}
.header-actions {
  display: flex;
  gap: 10px;
  align-items: center;
}

.health-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 18px;
  flex-wrap: wrap;
}
.health-lamp {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--bg-surface);
  font-size: 12px;
  font-family: var(--font-mono);
  color: var(--text-secondary);
}
.lamp-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--text-muted); }
.health-lamp.ok .lamp-dot { background: var(--accent-green); }
.health-lamp.ok { border-color: color-mix(in srgb, var(--accent-green) 40%, var(--border)); color: var(--accent-green); }
.health-lamp.err .lamp-dot { background: var(--accent-red); }
.health-lamp.err { border-color: color-mix(in srgb, var(--accent-red) 40%, var(--border)); color: var(--accent-red); }

.updated-at {
  margin-left: auto;
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-muted);
}

.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 22px;
}
.stat-card {
  padding: 14px 18px;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--bg-surface);
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.stat-value {
  font-family: var(--font-mono);
  font-size: 24px;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.1;
}
.stat-desc { font-size: 12px; color: var(--text-muted); }
.stat-card.admin-accent .stat-value { color: var(--accent-red); }
.stat-card.running .stat-value { color: var(--accent-blue); }
.stat-card.completed .stat-value { color: var(--accent-green); }
.stat-card.failed .stat-value { color: var(--accent-red); }

.chart-row {
  display: grid;
  grid-template-columns: 1fr 1fr 1.4fr;
  gap: 14px;
  margin-bottom: 16px;
}
.chart-card,
.panel-card,
.resource-card {
  border-radius: var(--radius-lg) !important;
  border: 1px solid var(--border) !important;
}
.chart-card-wide { grid-column: span 1; }
.chart { height: 220px; width: 100%; }
.chart-small { height: 160px; width: 100%; }
.panel-head {
  font-size: 13px;
  font-weight: 700;
  color: var(--text-primary);
}
.cpu-now,
.docker-summary {
  float: right;
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  display: inline-flex;
  gap: 6px;
  align-items: center;
}

.source-tag {
  float: right;
  margin-left: 8px;
  font-size: 10px;
  font-family: var(--font-mono);
  padding: 1px 6px;
  border-radius: 999px;
  border: 1px solid var(--border);
  color: var(--text-muted);
  background: var(--bg-base);
  letter-spacing: 0.5px;
}
.source-tag.host {
  color: var(--accent-green);
  border-color: color-mix(in srgb, var(--accent-green) 45%, var(--border));
  background: color-mix(in srgb, var(--accent-green) 10%, transparent);
}
.source-tag.container {
  color: var(--text-secondary);
}

.empty-muted {
  padding: 18px 0;
  text-align: center;
  font-size: 12px;
  color: var(--text-muted);
}

.guard-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
}
.guard-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-base);
}
.guard-label { font-size: 13px; color: var(--text-secondary); }
.guard-value {
  font-family: var(--font-mono);
  font-size: 18px;
  font-weight: 700;
  color: var(--text-primary);
}

.section-divider {
  display: flex;
  align-items: baseline;
  gap: 12px;
  margin: 24px 0 12px;
  padding-top: 12px;
  border-top: 1px dashed var(--border);
}
.section-divider > span:first-child {
  font-size: 15px;
  font-weight: 700;
  color: var(--admin-accent, var(--text-primary));
}
.divider-sub {
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-muted);
}

.resource-row {
  display: grid;
  grid-template-columns: 1.2fr 1fr 1.4fr;
  gap: 14px;
  margin-bottom: 14px;
}

.disk-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-top: 4px;
}
.disk-head {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
  margin-bottom: 4px;
}
.disk-mount {
  color: var(--text-primary);
  font-size: 12px;
}
.disk-used {
  font-family: var(--font-mono);
  color: var(--text-muted);
}

.ct-name {
  font-size: 12px;
  color: var(--text-primary);
  word-break: break-all;
}
.ct-metric { display: flex; flex-direction: column; gap: 4px; }
.ct-val {
  font-size: 12px;
  font-family: var(--font-mono);
  color: var(--text-secondary);
}

@media (max-width: 1280px) {
  .chart-row { grid-template-columns: 1fr 1fr; }
  .resource-row { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 768px) {
  .chart-row,
  .resource-row { grid-template-columns: 1fr; }
  .stat-grid { grid-template-columns: repeat(2, 1fr); }
}
</style>
