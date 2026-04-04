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

    <el-card class="panel">
      <template #header>
        <div class="card-header">
          <span>系统概览</span>
          <span class="meta">更新时间 {{ formatTime(metrics.generated_at) }}</span>
        </div>
      </template>
      <div class="system-grid">
        <div class="metric-item">
          <div class="label">API 状态</div>
          <el-tag :type="statusTagType(system.api_status)">{{ system.api_status }}</el-tag>
        </div>
        <div class="metric-item">
          <div class="label">数据库</div>
          <el-tag :type="statusTagType(system.database)">{{ system.database }}</el-tag>
        </div>
        <div class="metric-item">
          <div class="label">Redis</div>
          <el-tag :type="statusTagType(system.redis)">{{ system.redis }}</el-tag>
        </div>
        <div class="metric-item">
          <div class="label">MSF</div>
          <el-tag :type="statusTagType(system.msf)">{{ system.msf }}</el-tag>
        </div>
        <div class="metric-item">
          <div class="label">版本</div>
          <div class="value mono">{{ system.version || '-' }}</div>
        </div>
        <div class="metric-item">
          <div class="label">任务总数</div>
          <div class="value mono">{{ system.total_tasks || 0 }}</div>
        </div>
        <div class="metric-item">
          <div class="label">运行中任务</div>
          <div class="value mono running">{{ system.running_tasks || 0 }}</div>
        </div>
        <div class="metric-item">
          <div class="label">已完成任务</div>
          <div class="value mono success">{{ system.completed_tasks || 0 }}</div>
        </div>
        <div class="metric-item">
          <div class="label">失败任务</div>
          <div class="value mono danger">{{ system.failed_tasks || 0 }}</div>
        </div>
        <div class="metric-item">
          <div class="label">活动任务ID</div>
          <div class="value mono">{{ system.active_task_ids || 0 }}</div>
        </div>
      </div>
    </el-card>

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
        <el-table :data="categoryRows" size="small" class="table">
          <el-table-column prop="name" label="分类" min-width="160" />
          <el-table-column prop="count" label="数量" width="90" />
        </el-table>
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
          <span class="label">按执行后端：</span>
          <el-tag v-for="item in backendRows" :key="item.name" size="small" class="backend-tag">
            {{ item.name }}: {{ item.count }}
          </el-tag>
          <span v-if="!backendRows.length" class="empty-tip">暂无数据</span>
        </div>

        <el-table :data="invocation.top_tools || []" size="small" class="table">
          <el-table-column prop="tool" label="工具" min-width="140" />
          <el-table-column prop="calls" label="调用次数" width="90" />
          <el-table-column prop="success_rate" label="成功率" width="90">
            <template #default="{ row }">{{ row.success_rate }}%</template>
          </el-table-column>
          <el-table-column prop="avg_elapsed_ms" label="平均耗时" width="120">
            <template #default="{ row }">{{ formatMs(row.avg_elapsed_ms) }}</template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { trackEvent } from '@/metrics/tracker'

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
  Object.entries(invocation.value.by_backend || {}).map(([name, count]) => ({ name, count })),
)

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
  if (metricsEndpointMissing.value && trigger === 'auto') {
    return
  }
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

.system-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
}
.metric-item {
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-base);
  padding: 10px 12px;
}
.label { color: var(--text-secondary); font-size: 12px; }
.value { margin-top: 4px; color: var(--text-primary); font-weight: 700; font-size: 20px; }
.mono { font-family: var(--font-mono); }
.running { color: var(--accent-blue); }
.success { color: var(--accent-green); }
.danger { color: var(--accent-red); }

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

.backend-row {
  display: flex;
  gap: 6px;
  align-items: center;
  margin-bottom: 8px;
  flex-wrap: wrap;
}
.backend-tag { margin-right: 4px; }
.empty-tip { color: var(--text-muted); font-size: 12px; }
</style>
