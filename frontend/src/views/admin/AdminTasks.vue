<template>
  <div class="admin-tasks">
    <div class="section-header">
      <div>
        <h2 class="section-title">任务管理</h2>
        <p class="section-sub">所有用户的任务 · 强制终止 · 批量操作</p>
      </div>
      <div class="header-actions">
        <el-input v-model="keyword" placeholder="搜索目标 / ID / 创建者" clearable style="width: 220px" :prefix-icon="Search" size="small" />
        <el-select v-model="statusFilter" placeholder="状态" clearable size="small" style="width: 120px">
          <el-option label="运行中" value="running" />
          <el-option label="待处理" value="pending" />
          <el-option label="已完成" value="completed" />
          <el-option label="失败" value="failed" />
          <el-option label="已取消" value="cancelled" />
        </el-select>
        <el-select v-model="ownerFilter" placeholder="创建者" clearable size="small" style="width: 180px" filterable>
          <el-option v-for="u in userOptions" :key="u.id" :label="u.label" :value="u.id" />
        </el-select>
        <el-button :loading="loading" :icon="Refresh" size="small" @click="refresh">刷新</el-button>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat-card"><span class="stat-value">{{ stats.total }}</span><span class="stat-desc">全部</span></div>
      <div class="stat-card running"><span class="stat-value">{{ stats.running }}</span><span class="stat-desc">运行中</span></div>
      <div class="stat-card completed"><span class="stat-value">{{ stats.completed }}</span><span class="stat-desc">已完成</span></div>
      <div class="stat-card failed"><span class="stat-value">{{ stats.failed }}</span><span class="stat-desc">失败</span></div>
      <div class="stat-card cancelled"><span class="stat-value">{{ stats.cancelled }}</span><span class="stat-desc">已取消</span></div>
    </div>

    <el-card class="table-card" shadow="never">
      <div v-if="selectedRows.length" class="batch-bar">
        <span>已选 {{ selectedRows.length }} 项</span>
        <el-button size="small" type="danger" plain @click="batchDelete">批量删除</el-button>
        <el-button size="small" type="warning" plain @click="batchCancel" v-if="selectedRows.some(r => r.status === 'running')">批量终止</el-button>
      </div>

      <SkeletonBlock v-if="loading && !tasks.length" :rows="8" />

      <el-table
        v-else
        :data="pagedTasks"
        @selection-change="(v) => selectedRows = v"
        empty-text="当前筛选条件下没有任务"
        stripe
      >
        <el-table-column type="selection" width="44" />
        <el-table-column label="目标" min-width="200">
          <template #default="{ row }">
            <code class="target">{{ row.target }}</code>
          </template>
        </el-table-column>
        <el-table-column label="创建者" width="150">
          <template #default="{ row }">
            <el-tag size="small" effect="plain">
              {{ ownerName(row.owner_id) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <StatusBadge :status="row.status" />
          </template>
        </el-table-column>
        <el-table-column label="阶段" width="150">
          <template #default="{ row }">
            <PhaseBadge :phase="row.current_phase" />
          </template>
        </el-table-column>
        <el-table-column label="漏洞" width="70" align="center">
          <template #default="{ row }"><span class="mono">{{ row.findings_count || 0 }}</span></template>
        </el-table-column>
        <el-table-column label="Shell" width="70" align="center">
          <template #default="{ row }">
            <el-icon v-if="row.got_shell" class="shell yes"><CircleCheckFilled /></el-icon>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" width="160">
          <template #default="{ row }">
            <span class="mono small">{{ formatTime(row.created_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="240" align="center" fixed="right">
          <template #default="{ row }">
            <div class="actions">
              <el-button size="small" type="primary" @click="goDetail(row.task_id)">详情</el-button>
              <el-button
                v-if="row.status === 'running' || row.status === 'pending'"
                size="small" type="warning" plain
                @click="forceCancel(row)"
              >强制终止</el-button>
              <el-popconfirm :title="`确认删除任务 ${row.task_id.slice(0, 8)}？`" @confirm="handleDelete(row)">
                <template #reference>
                  <el-button size="small" type="danger">删除</el-button>
                </template>
              </el-popconfirm>
            </div>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-wrap" v-if="filteredTasks.length > pageSize">
        <el-pagination
          v-model:current-page="currentPage"
          :page-size="pageSize"
          :total="filteredTasks.length"
          layout="total, prev, pager, next"
          background
          small
        />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search, Refresh, CircleCheckFilled } from '@element-plus/icons-vue'
import { api } from '@/api'
import StatusBadge from '@/components/StatusBadge.vue'
import PhaseBadge from '@/components/PhaseBadge.vue'
import SkeletonBlock from '@/components/SkeletonBlock.vue'

const router = useRouter()

const loading = ref(false)
const tasks = ref([])
const users = ref([])
const keyword = ref('')
const statusFilter = ref('')
const ownerFilter = ref('')
const selectedRows = ref([])
const currentPage = ref(1)
const pageSize = 20

const userOptions = computed(() =>
  users.value.map(u => ({ id: u.id, label: `${u.nickname || u.username} (${u.username})` })),
)

function ownerName(ownerId) {
  if (!ownerId) return '—'
  const u = users.value.find(x => x.id === ownerId)
  if (!u) return ownerId.slice(0, 8)
  return u.nickname || u.username
}

const filteredTasks = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return tasks.value.filter(t => {
    if (statusFilter.value && t.status !== statusFilter.value) return false
    if (ownerFilter.value && t.owner_id !== ownerFilter.value) return false
    if (kw) {
      const haystack = [
        t.target, t.task_id, ownerName(t.owner_id),
      ].join(' ').toLowerCase()
      if (!haystack.includes(kw)) return false
    }
    return true
  })
})

const pagedTasks = computed(() => {
  const start = (currentPage.value - 1) * pageSize
  return filteredTasks.value.slice(start, start + pageSize)
})

const stats = computed(() => {
  const s = { total: tasks.value.length, running: 0, completed: 0, failed: 0, cancelled: 0 }
  for (const t of tasks.value) {
    if (t.status in s) s[t.status]++
  }
  return s
})

async function loadTasks() {
  loading.value = true
  try {
    const [taskList, usersRes] = await Promise.all([
      api.adminListTasks(),
      api.adminListUsers().catch(() => ({ users: [] })),
    ])
    tasks.value = Array.isArray(taskList) ? taskList : []
    users.value = usersRes?.users || []
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '加载任务失败')
  } finally {
    loading.value = false
  }
}

async function refresh() {
  await loadTasks()
}

function goDetail(id) {
  router.push(`/admin/tasks/${id}`)
}

async function forceCancel(row) {
  try {
    await ElMessageBox.confirm(
      `确认强制终止任务 ${row.task_id.slice(0, 8)} (${row.target})？`,
      '强制终止', { type: 'warning', confirmButtonText: '终止' },
    )
  } catch { return }
  try {
    await api.cancelTask(row.task_id)
    ElMessage.success('已请求终止')
    await loadTasks()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '终止失败')
  }
}

async function handleDelete(row) {
  try {
    await api.deleteTask(row.task_id)
    ElMessage.success('已删除')
    await loadTasks()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '删除失败')
  }
}

async function batchDelete() {
  try {
    await ElMessageBox.confirm(
      `确认删除选中的 ${selectedRows.value.length} 个任务？`,
      '批量删除', { type: 'warning' },
    )
  } catch { return }
  let ok = 0, fail = 0
  for (const row of selectedRows.value) {
    try {
      await api.deleteTask(row.task_id); ok++
    } catch { fail++ }
  }
  ElMessage.success(`已删除 ${ok} 个，失败 ${fail} 个`)
  selectedRows.value = []
  await loadTasks()
}

async function batchCancel() {
  const targets = selectedRows.value.filter(r => r.status === 'running')
  if (!targets.length) return
  try {
    await ElMessageBox.confirm(
      `确认批量终止 ${targets.length} 个运行中任务？`,
      '批量终止', { type: 'warning' },
    )
  } catch { return }
  let ok = 0
  for (const row of targets) {
    try { await api.cancelTask(row.task_id); ok++ } catch { /* ignore */ }
  }
  ElMessage.success(`已请求终止 ${ok} 个`)
  await loadTasks()
}

function formatTime(raw) {
  if (!raw) return '—'
  const t = new Date(raw)
  if (Number.isNaN(t.getTime())) return String(raw)
  return t.toLocaleString()
}

let timer = null
onMounted(() => {
  loadTasks()
  timer = setInterval(loadTasks, 15000)
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.section-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 18px;
  gap: 12px;
  flex-wrap: wrap;
}
.section-title {
  font-size: 20px; font-weight: 700; color: var(--text-primary); margin: 0 0 4px;
}
.section-sub { font-size: 13px; color: var(--text-secondary); margin: 0; }
.header-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }

.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.stat-card {
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--bg-surface);
  display: flex; flex-direction: column; gap: 2px;
}
.stat-value {
  font-family: var(--font-mono); font-size: 22px; font-weight: 700;
  color: var(--text-primary); line-height: 1.1;
}
.stat-desc { font-size: 12px; color: var(--text-muted); }
.stat-card.running .stat-value { color: var(--accent-blue); }
.stat-card.completed .stat-value { color: var(--accent-green); }
.stat-card.failed .stat-value { color: var(--accent-red); }
.stat-card.cancelled .stat-value { color: var(--text-muted); }

.table-card { border-radius: var(--radius-lg) !important; border: 1px solid var(--border) !important; }

.batch-bar {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 12px; margin-bottom: 10px;
  background: color-mix(in srgb, var(--accent-blue) 6%, transparent);
  border: 1px dashed color-mix(in srgb, var(--accent-blue) 40%, var(--border));
  border-radius: var(--radius-md);
  font-size: 13px;
}

.target { font-size: 12px; color: var(--text-primary); }
.mono { font-family: var(--font-mono); }
.mono.small { font-size: 11px; color: var(--text-muted); }
.shell.yes { color: var(--accent-green); font-size: 16px; }
.text-muted { color: var(--text-muted); }

.actions { display: flex; gap: 4px; justify-content: center; flex-wrap: wrap; }

.pagination-wrap { display: flex; justify-content: flex-end; margin-top: 14px; }
</style>
