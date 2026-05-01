<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">渗透任务中心</h1>
        <p class="page-sub">创建任务、管理队列、跟踪审批与利用状态</p>
      </div>
      <el-button type="primary" size="large" @click="goCreate">
        <el-icon><Plus /></el-icon>
        新建任务
      </el-button>
    </div>

    <div class="stats-bar">
      <div class="stat-item" :class="{ active: !filterStatus }" @click="filterStatus = ''">
        <span class="stat-num">{{ listStore.stats.total }}</span>
        <span class="stat-label">全部任务</span>
      </div>
      <div class="stat-item" :class="{ active: filterStatus === 'running' }" @click="filterStatus = filterStatus === 'running' ? '' : 'running'">
        <span class="stat-num running">{{ listStore.stats.running }}</span>
        <span class="stat-label">运行中</span>
      </div>
      <div class="stat-item" :class="{ active: filterStatus === 'completed' }" @click="filterStatus = filterStatus === 'completed' ? '' : 'completed'">
        <span class="stat-num completed">{{ listStore.stats.completed }}</span>
        <span class="stat-label">已完成</span>
      </div>
      <div class="stat-item" :class="{ active: filterStatus === 'failed' }" @click="filterStatus = filterStatus === 'failed' ? '' : 'failed'">
        <span class="stat-num failed">{{ listStore.stats.failed }}</span>
        <span class="stat-label">失败</span>
      </div>
      <div class="stat-item" :class="{ active: filterStatus === 'cancelled' }" @click="filterStatus = filterStatus === 'cancelled' ? '' : 'cancelled'">
        <span class="stat-num cancelled">{{ listStore.stats.cancelled }}</span>
        <span class="stat-label">已取消</span>
      </div>
      <div class="stat-item" :class="{ active: filterPhase === 'awaiting_approval' }" @click="toggleApproval">
        <span class="stat-num warn">{{ awaitingApprovalCount }}</span>
        <span class="stat-label">待审批</span>
      </div>
    </div>

    <el-card class="table-card">
      <div class="toolbar">
        <el-input
          v-model="searchKeyword"
          placeholder="搜索目标 IP / 域名"
          clearable
          style="width: 200px"
          :prefix-icon="Search"
        />
        <el-select v-model="filterStatus" placeholder="状态筛选" clearable style="width: 140px">
          <el-option label="运行中" value="running" />
          <el-option label="已完成" value="completed" />
          <el-option label="失败" value="failed" />
          <el-option label="已取消" value="cancelled" />
          <el-option label="待处理" value="pending" />
        </el-select>
        <el-select v-model="filterPhase" placeholder="阶段筛选" clearable style="width: 160px">
          <el-option label="侦察" value="recon" />
          <el-option label="漏洞扫描" value="vuln_scan" />
          <el-option label="利用决策" value="exploit_decision" />
          <el-option label="等待审批" value="awaiting_approval" />
          <el-option label="漏洞利用" value="exploit" />
          <el-option label="后渗透" value="post_exploit" />
          <el-option label="报告生成" value="report" />
        </el-select>
        <el-switch
          v-model="onlyShell"
          active-text="仅看 Shell"
          inactive-text="全部"
        />
        <el-button link @click="clearFilters">清除筛选</el-button>
      </div>

      <div class="batch-actions" v-if="selectedRows.length">
        <span>已选 {{ selectedRows.length }} 项</span>
        <el-button size="small" @click="openBatchReport">批量查看报告</el-button>
        <el-button size="small" type="danger" plain @click="batchDelete">批量删除</el-button>
      </div>

      <el-empty v-if="!listStore.loading && !filteredTasks.length" description="暂无匹配任务">
        <el-button type="primary" @click="goCreate">
          <el-icon><Plus /></el-icon> 创建第一个任务
        </el-button>
      </el-empty>

      <el-table
        v-else
        :data="sortedPagedTasks"
        v-loading="listStore.loading"
        @selection-change="onSelectionChange"
        @row-click="(row) => goDetail(row.task_id)"
        @sort-change="onSortChange"
      >
        <el-table-column type="selection" width="44" />
        <el-table-column label="目标" min-width="200" sortable="custom" prop="target">
          <template #default="{ row }">
            <code class="target">{{ row.target }}</code>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" width="100" sortable="custom" prop="created_at">
          <template #default="{ row }">
            <span class="text-muted" style="font-size:11px">{{ relativeTime(row.created_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="120">
          <template #default="{ row }">
            <StatusBadge :status="row.status" />
          </template>
        </el-table-column>
        <el-table-column label="阶段" width="140">
          <template #default="{ row }">
            <PhaseBadge :phase="row.current_phase" />
          </template>
        </el-table-column>
        <el-table-column label="漏洞" width="90" align="center" sortable prop="findings_count">
          <template #default="{ row }">
            <span class="mono">{{ row.findings_count || 0 }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Shell" width="80" align="center">
          <template #default="{ row }">
            <el-icon v-if="row.got_shell" class="shell yes"><CircleCheckFilled /></el-icon>
            <el-icon v-else class="shell no"><Remove /></el-icon>
          </template>
        </el-table-column>
        <el-table-column label="报告" width="90" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.report_path" type="success" size="small">已生成</el-tag>
            <span v-else class="text-muted">-</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="130" align="center" fixed="right">
          <template #default="{ row }">
            <div class="actions" @click.stop>
              <el-button size="small" type="primary" @click="goDetail(row.task_id)">详情</el-button>
              <el-dropdown trigger="click" @command="(cmd) => handleRowCommand(cmd, row)">
                <el-button size="small" circle class="action-more">
                  <el-icon><MoreFilled /></el-icon>
                </el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item v-if="row.report_path" command="report">
                      <el-icon><Document /></el-icon> 查看报告
                    </el-dropdown-item>
                    <el-dropdown-item command="copy">
                      <el-icon><CopyDocument /></el-icon> 复制目标
                    </el-dropdown-item>
                    <el-dropdown-item v-if="row.status === 'running' || row.status === 'pending'" command="cancel" divided>
                      <el-icon><VideoPause /></el-icon> 取消任务
                    </el-dropdown-item>
                    <el-dropdown-item command="delete" divided>
                      <el-icon><Delete /></el-icon>
                      <span style="color:var(--accent-red)">删除任务</span>
                    </el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </div>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-wrap" v-if="filteredTasks.length > 10">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="filteredTasks.length"
          layout="total, sizes, prev, pager, next, jumper"
          background
          small
        />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Search, MoreFilled, Document, CopyDocument, VideoPause, Delete,
} from '@element-plus/icons-vue'
import { useTaskListStore } from '@/stores/taskList'
import { trackEvent } from '@/metrics/tracker'
import StatusBadge from '@/components/StatusBadge.vue'
import PhaseBadge from '@/components/PhaseBadge.vue'

const router = useRouter()
const listStore = useTaskListStore()

const selectedRows = ref([])

const filterStatus = ref('')
const filterPhase = ref('')
const onlyShell = ref(false)
const searchKeyword = ref('')
const currentPage = ref(1)
const pageSize = ref(20)
const sortProp = ref('')
const sortOrder = ref('')

// ── 筛选持久化 ──
const FILTER_KEY = 'taskList_filters'
function saveFilters() {
  try { sessionStorage.setItem(FILTER_KEY, JSON.stringify({
    filterStatus: filterStatus.value, filterPhase: filterPhase.value,
    onlyShell: onlyShell.value, searchKeyword: searchKeyword.value,
    pageSize: pageSize.value,
  })) } catch { /* ignore */ }
}
function restoreFilters() {
  try {
    const raw = sessionStorage.getItem(FILTER_KEY)
    if (!raw) return
    const saved = JSON.parse(raw)
    if (saved.filterStatus) filterStatus.value = saved.filterStatus
    if (saved.filterPhase) filterPhase.value = saved.filterPhase
    if (saved.onlyShell) onlyShell.value = saved.onlyShell
    if (saved.searchKeyword) searchKeyword.value = saved.searchKeyword
    if (saved.pageSize) pageSize.value = saved.pageSize
  } catch { /* ignore */ }
}
watch([filterStatus, filterPhase, onlyShell, searchKeyword, pageSize], saveFilters)

const filteredTasks = computed(() => {
  const keyword = searchKeyword.value.trim().toLowerCase()
  return listStore.tasks.filter((task) => {
    if (keyword && !task.target?.toLowerCase().includes(keyword)) return false
    if (filterStatus.value && task.status !== filterStatus.value) return false
    if (filterPhase.value && task.current_phase !== filterPhase.value) return false
    if (onlyShell.value && !task.got_shell) return false
    return true
  })
})

const pagedTasks = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredTasks.value.slice(start, start + pageSize.value)
})

const sortedPagedTasks = computed(() => {
  if (!sortProp.value) return pagedTasks.value
  const arr = [...pagedTasks.value]
  const key = sortProp.value
  const asc = sortOrder.value === 'ascending'
  arr.sort((a, b) => {
    const va = a[key] ?? ''
    const vb = b[key] ?? ''
    if (typeof va === 'number' && typeof vb === 'number') return asc ? va - vb : vb - va
    return asc ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va))
  })
  return arr
})

watch([filterStatus, filterPhase, onlyShell, searchKeyword], () => {
  currentPage.value = 1
})

const awaitingApprovalCount = computed(() =>
  listStore.tasks.filter((task) => task.current_phase === 'awaiting_approval').length,
)

function clearFilters() {
  filterStatus.value = ''
  filterPhase.value = ''
  onlyShell.value = false
  searchKeyword.value = ''
  currentPage.value = 1
}

function onSelectionChange(rows) {
  selectedRows.value = rows
}

function goDetail(taskId) {
  router.push(`/tasks/${taskId}`)
}

function goReport(taskId) {
  router.push(`/reports/${taskId}`)
}

function goCreate() {
  router.push('/tasks/new')
}

// ── 统计栏快捷筛选 ──
function toggleApproval() {
  if (filterPhase.value === 'awaiting_approval') {
    filterPhase.value = ''
    filterStatus.value = ''
  } else {
    filterPhase.value = 'awaiting_approval'
    filterStatus.value = 'running'
  }
}

// ── 相对时间 ──
function relativeTime(dateStr) {
  if (!dateStr) return '-'
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return '刚刚'
  if (mins < 60) return `${mins}分钟前`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}小时前`
  const days = Math.floor(hours / 24)
  return `${days}天前`
}

// ── 排序 ──
function onSortChange({ prop, order }) {
  sortProp.value = prop || ''
  sortOrder.value = order || ''
}

// ── 行操作（下拉菜单） ──
function handleRowCommand(cmd, row) {
  if (cmd === 'report') goReport(row.task_id)
  else if (cmd === 'copy') {
    navigator.clipboard.writeText(row.target || '').then(() => ElMessage.success('已复制'))
  } else if (cmd === 'cancel') handleCancel(row)
  else if (cmd === 'delete') handleDelete(row)
}

async function handleCancel(row) {
  try {
    await ElMessageBox.confirm(
      `确定取消任务 ${row.target}？运行中的进程将被终止。`,
      '取消任务',
      { type: 'warning', confirmButtonText: '确认取消' },
    )
  } catch { return }
  try {
    await listStore.cancelTask(row.task_id)
    trackEvent('task.cancel', { taskId: row.task_id })
    ElMessage.success('任务已取消')
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '取消失败')
  }
}

async function handleDelete(row) {
  try {
    await ElMessageBox.confirm(
      `确认删除任务 ${row.target}？此操作不可撤销。`,
      '删除任务',
      { type: 'warning', confirmButtonText: '确认删除' },
    )
  } catch { return }
  try {
    await listStore.deleteTask(row.task_id)
    trackEvent('task.delete', { taskId: row.task_id })
    ElMessage.success('任务已删除')
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '删除失败')
  }
}

async function batchDelete() {
  const count = selectedRows.value.length
  try {
    await ElMessageBox.confirm(`确认删除选中的 ${count} 个任务？此操作不可撤销。`, '批量删除', {
      confirmButtonText: '确认删除',
      cancelButtonText: '取消',
      type: 'warning',
    })
  } catch { return }
  const results = await Promise.allSettled(
    selectedRows.value.map((item) => listStore.deleteTask(item.task_id)),
  )
  const failed = results.filter((r) => r.status === 'rejected').length
  trackEvent('task.batch_delete', { count })
  if (failed) {
    ElMessage.warning(`已删除 ${count - failed} 个任务，${failed} 个失败`)
  } else {
    ElMessage.success(`已删除 ${count} 个任务`)
  }
  selectedRows.value = []
}

function openBatchReport() {
  const withReport = selectedRows.value.filter((item) => item.report_path)
  if (!withReport.length) {
    ElMessage.warning('所选任务没有可用报告')
    return
  }
  router.push(`/reports/${withReport[0].task_id}`)
}

onMounted(() => {
  restoreFilters()
  listStore.fetchTasks()
})
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 18px; }
.page-title { font-size: 22px; color: var(--text-primary); font-weight: 700; }
.page-sub { margin-top: 4px; color: var(--text-secondary); font-size: 13px; }

.stats-bar { display: flex; gap: 12px; margin-bottom: 14px; padding: 14px 18px; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--bg-surface); }
.stat-item { display: flex; flex-direction: column; gap: 2px; padding: 6px 14px; border-radius: var(--radius-md); cursor: pointer; transition: background 0.15s; min-width: 70px; }
.stat-item:hover { background: var(--bg-hover); }
.stat-item.active { background: color-mix(in srgb, var(--accent-blue) 10%, transparent); }
.stat-num { font-family: var(--font-mono); font-size: 22px; color: var(--text-primary); font-weight: 700; }
.stat-num.running { color: var(--accent-blue); }
.stat-num.completed { color: var(--accent-green); }
.stat-num.failed { color: var(--accent-red); }
.stat-num.cancelled { color: var(--status-cancelled, #8b8fa3); }
.stat-num.warn { color: var(--accent-yellow); }
.stat-label { font-size: 12px; color: var(--text-muted); }

.table-card { border-radius: var(--radius-lg) !important; }
.toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 10px; }
.batch-actions { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; color: var(--text-secondary); font-size: 12px; }

.target {
  font-family: var(--font-mono);
  font-size: 12px;
  color: color-mix(in srgb, var(--accent-blue) 78%, #b8d4f0);
  font-weight: 500;
}
.mono { font-family: var(--font-mono); }
.shell { font-size: 15px; }
.shell.yes { color: var(--accent-green); }
.shell.no { color: var(--text-muted); }
.text-muted { color: var(--text-muted); }
.actions { display: flex; justify-content: center; align-items: center; gap: 6px; }
.action-more {
  border-color: var(--border) !important;
  background: var(--bg-elevated) !important;
  color: var(--text-secondary) !important;
}
.action-more:hover {
  border-color: var(--accent-blue) !important;
  color: var(--accent-blue) !important;
}
.pagination-wrap { display: flex; justify-content: flex-end; padding: 12px 0 4px; }
</style>
