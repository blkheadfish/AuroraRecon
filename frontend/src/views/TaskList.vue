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
      <div class="stat-item" @click="filterPhase = filterPhase === 'awaiting_approval' ? '' : 'awaiting_approval'">
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
        :data="pagedTasks"
        v-loading="listStore.loading"
        @selection-change="onSelectionChange"
        @row-click="(row) => goDetail(row.task_id)"
      >
        <el-table-column type="selection" width="44" />
        <el-table-column label="目标" min-width="220">
          <template #default="{ row }">
            <code class="target">{{ row.target }}</code>
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
        <el-table-column label="漏洞" width="90" align="center">
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
        <el-table-column label="操作" width="280" align="center">
          <template #default="{ row }">
            <div class="actions" @click.stop>
              <el-button class="action-detail" size="small" type="primary" @click="goDetail(row.task_id)">详情</el-button>
              <el-button
                v-if="row.report_path"
                class="action-report"
                size="small"
                text
                type="success"
                @click="goReport(row.task_id)"
              >报告</el-button>
              <el-button
                v-if="row.status === 'running' || row.status === 'pending'"
                size="small"
                type="warning"
                plain
                @click="handleCancel(row)"
              >取消</el-button>
              <el-popconfirm title="确认删除该任务？" @confirm="handleDelete(row)">
                <template #reference>
                  <el-button class="action-delete" size="small" type="danger">删除</el-button>
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

    <el-dialog v-model="showCreate" title="创建渗透测试任务" width="700px" :close-on-click-modal="false">
      <el-form :model="form" :rules="rules" ref="formRef" label-position="top">
        <el-form-item label="目标地址" prop="target">
          <el-input v-model="form.target" placeholder="IP / 域名 / IP:端口 / URL" clearable />
          <div class="form-tip">仅在合法授权范围内使用。</div>
        </el-form-item>
        <el-form-item label="工作流模式（workflow_mode）">
          <el-radio-group v-model="form.workflowMode" @change="onWorkflowModeChange">
            <el-radio-button label="pentest_engineer">渗透工程师</el-radio-button>
            <el-radio-button label="ctf_expert">CTF 选手</el-radio-button>
          </el-radio-group>
          <div class="form-tip">
            决定审批策略 / 证据门槛 / 轮次上限等默认值。下方选项可单项覆盖,只对本任务生效。
          </div>
        </el-form-item>
        <el-form-item label="审批模式">
          <el-radio-group v-model="form.autoApprove">
            <el-radio-button :label="false">手动审批</el-radio-button>
            <el-radio-button :label="true">全自动（跳过人工审批）</el-radio-button>
          </el-radio-group>
          <div class="form-tip">
            渗透工程师默认手动、CTF 选手默认全自动;此处显式选择会覆盖 mode 默认值。
          </div>
        </el-form-item>
        <el-collapse>
          <el-collapse-item title="高级参数（覆盖 workflow_mode 默认值）" name="advanced">
            <el-form-item label="证据门槛 success_gate_level">
              <el-radio-group v-model="form.successGateLevel">
                <el-radio-button label="">沿用默认</el-radio-button>
                <el-radio-button label="strict">严格</el-radio-button>
                <el-radio-button label="medium">中等</el-radio-button>
                <el-radio-button label="lenient">宽松</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="风险预算 risk_budget">
              <el-input-number v-model="form.riskBudget" :min="0" :max="50" controls-position="right" />
            </el-form-item>
            <el-form-item label="ReAct 最大轮次 max_react_rounds">
              <el-input-number v-model="form.maxReactRounds" :min="1" :max="200" controls-position="right" />
            </el-form-item>
            <el-form-item label="探索最大轮次 max_explore_rounds">
              <el-input-number v-model="form.maxExploreRounds" :min="1" :max="200" controls-position="right" />
            </el-form-item>
          </el-collapse-item>
        </el-collapse>
        <el-form-item label="授权说明">
          <el-input v-model="form.scopeNote" type="textarea" :rows="3" />
        </el-form-item>
        <el-form-item label="附加提示（Extra Hint）">
          <el-input
            v-model="form.extraHint"
            type="textarea"
            :rows="2"
            placeholder="例如：优先验证 Web RCE，避免长时间暴力破解"
          />
        </el-form-item>
        <el-form-item label="用户 Prompt 偏好（User Prompt）">
          <el-input
            v-model="form.userPrompt"
            type="textarea"
            :rows="4"
            placeholder="告诉系统你的偏好策略，例如先验证 PoC 再尝试利用、优先低噪声命令等"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreate = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="handleCreate">创建并开始</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import { useTaskListStore } from '@/stores/taskList'
import { trackEvent } from '@/metrics/tracker'
import StatusBadge from '@/components/StatusBadge.vue'
import PhaseBadge from '@/components/PhaseBadge.vue'

const router = useRouter()
const listStore = useTaskListStore()

const showCreate = ref(false)
const creating = ref(false)
const formRef = ref()
const selectedRows = ref([])

// workflow_mode 默认值矩阵,必须与后端 models._MODE_DEFAULTS 保持一致
const MODE_DEFAULTS = {
  pentest_engineer: { autoApprove: false },
  ctf_expert:       { autoApprove: true },
}

const form = ref({
  target: '',
  scopeNote: 'CTF/授权靶场测试',
  extraHint: '',
  userPrompt: '',
  workflowMode: 'pentest_engineer',
  autoApprove: MODE_DEFAULTS.pentest_engineer.autoApprove,
  successGateLevel: '',
  riskBudget: null,
  maxReactRounds: null,
  maxExploreRounds: null,
})

function onWorkflowModeChange(mode) {
  const defaults = MODE_DEFAULTS[mode] || MODE_DEFAULTS.pentest_engineer
  form.value.autoApprove = defaults.autoApprove
}

function isValidIPv4(host) {
  const parts = host.split('.')
  if (parts.length !== 4) return false
  return parts.every((item) => {
    if (!/^\d{1,3}$/.test(item)) return false
    const n = Number(item)
    return n >= 0 && n <= 255
  })
}

function parseHostPort(raw) {
  const match = raw.match(/:(\d{1,5})$/)
  if (!match) return { host: raw, port: '' }
  return {
    host: raw.slice(0, -match[0].length),
    port: match[1],
  }
}

function isValidHost(host) {
  if (!host) return false
  if (host === 'localhost') return true
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return isValidIPv4(host)
  const label = '[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?'
  const hostnamePattern = new RegExp(`^${label}(\\.${label})*$`)
  return hostnamePattern.test(host)
}

function isValidTarget(value) {
  const raw = String(value || '').trim()
  if (!raw) return false
  try {
    const u = new URL(raw)
    if (!['http:', 'https:'].includes(u.protocol)) return false
    if (!isValidHost(u.hostname)) return false
    if (u.port) {
      const p = Number(u.port)
      if (!Number.isFinite(p) || p < 1 || p > 65535) return false
    }
    return true
  } catch {
    // fall through to host / host:port validation
  }

  const { host, port } = parseHostPort(raw)
  if (!isValidHost(host) || host.includes(':')) return false
  if (port) {
    const p = Number(port)
    if (!Number.isFinite(p) || p < 1 || p > 65535) return false
  }
  return true
}

function validateTarget(_rule, value, callback) {
  if (!isValidTarget(value)) {
    callback(new Error('请输入有效目标：IP / 域名 / IP:端口 / URL'))
    return
  }
  callback()
}

const rules = {
  target: [{ validator: validateTarget, trigger: 'blur' }],
}

const filterStatus = ref('')
const filterPhase = ref('')
const onlyShell = ref(false)
const searchKeyword = ref('')
const currentPage = ref(1)
const pageSize = 20

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
  const start = (currentPage.value - 1) * pageSize
  return filteredTasks.value.slice(start, start + pageSize)
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

async function handleCreate() {
  await formRef.value.validate()
  creating.value = true
  try {
    const task = await listStore.createTask({
      target:           form.value.target,
      scopeNote:        form.value.scopeNote,
      extraHint:        form.value.extraHint,
      userPrompt:       form.value.userPrompt,
      workflowMode:     form.value.workflowMode,
      autoApprove:      form.value.autoApprove,
      successGateLevel: form.value.successGateLevel || null,
      riskBudget:       form.value.riskBudget,
      maxReactRounds:   form.value.maxReactRounds,
      maxExploreRounds: form.value.maxExploreRounds,
    })
    trackEvent('task.create', {
      target: form.value.target,
      workflowMode: form.value.workflowMode,
      autoApprove: form.value.autoApprove,
      taskId: task.task_id,
    })
    ElMessage.success(`任务已创建：${task.target}`)
    showCreate.value = false
    form.value = {
      target: '',
      scopeNote: 'CTF/授权靶场测试',
      extraHint: '',
      userPrompt: '',
      workflowMode: 'pentest_engineer',
      autoApprove: MODE_DEFAULTS.pentest_engineer.autoApprove,
      successGateLevel: '',
      riskBudget: null,
      maxReactRounds: null,
      maxExploreRounds: null,
    }
    router.push(`/tasks/${task.task_id}`)
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '创建失败')
  } finally {
    creating.value = false
  }
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

function handleDelete(row) {
  listStore.removeTask(row.task_id)
  trackEvent('task.delete', { taskId: row.task_id })
  ElMessage.success('任务已删除')
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
  selectedRows.value.forEach((item) => listStore.removeTask(item.task_id))
  trackEvent('task.batch_delete', { count })
  ElMessage.success(`已删除 ${count} 个任务`)
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
.actions { display: flex; justify-content: center; align-items: center; flex-wrap: wrap; gap: 8px; }
:deep(.action-detail.el-button) {
  font-weight: 600;
  color: #f0f7ff !important;
  box-shadow: 0 2px 10px color-mix(in srgb, var(--accent-blue) 28%, transparent);
}
:deep(.action-delete.el-button--danger) {
  font-weight: 600;
  color: #fff5f5 !important;
  border-color: color-mix(in srgb, var(--accent-red) 72%, #8b2d2d) !important;
  background: linear-gradient(
    155deg,
    color-mix(in srgb, var(--accent-red) 58%, #3a1218),
    color-mix(in srgb, var(--accent-red) 42%, #240c10)
  ) !important;
  box-shadow:
    0 3px 12px color-mix(in srgb, var(--accent-red) 35%, transparent),
    inset 0 0 0 1px color-mix(in srgb, #ffffff 12%, transparent);
}
:deep(.action-delete.el-button--danger:hover),
:deep(.action-delete.el-button--danger:focus-visible) {
  color: #ffffff !important;
  border-color: color-mix(in srgb, var(--accent-red) 85%, #c44) !important;
  background: linear-gradient(
    155deg,
    color-mix(in srgb, var(--accent-red) 68%, #4a1820),
    color-mix(in srgb, var(--accent-red) 50%, #2a0c12)
  ) !important;
}
.form-tip { margin-top: 4px; color: var(--text-muted); font-size: 12px; }
.pagination-wrap { display: flex; justify-content: flex-end; padding: 12px 0 4px; }
</style>
