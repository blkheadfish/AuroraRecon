<template>
  <div class="page-wrap">
    <!-- Page header -->
    <div class="page-header">
      <div>
        <h1 class="page-title">渗透测试任务</h1>
        <p class="page-sub">管理和监控所有渗透测试任务</p>
      </div>
      <el-button type="primary" @click="showCreate = true" size="large">
        <el-icon>
          <Plus/>
        </el-icon>
        新建任务
      </el-button>
    </div>

    <!-- Stats bar -->
    <div class="stats-bar">
      <div class="stat-item">
        <span class="stat-num">{{ tasks.length }}</span>
        <span class="stat-label">全部任务</span>
      </div>
      <div class="stat-item">
        <span class="stat-num running">{{ countByStatus('running') }}</span>
        <span class="stat-label">运行中</span>
      </div>
      <div class="stat-item">
        <span class="stat-num completed">{{ countByStatus('completed') }}</span>
        <span class="stat-label">已完成</span>
      </div>
      <div class="stat-item">
        <span class="stat-num failed">{{ countByStatus('failed') }}</span>
        <span class="stat-label">失败</span>
      </div>
    </div>

    <!-- Task table -->
    <el-card class="table-card" v-loading="loading" element-loading-background="rgba(22,27,34,0.8)">
      <el-empty v-if="!loading && tasks.length === 0" description="暂无任务，点击「新建任务」开始"/>

      <el-table
          v-else
          :data="tasks"
          row-class-name="task-row"
          @row-click="(row) => goDetail(row.task_id)"
          style="cursor: pointer;"
      >
        <el-table-column label="目标" min-width="180">
          <template #default="{ row }">
            <span class="target-text">{{ row.target }}</span>
          </template>
        </el-table-column>

        <el-table-column label="状态" width="120">
          <template #default="{ row }">
            <StatusBadge :status="row.status"/>
          </template>
        </el-table-column>

        <el-table-column label="当前阶段" width="150">
          <template #default="{ row }">
            <PhaseBadge :phase="row.current_phase"/>
          </template>
        </el-table-column>

        <el-table-column label="漏洞发现" width="110" align="center">
          <template #default="{ row }">
            <span class="findings-count" :class="row.findings_count > 0 ? 'has-findings' : ''">
              {{ row.findings_count }}
            </span>
          </template>
        </el-table-column>

        <el-table-column label="Shell" width="90" align="center">
          <template #default="{ row }">
            <el-icon v-if="row.got_shell" class="shell-icon got">
              <CircleCheckFilled/>
            </el-icon>
            <el-icon v-else class="shell-icon none">
              <Remove/>
            </el-icon>
          </template>
        </el-table-column>

        <el-table-column label="报告" width="90" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.report_path" type="success" size="small">已生成</el-tag>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>

        <!-- 操作列：宽度扩大以容纳两个按钮 -->
        <el-table-column label="操作" width="160" align="center">
          <template #default="{ row }">
            <div class="action-cell" @click.stop>
              <el-button
                  link
                  type="primary"
                  size="small"
                  @click="goDetail(row.task_id)"
              >
                详情
              </el-button>

              <!-- 运行中：显示"取消"（发送停止请求，标记为 failed） -->
              <el-popconfirm
                  v-if="row.status === 'running' || row.status === 'pending'"
                  title="确认取消该任务？"
                  confirm-button-text="取消任务"
                  cancel-button-text="保留"
                  confirm-button-type="danger"
                  @confirm="handleCancel(row)"
              >
                <template #reference>
                  <el-button link type="warning" size="small">取消</el-button>
                </template>
              </el-popconfirm>

              <!-- 非运行中：显示"删除"（从列表移除） -->
              <el-popconfirm
                  v-else
                  title="确认删除该任务记录？"
                  confirm-button-text="删除"
                  cancel-button-text="取消"
                  confirm-button-type="danger"
                  @confirm="handleDelete(row)"
              >
                <template #reference>
                  <el-button link type="danger" size="small">删除</el-button>
                </template>
              </el-popconfirm>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Create task dialog -->
    <el-dialog v-model="showCreate" title="新建渗透测试任务" width="500px" :close-on-click-modal="false">
      <el-form :model="form" label-position="top" :rules="rules" ref="formRef">
        <el-form-item label="目标地址" prop="target">
          <el-input
              v-model="form.target"
              placeholder="IP地址 / 域名 / URL，例：192.168.1.100"
              :prefix-icon="Aim"
              clearable
          />
          <div class="form-tip">支持 IP、域名、含端口的 URL，请确保已获得授权</div>
        </el-form-item>

        <el-form-item label="授权说明 / 测试备注" prop="scopeNote">
          <el-input
              v-model="form.scopeNote"
              type="textarea"
              :rows="3"
              placeholder="例：CTF 靶场测试 / 已获授权的内网渗透测试"
          />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="showCreate = false">取消</el-button>
        <el-button type="primary" @click="handleCreate" :loading="creating">
          创建并开始
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import {ref, computed, onMounted} from 'vue'
import {useRouter} from 'vue-router'
import {ElMessage} from 'element-plus'
import {Aim} from '@element-plus/icons-vue'
import {useTasksStore} from '@/stores/tasks'
import {api} from '@/api'
import StatusBadge from '@/components/StatusBadge.vue'
import PhaseBadge from '@/components/PhaseBadge.vue'

const router = useRouter()
const store = useTasksStore()
const tasks = computed(() => store.tasks)
const loading = computed(() => store.loading)

const showCreate = ref(false)
const creating = ref(false)
const formRef = ref()

const form = ref({target: '', scopeNote: 'CTF/授权靶场测试'})
const rules = {
  target: [{required: true, message: '请输入目标地址', trigger: 'blur'}],
}

const countByStatus = (s) => tasks.value.filter(t => t.status === s).length

function goDetail(id) {
  router.push(`/tasks/${id}`)
}

async function handleCreate() {
  await formRef.value.validate()
  creating.value = true
  try {
    const task = await store.createTask(form.value.target, form.value.scopeNote)
    ElMessage.success(`任务已创建，正在扫描 ${task.target}`)
    showCreate.value = false
    form.value = {target: '', scopeNote: 'CTF/授权靶场测试'}
    router.push(`/tasks/${task.task_id}`)
  } catch (e) {
    ElMessage.error('创建失败：' + (e?.response?.data?.detail || e.message))
  } finally {
    creating.value = false
  }
}

// 取消运行中的任务
async function handleCancel(row) {
  try {
    await api.cancelTask(row.task_id)
    store.updateTask({task_id: row.task_id, status: 'failed', current_phase: row.current_phase})
    ElMessage.warning(`任务 ${row.target} 已取消`)
  } catch (e) {
    // 后端如果尚未实现 cancel 接口，直接在前端标记
    store.updateTask({task_id: row.task_id, status: 'failed'})
    ElMessage.warning(`任务已在前端标记为取消（后端可能不支持强制停止）`)
  }
}

// 删除已完成/失败的任务
async function handleDelete(row) {
  try {
    await api.deleteTask(row.task_id)
  } catch {
    // 后端无 delete 接口时静默忽略，只做前端移除
  }
  store.removeTask(row.task_id)
  ElMessage.success('任务已删除')
}

onMounted(() => store.fetchTasks())
</script>

<style scoped>
.page-wrap {
  padding: 28px 32px;
  min-height: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 24px;
}

.page-title {
  font-size: 22px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 4px;
}

.page-sub {
  font-size: 13px;
  color: var(--text-secondary);
}

.stats-bar {
  display: flex;
  gap: 24px;
  margin-bottom: 20px;
  padding: 16px 24px;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
}

.stat-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.stat-num {
  font-family: var(--font-mono);
  font-size: 24px;
  font-weight: 600;
  color: var(--text-secondary);
}

.stat-num.running {
  color: var(--accent-blue);
}

.stat-num.completed {
  color: var(--accent-green);
}

.stat-num.failed {
  color: var(--accent-red);
}

.stat-label {
  font-size: 12px;
  color: var(--text-muted);
}

.table-card {
  border-radius: var(--radius-lg) !important;
}

.target-text {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--accent-blue);
}

.findings-count {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--text-muted);
}

.findings-count.has-findings {
  color: var(--accent-yellow);
  font-weight: 600;
}

.shell-icon {
  font-size: 16px;
}

.shell-icon.got {
  color: var(--accent-green);
}

.shell-icon.none {
  color: var(--text-muted);
}

.text-muted {
  color: var(--text-muted);
  font-size: 13px;
}

.form-tip {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 4px;
}

.action-cell {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
}
</style>