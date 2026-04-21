<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">管理员面板</h1>
        <p class="page-sub">账户与角色管理、系统运行时状态</p>
      </div>
      <el-button link @click="loadAll" :loading="loading">
        <el-icon><Refresh /></el-icon> 刷新
      </el-button>
    </div>

    <el-card class="panel">
      <template #header>
        <div class="card-head">
          <span class="card-title">用户列表</span>
          <span class="total-badge">共 {{ users.length }} 位用户</span>
        </div>
      </template>

      <el-table :data="users" size="small" stripe v-loading="loading">
        <el-table-column prop="username" label="用户名" min-width="140" />
        <el-table-column prop="nickname" label="昵称" min-width="140" />
        <el-table-column label="角色" width="140">
          <template #default="{ row }">
            <el-tag
              :type="row.role === 'admin' ? 'danger' : 'info'"
              size="small"
              effect="plain"
            >{{ row.role === 'admin' ? '管理员' : '普通用户' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="注册时间" min-width="170">
          <template #default="{ row }">
            <span class="mono">{{ formatTime(row.created_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="280" fixed="right">
          <template #default="{ row }">
            <el-button
              size="small"
              :type="row.role === 'admin' ? 'info' : 'warning'"
              plain
              :disabled="row.id === currentUserId"
              @click="toggleRole(row)"
            >
              <el-icon><Edit /></el-icon>
              {{ row.role === 'admin' ? '降为普通用户' : '提升为管理员' }}
            </el-button>
            <el-button
              size="small"
              type="primary"
              plain
              @click="openResetPassword(row)"
            >
              <el-icon><Key /></el-icon> 重置密码
            </el-button>
            <el-button
              size="small"
              type="danger"
              plain
              :disabled="row.id === currentUserId"
              @click="removeUser(row)"
            >
              <el-icon><Delete /></el-icon> 删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card class="panel">
      <template #header>
        <span class="card-title">LLM / Embedding 运行时（只读）</span>
      </template>

      <el-alert
        type="info"
        :closable="false"
        show-icon
        title="API Key 由服务端统一配置"
        description="目前通过环境变量 LLM_API_KEY / KB_EMBEDDING_API_KEY 在服务端注入；该面板仅展示当前生效的运行时配置，不回显 Key 本身，不支持在此写入。"
        class="hint-alert"
      />

      <el-descriptions :column="2" border size="small" v-if="runtime">
        <el-descriptions-item label="LLM 提供商">{{ runtime.llm.provider || '—' }}</el-descriptions-item>
        <el-descriptions-item label="LLM 模型">{{ runtime.llm.model || '—' }}</el-descriptions-item>
        <el-descriptions-item label="LLM Base URL" :span="2">
          <span class="mono">{{ runtime.llm.base_url || '—' }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="LLM API Key">
          <el-tag :type="runtime.llm.has_key ? 'success' : 'warning'" size="small" effect="plain">
            {{ runtime.llm.has_key ? '已分配' : '未配置' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="Embedding Key">
          <el-tag :type="runtime.embedding.has_key ? 'success' : 'warning'" size="small" effect="plain">
            {{ runtime.embedding.has_key ? '已分配' : '未配置' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="Embedding 模型">{{ runtime.embedding.model || '—' }}</el-descriptions-item>
        <el-descriptions-item label="Embedding Base URL">
          <span class="mono">{{ runtime.embedding.base_url || '—' }}</span>
        </el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-dialog
      v-model="resetDialogVisible"
      title="重置密码"
      width="420px"
      :close-on-click-modal="false"
    >
      <el-form label-width="90px" @submit.prevent>
        <el-form-item label="目标用户">
          <span class="mono">{{ resetTarget?.username }}</span>
        </el-form-item>
        <el-form-item label="新密码">
          <el-input
            v-model="resetForm.new_password"
            type="password"
            show-password
            placeholder="至少 6 位"
          />
        </el-form-item>
        <el-form-item label="确认">
          <el-input
            v-model="resetForm.confirm"
            type="password"
            show-password
            placeholder="再次输入"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="resetDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="resetting" @click="submitReset">
          确认重置
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Edit, Key, Delete, Refresh } from '@element-plus/icons-vue'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const currentUserId = ref(auth.user?.id || '')

const users = ref([])
const runtime = ref(null)
const loading = ref(false)

const resetDialogVisible = ref(false)
const resetTarget = ref(null)
const resetForm = ref({ new_password: '', confirm: '' })
const resetting = ref(false)

function formatTime(raw) {
  if (!raw) return '—'
  const d = new Date(raw)
  if (Number.isNaN(d.getTime())) return raw
  return d.toLocaleString()
}

async function loadUsers() {
  try {
    const res = await api.adminListUsers()
    users.value = res.users || []
  } catch (e) {
    const detail = e?.response?.data?.detail || e.message || '加载用户列表失败'
    ElMessage.error(detail)
  }
}

async function loadRuntime() {
  try {
    runtime.value = await api.adminGetLlmRuntime()
  } catch {
    runtime.value = null
  }
}

async function loadAll() {
  loading.value = true
  try {
    await Promise.all([loadUsers(), loadRuntime()])
  } finally {
    loading.value = false
  }
}

async function toggleRole(row) {
  const nextRole = row.role === 'admin' ? 'user' : 'admin'
  try {
    await ElMessageBox.confirm(
      `确定把 ${row.username} 的角色改为「${nextRole === 'admin' ? '管理员' : '普通用户'}」吗？`,
      '修改角色',
      { type: 'warning' },
    )
  } catch { return }
  try {
    await api.adminUpdateUserRole(row.id, nextRole)
    ElMessage.success('角色已更新')
    await loadUsers()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '更新失败')
  }
}

function openResetPassword(row) {
  resetTarget.value = row
  resetForm.value = { new_password: '', confirm: '' }
  resetDialogVisible.value = true
}

async function submitReset() {
  if (!resetTarget.value) return
  const pwd = resetForm.value.new_password || ''
  if (pwd.length < 6) {
    ElMessage.error('新密码至少 6 位')
    return
  }
  if (pwd !== resetForm.value.confirm) {
    ElMessage.error('两次输入的密码不一致')
    return
  }
  resetting.value = true
  try {
    await api.adminResetPassword(resetTarget.value.id, pwd)
    ElMessage.success('已重置密码')
    resetDialogVisible.value = false
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '重置失败')
  } finally {
    resetting.value = false
  }
}

async function removeUser(row) {
  try {
    await ElMessageBox.confirm(
      `确定删除用户 ${row.username}？该用户及其设置将被永久移除。`,
      '删除用户',
      { type: 'error', confirmButtonText: '删除', confirmButtonClass: 'el-button--danger' },
    )
  } catch { return }
  try {
    await api.adminDeleteUser(row.id)
    ElMessage.success('已删除')
    await loadUsers()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '删除失败')
  }
}

onMounted(loadAll)
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 16px;
}
.page-title { font-size: 22px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px; }
.page-sub   { font-size: 13px; color: var(--text-secondary); }

.panel { margin-bottom: 16px; border-radius: var(--radius-lg) !important; }
.card-head { display: flex; align-items: center; justify-content: space-between; }
.card-title { font-weight: 600; color: var(--text-primary); }
.total-badge { font-size: 12px; color: var(--text-muted); }

.hint-alert { margin-bottom: 14px; }

.mono { font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary); }
</style>
