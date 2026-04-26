<template>
  <div class="admin-users">
    <div class="section-header">
      <div>
        <h2 class="section-title">用户管理</h2>
        <p class="section-sub">管理系统中的账户与角色分配</p>
      </div>
      <el-button @click="loadUsers" :loading="loadingUsers" :icon="Refresh" circle />
    </div>

    <div class="stat-cards">
      <div class="stat-card">
        <span class="stat-value">{{ users.length }}</span>
        <span class="stat-desc">用户总数</span>
      </div>
      <div class="stat-card accent-admin">
        <span class="stat-value">{{ adminCount }}</span>
        <span class="stat-desc">管理员</span>
      </div>
      <div class="stat-card accent-user">
        <span class="stat-value">{{ users.length - adminCount }}</span>
        <span class="stat-desc">普通用户</span>
      </div>
    </div>

    <el-card class="data-card" shadow="never">
      <SkeletonBlock v-if="loadingUsers && !users.length" :rows="6" />
      <el-table v-else :data="users" stripe empty-text="暂无用户数据">
        <el-table-column prop="username" label="用户名" min-width="140">
          <template #default="{ row }">
            <span class="username-cell">
              <el-avatar :size="26" class="mini-avatar">{{ (row.username || 'U')[0].toUpperCase() }}</el-avatar>
              <code>{{ row.username }}</code>
            </span>
          </template>
        </el-table-column>
        <el-table-column prop="nickname" label="昵称" min-width="120">
          <template #default="{ row }">
            {{ row.nickname || '—' }}
          </template>
        </el-table-column>
        <el-table-column label="角色" width="120" align="center">
          <template #default="{ row }">
            <el-tag
              :type="row.role === 'admin' ? 'danger' : ''"
              size="small"
              effect="plain"
              round
            >{{ row.role === 'admin' ? '管理员' : '用户' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="注册时间" min-width="160">
          <template #default="{ row }">
            <span class="mono-sm">{{ formatTime(row.created_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="260" fixed="right" align="center">
          <template #default="{ row }">
            <div class="action-group">
              <el-tooltip :content="row.role === 'admin' ? '降为用户' : '提升管理员'" placement="top">
                <el-button
                  size="small"
                  :type="row.role === 'admin' ? 'info' : 'warning'"
                  plain
                  :disabled="row.id === currentUserId"
                  @click="toggleRole(row)"
                >
                  <el-icon><Edit /></el-icon>
                </el-button>
              </el-tooltip>
              <el-tooltip content="重置密码" placement="top">
                <el-button size="small" plain @click="openResetPassword(row)">
                  <el-icon><Key /></el-icon>
                </el-button>
              </el-tooltip>
              <el-tooltip content="删除用户" placement="top">
                <el-button
                  size="small"
                  type="danger"
                  plain
                  :disabled="row.id === currentUserId"
                  @click="removeUser(row)"
                >
                  <el-icon><Delete /></el-icon>
                </el-button>
              </el-tooltip>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Reset Password Dialog -->
    <el-dialog
      v-model="resetDialogVisible"
      title="重置密码"
      width="420px"
      :close-on-click-modal="false"
    >
      <el-form label-width="90px" @submit.prevent>
        <el-form-item label="目标用户">
          <code>{{ resetTarget?.username }}</code>
        </el-form-item>
        <el-form-item label="新密码">
          <el-input
            v-model="resetForm.new_password"
            type="password"
            show-password
            placeholder="至少 6 位"
          />
        </el-form-item>
        <el-form-item label="确认密码">
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
        <el-button type="primary" :loading="resetting" @click="submitReset">确认重置</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Edit, Key, Delete, Refresh } from '@element-plus/icons-vue'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'
import SkeletonBlock from '@/components/SkeletonBlock.vue'

const auth = useAuthStore()
const currentUserId = ref(auth.user?.id || '')

const users = ref([])
const loadingUsers = ref(false)
const adminCount = computed(() => users.value.filter(u => u.role === 'admin').length)

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
  loadingUsers.value = true
  try {
    const res = await api.adminListUsers()
    users.value = res.users || []
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '加载用户列表失败')
  } finally {
    loadingUsers.value = false
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
  if (pwd.length < 6) { ElMessage.error('新密码至少 6 位'); return }
  if (pwd !== resetForm.value.confirm) { ElMessage.error('两次输入的密码不一致'); return }
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

onMounted(loadUsers)
</script>

<style scoped>
.section-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 20px;
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

.stat-cards {
  display: flex;
  gap: 14px;
  margin-bottom: 20px;
}
.stat-card {
  flex: 1;
  padding: 16px 20px;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--bg-surface);
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.stat-value {
  font-family: var(--font-mono);
  font-size: 28px;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.1;
}
.stat-desc {
  font-size: 12px;
  color: var(--text-muted);
}
.stat-card.accent-admin .stat-value { color: var(--accent-red); }
.stat-card.accent-user .stat-value { color: var(--accent-blue); }

.data-card {
  border-radius: var(--radius-lg) !important;
  border: 1px solid var(--border) !important;
}
.data-card :deep(.el-card__body) {
  padding: 0;
}

.username-cell {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.username-cell code {
  font-size: 12px;
  color: var(--text-primary);
}
.mini-avatar {
  background: rgba(56, 139, 253, 0.15) !important;
  color: var(--accent-blue) !important;
  font-weight: 600;
  font-size: 11px;
}
.mono-sm {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-secondary);
}
.action-group {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
}

@media (max-width: 768px) {
  .stat-cards { flex-direction: column; }
}
</style>
