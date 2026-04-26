<template>
  <div class="admin-audit">
    <div class="section-header">
      <div>
        <h2 class="section-title">审计日志</h2>
        <p class="section-sub">记录所有管理员操作与系统事件</p>
      </div>
      <el-button @click="loadLogs" :loading="loading" :icon="Refresh" circle />
    </div>

    <!-- Filters -->
    <div class="filter-bar">
      <el-select
        v-model="filterAction"
        placeholder="操作类型"
        clearable
        style="width: 200px"
        @change="loadLogs"
      >
        <el-option label="修改角色" value="admin_update_role" />
        <el-option label="重置密码" value="admin_reset_password" />
        <el-option label="删除用户" value="admin_delete_user" />
        <el-option label="启停 Skill" value="admin_set_skill_enabled" />
        <el-option label="启停 Tool" value="admin_set_tool_enabled" />
      </el-select>
      <el-input
        v-model="filterOwner"
        placeholder="操作者 ID"
        clearable
        style="width: 200px"
        @clear="loadLogs"
        @keyup.enter="loadLogs"
      />
      <el-button @click="loadLogs" type="primary" plain size="small">筛选</el-button>
    </div>

    <el-card class="data-card" shadow="never">
      <SkeletonBlock v-if="loading && !logs.length" :rows="8" />
      <el-table v-else :data="logs" stripe empty-text="没有审计记录">
        <el-table-column label="时间" width="180">
          <template #default="{ row }">
            <span class="mono-sm">{{ formatTime(row.created_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" min-width="160">
          <template #default="{ row }">
            <el-tag size="small" effect="plain" round>{{ actionLabel(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="资源" min-width="200">
          <template #default="{ row }">
            <span class="resource-cell">
              <span class="res-type">{{ row.resource_type || '—' }}</span>
              <code>{{ row.resource_key || '—' }}</code>
            </span>
          </template>
        </el-table-column>
        <el-table-column label="操作者" width="140">
          <template #default="{ row }">
            <code class="mono-sm">{{ row.owner_id ? row.owner_id.slice(0, 8) + '…' : '—' }}</code>
          </template>
        </el-table-column>
        <el-table-column label="详情" min-width="200">
          <template #default="{ row }">
            <code class="detail-json">{{ JSON.stringify(row.detail || {}) }}</code>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-bar" v-if="total > pageSize">
        <el-pagination
          v-model:current-page="page"
          :page-size="pageSize"
          :total="total"
          layout="prev, pager, next"
          small
          @current-change="loadLogs"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '@/api'
import SkeletonBlock from '@/components/SkeletonBlock.vue'

const loading = ref(false)
const logs = ref([])
const page = ref(1)
const pageSize = 30
const total = ref(0)
const filterAction = ref('')
const filterOwner = ref('')

const ACTION_LABELS = {
  admin_update_role: '修改角色',
  admin_reset_password: '重置密码',
  admin_delete_user: '删除用户',
  admin_set_skill_enabled: '启停 Skill',
  admin_set_tool_enabled: '启停 Tool',
}

function actionLabel(action) {
  return ACTION_LABELS[action] || action
}

function formatTime(raw) {
  if (!raw) return '—'
  const d = new Date(raw)
  if (Number.isNaN(d.getTime())) return raw
  return d.toLocaleString()
}

async function loadLogs() {
  loading.value = true
  try {
    const res = await api.adminListAuditLogs({
      page: page.value,
      page_size: pageSize,
      action: filterAction.value || undefined,
      owner_id: filterOwner.value || undefined,
    })
    logs.value = res.items || []
    total.value = res.total || 0
  } catch {
    logs.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

onMounted(loadLogs)
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

.filter-bar {
  display: flex;
  gap: 10px;
  margin-bottom: 16px;
  flex-wrap: wrap;
  align-items: center;
}

.data-card {
  border-radius: var(--radius-lg) !important;
  border: 1px solid var(--border) !important;
}
.data-card :deep(.el-card__body) {
  padding: 0;
}

.mono-sm {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-secondary);
}

.resource-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}
.res-type {
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  font-family: var(--font-mono);
  letter-spacing: 0.04em;
}
.resource-cell code {
  font-size: 12px;
  color: var(--text-primary);
}

.detail-json {
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-secondary);
  word-break: break-all;
  max-width: 300px;
  display: inline-block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.pagination-bar {
  display: flex;
  justify-content: center;
  padding: 14px 16px;
  border-top: 1px solid var(--border-muted);
}
</style>
