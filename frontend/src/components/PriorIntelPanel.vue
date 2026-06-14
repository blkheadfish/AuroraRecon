<template>
  <div class="prior-intel-wrap" v-if="intel && !isEmpty">
    <div class="pi-header">
      <el-alert type="info" :closable="false" show-icon>
        <template #title>
          来自同租户 {{ intel.source_task_count }} 个过往任务的历史已知信息（仅作参考，将被本任务侦察验证刷新）
        </template>
      </el-alert>
    </div>

    <!-- 历史服务 -->
    <div class="info-card" v-if="intel.known_services?.length">
      <div class="card-title">
        <el-icon><Connection /></el-icon>
        历史已知服务
        <span class="count-badge">{{ intel.known_services.length }}</span>
      </div>
      <el-table :data="intel.known_services" size="small" max-height="320">
        <el-table-column label="主机" width="160">
          <template #default="{ row }">
            <code class="pi-code">{{ row.host }}</code>
          </template>
        </el-table-column>
        <el-table-column label="端口" width="80">
          <template #default="{ row }">
            <code class="pi-code">{{ row.port }}</code>
          </template>
        </el-table-column>
        <el-table-column label="服务" width="110">
          <template #default="{ row }">
            <span class="service-tag">{{ row.service || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="版本" min-width="140">
          <template #default="{ row }">
            <span class="version-text">{{ row.version || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Banner" min-width="160">
          <template #default="{ row }">
            <span v-if="row.banner" class="banner-text">{{ row.banner.slice(0, 60) }}{{ row.banner.length > 60 ? '…' : '' }}</span>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 历史指纹 -->
    <div class="info-card" v-if="fpEntries.length">
      <div class="card-title">
        <el-icon><Monitor /></el-icon>
        历史已知指纹
        <span class="count-badge">{{ fpEntries.length }}</span>
      </div>
      <div class="kv-list">
        <div v-for="[k, v] in fpEntries" :key="k" class="kv-row">
          <span class="kv-key">{{ k }}</span>
          <span class="kv-val">{{ v }}</span>
        </div>
      </div>
    </div>

    <!-- 历史发现/漏洞 -->
    <div class="info-card" v-if="intel.known_findings?.length">
      <div class="card-title">
        <el-icon><Warning /></el-icon>
        历史已知发现
        <span class="count-badge">{{ intel.known_findings.length }}</span>
      </div>
      <el-table :data="intel.known_findings" size="small" max-height="280">
        <el-table-column label="名称" min-width="160">
          <template #default="{ row }">
            <span>{{ row.name }}</span>
          </template>
        </el-table-column>
        <el-table-column label="严重度" width="90">
          <template #default="{ row }">
            <el-tag :type="severityTag(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="CVE" width="140">
          <template #default="{ row }">
            <a v-if="row.cve" class="cve-link" :href="`https://nvd.nist.gov/vuln/detail/${row.cve}`" target="_blank" rel="noopener">{{ row.cve }}</a>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 历史凭据提示（无明文） -->
    <div class="info-card" v-if="intel.credential_hints?.length">
      <div class="card-title">
        <el-icon><Lock /></el-icon>
        历史已知凭据（仅存在性提示，不含明文）
        <span class="count-badge">{{ intel.credential_hints.length }}</span>
      </div>
      <div class="cred-list">
        <div v-for="(c, i) in intel.credential_hints" :key="i" class="cred-row">
          <span class="cred-service">{{ c.service }}</span>
          <span class="cred-user">{{ c.username }}</span>
          <span class="cred-lock">🔒</span>
        </div>
      </div>
    </div>
  </div>
  <div v-else class="empty-state">
    <el-empty description="暂无历史先验情报" :image-size="60" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Connection, Monitor, Warning, Lock } from '@element-plus/icons-vue'

const props = defineProps({
  intel: { type: Object, default: null },
})

const fpEntries = computed(() => {
  const fps = props.intel?.known_fingerprints
  if (!fps || typeof fps !== 'object') return []
  return Object.entries(fps).filter(([, v]) => v)
})

const isEmpty = computed(() => {
  const i = props.intel
  if (!i) return true
  return !(
    (i.known_services?.length) ||
    (i.known_findings?.length) ||
    (i.credential_hints?.length) ||
    Object.keys(i.known_fingerprints || {}).length
  )
})

function severityTag(sev) {
  if (!sev) return ''
  const s = String(sev).toLowerCase()
  if (s === 'critical') return 'danger'
  if (s === 'high') return 'danger'
  if (s === 'medium') return 'warning'
  if (s === 'low') return 'info'
  return ''
}
</script>

<style scoped>
.prior-intel-wrap { padding: 4px 0; }
.pi-header { margin-bottom: 16px; }
.pi-code {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--accent-blue);
}
.info-card {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 14px 16px;
  margin-bottom: 16px;
}
.card-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 12px;
}
.count-badge {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--accent-blue);
  background: rgba(56,139,253,0.12);
  border: 1px solid rgba(56,139,253,0.25);
  padding: 1px 7px;
  border-radius: 10px;
}
.kv-list { display: flex; flex-direction: column; gap: 6px; }
.kv-row  { display: flex; justify-content: space-between; align-items: center; font-size: 12px; }
.kv-key  { color: var(--text-muted); flex-shrink: 0; margin-right: 12px; }
.kv-val  { color: var(--text-primary); font-family: var(--font-mono); font-size: 11px; word-break: break-all; }
.service-tag {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--accent-yellow);
}
.version-text {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-secondary);
}
.banner-text {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
}
.text-muted { color: var(--text-muted); font-size: 12px; }
.cve-link {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--accent-blue);
  text-decoration: none;
}
.cve-link:hover { text-decoration: underline; }
.cred-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.cred-row {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 12px;
}
.cred-service {
  font-family: var(--font-mono);
  color: var(--accent-yellow);
  min-width: 80px;
}
.cred-user {
  font-family: var(--font-mono);
  color: var(--text-primary);
}
.cred-lock { font-size: 13px; }
.empty-state { padding: 32px 0; }
</style>
