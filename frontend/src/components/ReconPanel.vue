<template>
  <div class="recon-wrap">
    <div v-if="isEmpty" class="empty-state">
      <el-empty description="侦察数据尚未就绪" />
    </div>

    <template v-else>
      <el-row :gutter="20">
        <!-- OS Info -->
        <el-col :span="8" v-if="osInfo && Object.keys(osInfo).length">
          <div class="info-card">
            <div class="card-title">
              <el-icon><Monitor /></el-icon> 系统信息
            </div>
            <div class="kv-list">
              <div v-for="(v, k) in osInfo" :key="k" class="kv-row">
                <span class="kv-key">{{ k }}</span>
                <span class="kv-val">{{ v }}</span>
              </div>
            </div>
          </div>
        </el-col>

        <!-- Port summary -->
        <el-col :span="osInfo && Object.keys(osInfo).length ? 16 : 24">
          <div class="info-card">
            <div class="card-title">
              <el-icon><Connection /></el-icon>
              开放端口
              <span class="count-badge">{{ ports.length }}</span>
            </div>

            <el-table :data="ports" size="small" max-height="340">
              <el-table-column label="端口" width="90">
                <template #default="{ row }">
                  <code class="port-num">{{ row.port }}/{{ row.protocol }}</code>
                </template>
              </el-table-column>
              <el-table-column label="状态" width="80">
                <template #default="{ row }">
                  <span class="port-state open">{{ row.state }}</span>
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
                  <el-tooltip v-if="row.banner" :content="row.banner" placement="top">
                    <span class="banner-text">{{ row.banner.slice(0, 40) }}{{ row.banner.length > 40 ? '…' : '' }}</span>
                  </el-tooltip>
                  <span v-else class="text-muted">—</span>
                </template>
              </el-table-column>
            </el-table>
          </div>
        </el-col>
      </el-row>

      <!-- Web paths -->
      <div class="info-card mt-16" v-if="displayPaths.length">
        <div class="card-title">
          <el-icon><Link /></el-icon>
          Web 路径发现
          <span class="count-badge">{{ displayPaths.length }}</span>
        </div>
        <div class="path-grid">
          <span
            v-for="(item, i) in displayPaths"
            :key="i"
            class="path-item"
            :class="{
              'path-high-value': item.highValue,
              'path-forbidden': item.status === 403,
            }"
          >
            <code>{{ item.path }}</code>
            <span v-if="item.status === 403" class="path-status-tag forbidden">403</span>
            <span v-if="item.badge" class="path-badge" :class="'badge-' + item.badge">{{ item.badge }}</span>
          </span>
        </div>
      </div>

      <!-- Subdomains -->
      <div class="info-card mt-16" v-if="subdomains.length">
        <div class="card-title">
          <el-icon><Share /></el-icon>
          子域名
          <span class="count-badge">{{ subdomains.length }}</span>
        </div>
        <div class="path-grid">
          <code v-for="(d, i) in subdomains" :key="i" class="path-item subdomain">{{ d }}</code>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const HIGH_VALUE_HINTS = new Set([
  'admin', 'login', 'config', 'backup', 'leak', 'upload', 'api', 'info_disclosure',
])

const BADGE_MAP = {
  admin: 'admin', login: 'login', config: 'config', backup: 'backup',
  leak: 'leak', upload: 'upload', api: 'api', info_disclosure: 'info',
}

const props = defineProps({
  task: Object,
})

const ports = computed(() => props.task?.open_ports || [])
const osInfo = computed(() => props.task?.os_info || {})
const subdomains = computed(() => props.task?.subdomains || [])

const displayPaths = computed(() => {
  const inventory = props.task?.web_paths_inventory
  if (inventory && inventory.length) {
    const verified = inventory.filter(
      item => item.status === 200 || item.status === 403 || item.status === 0
    )
    return verified
      .map(item => {
        const hints = item.hints || []
        const hvHints = hints.filter(h => HIGH_VALUE_HINTS.has(h))
        const badge = hvHints.length ? BADGE_MAP[hvHints[0]] || '' : ''
        return {
          path: item.path,
          status: item.status,
          confidence: item.confidence,
          highValue: hvHints.length > 0,
          badge,
        }
      })
      .sort((a, b) => {
        if (a.highValue !== b.highValue) return a.highValue ? -1 : 1
        return (b.confidence || 0) - (a.confidence || 0)
      })
  }
  const plain = props.task?.web_paths || []
  return plain.map(p => ({ path: p, status: 200, confidence: 0.5, highValue: false, badge: '' }))
})

const isEmpty = computed(() =>
  !ports.value.length && !displayPaths.value.length && !subdomains.value.length
)
</script>

<style scoped>
.recon-wrap { padding: 4px 0; }

.info-card {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 14px 16px;
  margin-bottom: 16px;
}

.mt-16 { margin-top: 0; }

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
.kv-key  { color: var(--text-muted); }
.kv-val  { color: var(--text-primary); font-family: var(--font-mono); font-size: 11px; }

.port-num {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--accent-blue);
}

.port-state.open {
  font-size: 11px;
  color: var(--accent-green);
  font-family: var(--font-mono);
}

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
  cursor: default;
}

.text-muted { color: var(--text-muted); font-size: 12px; }

.path-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.path-item {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-secondary);
  background: var(--bg-base);
  border: 1px solid var(--border);
  padding: 3px 8px;
  border-radius: var(--radius-sm);
  transition: border-color 0.15s;
}

.path-item:hover {
  border-color: var(--accent-blue);
  color: var(--accent-blue);
}

.path-item.path-high-value {
  border-color: rgba(255, 160, 50, 0.45);
  color: #e8a040;
}

.path-item.path-forbidden {
  opacity: 0.7;
}

.path-status-tag {
  font-size: 9px;
  padding: 0 4px;
  border-radius: 3px;
  font-family: var(--font-mono);
  line-height: 15px;
}

.path-status-tag.forbidden {
  color: #d18040;
  background: rgba(209, 128, 64, 0.15);
}

.path-badge {
  font-size: 9px;
  padding: 0 5px;
  border-radius: 3px;
  font-family: var(--font-mono);
  line-height: 15px;
  color: #e0a050;
  background: rgba(224, 160, 80, 0.12);
  border: 1px solid rgba(224, 160, 80, 0.25);
}

.badge-admin, .badge-login {
  color: #e06060;
  background: rgba(224, 96, 96, 0.12);
  border-color: rgba(224, 96, 96, 0.25);
}

.badge-config, .badge-backup, .badge-leak {
  color: #e0a050;
  background: rgba(224, 160, 80, 0.12);
  border-color: rgba(224, 160, 80, 0.25);
}

.badge-upload {
  color: #d070d0;
  background: rgba(208, 112, 208, 0.12);
  border-color: rgba(208, 112, 208, 0.25);
}

.badge-api {
  color: #60b0e0;
  background: rgba(96, 176, 224, 0.12);
  border-color: rgba(96, 176, 224, 0.25);
}

.badge-info {
  color: #80c080;
  background: rgba(128, 192, 128, 0.12);
  border-color: rgba(128, 192, 128, 0.25);
}

.path-item.subdomain {
  color: var(--accent-purple);
  border-color: rgba(188,140,255,0.2);
}
</style>
