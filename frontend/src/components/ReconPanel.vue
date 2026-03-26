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
      <div class="info-card mt-16" v-if="webPaths.length">
        <div class="card-title">
          <el-icon><Link /></el-icon>
          Web 路径发现
          <span class="count-badge">{{ webPaths.length }}</span>
        </div>
        <div class="path-grid">
          <code
            v-for="(p, i) in webPaths"
            :key="i"
            class="path-item"
          >{{ p }}</code>
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

const props = defineProps({
  task: Object,
})

const ports = computed(() => props.task?.open_ports || [])
const osInfo = computed(() => props.task?.os_info || {})
const webPaths = computed(() => props.task?.web_paths || [])
const subdomains = computed(() => props.task?.subdomains || [])

const isEmpty = computed(() =>
  !ports.value.length && !webPaths.value.length && !subdomains.value.length
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

.path-item.subdomain {
  color: var(--accent-purple);
  border-color: rgba(188,140,255,0.2);
}
</style>
