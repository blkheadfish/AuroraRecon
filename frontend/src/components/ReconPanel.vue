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
        <div class="card-title path-title">
          <div class="path-title-left">
            <el-icon><Link /></el-icon>
            Web 路径发现
            <span class="count-badge">{{ filteredLeafCount }}/{{ displayPaths.length }}</span>
          </div>
          <div class="path-title-right">
            <el-input
              v-model="search"
              placeholder="搜索路径…"
              clearable
              size="small"
              class="path-search"
            >
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
            <el-radio-group v-model="pathFilter" size="small" class="path-filter">
              <el-radio-button value="all">全部</el-radio-button>
              <el-radio-button value="high">高价值</el-radio-button>
              <el-radio-button value="s200">200</el-radio-button>
              <el-radio-button value="s403">403</el-radio-button>
            </el-radio-group>
            <el-button-group size="small" class="path-expand-ctrl">
              <el-button :icon="ArrowDown" title="展开全部" @click="expandAll" />
              <el-button :icon="ArrowUp" title="折叠全部" @click="collapseAll" />
            </el-button-group>
          </div>
        </div>

        <div v-if="!pathTree.length" class="tree-empty">
          <el-empty description="无匹配路径" :image-size="60" />
        </div>
        <el-tree
          v-else
          :key="treeKey"
          :data="pathTree"
          node-key="key"
          :default-expanded-keys="expandedKeys"
          :expand-on-click-node="false"
          :indent="14"
          class="path-tree"
        >
          <template #default="{ data }">
            <span
              class="tree-node"
              :class="{
                'tree-node-leaf': data.isLeaf,
                'tree-node-dir': !data.isLeaf,
                'tree-node-hv': data.highValue,
              }"
            >
              <span class="tree-label">
                <span v-if="!data.isLeaf" class="tree-dir-label">
                  {{ data.label }}<span class="tree-sep">/</span>
                </span>
                <el-tooltip
                  v-else
                  effect="dark"
                  placement="top"
                  :show-after="250"
                  :disabled="!hasTooltip(data)"
                >
                  <template #content>
                    <div class="tree-tooltip">
                      <div class="tt-path"><code>{{ data.fullPath }}</code></div>
                      <div v-if="data.confidence != null" class="tt-row">
                        置信度: <b>{{ Math.round((data.confidence || 0) * 100) }}%</b>
                      </div>
                      <div v-if="data.hints && data.hints.length" class="tt-row">
                        提示: {{ data.hints.join(', ') }}
                      </div>
                    </div>
                  </template>
                  <code class="tree-leaf-path">{{ data.label }}</code>
                </el-tooltip>
              </span>
              <span class="tree-meta">
                <span
                  v-if="data.isLeaf"
                  class="status-pill"
                  :class="'status-' + statusKind(data.status)"
                >{{ data.status || '?' }}</span>
                <span
                  v-if="data.badge"
                  class="path-badge"
                  :class="'badge-' + data.badge"
                >{{ data.badge }}</span>
                <el-icon
                  v-if="data.isLeaf"
                  class="copy-btn"
                  :title="'复制 ' + data.fullPath"
                  @click.stop="copyPath(data.fullPath)"
                ><CopyDocument /></el-icon>
              </span>
            </span>
          </template>
        </el-tree>
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

      <!-- Internal / AD Enumeration Results -->
      <div class="info-card mt-16" v-if="hasAdEnumResults">
        <div class="card-title">
          <el-icon><Connection /></el-icon>
          内网/AD 枚举结果
          <span class="count-badge">{{ adEnumTotal }}</span>
        </div>

        <div v-if="adShares.length" class="ad-sub-section">
          <div class="ad-sub-title">SMB 共享</div>
          <div class="ad-item-list">
            <div v-for="s in adShares" :key="s.id" class="ad-item">
              <span class="ad-item-label">{{ s.label }}</span>
              <span v-if="s.permission" class="ad-item-perm" :class="permClass(s.permission)">
                {{ s.permission }}
              </span>
            </div>
          </div>
        </div>

        <div v-if="adDomainUsers.length" class="ad-sub-section">
          <div class="ad-sub-title">域账户</div>
          <div class="ad-item-list">
            <code v-for="u in adDomainUsers" :key="u.id" class="ad-item-tag">{{ u.label }}</code>
          </div>
        </div>

        <div v-if="adSpns.length" class="ad-sub-section">
          <div class="ad-sub-title">Kerberos SPN</div>
          <div class="ad-item-list">
            <code v-for="s in adSpns" :key="s.id" class="ad-item-tag spn-tag">{{ s.label }}</code>
          </div>
        </div>

        <div v-if="adCredentials.length" class="ad-sub-section">
          <div class="ad-sub-title">凭据</div>
          <div class="ad-item-list">
            <div v-for="c in adCredentials" :key="c.id" class="ad-item">
              <span class="ad-item-label">{{ c.label }}</span>
              <span v-if="c.validated" class="ad-item-valid">已验</span>
              <span v-else class="ad-item-pend">待验</span>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import {
  Monitor, Connection, Link, Share,
  Search, ArrowDown, ArrowUp, CopyDocument,
} from '@element-plus/icons-vue'
import { usePathTree } from '@/composables/usePathTree'

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
          hints,
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
  return plain.map(p => ({
    path: p, status: 200, confidence: 0.5, hints: [], highValue: false, badge: '',
  }))
})

const pathFilter = ref('all')
const search = ref('')
const {
  tree: pathTree,
  leafCount: filteredLeafCount,
  highValueExpandKeys,
  allKeys,
} = usePathTree(displayPaths, pathFilter, search)

const expandedKeys = ref([])
const treeKey = ref(0)

function syncExpanded() {
  if (search.value.trim()) {
    expandedKeys.value = [...allKeys.value]
  } else if (pathFilter.value !== 'all') {
    expandedKeys.value = [...allKeys.value]
  } else {
    expandedKeys.value = [...highValueExpandKeys.value]
  }
  treeKey.value++
}

watch(highValueExpandKeys, () => syncExpanded(), { immediate: true })
watch(search, () => syncExpanded())
watch(pathFilter, () => syncExpanded())

function expandAll() {
  expandedKeys.value = [...allKeys.value]
  treeKey.value++
}

function collapseAll() {
  expandedKeys.value = []
  treeKey.value++
}

async function copyPath(path) {
  try {
    await navigator.clipboard.writeText(path)
    ElMessage.success(`已复制 ${path}`)
  } catch {
    ElMessage.error('复制失败')
  }
}

function statusKind(code) {
  if (code === 200) return 'ok'
  if (code === 403) return 'forbidden'
  if (code === 0 || code == null) return 'unknown'
  if (code >= 500) return 'error'
  if (code >= 300 && code < 400) return 'redirect'
  if (code === 401) return 'auth'
  return 'other'
}

function hasTooltip(data) {
  return !!(
    data.fullPath ||
    data.confidence != null ||
    (data.hints && data.hints.length)
  )
}

const isEmpty = computed(() =>
  !ports.value.length && !displayPaths.value.length && !subdomains.value.length
)

const adEnumNodes = computed(() => {
  const nodes = props.task?.attack_graph?.nodes || []
  return nodes.filter((n) => {
    const facts = n.facts || {}
    const type = n.type
    const subtype = facts.subtype
    return (
      (type === 'loot' && subtype === 'share') ||
      (type === 'credential' && (subtype === 'domain_user' || subtype === 'domain_group' || subtype === 'domain_computer')) ||
      (type === 'credential' && (facts.service === 'smb' || facts.service === 'ldap' || facts.service === 'kerberos')) ||
      (type === 'finding' && subtype === 'spn')
    )
  })
})

const adShares = computed(() =>
  adEnumNodes.value.filter((n) => n.type === 'loot').map((n) => ({
    id: n.id,
    label: n.label || n.id,
    permission: (n.facts || {}).permission || '',
  }))
)

const adDomainUsers = computed(() =>
  adEnumNodes.value.filter((n) => {
    const facts = n.facts || {}
    return n.type === 'credential' && (facts.subtype === 'domain_user' || facts.subtype === 'domain_group' || facts.subtype === 'domain_computer' || facts.domain)
  }).map((n) => ({
    id: n.id,
    label: n.label || n.id,
    type: n.type,
  }))
)

const adSpns = computed(() =>
  adEnumNodes.value.filter((n) => {
    const facts = n.facts || {}
    return n.type === 'finding' && facts.subtype === 'spn'
  }).map((n) => ({
    id: n.id,
    label: n.label || n.id,
  }))
)

const adCredentials = computed(() =>
  adEnumNodes.value.filter((n) => {
    const facts = n.facts || {}
    return n.type === 'credential' && !facts.subtype && !facts.domain
  }).map((n) => ({
    id: n.id,
    label: n.label || n.id,
    validated: !!((n.facts || {}).validated),
  }))
)

const adEnumTotal = computed(() => adEnumNodes.value.length)

const hasAdEnumResults = computed(() => adEnumNodes.value.length > 0)

function permClass(perm) {
  const p = perm.toUpperCase()
  if (p === 'READ') return 'perm-read'
  if (p === 'WRITE') return 'perm-write'
  if (p === 'NO ACCESS') return 'perm-noaccess'
  return ''
}
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

/* ============ Path tree (B2/B3/B4) ============ */
.path-title {
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 14px;
}

.path-title-left {
  display: flex;
  align-items: center;
  gap: 6px;
}

.path-title-right {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.path-search {
  width: 180px;
}

.path-filter :deep(.el-radio-button__inner) {
  padding: 5px 10px;
  font-size: 11px;
}

.path-expand-ctrl :deep(.el-button) {
  padding: 5px 8px;
}

.tree-empty {
  padding: 4px 0 2px;
}

.path-tree {
  background: transparent;
  font-size: 12px;
  --el-tree-node-hover-bg-color: rgba(56,139,253,0.06);
}

.path-tree :deep(.el-tree-node__content) {
  height: 28px;
  padding-right: 4px;
}

.path-tree :deep(.el-tree-node__content:hover) {
  background: rgba(56,139,253,0.06);
}

.path-tree :deep(.el-tree-node__content > *:last-child) {
  flex: 1;
  min-width: 0;
}

.tree-node {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  width: 100%;
  min-width: 0;
  padding-right: 4px;
}

.tree-label {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  min-width: 0;
  overflow: hidden;
}

.tree-dir-label {
  color: var(--text-secondary);
  font-family: var(--font-mono);
  font-size: 12px;
  white-space: nowrap;
}

.tree-sep {
  color: var(--text-muted);
  margin-left: 1px;
}

.tree-leaf-path {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.tree-node-hv.tree-node-dir .tree-dir-label {
  color: #e8a040;
}

.tree-node-hv.tree-node-leaf .tree-leaf-path {
  color: #f0b060;
  font-weight: 500;
}

.tree-meta {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}

.status-pill {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 9px;
  line-height: 15px;
  letter-spacing: 0.3px;
  border: 1px solid transparent;
}

.status-pill.status-ok {
  color: #48b97a;
  background: rgba(72, 185, 122, 0.14);
  border-color: rgba(72, 185, 122, 0.32);
}

.status-pill.status-forbidden {
  color: #e28a40;
  background: rgba(226, 138, 64, 0.14);
  border-color: rgba(226, 138, 64, 0.32);
}

.status-pill.status-auth {
  color: #c070e0;
  background: rgba(192, 112, 224, 0.14);
  border-color: rgba(192, 112, 224, 0.3);
}

.status-pill.status-redirect {
  color: #60b0e0;
  background: rgba(96, 176, 224, 0.14);
  border-color: rgba(96, 176, 224, 0.3);
}

.status-pill.status-error {
  color: #e06060;
  background: rgba(224, 96, 96, 0.14);
  border-color: rgba(224, 96, 96, 0.3);
}

.status-pill.status-unknown {
  color: var(--text-muted);
  background: rgba(160, 160, 160, 0.1);
  border-color: rgba(160, 160, 160, 0.25);
}

.status-pill.status-other {
  color: var(--text-muted);
  background: rgba(160, 160, 160, 0.1);
  border-color: rgba(160, 160, 160, 0.25);
}

.copy-btn {
  font-size: 13px;
  color: var(--text-muted);
  cursor: pointer;
  opacity: 0;
  transition: color 0.15s, opacity 0.15s;
}

.path-tree :deep(.el-tree-node__content:hover) .copy-btn {
  opacity: 1;
}

.copy-btn:hover {
  color: var(--accent-blue);
}

.tree-tooltip {
  max-width: 340px;
  font-size: 12px;
  line-height: 1.6;
}

.tree-tooltip .tt-path code {
  font-family: var(--font-mono);
  font-size: 11px;
  color: #ffd080;
  word-break: break-all;
}

.tree-tooltip .tt-row {
  color: #ddd;
  margin-top: 2px;
}

/* ============ AD / Internal Enum (W3-T1) ============ */
.ad-sub-section {
  margin-bottom: 12px;
}

.ad-sub-title {
  font-size: 12px;
  font-weight: 500;
  color: var(--accent-yellow);
  margin-bottom: 6px;
}

.ad-item-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.ad-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--bg-base);
  border: 1px solid var(--border);
  padding: 3px 8px;
  border-radius: var(--radius-sm);
  font-size: 12px;
}

.ad-item-label {
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: 11px;
}

.ad-item-perm {
  font-size: 10px;
  font-weight: 600;
  padding: 0 5px;
  border-radius: 3px;
}

.perm-read {
  color: #48b97a;
  background: rgba(72, 185, 122, 0.15);
}

.perm-write {
  color: #e28a40;
  background: rgba(226, 138, 64, 0.15);
}

.perm-noaccess {
  color: var(--text-muted);
  background: rgba(160, 160, 160, 0.1);
}

.ad-item-tag {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-secondary);
  background: var(--bg-base);
  border: 1px solid var(--border);
  padding: 2px 7px;
  border-radius: var(--radius-sm);
}

.ad-item-tag.spn-tag {
  color: #c070e0;
  border-color: rgba(192, 112, 224, 0.3);
}

.ad-item-valid {
  font-size: 10px;
  color: #48b97a;
  font-weight: 600;
}

.ad-item-pend {
  font-size: 10px;
  color: var(--text-muted);
}
</style>
