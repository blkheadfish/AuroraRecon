<template>
  <div class="findings-wrap">
    <div v-if="!findings.length" class="empty-state">
      <el-empty description="暂无漏洞发现" />
    </div>

    <template v-else>
      <!-- Summary bar -->
      <div class="severity-summary">
        <div
          v-for="sev in severityOrder"
          :key="sev"
          class="sev-chip"
          :class="`severity-${sev}`"
          @click="filterSev = filterSev === sev ? null : sev"
          :style="{ opacity: filterSev && filterSev !== sev ? 0.4 : 1 }"
        >
          <span class="sev-count">{{ countBySeverity(sev) }}</span>
          <span class="sev-label">{{ sevLabel[sev] }}</span>
        </div>
        <el-button v-if="filterSev" link size="small" @click="filterSev = null" class="clear-filter">
          清除筛选 ×
        </el-button>
      </div>

      <!-- Findings table -->
      <el-table
        :data="filteredFindings"
        row-key="vuln_id"
        :expand-row-keys="expandedRows"
        @expand-change="handleExpand"
      >
        <el-table-column type="expand">
          <template #default="{ row }">
            <div class="expand-detail">
              <div class="detail-grid">
                <div class="detail-item" v-if="row.description">
                  <div class="detail-label">描述</div>
                  <div class="detail-value">{{ row.description }}</div>
                </div>
                <div class="detail-item" v-if="row.cve">
                  <div class="detail-label">CVE</div>
                  <a :href="`https://nvd.nist.gov/vuln/detail/${row.cve}`"
                     target="_blank" class="cve-link">{{ row.cve }}</a>
                </div>
                <div class="detail-item" v-if="row.evidence">
                  <div class="detail-label">证据 / PoC</div>
                  <pre class="evidence-code">{{ row.evidence }}</pre>
                </div>
              </div>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="严重程度" width="110">
          <template #default="{ row }">
            <span class="sev-badge" :class="`severity-${row.severity}`">
              {{ sevLabel[row.severity] || row.severity }}
            </span>
          </template>
        </el-table-column>

        <el-table-column label="漏洞名称" min-width="200">
          <template #default="{ row }">
            <span class="vuln-name">{{ row.name }}</span>
          </template>
        </el-table-column>

        <el-table-column label="目标" width="160">
          <template #default="{ row }">
            <code class="target-code">{{ row.target || '—' }}<span v-if="row.port">:{{ row.port }}</span></code>
          </template>
        </el-table-column>

        <el-table-column label="发现工具" width="110">
          <template #default="{ row }">
            <span class="tool-tag">{{ row.tool || '—' }}</span>
          </template>
        </el-table-column>

        <el-table-column label="可利用" width="90" align="center">
          <template #default="{ row }">
            <el-icon v-if="row.exploitable" class="exploitable-yes"><CircleCheckFilled /></el-icon>
            <el-icon v-else class="exploitable-no"><Remove /></el-icon>
          </template>
        </el-table-column>

        <el-table-column label="CVE" width="130">
          <template #default="{ row }">
            <a v-if="row.cve"
               :href="`https://nvd.nist.gov/vuln/detail/${row.cve}`"
               target="_blank"
               class="cve-link-sm"
            >{{ row.cve }}</a>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>
      </el-table>
    </template>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  findings: { type: Array, default: () => [] }
})

const filterSev = ref(null)
const expandedRows = ref([])

const severityOrder = ['critical', 'high', 'medium', 'low', 'info']
const sevLabel = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

const filteredFindings = computed(() => {
  const sorted = [...props.findings].sort((a, b) => {
    return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  })
  if (!filterSev.value) return sorted
  return sorted.filter(f => f.severity === filterSev.value)
})

function countBySeverity(sev) {
  return props.findings.filter(f => f.severity === sev).length
}

function handleExpand(row, rows) {
  expandedRows.value = rows.map(r => r.vuln_id)
}
</script>

<style scoped>
.findings-wrap { padding: 4px 0; }

.severity-summary {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.sev-chip {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: 20px;
  cursor: pointer;
  border: 1px solid currentColor;
  transition: opacity 0.2s, transform 0.1s;
  font-size: 12px;
}

.sev-chip:hover { transform: translateY(-1px); }

.sev-count {
  font-family: var(--font-mono);
  font-weight: 600;
  font-size: 14px;
}

.sev-label { opacity: 0.85; }

.clear-filter {
  color: var(--text-muted) !important;
  font-size: 12px !important;
}

/* Severity badge (table) */
.sev-badge {
  font-family: var(--font-mono);
  font-size: 11px;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  border: 1px solid;
}

.vuln-name {
  font-size: 13px;
  color: var(--text-primary);
}

.target-code {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--accent-blue);
  background: rgba(56,139,253,0.08);
  padding: 2px 6px;
  border-radius: var(--radius-sm);
}

.tool-tag {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-secondary);
  background: var(--bg-elevated);
  padding: 2px 6px;
  border-radius: var(--radius-sm);
}

.exploitable-yes { color: var(--accent-red); font-size: 16px; }
.exploitable-no  { color: var(--text-muted); font-size: 16px; }

.cve-link-sm {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--accent-blue);
  text-decoration: none;
}
.cve-link-sm:hover { text-decoration: underline; }

.text-muted { color: var(--text-muted); font-size: 13px; }

/* Expand detail */
.expand-detail {
  padding: 16px 24px;
  background: var(--bg-base);
  border-top: 1px solid var(--border);
}

.detail-grid {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.detail-item { display: flex; flex-direction: column; gap: 4px; }
.detail-label {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
}

.detail-value {
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.6;
}

.cve-link {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--accent-blue);
}

.evidence-code {
  font-family: var(--font-mono);
  font-size: 12px;
  background: #0d1117;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 12px;
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 200px;
  overflow-y: auto;
}
</style>
