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
        <div class="confidence-filter">
          <span class="filter-label">置信度 ≥</span>
          <el-slider v-model="minConfidence" :min="0" :max="100" :step="10" :show-tooltip="true" style="width: 120px" size="small" />
          <span class="filter-value">{{ minConfidence }}%</span>
        </div>
        <el-switch v-model="showRejected" active-text="显示已驳回" size="small" />
      </div>

      <!-- Findings table -->
      <el-table
        :data="filteredFindings"
        row-key="vuln_id"
        :expand-row-keys="expandedRows"
        @expand-change="handleExpand"
        :row-class-name="rowClassName"
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
                <div class="detail-item" v-if="row.evidence">
                  <div class="detail-label">最小复现片段</div>
                  <code class="mini-poc">{{ minimalRepro(row.evidence) }}</code>
                </div>
                <div class="detail-item" v-if="row.verification_reasons?.length">
                  <div class="detail-label">复核原因</div>
                  <ul class="verify-reasons">
                    <li v-for="(reason, idx) in row.verification_reasons" :key="idx">{{ reason }}</li>
                  </ul>
                </div>
              </div>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="严重程度" width="140">
          <template #default="{ row }">
            <span class="sev-badge" :class="`severity-${row.severity}`">
              {{ sevLabel[row.severity] || row.severity }}
            </span>
            <span class="confidence-badge" :class="confidenceClass(row)">
              {{ row.confidence ?? 50 }}%
            </span>
            <el-tag v-if="row.verification_status === 'rejected'" size="small" type="info" class="rejected-tag">已驳回</el-tag>
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

        <el-table-column label="利用评分" width="120">
          <template #default="{ row }">
            <span class="exploit-score" :class="{ high: row.exploitable }">{{ exploitabilityScore(row) }}</span>
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
const minConfidence = ref(0)
const showRejected = ref(false)

const severityOrder = ['critical', 'high', 'medium', 'low', 'info']
const sevLabel = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

const filteredFindings = computed(() => {
  let list = [...props.findings]
  if (!showRejected.value) {
    list = list.filter(f => f.verification_status !== 'rejected')
  }
  if (minConfidence.value > 0) {
    list = list.filter(f => (f.confidence ?? 50) >= minConfidence.value)
  }
  list.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
  if (filterSev.value) {
    list = list.filter(f => f.severity === filterSev.value)
  }
  return list
})

function confidenceClass(row) {
  const c = row.confidence ?? 50
  if (c >= 70) return 'conf-high'
  if (c >= 40) return 'conf-mid'
  return 'conf-low'
}

function rowClassName({ row }) {
  if (row.verification_status === 'rejected') return 'row-rejected'
  return ''
}

function countBySeverity(sev) {
  return props.findings.filter(f => f.severity === sev).length
}

function handleExpand(row, rows) {
  expandedRows.value = rows.map(r => r.vuln_id)
}

function minimalRepro(evidence) {
  return String(evidence || '')
    .split('\n')
    .map(line => line.trim())
    .find(Boolean) || '-'
}

function exploitabilityScore(row) {
  const sevWeight = { critical: 40, high: 30, medium: 20, low: 10, info: 5 }[row.severity] || 10
  const exploitWeight = row.exploitable ? 45 : 10
  const evidenceWeight = row.evidence ? 15 : 5
  return `${Math.min(100, sevWeight + exploitWeight + evidenceWeight)} / 100`
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

.mini-poc {
  display: inline-block;
  max-width: 100%;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--accent-blue);
  padding: 4px 8px;
  border-radius: var(--radius-sm);
  background: rgba(56,139,253,0.08);
  border: 1px solid rgba(56,139,253,0.2);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.exploit-score {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-secondary);
}
.exploit-score.high {
  color: var(--accent-red);
  font-weight: 600;
}

.confidence-filter {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-left: auto;
  font-size: 12px;
  color: var(--text-secondary);
}
.filter-label { white-space: nowrap; }
.filter-value { font-family: var(--font-mono); min-width: 32px; text-align: right; }

.confidence-badge {
  font-family: var(--font-mono);
  font-size: 10px;
  padding: 1px 5px;
  border-radius: 8px;
  margin-left: 4px;
  border: 1px solid;
}
.conf-high { color: #3fb950; border-color: rgba(63,185,80,0.4); }
.conf-mid  { color: #d29922; border-color: rgba(210,153,34,0.4); }
.conf-low  { color: #8b949e; border-color: rgba(139,148,158,0.3); }

.rejected-tag { margin-left: 4px; }

:deep(.row-rejected) {
  opacity: 0.45;
}

.verify-reasons {
  margin: 0;
  padding-left: 18px;
  font-size: 12px;
  color: var(--text-secondary);
  line-height: 1.6;
}
</style>
