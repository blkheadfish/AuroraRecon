<template>
  <div class="admin-tools">
    <div class="section-header">
      <div>
        <h2 class="section-title">工具管理</h2>
        <p class="section-sub">启停控制 · 超时持久化 · 调用统计</p>
      </div>
      <div class="header-actions">
        <el-button-group>
          <el-button size="small" :loading="bulkLoading" @click="bulkSetAll(true)">全部启用</el-button>
          <el-button size="small" :loading="bulkLoading" @click="bulkSetAll(false)">全部禁用</el-button>
          <el-button size="small" :loading="bulkLoading" @click="bulkInvertAll">反选</el-button>
        </el-button-group>
        <el-select v-model="windowHours" size="small" style="width: 130px" @change="fetchAll">
          <el-option label="最近 6 小时" :value="6" />
          <el-option label="最近 24 小时" :value="24" />
          <el-option label="最近 72 小时" :value="72" />
        </el-select>
        <el-button :loading="loading" :icon="Refresh" size="small" @click="fetchAll">刷新</el-button>
      </div>
    </div>

    <div class="summary-grid">
      <div class="summary-card"><span class="summary-label">工具总数</span><span class="summary-value mono">{{ totalTools }}</span></div>
      <div class="summary-card"><span class="summary-label">类别数</span><span class="summary-value mono">{{ groupedCategories.length }}</span></div>
      <div class="summary-card"><span class="summary-label">已禁用</span><span class="summary-value mono admin-red">{{ disabledCount }}</span></div>
      <div class="summary-card"><span class="summary-label">超时自定义</span><span class="summary-value mono">{{ customTimeoutCount }}</span></div>
    </div>

    <el-card class="panel" shadow="never">
      <SkeletonBlock v-if="loading && !groupedCategories.length" :rows="8" />
      <el-empty v-else-if="!groupedCategories.length" description="暂未注册任何工具，请检查 backend/tools/ 配置" />

      <el-collapse v-else v-model="activeCategories">
        <el-collapse-item
          v-for="group in groupedCategories"
          :key="group.category"
          :name="group.category"
        >
          <template #title>
            <div class="collapse-title">
              <div class="cat-header" :style="categoryStyle(group.category)">
                <span class="cat-marker" aria-hidden="true"></span>
                <span class="cat-name">{{ resolveCategoryLabel(group.category) }}</span>
                <el-tag size="small" class="cat-count">{{ group.items.length }}</el-tag>
                <div class="group-actions" @click.stop>
                  <el-button size="small" text :disabled="bulkLoading" @click="bulkSetGroup(group, true)">组内全启用</el-button>
                  <el-button size="small" text :disabled="bulkLoading" @click="bulkSetGroup(group, false)">组内全禁用</el-button>
                  <el-button size="small" text :disabled="bulkLoading" @click="bulkInvertGroup(group)">组内反选</el-button>
                </div>
              </div>
            </div>
          </template>

          <el-table :data="group.items" size="small" stripe>
            <el-table-column prop="name" label="工具名" min-width="220">
              <template #default="{ row }">
                <code class="tool-name">{{ row.name }}</code>
              </template>
            </el-table-column>
            <el-table-column prop="executor" label="执行器" width="140" />
            <el-table-column label="超时 (秒)" width="160" align="center">
              <template #default="{ row }">
                <el-input-number
                  :model-value="row.timeout"
                  :min="1" :max="7200" :step="10" size="small"
                  controls-position="right"
                  style="width: 120px"
                  @change="(val) => onTimeoutChange(row, val)"
                  :disabled="savingTimeout[row.name]"
                />
              </template>
            </el-table-column>
            <el-table-column label="调用次数" width="100" align="center">
              <template #default="{ row }">
                <span class="mono">{{ toolStats[row.name]?.calls ?? 0 }}</span>
              </template>
            </el-table-column>
            <el-table-column label="成功率" width="110" align="center">
              <template #default="{ row }">
                <span v-if="toolStats[row.name]" class="mono" :class="rateClass(toolStats[row.name].success_rate)">
                  {{ toolStats[row.name].success_rate }}%
                </span>
                <span v-else class="text-muted">—</span>
              </template>
            </el-table-column>
            <el-table-column label="平均耗时" width="110" align="center">
              <template #default="{ row }">
                <span v-if="toolStats[row.name]" class="mono small">{{ Math.round(toolStats[row.name].avg_elapsed_ms) }} ms</span>
                <span v-else class="text-muted">—</span>
              </template>
            </el-table-column>
            <el-table-column label="启用" width="90" align="center">
              <template #default="{ row }">
                <el-switch
                  :model-value="row.enabled"
                  @change="(v) => onToggleEnabled(row, v)"
                  :disabled="savingEnabled[row.name]"
                />
              </template>
            </el-table-column>
          </el-table>
        </el-collapse-item>
      </el-collapse>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '@/api'
import { resolveCategoryColor } from '@/utils/categoryColor'
import { resolveCategoryLabel } from '@/utils/categoryLabel'
import SkeletonBlock from '@/components/SkeletonBlock.vue'

const loading = ref(false)
const windowHours = ref(24)
const totalTools = ref(0)
const rawTools = ref([])
const topTools = ref([])
const overrides = ref([])
const activeCategories = ref([])
const savingEnabled = reactive({})
const savingTimeout = reactive({})
const bulkLoading = ref(false)

const groupedCategories = computed(() => {
  const map = new Map()
  for (const item of rawTools.value) {
    const category = String(item.category || 'uncategorized')
    if (!map.has(category)) map.set(category, [])
    map.get(category).push(item)
  }
  const rows = [...map.entries()].map(([category, items]) => ({
    category,
    items: items.sort((a, b) => String(a.name).localeCompare(String(b.name))),
  }))
  rows.sort((a, b) => a.category.localeCompare(b.category))
  return rows
})

const toolStats = computed(() => {
  const map = {}
  for (const t of topTools.value) {
    map[t.tool] = t
  }
  return map
})

const disabledCount = computed(() => rawTools.value.filter(t => t.enabled === false).length)

const customTimeoutCount = computed(() => {
  let n = 0
  for (const o of overrides.value) {
    try {
      const d = o.detail_json ? JSON.parse(o.detail_json) : {}
      if (d && typeof d.timeout !== 'undefined') n++
    } catch { /* ignore */ }
  }
  return n
})

function categoryStyle(category) {
  return { '--cat-tone': resolveCategoryColor(category) }
}

function rateClass(rate) {
  if (rate >= 80) return 'rate-ok'
  if (rate >= 50) return 'rate-warn'
  return 'rate-err'
}

async function fetchAll() {
  loading.value = true
  try {
    const [metrics, overridesRes] = await Promise.all([
      api.getMetricsOverview(windowHours.value),
      api.adminListOverrides('tool').catch(() => ({ items: [] })),
    ])
    const overview = metrics?.tool_overview || {}
    totalTools.value = Number(overview.total_tools || 0)
    rawTools.value = overview.tools || []
    topTools.value = metrics?.tool_invocation_overview?.top_tools || []
    overrides.value = overridesRes?.items || []
    activeCategories.value = groupedCategories.value.map(g => g.category)
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '加载失败')
  } finally {
    loading.value = false
  }
}

async function onToggleEnabled(row, value) {
  savingEnabled[row.name] = true
  try {
    await api.adminSetToolEnabled(row.name, value)
    row.enabled = value
    ElMessage.success(`工具 ${row.name} 已${value ? '启用' : '禁用'}`)
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '操作失败')
  } finally {
    savingEnabled[row.name] = false
  }
}

async function applyBulkToggle(rows, computeTarget, successLabel) {
  if (!rows.length) {
    ElMessage.info('没有可操作的工具')
    return
  }
  bulkLoading.value = true
  let ok = 0
  let failed = 0
  try {
    for (const row of rows) {
      const target = computeTarget(row)
      if (row.enabled === target) continue
      try {
        await api.adminSetToolEnabled(row.name, target)
        row.enabled = target
        ok += 1
      } catch {
        failed += 1
      }
    }
    if (failed === 0) {
      ElMessage.success(`${successLabel} ${ok} 项`)
    } else {
      ElMessage.warning(`${successLabel} 成功 ${ok} 项，失败 ${failed} 项`)
    }
  } finally {
    bulkLoading.value = false
  }
}

function bulkSetAll(value) {
  return applyBulkToggle(rawTools.value, () => value, value ? '批量启用' : '批量禁用')
}
function bulkInvertAll() {
  return applyBulkToggle(rawTools.value, row => !row.enabled, '批量反选')
}
function bulkSetGroup(group, value) {
  return applyBulkToggle(group.items, () => value, value ? '组内启用' : '组内禁用')
}
function bulkInvertGroup(group) {
  return applyBulkToggle(group.items, row => !row.enabled, '组内反选')
}

async function onTimeoutChange(row, value) {
  if (!value || value === row.timeout) return
  savingTimeout[row.name] = true
  try {
    await api.adminSetToolTimeout(row.name, value)
    row.timeout = value
    ElMessage.success(`超时已更新为 ${value} 秒`)
    const existing = overrides.value.find(o => o.resource_type === 'tool' && o.resource_key === row.name)
    if (existing) existing.detail_json = JSON.stringify({ timeout: value })
    else overrides.value.push({
      id: row.name, resource_type: 'tool', resource_key: row.name,
      enabled: true, detail_json: JSON.stringify({ timeout: value }), updated_at: new Date().toISOString(),
    })
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '保存超时失败')
  } finally {
    savingTimeout[row.name] = false
  }
}

onMounted(fetchAll)
</script>

<style scoped>
.section-header {
  display: flex; align-items: flex-start; justify-content: space-between;
  margin-bottom: 18px; gap: 12px; flex-wrap: wrap;
}
.section-title { font-size: 20px; font-weight: 700; color: var(--text-primary); margin: 0 0 4px; }
.section-sub { font-size: 13px; color: var(--text-secondary); margin: 0; }
.header-actions { display: flex; gap: 10px; align-items: center; }

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 12px; margin-bottom: 16px;
}
.summary-card {
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--bg-surface);
  display: flex; flex-direction: column; gap: 2px;
}
.summary-label { font-size: 12px; color: var(--text-muted); }
.summary-value {
  font-family: var(--font-mono); font-size: 22px; font-weight: 700;
  color: var(--text-primary); line-height: 1.1;
}
.admin-red { color: var(--accent-red); }
.mono { font-family: var(--font-mono); }
.small { font-size: 11px; }

.panel { border-radius: var(--radius-lg) !important; border: 1px solid var(--border) !important; }

.tool-name { font-size: 12px; color: var(--text-primary); }
.text-muted { color: var(--text-muted); }
.rate-ok { color: var(--accent-green); }
.rate-warn { color: var(--accent-yellow); }
.rate-err { color: var(--accent-red); }

.collapse-title { display: flex; align-items: center; width: 100%; }
.cat-header {
  width: 100%; display: flex; align-items: center; gap: 10px;
  padding: 7px 10px; border-radius: 10px;
  border: 1px solid color-mix(in srgb, var(--cat-tone) 48%, var(--border));
  background: linear-gradient(
    90deg,
    color-mix(in srgb, var(--cat-tone) 24%, var(--bg-elevated)),
    color-mix(in srgb, var(--cat-tone) 7%, transparent)
  );
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--cat-tone) 14%, transparent);
}
.cat-marker {
  width: 4px; height: 18px; border-radius: 99px;
  background: color-mix(in srgb, var(--cat-tone) 82%, #ffffff);
  box-shadow: 0 0 8px color-mix(in srgb, var(--cat-tone) 36%, transparent);
}
.cat-name {
  color: var(--text-primary); font-size: 15px;
  letter-spacing: 0.02em; font-weight: 700;
}
:deep(.cat-count.el-tag) {
  margin-left: auto;
  font-family: var(--font-mono); font-weight: 700;
  color: color-mix(in srgb, var(--text-primary) 88%, var(--cat-tone));
  border-color: color-mix(in srgb, var(--cat-tone) 54%, var(--border));
  background: color-mix(in srgb, var(--bg-base) 82%, transparent);
}
.group-actions {
  display: inline-flex;
  gap: 2px;
  margin-left: 4px;
  padding-left: 8px;
  border-left: 1px solid color-mix(in srgb, var(--cat-tone) 30%, var(--border));
}
.group-actions :deep(.el-button) {
  height: 24px;
  padding: 0 8px;
  font-size: 11px;
  color: var(--text-secondary);
}
.group-actions :deep(.el-button:hover) {
  color: color-mix(in srgb, var(--cat-tone) 75%, var(--text-primary));
  background: transparent;
}
:deep(.el-collapse-item__header) {
  height: auto; padding: 6px 0; background: transparent;
}
</style>
