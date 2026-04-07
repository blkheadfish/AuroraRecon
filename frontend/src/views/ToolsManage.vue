<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">工具管理</h1>
        <p class="page-sub">按类别查看已注册工具，支持展开/收起</p>
      </div>
      <div class="header-actions">
        <el-select v-model="windowHours" size="small" style="width: 130px">
          <el-option label="最近 6 小时" :value="6" />
          <el-option label="最近 24 小时" :value="24" />
          <el-option label="最近 72 小时" :value="72" />
        </el-select>
        <el-button @click="fetchTools" :loading="loading">刷新</el-button>
      </div>
    </div>

    <div class="summary-grid">
      <el-card class="summary-card">
        <div class="summary-label">工具总数</div>
        <div class="summary-value mono">{{ totalTools }}</div>
      </el-card>
      <el-card class="summary-card">
        <div class="summary-label">类别数</div>
        <div class="summary-value mono">{{ groupedCategories.length }}</div>
      </el-card>
      <el-card class="summary-card">
        <div class="summary-label">执行器数</div>
        <div class="summary-value mono">{{ executorCount }}</div>
      </el-card>
    </div>

    <el-card class="panel" v-loading="loading">
      <el-empty v-if="!groupedCategories.length" description="暂无工具数据" />

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
              </div>
            </div>
          </template>

          <el-table :data="group.items" size="small">
            <el-table-column prop="name" label="工具名" min-width="180" />
            <el-table-column prop="executor" label="执行器" width="140" />
            <el-table-column prop="timeout" label="超时(s)" width="100" align="center" />
          </el-table>
        </el-collapse-item>
      </el-collapse>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { resolveCategoryColor } from '@/utils/categoryColor'
import { resolveCategoryLabel } from '@/utils/categoryLabel'

const loading = ref(false)
const windowHours = ref(24)
const totalTools = ref(0)
const rawTools = ref([])
const rawExecutors = ref({})
const activeCategories = ref([])
const warnedOnce = ref(false)

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

const executorCount = computed(() => Object.keys(rawExecutors.value || {}).length)

function categoryStyle(category) {
  return {
    '--cat-tone': resolveCategoryColor(category),
  }
}

async function fetchTools() {
  loading.value = true
  try {
    const metrics = await api.getMetricsOverview(windowHours.value)
    const overview = metrics?.tool_overview || {}
    totalTools.value = Number(overview.total_tools || 0)
    rawTools.value = overview.tools || []
    rawExecutors.value = overview.by_executor || {}
    activeCategories.value = groupedCategories.value.map((item) => item.category)
    warnedOnce.value = false
  } catch (e) {
    totalTools.value = 0
    rawTools.value = []
    rawExecutors.value = {}
    const status = e?.response?.status ?? null
    if (status === 404) {
      if (!warnedOnce.value) {
        warnedOnce.value = true
        ElMessage.warning('后端暂未提供可用工具概览接口')
      }
    } else {
      ElMessage.error(e?.response?.data?.detail || e.message || '读取工具概览失败')
    }
  } finally {
    loading.value = false
  }
}

onMounted(fetchTools)
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; }
.page-title { font-size: 24px; font-weight: 700; color: var(--text-primary); }
.page-sub { margin-top: 4px; color: var(--text-secondary); font-size: 13px; }
.header-actions { display: flex; gap: 8px; align-items: center; }

.summary-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin-bottom: 12px; }
.summary-card :deep(.el-card__body) { padding: 12px !important; }
.summary-label { color: var(--text-muted); font-size: 12px; }
.summary-value { margin-top: 5px; color: var(--text-primary); font-size: 20px; font-weight: 700; }
.mono { font-family: var(--font-mono); }

.panel { border-radius: var(--radius-lg) !important; }
.collapse-title {
  display: flex;
  align-items: center;
  width: 100%;
}
.cat-header {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 7px 10px;
  border-radius: 10px;
  border: 1px solid color-mix(in srgb, var(--cat-tone) 48%, var(--border));
  background: linear-gradient(
    90deg,
    color-mix(in srgb, var(--cat-tone) 24%, var(--bg-elevated)),
    color-mix(in srgb, var(--cat-tone) 7%, transparent)
  );
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--cat-tone) 14%, transparent);
}
.cat-marker {
  width: 4px;
  height: 18px;
  border-radius: 99px;
  background: color-mix(in srgb, var(--cat-tone) 82%, #ffffff);
  box-shadow: 0 0 8px color-mix(in srgb, var(--cat-tone) 36%, transparent);
}
.cat-name {
  color: var(--text-primary);
  font-size: 15px;
  letter-spacing: 0.02em;
  font-weight: 700;
}
:deep(.cat-count.el-tag) {
  margin-left: auto;
  font-family: var(--font-mono);
  font-weight: 700;
  color: color-mix(in srgb, var(--text-primary) 88%, var(--cat-tone));
  border-color: color-mix(in srgb, var(--cat-tone) 54%, var(--border));
  background: color-mix(in srgb, var(--bg-base) 82%, transparent);
}
:deep(.el-collapse-item__header) {
  height: auto;
  padding: 6px 0;
  background: transparent;
}

@media (max-width: 900px) {
  .summary-grid { grid-template-columns: 1fr; }
}
</style>
