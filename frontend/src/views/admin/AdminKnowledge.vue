<template>
  <div class="admin-knowledge">
    <div class="section-header">
      <div>
        <h2 class="section-title">知识库治理</h2>
        <p class="section-sub">按类别分组 · 全局版本编辑 · 构建与重载</p>
      </div>
      <div class="header-actions">
        <el-button type="success" size="small" @click="buildAll" :loading="buildAllLoading">一键构建</el-button>
        <el-button :icon="Refresh" size="small" @click="fetchEntries" :loading="entriesLoading">刷新</el-button>
        <el-button type="primary" size="small" @click="reloadKB" :loading="reloadLoading">重载知识库</el-button>
      </div>
    </div>

    <div class="admin-notice">
      <el-icon class="notice-icon"><Warning /></el-icon>
      <span class="notice-text">
        管理员在此页所做的编辑会写入全局层（<code>backend/knowledge/kb_data/</code>），对全体用户生效。
      </span>
    </div>

    <div class="summary-grid">
      <div class="summary-card"><span class="summary-label">条目总数</span><span class="summary-value mono">{{ entries.length }}</span></div>
      <div class="summary-card"><span class="summary-label">类别数</span><span class="summary-value mono">{{ groupedEntries.length }}</span></div>
    </div>

    <el-card class="panel" shadow="never">
      <SkeletonBlock v-if="entriesLoading && !groupedEntries.length" :rows="8" />
      <el-empty v-else-if="!groupedEntries.length" description="知识库暂为空，请先在用户侧添加或构建条目" />

      <el-collapse v-else v-model="activeCategories">
        <el-collapse-item
          v-for="group in groupedEntries"
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

          <el-table :data="group.items" size="small" stripe>
            <el-table-column prop="vuln_id" label="Vuln ID" min-width="200">
              <template #default="{ row }"><code class="vuln-id">{{ row.vuln_id }}</code></template>
            </el-table-column>
            <el-table-column label="描述" min-width="240">
              <template #default="{ row }">
                <span :title="row.description" class="desc">{{ row.description }}</span>
              </template>
            </el-table-column>
            <el-table-column label="CVEs" min-width="160">
              <template #default="{ row }">
                <span class="mono-text">{{ (row.cves || []).join(', ') || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="标签" min-width="120">
              <template #default="{ row }">
                <span>{{ (row.tags || []).join(', ') || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="default_port" label="端口" width="76" align="center">
              <template #default="{ row }">{{ row.default_port ?? '-' }}</template>
            </el-table-column>
            <el-table-column label="操作" width="200" align="center">
              <template #default="{ row }">
                <div class="ops">
                  <el-button size="small" @click="openDrawer(row)">查看</el-button>
                  <el-button size="small" type="primary" @click="openEditor(row)">编辑</el-button>
                </div>
              </template>
            </el-table-column>
          </el-table>
        </el-collapse-item>
      </el-collapse>
    </el-card>

    <el-drawer v-model="drawerVisible" title="知识条目详情" size="58%">
      <template v-if="selectedEntry">
        <div class="entry-meta">
          <div><b>Vuln ID：</b><code>{{ selectedEntry.vuln_id }}</code></div>
          <div><b>分类：</b>{{ resolveCategoryLabel(selectedEntry.category) }}</div>
          <div><b>CVEs：</b>{{ (selectedEntry.cves || []).join(', ') || '-' }}</div>
          <div><b>标签：</b>{{ (selectedEntry.tags || []).join(', ') || '-' }}</div>
          <div><b>端口：</b>{{ selectedEntry.default_port ?? '-' }}</div>
        </div>

        <div class="drawer-actions">
          <el-button type="primary" @click="openEditor(selectedEntry)">编辑</el-button>
          <el-button type="success" size="small" @click="buildEntry" :loading="buildingEntry">构建本条</el-button>
        </div>

        <pre class="json-preview"><code class="hljs language-json" v-html="selectedJsonHighlighted"></code></pre>
      </template>
    </el-drawer>

    <el-dialog
      v-model="editorVisible"
      :title="selectedEntry ? `编辑 · ${selectedEntry.vuln_id}` : '编辑 JSON'"
      width="72%"
      destroy-on-close
    >
      <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 10px">
        保存后将直接覆盖 <code>backend/knowledge/kb_data/{{ selectedEntry?.vuln_id }}.json</code>，对所有用户生效。
      </el-alert>
      <div class="editor-wrap">
        <div class="editor-pane">
          <div class="pane-title">JSON 编辑</div>
          <el-input v-model="jsonDraft" type="textarea" :rows="22" class="json-input" />
        </div>
        <div class="preview-pane">
          <div class="pane-title">高亮预览</div>
          <pre class="json-preview editor-preview"><code class="hljs language-json" v-html="draftJsonHighlighted"></code></pre>
        </div>
      </div>
      <template #footer>
        <el-button @click="editorVisible = false">取消</el-button>
        <el-button type="primary" :loading="saveLoading" @click="saveJson">保存并重载</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh, Warning } from '@element-plus/icons-vue'
import hljs from 'highlight.js/lib/core'
import jsonLanguage from 'highlight.js/lib/languages/json'
import { api } from '@/api'
import { resolveCategoryColor } from '@/utils/categoryColor'
import { resolveCategoryLabel } from '@/utils/categoryLabel'
import SkeletonBlock from '@/components/SkeletonBlock.vue'

hljs.registerLanguage('json', jsonLanguage)

const entriesLoading = ref(false)
const entries = ref([])
const reloadLoading = ref(false)
const buildAllLoading = ref(false)
const activeCategories = ref([])

const selectedEntry = ref(null)
const selectedJsonRaw = ref('')
const drawerVisible = ref(false)

const editorVisible = ref(false)
const saveLoading = ref(false)
const jsonDraft = ref('')
const buildingEntry = ref(false)

function escapeHtml(text) {
  return String(text || '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
}
function highlightJson(text) {
  const raw = String(text || '')
  if (!raw) return ''
  try { return hljs.highlight(raw, { language: 'json' }).value } catch { return escapeHtml(raw) }
}
function prettyJson(raw) {
  try { return JSON.stringify(JSON.parse(raw), null, 2) } catch { return raw }
}

const selectedJsonHighlighted = computed(() => highlightJson(prettyJson(selectedJsonRaw.value)))
const draftJsonHighlighted = computed(() => highlightJson(jsonDraft.value))

const groupedEntries = computed(() => {
  const map = new Map()
  for (const item of entries.value) {
    const category = String(item.category || 'uncategorized')
    if (!map.has(category)) map.set(category, [])
    map.get(category).push(item)
  }
  const groups = [...map.entries()].map(([category, items]) => ({
    category,
    items: items.sort((a, b) => String(a.vuln_id || '').localeCompare(String(b.vuln_id || ''))),
  }))
  groups.sort((a, b) => a.category.localeCompare(b.category))
  return groups
})

function categoryStyle(category) {
  return { '--cat-tone': resolveCategoryColor(category) }
}

async function fetchEntries() {
  entriesLoading.value = true
  try {
    const res = await api.getKnowledgeEntries()
    entries.value = res.entries || []
    activeCategories.value = groupedEntries.value.map(g => g.category)
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '读取知识库列表失败')
  } finally {
    entriesLoading.value = false
  }
}

async function reloadKB() {
  reloadLoading.value = true
  try {
    await api.reloadKnowledge()
    ElMessage.success('知识库已重载')
    await fetchEntries()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '重载知识库失败')
  } finally {
    reloadLoading.value = false
  }
}

async function buildAll() {
  try {
    await ElMessageBox.confirm('确认全量构建知识库？可能耗时数分钟。', '一键构建', { type: 'warning' })
  } catch { return }
  buildAllLoading.value = true
  try {
    const res = await api.buildKnowledge()
    ElMessage.success(`构建完成：成功 ${res.success}，失败 ${res.failed}`)
    await fetchEntries()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '全量构建失败')
  } finally {
    buildAllLoading.value = false
  }
}

async function openDrawer(row) {
  selectedEntry.value = row
  selectedJsonRaw.value = ''
  drawerVisible.value = true
  try {
    const raw = await api.getKnowledgeRaw(row.vuln_id)
    selectedJsonRaw.value = raw.json || ''
  } catch (e) {
    selectedJsonRaw.value = `读取失败: ${e?.response?.data?.detail || e.message}`
  }
}

async function buildEntry() {
  const vulnId = selectedEntry.value?.vuln_id
  if (!vulnId) return
  buildingEntry.value = true
  try {
    const res = await api.buildKnowledge(vulnId)
    if (res.failed > 0) ElMessage.warning(`${vulnId} 构建失败，请检查后端日志`)
    else ElMessage.success(`${vulnId} 构建成功`)
    await fetchEntries()
    try {
      const raw = await api.getKnowledgeRaw(vulnId)
      selectedJsonRaw.value = raw.json || ''
    } catch { /* ignore */ }
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '构建失败')
  } finally {
    buildingEntry.value = false
  }
}

async function openEditor(row) {
  selectedEntry.value = row
  jsonDraft.value = ''
  try {
    const raw = await api.getKnowledgeRaw(row.vuln_id)
    selectedJsonRaw.value = raw.json || ''
    jsonDraft.value = prettyJson(raw.json || '')
    editorVisible.value = true
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '读取 JSON 失败')
  }
}

async function saveJson() {
  const entry = selectedEntry.value
  if (!entry?.vuln_id) return
  if (!jsonDraft.value.trim()) {
    ElMessage.warning('JSON 内容不能为空')
    return
  }
  try {
    await ElMessageBox.confirm(
      `确认将 ${entry.vuln_id} 保存？所有用户都将看到此版本。`,
      '保存知识条目', { type: 'warning' },
    )
  } catch { return }
  saveLoading.value = true
  try {
    await api.adminSaveKnowledgeRawGlobal(entry.vuln_id, jsonDraft.value)
    await api.reloadKnowledge()
    selectedJsonRaw.value = jsonDraft.value
    editorVisible.value = false
    ElMessage.success('全局版本已保存并重载')
    await fetchEntries()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '保存 JSON 失败')
  } finally {
    saveLoading.value = false
  }
}

onMounted(fetchEntries)
</script>

<style scoped>
.section-header {
  display: flex; align-items: flex-start; justify-content: space-between;
  margin-bottom: 18px; gap: 12px; flex-wrap: wrap;
}
.section-title { font-size: 20px; font-weight: 700; color: var(--text-primary); margin: 0 0 4px; }
.section-sub { font-size: 13px; color: var(--text-secondary); margin: 0; }
.header-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }

.admin-notice {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  margin-bottom: 14px;
  border: 1px solid color-mix(in srgb, var(--accent-red) 40%, var(--border));
  background: color-mix(in srgb, var(--accent-red) 10%, var(--bg-surface));
  border-radius: var(--radius-md);
  color: color-mix(in srgb, var(--accent-red) 70%, var(--text-primary));
  font-size: 12.5px;
  line-height: 1.5;
}
.admin-notice .notice-icon {
  flex-shrink: 0;
  font-size: 16px;
  color: var(--accent-red);
}
.admin-notice .notice-text { flex: 1; }
.admin-notice code {
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 1px 6px;
  border-radius: 4px;
  background: color-mix(in srgb, var(--accent-red) 16%, var(--bg-base));
  color: color-mix(in srgb, var(--accent-red) 85%, var(--text-primary));
}

.summary-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
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
.mono { font-family: var(--font-mono); }
.mono-text { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); }

.panel { border-radius: var(--radius-lg) !important; border: 1px solid var(--border) !important; }

.vuln-id { font-size: 12px; color: var(--text-primary); }
.desc { font-size: 12px; color: var(--text-secondary); }
.ops { display: flex; justify-content: center; gap: 6px; flex-wrap: wrap; }

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
:deep(.el-collapse-item__header) {
  height: auto; padding: 6px 0; background: transparent;
}

.entry-meta { display: grid; gap: 8px; margin-bottom: 12px; color: var(--text-secondary); }
.drawer-actions { display: flex; justify-content: flex-end; gap: 8px; margin-bottom: 10px; }

.json-preview {
  margin: 0; padding: 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--hljs-bg);
  color: var(--hljs-fg);
  max-height: 62vh;
  overflow: auto;
  white-space: pre-wrap; word-break: break-word;
  font-family: var(--font-mono); font-size: 12px; line-height: 1.6;
}

.editor-wrap { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.pane-title { margin-bottom: 6px; color: var(--text-secondary); font-size: 12px; }
.json-input :deep(.el-textarea__inner) {
  min-height: 520px !important;
  font-family: var(--font-mono); font-size: 12px; line-height: 1.55;
}
.editor-preview { min-height: 520px; max-height: 520px; }

@media (max-width: 1100px) {
  .editor-wrap { grid-template-columns: 1fr; }
  .json-input :deep(.el-textarea__inner) { min-height: 300px !important; }
  .editor-preview { min-height: 300px; max-height: 300px; }
}
</style>
