<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">知识库管理</h1>
        <p class="page-sub">支持查看与编辑检测知识 JSON，保存后重载知识库</p>
      </div>
      <div class="header-actions">
        <el-button @click="fetchEntries" :loading="entriesLoading">刷新</el-button>
        <el-button class="header-reload-btn" type="primary" @click="reloadKB" :loading="reloadLoading">重载知识库</el-button>
      </div>
    </div>

    <el-card class="panel" v-loading="entriesLoading">
      <el-empty v-if="!groupedEntries.length" description="暂无知识库条目" />

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
                <span class="cat-name">{{ group.category }}</span>
                <el-tag size="small" class="cat-count">{{ group.items.length }}</el-tag>
              </div>
            </div>
          </template>

          <el-table :data="group.items" size="small">
            <el-table-column prop="vuln_id" label="Vuln ID" min-width="200" />
            <el-table-column label="描述" min-width="240">
              <template #default="{ row }">
                <span :title="row.description">{{ row.description }}</span>
              </template>
            </el-table-column>
            <el-table-column label="CVEs" min-width="180">
              <template #default="{ row }">
                <span class="mono-text">{{ (row.cves || []).join(', ') || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="Tags" min-width="160">
              <template #default="{ row }">
                <span>{{ (row.tags || []).join(', ') || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="default_port" label="端口" width="90" align="center">
              <template #default="{ row }">
                {{ row.default_port ?? '-' }}
              </template>
            </el-table-column>
            <el-table-column label="操作" width="200" align="center">
              <template #default="{ row }">
                <div class="ops">
                  <el-button class="op-view" size="small" @click="openDrawer(row)">查看</el-button>
                  <el-button class="op-edit" size="small" @click="openEditor(row)">编辑</el-button>
                </div>
              </template>
            </el-table-column>
          </el-table>
        </el-collapse-item>
      </el-collapse>
    </el-card>

    <el-drawer v-model="drawerVisible" title="知识条目详情" size="55%">
      <template v-if="selectedEntry">
        <div class="entry-meta">
          <div><b>Vuln ID：</b><code>{{ selectedEntry.vuln_id }}</code></div>
          <div><b>分类：</b>{{ selectedEntry.category }}</div>
          <div><b>CVEs：</b>{{ (selectedEntry.cves || []).join(', ') || '-' }}</div>
          <div><b>Tags：</b>{{ (selectedEntry.tags || []).join(', ') || '-' }}</div>
          <div><b>端口：</b>{{ selectedEntry.default_port ?? '-' }}</div>
        </div>
        <div class="drawer-actions">
          <el-button class="drawer-edit-btn" @click="openEditor(selectedEntry)">编辑 JSON</el-button>
        </div>
        <pre class="json-preview"><code class="hljs language-json" v-html="selectedJsonHighlighted"></code></pre>
      </template>
    </el-drawer>

    <el-dialog
      v-model="editorVisible"
      :title="selectedEntry ? `编辑 JSON · ${selectedEntry.vuln_id}` : '编辑 JSON'"
      width="72%"
      destroy-on-close
    >
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
import { ElMessage } from 'element-plus'
import hljs from 'highlight.js/lib/core'
import jsonLanguage from 'highlight.js/lib/languages/json'
import { api } from '@/api'
import { resolveCategoryColor } from '@/utils/categoryColor'

hljs.registerLanguage('json', jsonLanguage)

const entriesLoading = ref(false)
const entries = ref([])
const reloadLoading = ref(false)
const activeCategories = ref([])

const selectedEntry = ref(null)
const selectedJsonRaw = ref('')
const drawerVisible = ref(false)
const editorVisible = ref(false)
const saveLoading = ref(false)
const jsonDraft = ref('')

function escapeHtml(text) {
  return String(text || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function highlightJson(text) {
  const raw = String(text || '')
  if (!raw) return ''
  try {
    return hljs.highlight(raw, { language: 'json' }).value
  } catch {
    return escapeHtml(raw)
  }
}

function prettyJson(raw) {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
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
  return {
    '--cat-tone': resolveCategoryColor(category),
  }
}

async function fetchEntries() {
  entriesLoading.value = true
  try {
    const res = await api.getKnowledgeEntries()
    entries.value = res.entries || []
    activeCategories.value = groupedEntries.value.map((g) => g.category)
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
  saveLoading.value = true
  try {
    await api.saveKnowledgeRaw(entry.vuln_id, jsonDraft.value)
    await api.reloadKnowledge()
    selectedJsonRaw.value = jsonDraft.value
    editorVisible.value = false
    ElMessage.success('JSON 已保存并重载知识库')
    await fetchEntries()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '保存 JSON 失败')
  } finally {
    saveLoading.value = false
  }
}

onMounted(async () => {
  await fetchEntries()
})
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; }
.page-title { font-size: 24px; font-weight: 700; color: var(--text-primary); }
.page-sub { color: var(--text-secondary); font-size: 13px; margin-top: 4px; }
.header-actions { display: flex; gap: 8px; }
:deep(.header-reload-btn.el-button--primary) {
  color: #f6fbff !important;
  font-weight: 600;
  background: linear-gradient(
    145deg,
    color-mix(in srgb, var(--accent-blue) 72%, #1a3d5c),
    color-mix(in srgb, var(--accent-blue) 54%, var(--bg-elevated))
  ) !important;
  border: 1px solid color-mix(in srgb, var(--accent-blue) 78%, #2a5080) !important;
  box-shadow: 0 4px 14px color-mix(in srgb, var(--accent-blue) 28%, transparent);
}
:deep(.header-reload-btn.el-button--primary:hover),
:deep(.header-reload-btn.el-button--primary:focus-visible) {
  color: #ffffff !important;
  border-color: color-mix(in srgb, var(--accent-blue) 88%, #3d6fa8) !important;
  background: linear-gradient(
    145deg,
    color-mix(in srgb, var(--accent-blue) 82%, #1f4a6e),
    color-mix(in srgb, var(--accent-blue) 62%, var(--bg-elevated))
  ) !important;
}
.ops { display: flex; justify-content: center; flex-wrap: wrap; gap: 8px; }
.op-view {
  color: var(--text-primary);
  background: var(--bg-elevated);
  border: 1px solid var(--border);
}
.op-view:hover {
  border-color: var(--accent-blue);
  color: var(--accent-blue);
}
:deep(.op-edit.el-button) {
  color: #ecf7ff !important;
  background: linear-gradient(
    145deg,
    color-mix(in srgb, var(--accent-blue) 48%, var(--bg-elevated)),
    color-mix(in srgb, var(--accent-blue) 28%, #0d1520)
  ) !important;
  border: 1px solid color-mix(in srgb, var(--accent-blue) 68%, var(--border)) !important;
  font-weight: 600;
  box-shadow:
    inset 0 0 0 1px color-mix(in srgb, #ffffff 8%, transparent),
    0 4px 12px color-mix(in srgb, var(--accent-blue) 22%, transparent);
}
:deep(.op-edit.el-button:hover),
:deep(.op-edit.el-button:focus-visible) {
  color: #ffffff !important;
  border-color: color-mix(in srgb, var(--accent-blue) 82%, var(--border)) !important;
  background: linear-gradient(
    145deg,
    color-mix(in srgb, var(--accent-blue) 58%, var(--bg-elevated)),
    color-mix(in srgb, var(--accent-blue) 38%, #0d1520)
  ) !important;
}

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
.mono-text { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); }
.entry-meta { display: grid; gap: 8px; margin-bottom: 12px; color: var(--text-secondary); }
.drawer-actions { display: flex; justify-content: flex-end; margin-bottom: 10px; }
:deep(.drawer-edit-btn.el-button) {
  color: #ecf7ff !important;
  background: linear-gradient(
    145deg,
    color-mix(in srgb, var(--accent-blue) 44%, var(--bg-elevated)),
    color-mix(in srgb, var(--accent-green) 20%, var(--bg-elevated))
  ) !important;
  border: 1px solid color-mix(in srgb, var(--accent-blue) 78%, var(--border)) !important;
  box-shadow:
    inset 0 0 0 1px color-mix(in srgb, var(--accent-green) 28%, transparent),
    0 6px 14px color-mix(in srgb, var(--accent-blue) 28%, transparent);
  font-weight: 600;
  letter-spacing: 0.02em;
}
:deep(.drawer-edit-btn.el-button:hover) {
  color: #ffffff !important;
  border-color: color-mix(in srgb, var(--accent-green) 82%, var(--accent-blue)) !important;
  background: linear-gradient(
    145deg,
    color-mix(in srgb, var(--accent-blue) 52%, var(--bg-elevated)),
    color-mix(in srgb, var(--accent-green) 34%, var(--bg-elevated))
  ) !important;
}
:deep(.drawer-edit-btn.el-button:focus-visible) {
  outline: 2px solid color-mix(in srgb, var(--accent-green) 70%, #ffffff);
  outline-offset: 1px;
}
:deep(.drawer-edit-btn.el-button:active) {
  transform: translateY(1px);
}

.json-preview {
  margin: 0;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--hljs-bg);
  color: var(--hljs-fg);
  max-height: 62vh;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.6;
}

.editor-wrap {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
.pane-title {
  margin-bottom: 6px;
  color: var(--text-secondary);
  font-size: 12px;
}
.json-input :deep(.el-textarea__inner) {
  min-height: 520px !important;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.55;
}
.editor-preview {
  min-height: 520px;
  max-height: 520px;
}

@media (max-width: 1100px) {
  .editor-wrap { grid-template-columns: 1fr; }
  .json-input :deep(.el-textarea__inner) { min-height: 300px !important; }
  .editor-preview { min-height: 300px; max-height: 300px; }
}
</style>
