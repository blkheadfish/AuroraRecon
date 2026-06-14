<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">技能管理</h1>
        <p class="page-sub">支持查看与编辑 YAML，保存后自动重载技能注册表</p>
      </div>
      <div class="header-actions">
        <el-button @click="fetchSkills" :loading="skillsLoading">刷新</el-button>
        <el-button class="header-reload-btn" type="primary" @click="reloadAllSkills" :loading="reloadLoading">重载技能</el-button>
      </div>
    </div>

    <el-card class="panel" v-loading="skillsLoading">
      <el-empty v-if="!groupedSkills.length" description="暂无技能数据" />

      <el-collapse v-else v-model="activeCategories">
        <el-collapse-item
          v-for="group in groupedSkills"
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
            <el-table-column prop="skill_id" label="技能 ID" min-width="180" />
            <el-table-column prop="name" label="名称" min-width="180" />
            <el-table-column prop="paths_count" label="利用路径" width="100" align="center" />
            <el-table-column prop="probes_count" label="探测数" width="90" align="center" />
            <el-table-column label="来源文件" min-width="260">
              <template #default="{ row }">
                <code class="source-path">{{ shortSource(row.source) }}</code>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="200" align="center">
              <template #default="{ row }">
                <div class="ops">
                  <el-button class="op-view" size="small" @click="openSkillDrawer(row)">查看</el-button>
                  <el-button class="op-edit" size="small" @click="openSkillEditor(row)">编辑</el-button>
                </div>
              </template>
            </el-table-column>
          </el-table>
        </el-collapse-item>
      </el-collapse>
    </el-card>

    <!-- W4-T3: 草案（待审核） -->
    <el-card class="panel" v-if="drafts.length" style="margin-top: 16px">
      <template #header>
        <div class="card-header">
          <span class="card-header-title">草案（待审核）</span>
          <el-tag type="warning" size="small">{{ drafts.length }} 个</el-tag>
        </div>
      </template>
      <el-table :data="drafts" size="small">
        <el-table-column prop="skill_id" label="技能 ID" min-width="180" />
        <el-table-column prop="name" label="名称" min-width="140" />
        <el-table-column prop="category" label="分类" width="120">
          <template #default="{ row }">
            <el-tag size="small">{{ row.category }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="来源任务" width="140">
          <template #default="{ row }">
            <code class="source-path">{{ row.source_task_id?.slice(0, 12) || '—' }}</code>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="260" align="center">
          <template #default="{ row }">
            <div class="ops">
              <el-button class="op-view" size="small" @click="previewDraft(row)">预览</el-button>
              <el-button type="success" size="small" @click="promoteDraft(row)">转正</el-button>
              <el-button type="danger" size="small" plain @click="discardDraft(row)">丢弃</el-button>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="draftPreviewVisible" title="草案预览" width="60%" destroy-on-close>
      <pre class="yaml-preview"><code class="hljs language-yaml" v-html="selectedDraftHighlighted"></code></pre>
      <template #footer>
        <el-button @click="draftPreviewVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="skillDrawerVisible" title="技能详情" size="55%">
      <template v-if="selectedSkill">
        <div class="skill-meta">
          <div><b>技能 ID：</b><code>{{ selectedSkill.skill_id }}</code></div>
          <div><b>名称：</b>{{ selectedSkill.name }}</div>
          <div><b>分类：</b>{{ resolveCategoryLabel(selectedSkill.category) }}</div>
          <div><b>路径数：</b>{{ selectedSkill.paths_count }}，<b>探测数：</b>{{ selectedSkill.probes_count }}</div>
          <div><b>来源：</b><code>{{ selectedSkill.source }}</code></div>
        </div>
        <!-- W4-T2: 执行学习统计 -->
        <div v-if="skillStats" class="skill-stats-section">
          <h4 class="stats-title">执行学习统计</h4>
          <div class="stats-summary">
            <span>总执行 {{ skillStats.total_runs }} 次</span>
            <span class="stats-sep">|</span>
            <span>成功率 <b>{{ (skillStats.success_rate * 100).toFixed(0) }}%</b></span>
          </div>
          <div class="stats-block" v-if="sceneStatEntries.length">
            <div class="stats-subtitle">分场景成功率</div>
            <el-table :data="sceneStatEntries" size="small" max-height="200">
              <el-table-column label="场景" width="140">
                <template #default="{ row }">
                  <el-tag size="small" :type="sceneTag(row[0])">{{ row[0] }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="执行次数" width="100" align="center">
                <template #default="{ row }">{{ row[1].total }}</template>
              </el-table-column>
              <el-table-column label="成功率" min-width="120" align="center">
                <template #default="{ row }">
                  <span :style="{ color: rateColor(row[1].rate) }">{{ (row[1].rate * 100).toFixed(0) }}%</span>
                </template>
              </el-table-column>
            </el-table>
          </div>
          <div class="text-muted" v-else-if="skillStats.total_runs > 0">样本不足，暂无分场景统计</div>
        </div>
        <div v-else class="text-muted skill-stats-placeholder">暂无执行记录</div>
        <div class="drawer-actions">
          <el-button class="drawer-edit-btn" @click="openSkillEditor(selectedSkill)">编辑 YAML</el-button>
        </div>
        <pre class="yaml-preview"><code class="hljs language-yaml" v-html="selectedSkillHighlighted"></code></pre>
      </template>
    </el-drawer>

    <el-dialog
      v-model="skillEditorVisible"
      :title="selectedSkill ? `编辑 YAML · ${selectedSkill.skill_id}` : '编辑 YAML'"
      width="72%"
      destroy-on-close
    >
      <div class="editor-wrap">
        <div class="editor-pane">
          <div class="pane-title">YAML 编辑</div>
          <el-input v-model="skillYamlDraft" type="textarea" :rows="22" class="yaml-input" />
        </div>
        <div class="preview-pane">
          <div class="pane-title">高亮预览</div>
          <pre class="yaml-preview editor-preview"><code class="hljs language-yaml" v-html="draftSkillHighlighted"></code></pre>
        </div>
      </div>
      <template #footer>
        <el-button @click="skillEditorVisible = false">取消</el-button>
        <el-button type="primary" :loading="saveSkillLoading" @click="saveSkillYaml">保存并重载</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import hljs from 'highlight.js/lib/core'
import yamlLanguage from 'highlight.js/lib/languages/yaml'
import { api } from '@/api'
import { resolveCategoryColor } from '@/utils/categoryColor'
import { resolveCategoryLabel } from '@/utils/categoryLabel'

hljs.registerLanguage('yaml', yamlLanguage)

const skillsLoading = ref(false)
const skills = ref([])
const reloadLoading = ref(false)
const activeCategories = ref([])

const selectedSkill = ref(null)
const selectedSkillRaw = ref('')
const skillDrawerVisible = ref(false)
const skillEditorVisible = ref(false)
const saveSkillLoading = ref(false)
const skillYamlDraft = ref('')
const skillStats = ref(null)

const sceneStatEntries = computed(() => {
  if (!skillStats.value?.scene_breakdown) return []
  return Object.entries(skillStats.value.scene_breakdown).sort((a, b) => b[1].rate - a[1].rate)
})

function sceneTag(scene) {
  const s = String(scene || '').toLowerCase()
  if (s === 'web') return 'primary'
  if (s === 'intranet' || s === 'ad') return 'warning'
  if (s === 'cloud') return 'info'
  return ''
}

function rateColor(rate) {
  if (rate >= 0.7) return '#48b97a'
  if (rate >= 0.4) return '#d9a84e'
  return '#e06979'
}

// W4-T3: 草案
const drafts = ref([])
const draftPreviewVisible = ref(false)
const selectedDraft = ref(null)

const selectedDraftHighlighted = computed(() => {
  if (!selectedDraft.value?.yaml) return ''
  try {
    return hljs.highlight(selectedDraft.value.yaml, { language: 'yaml' }).value
  } catch {
    return escapeHtml(selectedDraft.value.yaml)
  }
})

function shortSource(source) {
  return String(text || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function highlightYaml(text) {
  const raw = String(text || '')
  if (!raw) return ''
  try {
    return hljs.highlight(raw, { language: 'yaml' }).value
  } catch {
    return escapeHtml(raw)
  }
}

const selectedSkillHighlighted = computed(() => highlightYaml(selectedSkillRaw.value))
const draftSkillHighlighted = computed(() => highlightYaml(skillYamlDraft.value))
const groupedSkills = computed(() => {
  const map = new Map()
  for (const item of skills.value) {
    const category = String(item.category || 'uncategorized')
    if (!map.has(category)) map.set(category, [])
    map.get(category).push(item)
  }
  const groups = [...map.entries()].map(([category, items]) => ({
    category,
    items: items.sort((a, b) => String(a.skill_id || '').localeCompare(String(b.skill_id || ''))),
  }))
  groups.sort((a, b) => a.category.localeCompare(b.category))
  return groups
})

function categoryStyle(category) {
  return {
    '--cat-tone': resolveCategoryColor(category),
  }
}

async function fetchSkills() {
  skillsLoading.value = true
  try {
    const res = await api.getSkills()
    skills.value = res.skills || []
    activeCategories.value = groupedSkills.value.map((group) => group.category)
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '读取技能列表失败')
  } finally {
    skillsLoading.value = false
  }
}

async function reloadAllSkills() {
  reloadLoading.value = true
  try {
    await api.reloadSkills()
    ElMessage.success('技能已重载')
    await fetchSkills()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '重载技能失败')
  } finally {
    reloadLoading.value = false
  }
}

async function openSkillDrawer(row) {
  selectedSkill.value = row
  selectedSkillRaw.value = ''
  skillStats.value = null
  skillDrawerVisible.value = true
  try {
    const raw = await api.getSkillRaw(row.skill_id)
    selectedSkillRaw.value = raw.yaml || ''
  } catch (e) {
    selectedSkillRaw.value = `读取失败: ${e?.response?.data?.detail || e.message}`
  }
  // W4-T2: load execution stats
  try {
    skillStats.value = await api.getSkillStats(row.skill_id)
  } catch {
    skillStats.value = null
  }
}

async function openSkillEditor(row) {
  selectedSkill.value = row
  skillYamlDraft.value = ''
  try {
    const raw = await api.getSkillRaw(row.skill_id)
    selectedSkillRaw.value = raw.yaml || ''
    skillYamlDraft.value = raw.yaml || ''
    skillEditorVisible.value = true
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '读取 YAML 失败')
  }
}

async function saveSkillYaml() {
  const skill = selectedSkill.value
  if (!skill?.skill_id) return
  if (!skillYamlDraft.value.trim()) {
    ElMessage.warning('YAML 内容不能为空')
    return
  }
  saveSkillLoading.value = true
  try {
    await api.saveSkillRaw(skill.skill_id, skillYamlDraft.value)
    await api.reloadSkills()
    selectedSkillRaw.value = skillYamlDraft.value
    skillEditorVisible.value = false
    ElMessage.success('YAML 已保存并重载')
    await fetchSkills()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '保存 YAML 失败')
  } finally {
    saveSkillLoading.value = false
  }
}

// ── W4-T3: 草案管理 ────────────────────────────────

async function fetchDrafts() {
  try {
    const res = await api.getSkillDrafts()
    drafts.value = res.drafts || []
  } catch {
    // 静默处理
  }
}

function previewDraft(row) {
  selectedDraft.value = row
  draftPreviewVisible.value = true
}

async function promoteDraft(row) {
  try {
    await api.promoteSkillDraft(row.skill_id || row.filename)
    ElMessage.success(`草案 ${row.name || row.skill_id} 已转正`)
    await fetchDrafts()
    await fetchSkills()
    await api.reloadSkills()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '转正失败')
  }
}

async function discardDraft(row) {
  try {
    await api.deleteSkillDraft(row.skill_id || row.filename)
    ElMessage.success(`草案 ${row.name || row.skill_id} 已丢弃`)
    await fetchDrafts()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '丢弃失败')
  }
}

onMounted(async () => {
  await fetchSkills()
  fetchDrafts()
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
.source-path { font-family: var(--font-mono); color: var(--text-muted); font-size: 11px; }
.skill-meta { display: grid; gap: 8px; margin-bottom: 12px; color: var(--text-secondary); }
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

.yaml-preview {
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
.yaml-input :deep(.el-textarea__inner) {
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
  .yaml-input :deep(.el-textarea__inner) { min-height: 300px !important; }
  .editor-preview { min-height: 300px; max-height: 300px; }
}

/* W4-T2: skill stats in drawer */
.skill-stats-section {
  margin-top: 16px;
  padding: 12px;
  background: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
}
.stats-title {
  margin: 0 0 8px;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}
.stats-summary {
  font-size: 12px;
  color: var(--text-secondary);
  margin-bottom: 10px;
}
.stats-sep { margin: 0 8px; color: var(--text-muted); }
.stats-block { margin-top: 8px; }
.stats-subtitle {
  font-size: 12px;
  color: var(--text-muted);
  margin-bottom: 6px;
}
.text-muted { color: var(--text-muted); font-size: 12px; }
.skill-stats-placeholder { margin-top: 8px; }

/* W4-T3 */
.card-header { display: flex; align-items: center; gap: 8px; }
.card-header-title { font-size: 14px; font-weight: 600; color: var(--text-primary); }
</style>
