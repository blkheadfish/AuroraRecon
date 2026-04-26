<template>
  <div class="admin-skills">
    <div class="section-header">
      <div>
        <h2 class="section-title">Skills 管理</h2>
        <p class="section-sub">按类别分组 · 查看/编辑 YAML · 启停开关</p>
      </div>
      <div class="header-actions">
        <el-button-group>
          <el-button size="small" :loading="bulkLoading" @click="bulkSetAll(true)">全部启用</el-button>
          <el-button size="small" :loading="bulkLoading" @click="bulkSetAll(false)">全部禁用</el-button>
          <el-button size="small" :loading="bulkLoading" @click="bulkInvertAll">反选</el-button>
        </el-button-group>
        <el-button :loading="skillsLoading" :icon="Refresh" size="small" @click="fetchSkills">刷新</el-button>
        <el-button type="primary" size="small" @click="reloadAllSkills" :loading="reloadLoading">重载技能</el-button>
      </div>
    </div>

    <div class="summary-grid">
      <div class="summary-card"><span class="summary-label">技能总数</span><span class="summary-value mono">{{ skills.length }}</span></div>
      <div class="summary-card"><span class="summary-label">类别数</span><span class="summary-value mono">{{ groupedSkills.length }}</span></div>
      <div class="summary-card"><span class="summary-label">已禁用</span><span class="summary-value mono admin-red">{{ disabledCount }}</span></div>
    </div>

    <el-card class="panel" shadow="never">
      <SkeletonBlock v-if="skillsLoading && !groupedSkills.length" :rows="8" />
      <el-empty v-else-if="!groupedSkills.length" description="没有找到可用技能，检查 backend/skills/ 是否存在 YAML" />

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
                <div class="group-actions" @click.stop>
                  <el-button size="small" text :disabled="bulkLoading" @click="bulkSetGroup(group, true)">组内全启用</el-button>
                  <el-button size="small" text :disabled="bulkLoading" @click="bulkSetGroup(group, false)">组内全禁用</el-button>
                  <el-button size="small" text :disabled="bulkLoading" @click="bulkInvertGroup(group)">组内反选</el-button>
                </div>
              </div>
            </div>
          </template>

          <el-table :data="group.items" size="small" stripe>
            <el-table-column prop="skill_id" label="技能 ID" min-width="180">
              <template #default="{ row }"><code class="skill-id">{{ row.skill_id }}</code></template>
            </el-table-column>
            <el-table-column prop="name" label="名称" min-width="180" />
            <el-table-column prop="paths_count" label="利用路径" width="100" align="center" />
            <el-table-column prop="probes_count" label="探测数" width="90" align="center" />
            <el-table-column label="来源文件" min-width="240">
              <template #default="{ row }">
                <code class="source-path">{{ shortSource(row.source) }}</code>
              </template>
            </el-table-column>
            <el-table-column label="启用" width="80" align="center">
              <template #default="{ row }">
                <el-switch
                  :model-value="row.enabled !== false"
                  :disabled="savingEnabled[row.skill_id]"
                  @change="(v) => onToggleEnabled(row, v)"
                />
              </template>
            </el-table-column>
            <el-table-column label="操作" width="180" align="center">
              <template #default="{ row }">
                <div class="ops">
                  <el-button size="small" @click="openSkillDrawer(row)">查看</el-button>
                  <el-button size="small" type="primary" @click="openSkillEditor(row)">编辑</el-button>
                </div>
              </template>
            </el-table-column>
          </el-table>
        </el-collapse-item>
      </el-collapse>
    </el-card>

    <el-drawer v-model="skillDrawerVisible" title="技能详情" size="55%">
      <template v-if="selectedSkill">
        <div class="skill-meta">
          <div><b>技能 ID：</b><code>{{ selectedSkill.skill_id }}</code></div>
          <div><b>名称：</b>{{ selectedSkill.name }}</div>
          <div><b>分类：</b>{{ resolveCategoryLabel(selectedSkill.category) }}</div>
          <div><b>路径数：</b>{{ selectedSkill.paths_count }}，<b>探测数：</b>{{ selectedSkill.probes_count }}</div>
          <div><b>来源：</b><code>{{ selectedSkill.source }}</code></div>
        </div>
        <div class="drawer-actions">
          <el-button type="primary" @click="openSkillEditor(selectedSkill)">编辑 YAML</el-button>
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
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import hljs from 'highlight.js/lib/core'
import yamlLanguage from 'highlight.js/lib/languages/yaml'
import { api } from '@/api'
import { resolveCategoryColor } from '@/utils/categoryColor'
import { resolveCategoryLabel } from '@/utils/categoryLabel'
import SkeletonBlock from '@/components/SkeletonBlock.vue'

hljs.registerLanguage('yaml', yamlLanguage)

const skillsLoading = ref(false)
const skills = ref([])
const reloadLoading = ref(false)
const activeCategories = ref([])
const savingEnabled = reactive({})
const bulkLoading = ref(false)

const selectedSkill = ref(null)
const selectedSkillRaw = ref('')
const skillDrawerVisible = ref(false)
const skillEditorVisible = ref(false)
const saveSkillLoading = ref(false)
const skillYamlDraft = ref('')

function shortSource(source) {
  if (!source) return '-'
  const normalized = String(source).replaceAll('\\', '/')
  const idx = normalized.lastIndexOf('/backend/skills/')
  return idx >= 0 ? normalized.slice(idx + 1) : normalized
}

function escapeHtml(text) {
  return String(text || '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
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

const disabledCount = computed(() => skills.value.filter(s => s.enabled === false).length)

function categoryStyle(category) {
  return { '--cat-tone': resolveCategoryColor(category) }
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

async function onToggleEnabled(row, value) {
  savingEnabled[row.skill_id] = true
  try {
    await api.adminSetSkillEnabled(row.skill_id, value)
    row.enabled = value
    ElMessage.success(`${row.skill_id} 已${value ? '启用' : '禁用'}`)
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '操作失败')
  } finally {
    savingEnabled[row.skill_id] = false
  }
}

async function applyBulkToggle(rows, computeTarget, successLabel) {
  if (!rows.length) {
    ElMessage.info('没有可操作的技能')
    return
  }
  bulkLoading.value = true
  let ok = 0
  let failed = 0
  try {
    for (const row of rows) {
      const target = computeTarget(row)
      if ((row.enabled !== false) === target) continue
      try {
        await api.adminSetSkillEnabled(row.skill_id, target)
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
  return applyBulkToggle(skills.value, () => value, value ? '批量启用' : '批量禁用')
}
function bulkInvertAll() {
  return applyBulkToggle(skills.value, row => row.enabled === false, '批量反选')
}
function bulkSetGroup(group, value) {
  return applyBulkToggle(group.items, () => value, value ? '组内启用' : '组内禁用')
}
function bulkInvertGroup(group) {
  return applyBulkToggle(group.items, row => row.enabled === false, '组内反选')
}

async function openSkillDrawer(row) {
  selectedSkill.value = row
  selectedSkillRaw.value = ''
  skillDrawerVisible.value = true
  try {
    const raw = await api.getSkillRaw(row.skill_id)
    selectedSkillRaw.value = raw.yaml || ''
  } catch (e) {
    selectedSkillRaw.value = `读取失败: ${e?.response?.data?.detail || e.message}`
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

onMounted(fetchSkills)
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
.admin-red { color: var(--accent-red); }
.mono { font-family: var(--font-mono); }

.panel { border-radius: var(--radius-lg) !important; border: 1px solid var(--border) !important; }

.skill-id { font-size: 12px; color: var(--text-primary); }
.source-path { font-family: var(--font-mono); color: var(--text-muted); font-size: 11px; }
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

.skill-meta { display: grid; gap: 8px; margin-bottom: 12px; color: var(--text-secondary); }
.drawer-actions { display: flex; justify-content: flex-end; margin-bottom: 10px; }

.yaml-preview {
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
.yaml-input :deep(.el-textarea__inner) {
  min-height: 520px !important;
  font-family: var(--font-mono); font-size: 12px; line-height: 1.55;
}
.editor-preview { min-height: 520px; max-height: 520px; }

@media (max-width: 1100px) {
  .editor-wrap { grid-template-columns: 1fr; }
  .yaml-input :deep(.el-textarea__inner) { min-height: 300px !important; }
  .editor-preview { min-height: 300px; max-height: 300px; }
}
</style>
