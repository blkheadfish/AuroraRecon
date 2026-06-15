<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">技能管理</h1>
        <p class="page-sub">目录树浏览 · 在线编辑 · 保存后自动重载</p>
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

          <div class="skill-list">
            <div v-for="item in group.items" :key="item.skill_id" class="skill-row">
              <div class="skill-row-main" @click="toggleTree(item)">
                <el-icon class="skill-expand-icon" :class="{ expanded: expandedSkillId === item.skill_id }">
                  <ArrowRight />
                </el-icon>
                <span class="skill-name">{{ item.name || item.skill_id }}</span>
                <code class="skill-id">{{ item.skill_id }}</code>
                <span class="skill-meta">
                  <el-tag size="small" effect="plain" type="info" v-if="item.paths_count">{{ item.paths_count }} 路径</el-tag>
                  <el-tag size="small" effect="plain" type="info" v-if="item.probes_count">{{ item.probes_count }} 探测</el-tag>
                </span>
              </div>

              <div v-if="expandedSkillId === item.skill_id" class="skill-tree-panel">
                <div v-if="treeLoading[item.skill_id]" class="tree-loading">
                  <el-icon class="loading-icon"><Loading /></el-icon> 加载中...
                </div>
                <div v-else-if="skillTrees[item.skill_id]" class="file-tree">
                  <TreeNode
                    v-for="node in skillTrees[item.skill_id]"
                    :key="node.path"
                    :node="node"
                    :skill-id="item.skill_id"
                    :active-path="activeFilePath"
                    @select="openFile"
                  />
                </div>
                <div v-else class="tree-empty">
                  <el-button size="small" text @click.stop="loadTree(item)">加载目录树</el-button>
                </div>
              </div>
            </div>
          </div>
        </el-collapse-item>
      </el-collapse>
    </el-card>

    <!-- W4-T3: 草案 -->
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
              <el-button class="op-edit" size="small" @click="openDraftEditor(row)">编辑</el-button>
              <el-button type="success" size="small" @click="promoteDraft(row)">转正</el-button>
              <el-button type="danger" size="small" @click="discardDraft(row)">丢弃</el-button>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- ── 文件编辑抽屉 ─────────────────────────────────── -->
    <el-drawer
      v-model="drawerFileVisible"
      direction="rtl"
      size="55%"
      :with-header="false"
      destroy-on-close
    >
      <div class="file-drawer" v-if="editingFile">
        <div class="file-drawer-header">
          <div class="file-drawer-title">
            <el-tag size="small" :type="fileTagType(editingFile.filename)">
              {{ editingFile.filename }}
            </el-tag>
            <code class="file-drawer-path">{{ editingFile.skill_id }} / {{ editingFile.path }}</code>
          </div>
          <div class="file-drawer-actions">
            <span v-if="fileDirty" class="dirty-tip">未保存</span>
            <el-button type="primary" size="small" @click="saveFile" :loading="fileSaving">保存</el-button>
            <el-button size="small" @click="drawerFileVisible = false">
              <el-icon><Close /></el-icon>
            </el-button>
          </div>
        </div>
        <div class="file-drawer-tabs">
          <button class="editor-tab" :class="{ active: editorTab === 'edit' }" @click="editorTab = 'edit'">编辑</button>
          <button class="editor-tab" :class="{ active: editorTab === 'preview' }" @click="editorTab = 'preview'">预览</button>
        </div>
        <div class="file-drawer-body" v-loading="fileLoading">
          <el-input
            v-show="editorTab === 'edit'"
            v-model="editingFile.content"
            type="textarea"
            class="editor-textarea-drawer"
            resize="none"
            placeholder="加载中..."
            @input="onEditorInput"
          />
          <pre v-show="editorTab === 'preview'" class="editor-highlight-drawer"><code v-html="highlightedHtml" /></pre>
        </div>
      </div>
    </el-drawer>

    <!-- ── 旧版 YAML 编辑抽屉 ──────────────────────────── -->
    <el-drawer v-model="drawerVisible" title="编辑 Skill YAML" size="60%" direction="rtl">
      <template #header>
        <div class="drawer-header-row">
          <span>编辑 · {{ editingSkillId }}</span>
          <el-tag v-if="drawerDirty" type="warning" size="small" style="margin-left: 8px">已修改</el-tag>
        </div>
      </template>
      <el-input
        v-if="drawerVisible"
        v-model="drawerYaml"
        type="textarea"
        class="yaml-editor"
        :rows="28"
        resize="vertical"
        placeholder="加载中..."
        :disabled="drawerLoading"
      />
      <div class="drawer-footer">
        <el-dropdown v-if="selectedSkillStats" style="margin-right: auto">
          <el-button size="small">
            统计 <el-icon><ArrowDown /></el-icon>
          </el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item>总执行: {{ selectedSkillStats.total_runs }}</el-dropdown-item>
              <el-dropdown-item>成功率: {{ (selectedSkillStats.success_rate * 100).toFixed(1) }}%</el-dropdown-item>
              <el-dropdown-item divided v-if="Object.keys(selectedSkillStats.scene_breakdown || {}).length">
                场景分布:
                <span v-for="(v, k) in selectedSkillStats.scene_breakdown" :key="k" style="display:block;font-size:11px;padding-left:12px">
                  {{ k }}: {{ v.total }}次 / {{ (v.rate * 100).toFixed(0) }}%
                </span>
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <el-button size="small" @click="drawerVisible = false">取消</el-button>
        <el-button type="primary" size="small" @click="saveDrawerYaml" :loading="drawerSaving">保存并重载</el-button>
      </div>
    </el-drawer>

    <!-- ── 草案预览弹窗 ───────────────────────────────── -->
    <el-dialog v-model="draftPreviewVisible" title="草案预览" width="700px">
      <pre class="draft-preview-yaml">{{ draftPreviewContent }}</pre>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, nextTick, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { ArrowRight, ArrowDown, Close, Document, Loading } from '@element-plus/icons-vue'
import hljs from 'highlight.js/lib/core'
import yaml from 'highlight.js/lib/languages/yaml'
import markdown from 'highlight.js/lib/languages/markdown'
import python from 'highlight.js/lib/languages/python'
import bash from 'highlight.js/lib/languages/bash'
import json from 'highlight.js/lib/languages/json'
import xml from 'highlight.js/lib/languages/xml'
import { api } from '@/api'
import { trackEvent } from '@/metrics/tracker'
import { resolveCategoryLabel } from '@/utils/categoryLabel'
import { resolveCategoryColor } from '@/utils/categoryColor'

hljs.registerLanguage('yaml', yaml)
hljs.registerLanguage('yml', yaml)
hljs.registerLanguage('markdown', markdown)
hljs.registerLanguage('md', markdown)
hljs.registerLanguage('python', python)
hljs.registerLanguage('bash', bash)
hljs.registerLanguage('json', json)
hljs.registerLanguage('xml', xml)
hljs.registerLanguage('html', xml)

function categoryStyle(category: string) { return { '--cat-tone': resolveCategoryColor(category) } }

// ── 目录树子组件 ───────────────────────────────────────
const TreeNode = defineComponent({
  name: 'FileTreeNode',
  props: { node: Object, skillId: String, activePath: String },
  emits: ['select'],
  setup(props, { emit }) {
    const expanded = ref(false)
    const node = props.node as any
    function toggle() {
      if (node.type === 'directory') expanded.value = !expanded.value
      else emit('select', props.skillId, node)
    }
    const icon = node.type === 'directory' ? (expanded.value ? ArrowDown : ArrowRight) : Document
    return () => [
      h('div', {
        class: `tree-node ${node.type} ${(props.activePath === node.path) ? 'active' : ''}`,
        style: { paddingLeft: `${(node._depth || 0) * 16 + 8}px` },
        onClick: toggle,
      }, [
        h('span', { class: 'tree-node-icon' }, [h(icon)]),
        h('span', { class: 'tree-node-name' }, node.name),
        node.type === 'file' && node.size ? h('span', { class: 'tree-node-size' }, formatSize(node.size)) : null,
      ]),
      node.type === 'directory' && expanded.value && node.children
        ? node.children.map((c: any) => h(TreeNode, {
          key: c.path,
          node: { ...c, _depth: (node._depth || 0) + 1 },
          skillId: props.skillId,
          activePath: props.activePath,
          onSelect: (sid: string, n: any) => emit('select', sid, n),
        }))
        : null,
    ]
  },
})

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)}KB`
  return `${(bytes / 1048576).toFixed(1)}MB`
}

// ── 主数据 ─────────────────────────────────────────────
const skills = ref<any[]>([])
const drafts = ref<any[]>([])
const skillsLoading = ref(false)
const reloadLoading = ref(false)
const activeCategories = ref<string[]>([])

const expandedSkillId = ref('')
const skillTrees = ref<Record<string, any[]>>({})
const treeLoading = ref<Record<string, boolean>>({})

const drawerFileVisible = ref(false)
const editingFile = ref<any>(null)
const fileLoading = ref(false)
const fileSaving = ref(false)
const fileDirty = ref(false)
const activeFilePath = ref('')
const editorTab = ref<'edit' | 'preview'>('edit')

const highlightedHtml = computed(() => {
  const file = editingFile.value
  if (!file || !file.content) return ''
  const ext = (file.filename || '').split('.').pop()?.toLowerCase() || ''
  const langMap: Record<string, string> = { yaml: 'yaml', yml: 'yaml', md: 'markdown', py: 'python', sh: 'bash', bash: 'bash', json: 'json', xml: 'xml', html: 'xml' }
  const lang = langMap[ext] || ''
  try {
    if (lang && hljs.getLanguage(lang)) return hljs.highlight(file.content, { language: lang }).value
    return hljs.highlightAuto(file.content).value
  } catch { return file.content.replace(/</g, '&lt;').replace(/>/g, '&gt;') }
})

function onEditorInput() {
  fileDirty.value = editingFile.value?.content !== editingFile.value?._original
}

const drawerVisible = ref(false)
const drawerYaml = ref('')
const editingSkillId = ref('')
const drawerDirty = ref(false)
const drawerLoading = ref(false)
const drawerSaving = ref(false)
const selectedSkillStats = ref<any>(null)

const draftPreviewVisible = ref(false)
const draftPreviewContent = ref('')

// ── Computed ───────────────────────────────────────────
const groupedSkills = computed(() => {
  const map = new Map<string, any[]>()
  for (const item of skills.value) {
    const category = String(item.category || 'uncategorized')
    if (!map.has(category)) map.set(category, [])
    map.get(category)!.push(item)
  }
  return Array.from(map.entries()).map(([category, items]) => ({ category, items }))
})

function fileTagType(filename: string): string {
  if (filename.endsWith('.yaml') || filename.endsWith('.yml')) return 'warning'
  if (filename.endsWith('.md')) return 'info'
  if (filename.endsWith('.py')) return 'success'
  return ''
}

// ── API ────────────────────────────────────────────────
async function fetchSkills() {
  skillsLoading.value = true
  try {
    const res = await api.getSkills()
    skills.value = res.skills || []
    trackEvent('skills.list', { total: res.total })
  } catch { ElMessage.error('加载技能列表失败') }
  finally { skillsLoading.value = false }
}

async function fetchDrafts() {
  try { const res = await api.getSkillDrafts(); drafts.value = res.drafts || [] } catch { /* ignore */ }
}

async function reloadAllSkills() {
  reloadLoading.value = true
  try {
    const res = await api.reloadSkills()
    ElMessage.success(`已重载 ${res.total} 个技能`)
    await fetchSkills()
    skillTrees.value = {}
    expandedSkillId.value = ''
  } catch { ElMessage.error('重载失败') }
  finally { reloadLoading.value = false }
}

// ── 目录树 ─────────────────────────────────────────────
async function loadTree(item: any) {
  const sid = item.skill_id
  treeLoading.value[sid] = true
  try { const res = await api.getSkillTree(sid); skillTrees.value[sid] = res.tree || [] }
  catch { ElMessage.error(`无法加载 ${sid} 的目录树`); skillTrees.value[sid] = [] }
  finally { treeLoading.value[sid] = false }
}

function toggleTree(item: any) {
  const sid = item.skill_id
  expandedSkillId.value = expandedSkillId.value === sid ? '' : sid
  if (!skillTrees.value[sid]) loadTree(item)
}

// ── 文件编辑 ───────────────────────────────────────────
async function openFile(skillId: string, node: any) {
  if (node.type !== 'file') return
  activeFilePath.value = node.path
  fileLoading.value = true
  editorTab.value = 'edit'
  editingFile.value = { skill_id: skillId, path: node.path, filename: node.name, content: '', _original: '' }
  drawerFileVisible.value = true
  try {
    const res = await api.getSkillFile(skillId, node.path)
    editingFile.value._original = res.content
    editingFile.value.content = res.content
    fileDirty.value = false
  } catch {
    ElMessage.error(`无法加载: ${node.path}`)
    drawerFileVisible.value = false
  } finally { fileLoading.value = false }
}

async function saveFile() {
  if (!editingFile.value) return
  fileSaving.value = true
  try {
    await api.saveSkillFile(editingFile.value.skill_id, editingFile.value.path, editingFile.value.content)
    editingFile.value._original = editingFile.value.content
    fileDirty.value = false
    ElMessage.success(`已保存 ${editingFile.value.filename}`)
  } catch { ElMessage.error(`保存失败`) }
  finally { fileSaving.value = false }
}

// ── 旧版 YAML 编辑 ────────────────────────────────────
async function openSkillDrawer(row: any) {
  editingSkillId.value = row.skill_id
  drawerVisible.value = true
  drawerYaml.value = ''
  drawerLoading.value = true
  drawerDirty.value = false
  try { const res = await api.getSkillRaw(row.skill_id); drawerYaml.value = res.yaml || '' }
  catch { ElMessage.error('无法加载 YAML'); drawerVisible.value = false }
  finally { drawerLoading.value = false }
}

async function saveDrawerYaml() {
  drawerSaving.value = true
  try { await api.saveSkillRaw(editingSkillId.value, drawerYaml.value); drawerDirty.value = false; ElMessage.success('已保存，技能已重载') }
  catch (e: any) { ElMessage.error(`保存失败: ${e?.response?.data?.detail || e.message}`) }
  finally { drawerSaving.value = false }
}

function openSkillEditor(row: any) { openSkillDrawer(row) }

// ── 草案 ───────────────────────────────────────────────
function previewDraft(row: any) { draftPreviewContent.value = row.yaml || row.content || JSON.stringify(row, null, 2); draftPreviewVisible.value = true }
function openDraftEditor(row: any) { editingSkillId.value = row.skill_id || row.name; drawerYaml.value = row.yaml || ''; drawerVisible.value = true; drawerDirty.value = false; drawerLoading.value = false }
async function promoteDraft(row: any) { try { await api.promoteSkillDraft(row.name || row.skill_id); ElMessage.success(`草案已转正`); await fetchDrafts(); await fetchSkills() } catch { ElMessage.error('转正失败') } }
async function discardDraft(row: any) { try { await api.deleteSkillDraft(row.name || row.skill_id); ElMessage.success(`已丢弃`); await fetchDrafts() } catch { ElMessage.error('丢弃失败') } }

onMounted(() => { fetchSkills(); fetchDrafts() })
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.page-title { font-size: 22px; color: var(--text-primary); font-weight: 700; }
.page-sub { color: var(--text-secondary); font-size: 13px; margin-top: 4px; }
.header-actions { display: flex; gap: 8px; }
.panel { margin-bottom: 0; }

/* ── 折叠标题 ────────────────────────────── */
.collapse-title { width: 100%; }
.cat-header { display: flex; align-items: center; gap: 10px; }
.cat-marker { width: 4px; height: 18px; border-radius: 2px; background: var(--cat-tone, var(--accent-blue)); }
.cat-name { font-weight: 600; color: var(--cat-tone, var(--text-primary)); font-size: 14px; }
.cat-count { margin-left: 8px; }
:deep(.cat-count.el-tag) {
  font-family: var(--font-mono);
  font-weight: 700;
  color: color-mix(in srgb, var(--text-primary) 88%, var(--cat-tone, var(--accent-blue)));
  border-color: color-mix(in srgb, var(--cat-tone, var(--accent-blue)) 54%, var(--border));
  background: color-mix(in srgb, var(--bg-base) 82%, transparent);
}

/* ── 技能列表 ────────────────────────────── */
.skill-list { padding: 4px 0; }
.skill-row { border-bottom: 1px solid var(--border-muted); }
.skill-row:last-child { border-bottom: none; }
.skill-row-main { display: flex; align-items: center; gap: 8px; padding: 8px 12px; cursor: pointer; border-radius: var(--radius-sm); transition: background var(--t-fast) var(--ease-out); }
.skill-row-main:hover { background: var(--bg-hover); }
.skill-expand-icon { font-size: 12px; color: var(--text-muted); transition: transform 0.2s; }
.skill-expand-icon.expanded { transform: rotate(90deg); }
.skill-name { font-weight: 500; color: var(--text-primary); font-size: 13px; }
.skill-id { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); background: var(--bg-elevated); padding: 1px 6px; border-radius: 3px; }
.skill-meta { margin-left: auto; display: flex; gap: 4px; }

/* ── 目录树面板 ─────────────────────────── */
.skill-tree-panel { padding: 8px 12px 12px 28px; background: var(--bg-elevated); border-top: 1px solid var(--border-muted); }
.tree-loading { font-size: 12px; color: var(--text-muted); padding: 8px 0; display: flex; align-items: center; gap: 6px; }
.tree-empty { padding: 8px 0; }
.file-tree { font-size: 12px; }
:deep(.tree-node) { display: flex; align-items: center; gap: 6px; padding: 3px 8px; cursor: pointer; border-radius: var(--radius-sm); transition: background var(--t-fast) var(--ease-out); color: var(--text-secondary); }
:deep(.tree-node:hover) { background: var(--bg-hover); }
:deep(.tree-node.active) { background: color-mix(in srgb, var(--accent-blue) 12%, var(--bg-elevated)); color: var(--accent-blue); }
:deep(.tree-node.directory) { font-weight: 600; color: var(--text-primary); }
:deep(.tree-node-icon) { font-size: 12px; display: flex; align-items: center; width: 14px; flex-shrink: 0; }
:deep(.tree-node-name) { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
:deep(.tree-node-size) { font-size: 10px; color: var(--text-muted); flex-shrink: 0; }

/* ── 文件编辑抽屉 ───────────────────────── */
.file-drawer { display: flex; flex-direction: column; height: 100%; }
.file-drawer-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px 12px; border-bottom: 1px solid var(--border); gap: 8px; flex-shrink: 0; }
.file-drawer-title { display: flex; align-items: center; gap: 8px; min-width: 0; }
.file-drawer-path { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-drawer-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }

.file-drawer-tabs { display: flex; padding: 0 20px; border-bottom: 1px solid var(--border-muted); background: var(--bg-elevated); flex-shrink: 0; }
.editor-tab { padding: 8px 20px; font-size: 12px; font-family: var(--font-mono); color: var(--text-muted); background: none; border: none; border-bottom: 2px solid transparent; cursor: pointer; transition: color var(--t-fast), border-color var(--t-fast); }
.editor-tab:hover { color: var(--text-primary); }
.editor-tab.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); }

.file-drawer-body { flex: 1; overflow: hidden; position: relative; }
.editor-textarea-drawer { height: 100%; }
.editor-textarea-drawer :deep(textarea) { font-family: var(--font-mono) !important; font-size: 13px !important; line-height: 1.65 !important; background: var(--bg-base) !important; color: var(--text-primary) !important; border: none !important; border-radius: 0 !important; resize: none !important; height: 100% !important; padding: 14px 20px !important; }
.editor-highlight-drawer { margin: 0; padding: 14px 20px; height: 100%; overflow: auto; background: var(--hljs-bg); font-family: var(--font-mono); font-size: 13px; line-height: 1.65; white-space: pre; color: var(--hljs-fg); border: none; border-radius: 0; }
.editor-highlight-drawer :deep(code) { font-family: inherit; font-size: inherit; background: transparent; }

.dirty-tip { color: var(--accent-yellow); font-size: 12px; font-family: var(--font-mono); }

/* ── 旧版抽屉 ────────────────────────────── */
.drawer-header-row { display: flex; align-items: center; }
.yaml-editor :deep(textarea) { font-family: var(--font-mono); font-size: 12px; line-height: 1.6; }
.drawer-footer { display: flex; gap: 8px; align-items: center; margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border); }

/* ── 草案 ─────────────────────────────────── */
.card-header { display: flex; align-items: center; gap: 12px; }
.card-header-title { font-weight: 600; color: var(--text-primary); }
.source-path { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); word-break: break-all; }
.ops { display: flex; gap: 6px; flex-wrap: wrap; }
.draft-preview-yaml { font-family: var(--font-mono); font-size: 12px; line-height: 1.6; background: var(--bg-base); padding: 16px; border-radius: var(--radius-md); white-space: pre-wrap; max-height: 500px; overflow: auto; }
</style>
