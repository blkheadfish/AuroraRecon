<template>
  <div class="report-wrap">
    <div v-if="loading" class="report-loading">
      <el-icon class="loading-icon"><Loading /></el-icon>
      <span>加载报告中...</span>
    </div>

    <div v-else-if="!aiOriginal" class="empty-state">
      <div class="empty-inner">
        <el-icon class="empty-icon"><Document /></el-icon>
        <p>报告尚未生成</p>
        <p class="empty-hint">任务完成后系统将自动生成渗透测试报告</p>
      </div>
    </div>

    <template v-else>
      <div class="report-cover">
        <div class="cover-brand">
          <span class="cover-logo">Aurora<span class="cover-logo-green">Recon</span></span>
          <span class="cover-badge">渗透测试报告</span>
        </div>
        <div class="cover-meta" v-if="task">
          <div class="cover-meta-row">
            <span class="cover-label">目标</span>
            <span class="cover-value">{{ task.target || '—' }}</span>
          </div>
          <div class="cover-meta-row">
            <span class="cover-label">报告 ID</span>
            <span class="cover-value mono">{{ task.task_id || taskId }}</span>
          </div>
          <div class="cover-meta-row">
            <span class="cover-label">生成时间</span>
            <span class="cover-value mono">{{ fmtDate(task.updated_at || task.created_at) }}</span>
          </div>
        </div>
      </div>

      <div class="report-section" v-if="task">
        <h2 class="section-title">执行摘要</h2>
        <div class="summary-cards">
          <div class="summary-card">
            <span class="sc-value" style="color: var(--accent-blue)">{{ task.findings?.length || 0 }}</span>
            <span class="sc-label">发现漏洞</span>
          </div>
          <div class="summary-card">
            <span class="sc-value" style="color: var(--accent-red)">{{ criticCount }}</span>
            <span class="sc-label">严重/高危</span>
          </div>
          <div class="summary-card">
            <span class="sc-value" style="color: var(--accent-green)">{{ exploitedCount }}</span>
            <span class="sc-label">已成功利用</span>
          </div>
          <div class="summary-card">
            <span class="sc-value" style="color: var(--accent-yellow)">{{ task.credential_store?.length || 0 }}</span>
            <span class="sc-label">获取凭据</span>
          </div>
        </div>
      </div>

      <div class="report-toolbar">
        <div class="toolbar-left">
          <span class="report-label">
            <el-icon><Document /></el-icon>
            详细报告
          </span>
          <code class="report-path" v-if="reportPath">{{ reportPath }}</code>
        </div>
        <div class="toolbar-right">
          <ReportEditorToggle v-model="viewMode" />
          <span v-if="isDirty" class="dirty-tip">未保存</span>
          <el-button size="small" @click="saveDraft">保存草稿</el-button>
          <el-button size="small" @click="restoreOriginal">恢复 AI 原文</el-button>
          <el-button size="small" @click="copyCurrent">
            <el-icon><CopyDocument /></el-icon>
            复制
          </el-button>
          <el-button size="small" @click="downloadMd">
            <el-icon><Download /></el-icon>
            下载 .md
          </el-button>
          <el-button size="small" @click="exportPdf" type="primary" plain>
            <el-icon><Printer /></el-icon>
            导出 PDF
          </el-button>
        </div>
      </div>

      <div class="content-wrap" :class="{ editing: viewMode === 'edit' }">
        <MarkdownEditorPane v-if="viewMode === 'edit'" v-model="draft" class="editor-pane" />
        <MarkdownPreviewPane :html="renderedHtml" class="preview-pane" />
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { onBeforeRouteLeave } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Document } from '@element-plus/icons-vue'
import { marked } from 'marked'
import hljs from 'highlight.js/lib/core'
import mdLang from 'highlight.js/lib/languages/markdown'
import xml from 'highlight.js/lib/languages/xml'
import http from 'highlight.js/lib/languages/http'
import bash from 'highlight.js/lib/languages/bash'
import json from 'highlight.js/lib/languages/json'
import python from 'highlight.js/lib/languages/python'
import { api } from '@/api'
import { trackEvent } from '@/metrics/tracker'
import ReportEditorToggle from '@/components/ReportEditorToggle.vue'
import MarkdownEditorPane from '@/components/MarkdownEditorPane.vue'
import MarkdownPreviewPane from '@/components/MarkdownPreviewPane.vue'

hljs.registerLanguage('markdown', mdLang)
hljs.registerLanguage('html', xml)
hljs.registerLanguage('xml', xml)
hljs.registerLanguage('http', http)
hljs.registerLanguage('bash', bash)
hljs.registerLanguage('json', json)
hljs.registerLanguage('python', python)

const props = defineProps({
  taskId: { type: String, required: true },
  task: { type: Object, default: null },
})

const loading = ref(true)
const aiOriginal = ref('')
const reportPath = ref('')
const viewMode = ref('preview')
const draft = ref('')
const lastSavedDraft = ref('')
let persistTimer = null

const storageKey = computed(() => `report.draft.${props.taskId}`)

const criticCount = computed(() => {
  const f = props.task?.findings || []
  return f.filter((x) => x.severity === 'critical' || x.severity === 'high').length
})
const exploitedCount = computed(() => {
  const f = props.task?.findings || []
  return f.filter((x) => x.exploitable).length
})

function fmtDate(ts) {
  if (!ts) return '—'
  try { return new Date(ts).toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric' }) } catch { return ts }
}

function sanitize(input) {
  return String(input || '').replace(/<script[\s\S]*?>/gi, '').replace(/<style[\s\S]*?>/gi, '').replace(/<iframe[\s\S]*?>/gi, '').replace(/\son\w+="[^"]*"/g, '').replace(/\son\w+='[^']*'/g, '')
}
function wrapTbl(input) {
  return String(input || '').replace(/<table>/g, '<div class="table-scroll"><table>').replace(/<\/table>/g, '</table></div>')
}
function esc(text) {
  return String(text || '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
}

const renderedHtml = computed(() => {
  if (!draft.value) return ''
  const renderer = new marked.Renderer()
  renderer.code = function (code, lang) {
    const text = typeof code === 'object' ? code.text : code
    const language = typeof code === 'object' ? code.lang : lang
    const normalizedLang = String(language || '').trim().toLowerCase()
    let highlighted = text
    try {
      if (normalizedLang && hljs.getLanguage(normalizedLang)) {
        highlighted = hljs.highlight(text, { language: normalizedLang }).value
      } else {
        highlighted = hljs.highlightAuto(text).value
      }
    } catch { highlighted = esc(text) }
    return `<pre><code class="hljs language-${normalizedLang || 'text'}">${highlighted}</code></pre>`
  }
  const raw = marked.parse(draft.value, { renderer, gfm: true, breaks: false })
  return sanitize(wrapTbl(String(raw)))
})

const isDirty = computed(() => draft.value !== lastSavedDraft.value)
watch(draft, (value) => {
  if (persistTimer) clearTimeout(persistTimer)
  persistTimer = setTimeout(() => localStorage.setItem(storageKey.value, value), 250)
}, { flush: 'post' })
watch(viewMode, (value) => trackEvent('report.view_mode.switch', { value, taskId: props.taskId }))

function beforeUnload(e) {
  if (!isDirty.value) return
  e.preventDefault(); e.returnValue = ''
}
onBeforeRouteLeave(() => !isDirty.value || window.confirm('报告有未保存修改，确认离开当前页面吗？'))

async function loadReport() {
  loading.value = true
  try {
    const report = await api.getReport(props.taskId)
    aiOriginal.value = report?.markdown || ''
    reportPath.value = report?.path || ''
    draft.value = localStorage.getItem(storageKey.value) || aiOriginal.value
    lastSavedDraft.value = draft.value
  } catch { aiOriginal.value = ''; draft.value = ''; lastSavedDraft.value = '' }
  finally { loading.value = false }
}
function saveDraft() {
  localStorage.setItem(storageKey.value, draft.value)
  lastSavedDraft.value = draft.value
  trackEvent('report.draft.save', { taskId: props.taskId, length: draft.value.length })
  ElMessage.success('草稿已保存')
}
function restoreOriginal() {
  draft.value = aiOriginal.value
  trackEvent('report.draft.restore_ai', { taskId: props.taskId })
  ElMessage.success('已恢复 AI 原始报告')
}
function copyCurrent() {
  navigator.clipboard.writeText(draft.value || '')
  trackEvent('report.copy', { taskId: props.taskId, mode: viewMode.value })
  ElMessage.success('当前报告内容已复制')
}
function downloadMd() {
  const blob = new Blob([draft.value], { type: 'text/markdown' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = `pentest_report_${props.taskId}.md`; a.click()
  URL.revokeObjectURL(url)
  trackEvent('report.download', { taskId: props.taskId, length: draft.value.length })
  ElMessage.success('报告已下载')
}
function exportPdf() {
  trackEvent('report.export_pdf', { taskId: props.taskId })
  ElMessage.info('正在准备打印，请在弹出的打印对话框中选择"另存为 PDF"')
  setTimeout(() => window.print(), 100)
}

onMounted(() => { window.addEventListener('beforeunload', beforeUnload); loadReport() })
onBeforeUnmount(() => window.removeEventListener('beforeunload', beforeUnload))
</script>

<style scoped>
.report-wrap { padding: 4px 0; }
.report-loading { display: flex; align-items: center; gap: 10px; justify-content: center; color: var(--text-muted); padding: 40px; }
.loading-icon { animation: spin 1s linear infinite; font-size: 18px; }
@keyframes spin { to { transform: rotate(360deg); } }
.empty-state { display: flex; justify-content: center; padding: 80px 0; }
.empty-inner { display: flex; flex-direction: column; align-items: center; gap: 12px; }
.empty-icon { font-size: 48px; color: var(--text-muted); opacity: 0.3; }
.empty-inner p { color: var(--text-secondary); font-size: 14px; margin: 0; }
.empty-hint { color: var(--text-muted) !important; font-size: 12px !important; }

.report-cover {
  background: linear-gradient(135deg, var(--bg-surface) 0%, color-mix(in srgb, var(--accent-blue) 8%, var(--bg-elevated)) 100%);
  border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 32px 36px; margin-bottom: 20px;
}
.cover-brand { display: flex; align-items: baseline; gap: 14px; margin-bottom: 24px; }
.cover-logo { font-family: var(--font-orbitron); font-size: 28px; font-weight: 700; color: var(--text-primary); letter-spacing: 0.04em; }
.cover-logo-green { color: var(--accent-green); }
.cover-badge { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); border: 1px solid var(--border); padding: 4px 10px; border-radius: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
.cover-meta { display: flex; flex-direction: column; gap: 8px; }
.cover-meta-row { display: flex; gap: 16px; align-items: center; }
.cover-label { font-size: 12px; color: var(--text-muted); min-width: 64px; text-transform: uppercase; letter-spacing: 0.04em; }
.cover-value { font-size: 14px; color: var(--text-primary); }
.cover-value.mono { font-family: var(--font-mono); font-size: 12px; }

.report-section { margin-bottom: 20px; }
.section-title { font-size: 16px; font-weight: 700; color: var(--text-primary); margin: 0 0 12px; padding-bottom: 8px; border-bottom: 2px solid var(--border); }
.summary-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.summary-card { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 16px; display: flex; flex-direction: column; align-items: center; gap: 4px; }
.sc-value { font-family: var(--font-orbitron); font-size: 28px; font-weight: 700; line-height: 1.2; }
.sc-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; }

.report-toolbar { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-elevated); padding: 10px 12px; margin-bottom: 12px; }
.toolbar-left { display: flex; align-items: center; gap: 8px; }
.toolbar-right { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.dirty-tip { color: var(--accent-yellow); font-size: 12px; font-family: var(--font-mono); }
.report-label { display: flex; align-items: center; gap: 6px; color: var(--text-secondary); font-size: 13px; font-weight: 600; }
.report-path { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); border: 1px solid var(--border); background: var(--bg-base); border-radius: var(--radius-sm); padding: 2px 8px; }
.content-wrap { display: grid; grid-template-columns: 1fr; gap: 12px; }
.content-wrap.editing { grid-template-columns: 1fr 1fr; }
@media print { .report-toolbar, .page-header, .header-actions { display: none !important; } .report-cover { border: 1px solid #ddd !important; background: #f9f9f9 !important; } }
</style>
