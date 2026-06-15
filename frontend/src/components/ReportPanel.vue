<template>
  <div class="report-wrap">
    <div v-if="loading" class="report-loading">
      <el-icon class="loading-icon"><Loading /></el-icon>
      <span>加载报告中...</span>
    </div>

    <div v-else-if="!aiOriginal" class="empty-state">
      <el-empty description="报告尚未生成" />
    </div>

    <template v-else>
      <div class="report-toolbar">
        <div class="toolbar-left">
          <span class="report-label">
            <el-icon><Document /></el-icon>
            渗透测试报告
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
        <MarkdownEditorPane
          v-if="viewMode === 'edit'"
          v-model="draft"
          class="editor-pane"
        />
        <MarkdownPreviewPane :html="renderedHtml" class="preview-pane" />
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { onBeforeRouteLeave } from 'vue-router'
import { ElMessage } from 'element-plus'
import { marked } from 'marked'
import hljs from 'highlight.js/lib/core'
import markdown from 'highlight.js/lib/languages/markdown'
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

hljs.registerLanguage('markdown', markdown)
hljs.registerLanguage('html', xml)
hljs.registerLanguage('xml', xml)
hljs.registerLanguage('http', http)
hljs.registerLanguage('bash', bash)
hljs.registerLanguage('json', json)
hljs.registerLanguage('python', python)

const props = defineProps({
  taskId: { type: String, required: true },
})

const loading = ref(true)
const aiOriginal = ref('')
const reportPath = ref('')
const viewMode = ref('preview')
const draft = ref('')
const lastSavedDraft = ref('')

let persistTimer = null

const storageKey = computed(() => `report.draft.${props.taskId}`)

function sanitizeHtml(input) {
  return input
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, '')
    .replace(/<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi, '')
    .replace(/\son\w+="[^"]*"/g, '')
    .replace(/\son\w+='[^']*'/g, '')
}

function wrapTables(input) {
  return String(input || '')
    .replace(/<table>/g, '<div class="table-scroll"><table>')
    .replace(/<\/table>/g, '</table></div>')
}

function escapeHtml(text) {
  return String(text || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
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
    } catch {
      highlighted = escapeHtml(text)
    }
    return `<pre><code class="hljs language-${normalizedLang || 'text'}">${highlighted}</code></pre>`
  }
  const raw = marked.parse(draft.value, {
    renderer,
    gfm: true,
    breaks: false,
  })
  return sanitizeHtml(wrapTables(raw))
})

const isDirty = computed(() => draft.value !== lastSavedDraft.value)

watch(
  draft,
  (value) => {
    if (persistTimer) clearTimeout(persistTimer)
    persistTimer = setTimeout(() => {
      localStorage.setItem(storageKey.value, value)
    }, 250)
  },
  { flush: 'post' },
)

watch(viewMode, (value) => {
  trackEvent('report.view_mode.switch', { value, taskId: props.taskId })
})

function beforeUnloadHandler(e) {
  if (!isDirty.value) return
  e.preventDefault()
  e.returnValue = ''
}

onBeforeRouteLeave(() => {
  if (!isDirty.value) return true
  return window.confirm('报告有未保存修改，确认离开当前页面吗？')
})

async function loadReport() {
  loading.value = true
  try {
    const report = await api.getReport(props.taskId)
    aiOriginal.value = report?.markdown || ''
    reportPath.value = report?.path || ''
    draft.value = localStorage.getItem(storageKey.value) || aiOriginal.value
    lastSavedDraft.value = draft.value
  } catch {
    aiOriginal.value = ''
    draft.value = ''
    lastSavedDraft.value = ''
  } finally {
    loading.value = false
  }
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
  a.href = url
  a.download = `pentest_report_${props.taskId}.md`
  a.click()
  URL.revokeObjectURL(url)
  trackEvent('report.download', { taskId: props.taskId, length: draft.value.length })
  ElMessage.success('报告已下载')
}

function exportPdf() {
  trackEvent('report.export_pdf', { taskId: props.taskId })
  ElMessage.info('正在准备打印，请在弹出的打印对话框中选择"另存为 PDF"')
  setTimeout(() => window.print(), 100)
}

onMounted(() => {
  window.addEventListener('beforeunload', beforeUnloadHandler)
  loadReport()
})

onBeforeUnmount(() => {
  window.removeEventListener('beforeunload', beforeUnloadHandler)
})
</script>

<style scoped>
.report-wrap { padding: 4px 0; }
.report-loading { display: flex; align-items: center; gap: 10px; justify-content: center; color: var(--text-muted); padding: 40px; }
.loading-icon { animation: spin 1s linear infinite; font-size: 18px; }
@keyframes spin { to { transform: rotate(360deg); } }

.report-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-elevated);
  padding: 10px 12px;
  margin-bottom: 12px;
}
.toolbar-left { display: flex; align-items: center; gap: 8px; }
.toolbar-right { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.dirty-tip {
  color: var(--accent-yellow);
  font-size: 12px;
  font-family: var(--font-mono);
}
.report-label { display: flex; align-items: center; gap: 6px; color: var(--text-secondary); font-size: 13px; font-weight: 600; }
.report-path { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); border: 1px solid var(--border); background: var(--bg-base); border-radius: var(--radius-sm); padding: 2px 8px; }

.content-wrap { display: grid; grid-template-columns: 1fr; gap: 12px; }
.content-wrap.editing { grid-template-columns: 1fr 1fr; }
</style>
