<template>
  <div class="report-wrap">
    <div v-if="loading" class="report-loading">
      <el-icon class="loading-icon"><Loading /></el-icon>
      <span>加载报告中...</span>
    </div>

    <div v-else-if="!report" class="empty-state">
      <el-empty description="报告尚未生成" />
    </div>

    <template v-else>
      <!-- Report toolbar -->
      <div class="report-toolbar">
        <div class="toolbar-left">
          <span class="report-label">
            <el-icon><Document /></el-icon>
            渗透测试报告
          </span>
          <code class="report-path" v-if="report.path">{{ report.path }}</code>
        </div>
        <div class="toolbar-right">
          <el-button-group size="small">
            <el-button @click="previewMode = 'rendered'" :type="previewMode === 'rendered' ? 'primary' : ''">
              预览
            </el-button>
            <el-button @click="previewMode = 'markdown'" :type="previewMode === 'markdown' ? 'primary' : ''">
              Markdown
            </el-button>
          </el-button-group>
          <el-button size="small" @click="copyRawMd">
            <el-icon><CopyDocument /></el-icon> 复制 Raw
          </el-button>
          <el-button size="small" @click="downloadMd">
            <el-icon><Download /></el-icon> 下载 .md
          </el-button>
        </div>
      </div>

      <!-- Rendered markdown -->
      <div v-if="previewMode === 'rendered'" class="report-body markdown-body" ref="renderedRef" v-html="renderedHtml" />

      <!-- Raw markdown with highlight -->
      <div v-else class="report-body">
        <div class="md-raw-wrap">
          <div class="line-numbers" aria-hidden="true">
            <span v-for="n in mdLineCount" :key="n">{{ n }}</span>
          </div>
          <pre class="md-raw"><code v-html="highlightedMd"></code></pre>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch, nextTick } from 'vue'
import { ElMessage } from 'element-plus'
import { marked } from 'marked'
import hljs from 'highlight.js/lib/core'
import markdown from 'highlight.js/lib/languages/markdown'
import xml from 'highlight.js/lib/languages/xml'
import http from 'highlight.js/lib/languages/http'
import bash from 'highlight.js/lib/languages/bash'
import json from 'highlight.js/lib/languages/json'
import css from 'highlight.js/lib/languages/css'
import { api } from '@/api'

hljs.registerLanguage('markdown', markdown)
hljs.registerLanguage('html', xml)
hljs.registerLanguage('xml', xml)
hljs.registerLanguage('http', http)
hljs.registerLanguage('bash', bash)
hljs.registerLanguage('json', json)
hljs.registerLanguage('css', css)

const props = defineProps({ taskId: String })

const loading = ref(true)
const report = ref(null)
const previewMode = ref('rendered')
const renderedRef = ref(null)

const renderedHtml = computed(() => {
  if (!report.value?.markdown) return ''

  const renderer = new marked.Renderer()

  renderer.code = function (code, lang) {
    let text = typeof code === 'object' ? code.text : code
    let language = typeof code === 'object' ? code.lang : lang

    let highlighted = text
    if (language && hljs.getLanguage(language)) {
      try { highlighted = hljs.highlight(text, { language }).value } catch {}
    } else {
      try { highlighted = hljs.highlightAuto(text).value } catch {}
    }

    return `<pre><code class="hljs language-${language || ''}">${highlighted}</code></pre>`
  }

  return marked.parse(report.value.markdown, { renderer, breaks: true })
})

const highlightedMd = computed(() => {
  if (!report.value?.markdown) return ''
  try {
    return hljs.highlight(report.value.markdown, { language: 'markdown' }).value
  } catch {
    return report.value.markdown
  }
})

const mdLineCount = computed(() =>
    (report.value?.markdown || '').split('\n').length
)

// 渲染完成后注入 mac 风格头部 + 复制按钮
watch(renderedHtml, async () => {
  await nextTick()
  injectCodeBlockHeaders()
})

function injectCodeBlockHeaders() {
  if (!renderedRef.value) return
  const pres = renderedRef.value.querySelectorAll('pre')
  pres.forEach((pre) => {
    if (pre.querySelector('.code-block-header')) return

    const code = pre.querySelector('code')
    const rawText = code ? code.textContent : pre.textContent
    const langClass = code?.className?.match(/language-(\w+)/)?.[1] || ''

    const header = document.createElement('div')
    header.className = 'code-block-header'
    header.innerHTML = `
      <div class="mac-dots">
        <span class="dot red"></span>
        <span class="dot yellow"></span>
        <span class="dot green"></span>
      </div>
      <span class="code-lang">${langClass}</span>
      <button class="copy-btn" title="复制代码">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        </svg>
        <span class="copy-text">复制</span>
      </button>
    `

    const btn = header.querySelector('.copy-btn')
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(rawText).then(() => {
        const textEl = btn.querySelector('.copy-text')
        textEl.textContent = '已复制'
        setTimeout(() => { textEl.textContent = '复制' }, 1500)
      })
    })

    pre.classList.add('mac-code-block')
    pre.insertBefore(header, pre.firstChild)
  })
}

onMounted(async () => {
  try {
    report.value = await api.getReport(props.taskId)
  } catch {
    report.value = null
  } finally {
    loading.value = false
  }
})

function copyRawMd() {
  if (!report.value?.markdown) return
  navigator.clipboard.writeText(report.value.markdown)
  ElMessage.success('Markdown 已复制到剪贴板')
}

function downloadMd() {
  if (!report.value?.markdown) return
  const blob = new Blob([report.value.markdown], { type: 'text/markdown' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `pentest_report_${props.taskId}.md`
  a.click()
  URL.revokeObjectURL(url)
  ElMessage.success('报告已下载')
}
</script>

<style scoped>
.report-wrap { padding: 4px 0; }

.report-loading {
  display: flex; align-items: center; gap: 10px; padding: 40px;
  color: var(--text-muted); justify-content: center;
}
.loading-icon { animation: spin 1s linear infinite; font-size: 18px; }
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

.report-toolbar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 14px; background: var(--bg-elevated); border: 1px solid var(--border);
  border-bottom: none; border-radius: var(--radius-md) var(--radius-md) 0 0;
  flex-wrap: wrap; gap: 8px;
}
.toolbar-left { display: flex; align-items: center; gap: 10px; }
.toolbar-right { display: flex; align-items: center; gap: 8px; }
.report-label {
  display: flex; align-items: center; gap: 6px;
  font-size: 13px; color: var(--text-secondary); font-weight: 500;
}
.report-path {
  font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);
  background: var(--bg-base); padding: 2px 8px; border-radius: var(--radius-sm);
  border: 1px solid var(--border);
}
.report-body {
  border: 1px solid var(--border);
  border-radius: 0 0 var(--radius-md) var(--radius-md);
  overflow: hidden;
}

/* ── Rendered Markdown (theme-aware) ───────────── */
.markdown-body {
  padding: 32px 40px; max-height: 700px; overflow-y: auto;
  background: var(--bg-base); color: var(--text-primary);
  font-size: 14px; line-height: 1.7;
  transition: background 0.2s, color 0.2s;
}

:deep(.markdown-body h1) {
  font-size: 24px; font-weight: 600; color: var(--text-primary);
  border-bottom: 1px solid var(--border); padding-bottom: 10px; margin: 28px 0 16px;
}
:deep(.markdown-body h2) {
  font-size: 20px; font-weight: 600; color: var(--text-primary);
  border-bottom: 1px solid var(--border); padding-bottom: 8px; margin: 24px 0 12px;
}
:deep(.markdown-body h3) { font-size: 16px; font-weight: 600; color: var(--text-primary); margin: 20px 0 10px; }
:deep(.markdown-body h4) { font-size: 14px; font-weight: 600; color: var(--text-primary); margin: 16px 0 8px; }
:deep(.markdown-body p) { margin: 10px 0; color: var(--text-secondary); }
:deep(.markdown-body strong) { color: var(--text-primary); font-weight: 600; }
:deep(.markdown-body hr) { border: none; border-top: 1px solid var(--border); margin: 20px 0; }

:deep(.markdown-body code) {
  font-family: var(--font-mono); font-size: 12px;
  background: var(--code-inline-bg); padding: 2px 6px; border-radius: 4px;
  color: var(--code-inline-fg); border: 1px solid var(--code-border);
}

/* ── Mac-style code blocks ─────────────────────── */
:deep(.markdown-body pre) {
  position: relative; background: var(--code-bg);
  border: 1px solid var(--code-border); border-radius: 8px;
  padding: 0; overflow: hidden; margin: 14px 0;
}

:deep(.markdown-body pre.mac-code-block > code) {
  display: block; padding: 16px; max-height: 400px; overflow: auto;
  background: none; border: none; color: var(--code-text);
  font-family: var(--font-mono); font-size: 12.5px; line-height: 1.6; white-space: pre;
}

:deep(.markdown-body pre:not(.mac-code-block)) {
  padding: 16px; max-height: 400px; overflow: auto;
}
:deep(.markdown-body pre:not(.mac-code-block) code) {
  background: none; border: none; padding: 0;
  color: var(--code-text); font-size: 12.5px; line-height: 1.6;
}

:deep(.code-block-header) {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 12px; background: var(--code-header-bg);
  border-bottom: 1px solid var(--code-border); user-select: none;
}
:deep(.mac-dots) { display: flex; gap: 6px; }
:deep(.mac-dots .dot) { width: 12px; height: 12px; border-radius: 50%; }
:deep(.mac-dots .dot.red) { background: #ff5f57; }
:deep(.mac-dots .dot.yellow) { background: #febc2e; }
:deep(.mac-dots .dot.green) { background: #28c840; }

:deep(.code-lang) {
  flex: 1; font-family: var(--font-mono); font-size: 11px;
  color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em;
}
:deep(.copy-btn) {
  display: flex; align-items: center; gap: 4px;
  background: none; border: 1px solid var(--code-border); border-radius: 4px;
  padding: 3px 8px; color: var(--text-muted); font-size: 11px;
  font-family: var(--font-mono); cursor: pointer; transition: all 0.15s;
}
:deep(.copy-btn:hover) {
  background: var(--bg-hover); color: var(--text-primary); border-color: var(--text-muted);
}

/* Scrollbar */
:deep(.markdown-body pre code::-webkit-scrollbar),
:deep(.markdown-body pre::-webkit-scrollbar) { width: 6px; height: 6px; }
:deep(.markdown-body pre code::-webkit-scrollbar-thumb),
:deep(.markdown-body pre::-webkit-scrollbar-thumb) { background: var(--border); border-radius: 3px; }

/* Tables */
:deep(.markdown-body table) { width: 100%; border-collapse: collapse; font-size: 13px; margin: 14px 0; }
:deep(.markdown-body th),
:deep(.markdown-body td) { border: 1px solid var(--border); padding: 8px 12px; }
:deep(.markdown-body th) { background: var(--bg-elevated); color: var(--text-secondary); font-weight: 600; text-align: left; }
:deep(.markdown-body td) { color: var(--text-secondary); }

/* Lists */
:deep(.markdown-body ul),
:deep(.markdown-body ol) { padding-left: 24px; color: var(--text-secondary); }
:deep(.markdown-body li) { margin: 4px 0; }
:deep(.markdown-body li strong) { color: var(--text-primary); }

/* Links */
:deep(.markdown-body a) { color: var(--accent-blue); text-decoration: none; }
:deep(.markdown-body a:hover) { text-decoration: underline; }

/* Blockquote */
:deep(.markdown-body blockquote) {
  border-left: 3px solid var(--accent-blue); padding-left: 14px;
  margin: 12px 0; color: var(--text-secondary);
}

/* Details/Summary */
:deep(.markdown-body details) {
  border: 1px solid var(--border); border-radius: 6px;
  padding: 8px 14px; margin: 10px 0; background: var(--bg-elevated);
}
:deep(.markdown-body summary) {
  cursor: pointer; color: var(--accent-blue); font-weight: 500; font-size: 13px;
}

/* ── Raw Markdown View ─────────────────────────── */
.md-raw-wrap {
  display: flex; max-height: 700px; overflow: auto;
  background: var(--hljs-bg);
}
.line-numbers {
  display: flex; flex-direction: column; align-items: flex-end;
  padding: 16px 10px 16px 16px; color: var(--text-muted);
  font-family: var(--font-mono); font-size: 12px; line-height: 1.7;
  user-select: none; border-right: 1px solid var(--border);
  min-width: 48px; background: var(--hljs-bg);
}
.md-raw {
  margin: 0; padding: 16px; flex: 1; background: transparent;
  font-family: var(--font-mono); font-size: 12.5px; line-height: 1.7;
  white-space: pre-wrap; color: var(--text-secondary);
}
</style>