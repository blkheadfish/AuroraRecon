<template>
  <div ref="previewRef" class="preview markdown-body" v-html="html"></div>
</template>

<script setup>
import { nextTick, onMounted, ref, watch } from 'vue'

const props = defineProps({
  html: { type: String, default: '' },
})

const previewRef = ref(null)

watch(
  () => props.html,
  async () => {
    await nextTick()
    injectCodeBlockHeaders()
    processSeverityCallouts()
  },
)

onMounted(async () => {
  await nextTick()
  injectCodeBlockHeaders()
  processSeverityCallouts()
})

function processSeverityCallouts() {
  if (!previewRef.value) return
  const blockquotes = previewRef.value.querySelectorAll('blockquote')
  blockquotes.forEach((bq) => {
    if (bq.dataset.severityProcessed) return
    bq.dataset.severityProcessed = '1'
    const text = (bq.textContent || '').toLowerCase()
    if (text.includes('critical') || text.includes('严重') || text.includes('紧急')) {
      bq.classList.add('callout-critical')
    } else if (text.includes('high') || text.includes('高危') || text.includes('高风险')) {
      bq.classList.add('callout-high')
    } else if (text.includes('medium') || text.includes('中危') || text.includes('中风险')) {
      bq.classList.add('callout-medium')
    } else if (text.includes('low') || text.includes('低危') || text.includes('低风险')) {
      bq.classList.add('callout-low')
    } else if (text.includes('warn') || text.includes('caution') || text.includes('注意') || text.includes('警告')) {
      bq.classList.add('callout-warning')
    } else if (text.includes('info') || text.includes('note') || text.includes('提示') || text.includes('建议')) {
      bq.classList.add('callout-info')
    } else if (text.includes('success') || text.includes('修复') || text.includes('完成') || text.includes('通过')) {
      bq.classList.add('callout-success')
    }
  })
}

function injectCodeBlockHeaders() {
  if (!previewRef.value) return
  const pres = previewRef.value.querySelectorAll('pre')
  pres.forEach((pre) => {
    if (pre.querySelector('.code-block-header')) return

    const code = pre.querySelector('code')
    const rawText = code ? code.textContent : pre.textContent
    const langClass = code?.className?.match(/language-([\w-]+)/)?.[1] || 'text'

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
      navigator.clipboard.writeText(rawText || '').then(() => {
        const textEl = btn.querySelector('.copy-text')
        textEl.textContent = '已复制'
        setTimeout(() => { textEl.textContent = '复制' }, 1500)
      })
    })

    pre.classList.add('mac-code-block')
    pre.insertBefore(header, pre.firstChild)
  })
}
</script>

<style scoped>
.preview {
  padding: 32px 36px;
  min-height: 540px;
  max-height: 700px;
  overflow-y: auto;
  background: var(--bg-base);
  color: var(--text-primary);
  font-size: 14px;
  line-height: 1.8;
  font-family: var(--font-sans);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  transition: background 0.2s, color 0.2s;
}

:deep(.markdown-body) {
  letter-spacing: 0.01em;
  word-break: break-word;
  overflow-wrap: anywhere;
}

/* ── Headings: unified font-family, consistent spacing ── */
:deep(.markdown-body h1) {
  font-size: 24px;
  font-weight: 700;
  color: var(--text-primary);
  border-bottom: 2px solid var(--border);
  padding-bottom: 10px;
  margin: 32px 0 16px;
  line-height: 1.35;
  font-family: var(--font-sans);
}

:deep(.markdown-body h2) {
  font-size: 19px;
  font-weight: 600;
  color: var(--text-primary);
  border-bottom: 1px solid var(--border);
  padding-bottom: 8px;
  margin: 28px 0 14px;
  line-height: 1.4;
  font-family: var(--font-sans);
}

:deep(.markdown-body h3) {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
  margin: 22px 0 10px;
  line-height: 1.45;
  font-family: var(--font-sans);
}

:deep(.markdown-body h4) {
  font-size: 14.5px;
  font-weight: 600;
  color: var(--text-primary);
  margin: 18px 0 8px;
  padding-top: 6px;
  border-top: 1px dashed color-mix(in srgb, var(--border) 60%, transparent);
  line-height: 1.5;
  font-family: var(--font-sans);
}

:deep(.markdown-body h5) {
  font-size: 13.5px;
  font-weight: 600;
  color: var(--text-primary);
  margin: 16px 0 6px;
  line-height: 1.5;
  font-family: var(--font-sans);
}

/* ── Body text ── */
:deep(.markdown-body p) {
  margin: 10px 0;
  color: var(--text-secondary);
  line-height: 1.8;
  font-family: var(--font-sans);
  font-size: 14px;
}

:deep(.markdown-body strong) {
  color: var(--text-primary);
  font-weight: 600;
}

:deep(.markdown-body hr) {
  border: none;
  border-top: 1px solid color-mix(in srgb, var(--border) 70%, transparent);
  margin: 20px 0;
}

/* ── Inline code ── */
:deep(.markdown-body code) {
  font-family: var(--font-mono);
  font-size: 12.5px;
  background: var(--code-inline-bg);
  padding: 2px 6px;
  border-radius: 4px;
  color: var(--code-inline-fg);
  border: 1px solid var(--code-border);
}

/* ── Code blocks ── */
:deep(.markdown-body pre) {
  position: relative;
  background: var(--code-bg) !important;
  border: 1px solid var(--code-border) !important;
  border-radius: 8px;
  padding: 0;
  overflow: hidden;
  margin: 14px 0 18px;
  box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
}

:deep(.markdown-body pre.mac-code-block > code) {
  display: block;
  padding: 14px 16px;
  max-height: 420px;
  overflow: auto;
  background: transparent !important;
  border: none;
  color: var(--hljs-fg);
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 1.65;
  white-space: pre;
}

:deep(.markdown-body pre:not(.mac-code-block)) {
  padding: 16px;
  max-height: 420px;
  overflow: auto;
}

:deep(.markdown-body pre:not(.mac-code-block) code) {
  background: transparent !important;
  border: none;
  padding: 0;
  color: var(--hljs-fg);
  font-size: 12.5px;
  line-height: 1.65;
}

:deep(.markdown-body pre code.hljs) {
  background: transparent !important;
}

:deep(.code-block-header) {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  background: var(--code-header-bg);
  border-bottom: 1px solid var(--code-border);
  user-select: none;
}

:deep(.mac-dots) { display: flex; gap: 6px; }
:deep(.mac-dots .dot) { width: 12px; height: 12px; border-radius: 50%; }
:deep(.mac-dots .dot.red) { background: #ff5f57; }
:deep(.mac-dots .dot.yellow) { background: #febc2e; }
:deep(.mac-dots .dot.green) { background: #28c840; }

:deep(.code-lang) {
  flex: 1;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

:deep(.copy-btn) {
  display: flex;
  align-items: center;
  gap: 4px;
  background: none;
  border: 1px solid var(--code-border);
  border-radius: 4px;
  padding: 3px 8px;
  color: var(--text-muted);
  font-size: 11px;
  font-family: var(--font-mono);
  cursor: pointer;
  transition: all 0.15s;
}

:deep(.copy-btn:hover) {
  background: var(--bg-hover);
  color: var(--text-primary);
  border-color: var(--text-muted);
}

:deep(.markdown-body pre code::-webkit-scrollbar),
:deep(.markdown-body pre::-webkit-scrollbar) {
  width: 6px;
  height: 6px;
}

:deep(.markdown-body pre code::-webkit-scrollbar-thumb),
:deep(.markdown-body pre::-webkit-scrollbar-thumb) {
  background: var(--border);
  border-radius: 3px;
}

/* ── Tables ── */
:deep(.markdown-body .table-scroll) {
  margin: 14px 0 18px;
  overflow-x: auto;
  border: 1px solid var(--border) !important;
  border-radius: 8px;
  background: var(--bg-surface);
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.2);
}

:deep(.markdown-body table) {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  min-width: 480px;
  margin: 0;
  display: table;
  line-height: 1.7;
  font-family: var(--font-sans);
}

:deep(.markdown-body th),
:deep(.markdown-body td) {
  border: 1px solid var(--border) !important;
  padding: 10px 12px;
  vertical-align: top;
  line-height: 1.7;
  word-break: break-word;
  white-space: normal;
  font-size: 13px;
}

:deep(.markdown-body th) {
  background: var(--bg-elevated);
  color: var(--text-primary);
  font-weight: 600;
  text-align: left;
  white-space: normal;
  font-family: var(--font-sans);
}

:deep(.markdown-body td) {
  color: var(--text-secondary);
  font-family: var(--font-sans);
}

:deep(.markdown-body td code) {
  font-size: 12px;
}

:deep(.markdown-body tbody tr:nth-child(even)) {
  background: color-mix(in srgb, var(--bg-elevated) 48%, transparent);
}

:deep(.markdown-body tbody tr:hover) {
  background: color-mix(in srgb, var(--bg-hover) 60%, transparent);
}

/* ── Lists ── */
:deep(.markdown-body ul),
:deep(.markdown-body ol) {
  padding-left: 22px;
  color: var(--text-secondary);
  margin: 10px 0;
  line-height: 1.8;
  font-family: var(--font-sans);
}

:deep(.markdown-body li) {
  margin: 6px 0;
  line-height: 1.8;
}

:deep(.markdown-body li strong) {
  color: var(--text-primary);
}

/* ── Links ── */
:deep(.markdown-body a) {
  color: var(--accent-blue);
  text-decoration: none;
}

:deep(.markdown-body a:hover) {
  text-decoration: underline;
}

/* ── Blockquotes ── */
:deep(.markdown-body blockquote) {
  border-left: 3px solid var(--accent-blue);
  padding: 8px 16px;
  margin: 12px 0;
  color: var(--text-secondary);
  line-height: 1.7;
  background: color-mix(in srgb, var(--accent-blue) 4%, transparent);
  border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  font-size: 13px;
}

:deep(.markdown-body blockquote p) {
  margin: 4px 0;
}

:deep(.markdown-body blockquote.callout-critical) {
  border-left-color: var(--accent-red);
  background: color-mix(in srgb, var(--accent-red) 8%, transparent);
}
:deep(.markdown-body blockquote.callout-critical strong) {
  color: var(--accent-red);
}

:deep(.markdown-body blockquote.callout-high) {
  border-left-color: var(--accent-orange);
  background: color-mix(in srgb, var(--accent-orange) 8%, transparent);
}
:deep(.markdown-body blockquote.callout-high strong) {
  color: var(--accent-orange);
}

:deep(.markdown-body blockquote.callout-medium) {
  border-left-color: var(--accent-yellow);
  background: color-mix(in srgb, var(--accent-yellow) 8%, transparent);
}

:deep(.markdown-body blockquote.callout-low) {
  border-left-color: var(--accent-blue);
  background: color-mix(in srgb, var(--accent-blue) 8%, transparent);
}

:deep(.markdown-body blockquote.callout-warning) {
  border-left-color: var(--accent-yellow);
  background: color-mix(in srgb, var(--accent-yellow) 10%, transparent);
}

:deep(.markdown-body blockquote.callout-info) {
  border-left-color: var(--accent-blue);
  background: color-mix(in srgb, var(--accent-blue) 6%, transparent);
}

:deep(.markdown-body blockquote.callout-success) {
  border-left-color: var(--accent-green);
  background: color-mix(in srgb, var(--accent-green) 8%, transparent);
}

/* ── Details/Summary ── */
:deep(.markdown-body details) {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
  margin: 12px 0 14px;
  background: var(--bg-elevated);
}

:deep(.markdown-body summary) {
  cursor: pointer;
  color: var(--accent-blue);
  font-weight: 500;
  font-size: 13px;
}

/* ── Fallback selectors for v-html content ── */
.preview :deep(table) {
  border-collapse: collapse !important;
  width: 100% !important;
}

.preview :deep(th),
.preview :deep(td) {
  border: 1px solid var(--border) !important;
  padding: 10px 12px !important;
}

.preview :deep(pre) {
  background: var(--code-bg) !important;
  border: 1px solid var(--code-border) !important;
}

.preview :deep(pre code.hljs) {
  background: transparent !important;
}
</style>
