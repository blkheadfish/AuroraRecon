<template>
  <div class="payload-wrap">
    <div class="payload-header">
      <span class="payload-title">{{ title }}</span>
      <div class="payload-actions">
        <el-tag v-if="truncated" size="small" type="warning" effect="light">truncated</el-tag>
        <span class="lang">{{ language }}</span>
        <el-button v-if="shouldCollapse" link size="small" @click="expanded = !expanded">
          {{ expanded ? '收起' : '展开' }}
        </el-button>
        <el-button link size="small" @click="copyCode">复制</el-button>
      </div>
    </div>
    <div v-if="truncated" class="truncated-tip">
      后端输出已截断，原始长度 {{ effectiveTotalLen }} 字符。
    </div>
    <pre class="payload-body" :style="bodyStyle"><code class="hljs" v-html="highlighted"></code></pre>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import hljs from 'highlight.js/lib/core'
import bash from 'highlight.js/lib/languages/bash'
import json from 'highlight.js/lib/languages/json'
import http from 'highlight.js/lib/languages/http'
import python from 'highlight.js/lib/languages/python'
import xml from 'highlight.js/lib/languages/xml'

hljs.registerLanguage('bash', bash)
hljs.registerLanguage('json', json)
hljs.registerLanguage('http', http)
hljs.registerLanguage('python', python)
hljs.registerLanguage('xml', xml)

const props = defineProps({
  title: { type: String, default: 'Payload' },
  language: { type: String, default: 'bash' },
  code: { type: String, default: '' },
  truncated: { type: Boolean, default: false },
  totalLen: { type: Number, default: 0 },
})

const COLLAPSED_HEIGHT = 400
const expanded = ref(false)

function escapeHtml(text) {
  return String(text || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

const codeLength = computed(() => String(props.code || '').length)
const lineCount = computed(() => String(props.code || '').split(/\r?\n/).length)
const shouldCollapse = computed(() => codeLength.value > 1800 || lineCount.value > 30)
const effectiveTotalLen = computed(() => {
  const n = Number(props.totalLen || 0)
  return Number.isFinite(n) && n > 0 ? n : codeLength.value
})
const bodyStyle = computed(() => {
  if (!shouldCollapse.value || expanded.value) {
    return { maxHeight: 'none' }
  }
  return { maxHeight: `${COLLAPSED_HEIGHT}px` }
})

const highlighted = computed(() => {
  if (!props.code) return ''
  const raw = String(props.code || '')
  if (['text', 'plain', 'plaintext', 'output'].includes(String(props.language || '').toLowerCase())) {
    return escapeHtml(raw)
  }
  try {
    if (hljs.getLanguage(props.language)) {
      return hljs.highlight(raw, { language: props.language }).value
    }
    return hljs.highlightAuto(raw).value
  } catch {
    return escapeHtml(raw)
  }
})

function copyCode() {
  navigator.clipboard.writeText(props.code || '')
  ElMessage.success('代码片段已复制')
}

watch(
  () => props.code,
  () => {
    expanded.value = false
  },
)
</script>

<style scoped>
.payload-wrap { border: 1px solid var(--border); border-radius: var(--radius-md); overflow: hidden; }
.payload-header { display: flex; justify-content: space-between; align-items: center; padding: 8px 10px; background: var(--code-header-bg); border-bottom: 1px solid var(--code-border); }
.payload-title { font-size: 12px; color: var(--text-secondary); font-weight: 600; }
.payload-actions { display: flex; align-items: center; gap: 10px; }
.lang { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); text-transform: uppercase; }
.truncated-tip {
  padding: 7px 10px;
  border-bottom: 1px dashed color-mix(in srgb, var(--accent-yellow) 35%, transparent);
  color: color-mix(in srgb, var(--accent-yellow) 82%, white);
  background: color-mix(in srgb, var(--accent-yellow) 10%, transparent);
  font-size: 11px;
}
.payload-body {
  margin: 0;
  padding: 12px;
  background: var(--hljs-bg);
  overflow: auto;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
