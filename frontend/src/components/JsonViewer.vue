<template>
  <div class="json-viewer">
    <!-- Toolbar -->
    <div class="viewer-toolbar">
      <span class="viewer-title">
        <el-icon><DataLine/></el-icon>
        {{ title }}
      </span>
      <div class="toolbar-actions">
        <span v-if="currentPath.length" class="path-crumb">
          <span class="crumb-seg" @click="currentPath = []">root</span>
          <span v-for="(seg, i) in currentPath" :key="i">
            <span class="crumb-sep">/</span>
            <span class="crumb-seg" @click="navigateTo(i)">{{ seg }}</span>
          </span>
        </span>

        <el-button-group size="small">
          <el-button @click="viewMode = 'tree'" :type="viewMode === 'tree' ? 'primary' : ''">Tree</el-button>
          <el-button @click="viewMode = 'raw'" :type="viewMode === 'raw'  ? 'primary' : ''">Raw</el-button>
        </el-button-group>

        <el-button size="small" @click="expandAll = !expandAll">
          {{ expandAll ? '全部折叠' : '全部展开' }}
        </el-button>

        <el-button size="small" @click="copyJson">
          <el-icon>
            <CopyDocument/>
          </el-icon>
        </el-button>
      </div>
    </div>

    <!-- Raw view -->
    <div v-if="viewMode === 'raw'" class="code-wrap">
      <div class="line-numbers" aria-hidden="true">
        <span v-for="n in lineCount" :key="n">{{ n }}</span>
      </div>
      <pre class="code-block"><code v-html="highlighted"></code></pre>
    </div>

    <!-- Tree view — 与 Raw 完全相同的容器/字体 -->
    <div v-else class="code-wrap">
      <div class="tree-gutter" aria-hidden="true"></div>
      <div class="tree-block">
        <!-- root 节点：直接渲染 { 开括号，不带 "root": 前缀 -->
        <JsonNode
            v-if="currentData !== undefined"
            :data="currentData"
            :depth="0"
            :force-expand="expandAll"
            @drill-down="handleDrillDown"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
import {ref, computed} from 'vue'
import {ElMessage} from 'element-plus'
import hljs from 'highlight.js/lib/core'
import json from 'highlight.js/lib/languages/json'
import 'highlight.js/styles/github-dark.css'
import JsonNode from './JsonNode.vue'

hljs.registerLanguage('json', json)

const props = defineProps({
  data: {type: [Object, Array, null], default: null},
  title: {type: String, default: 'JSON'},
})

const viewMode = ref('tree')
const expandAll = ref(false)
const currentPath = ref([])

const currentData = computed(() => {
  let d = props.data
  for (const key of currentPath.value) {
    if (d === null || d === undefined) return undefined
    d = d[key]
  }
  return d
})

const jsonString = computed(() => {
  try {
    return JSON.stringify(currentData.value, null, 2)
  } catch {
    return String(currentData.value)
  }
})

const highlighted = computed(() => {
  try {
    return hljs.highlight(jsonString.value, {language: 'json'}).value
  } catch {
    return jsonString.value
  }
})

const lineCount = computed(() => jsonString.value.split('\n').length)

function navigateTo(idx) {
  currentPath.value = currentPath.value.slice(0, idx + 1)
}

function handleDrillDown(key) {
  currentPath.value.push(String(key))
}

function copyJson() {
  navigator.clipboard.writeText(jsonString.value)
  ElMessage.success('JSON 已复制')
}
</script>

<style scoped>
/* ── 整体容器 ── */
.json-viewer {
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
  background: var(--hljs-bg);
}

/* ── Toolbar ── */
.viewer-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 14px;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border);
  flex-wrap: wrap;
  gap: 8px;
}

.viewer-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text-secondary);
  font-family: var(--font-mono);
}

.toolbar-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.path-crumb {
  display: flex;
  align-items: center;
  font-size: 12px;
  font-family: var(--font-mono);
}

.crumb-seg {
  color: var(--accent-blue);
  cursor: pointer;
  padding: 0 2px;
}

.crumb-seg:hover {
  text-decoration: underline;
}

.crumb-sep {
  color: var(--text-muted);
  padding: 0 2px;
}

/* ── 共享代码区容器（Raw & Tree 完全一致）── */
.code-wrap {
  display: flex;
  max-height: 520px;
  overflow: auto;
}

/* Raw：行号列 */
.line-numbers {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  padding: 14px 10px 14px 14px;
  background: var(--hljs-bg);
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 1.8;
  user-select: none;
  border-right: 1px solid var(--border);
  min-width: 48px;
  flex-shrink: 0;
}

/* Raw：代码块 */
.code-block :deep(*) {
  margin: 0;
  padding: 14px 16px;
  flex: 1;
  background: transparent;
  font-family: var(--font-mono), monospace !important;
  font-size: 12.5px;
  line-height: 1.8;
  white-space: pre;
  overflow: visible;
  color: var(--hljs-fg);
}

/* Tree：占位列（与行号列等宽，保持对齐） */
.tree-gutter {
  width: 48px;
  flex-shrink: 0;
  border-right: 1px solid var(--border);
  background: var(--hljs-bg);
}

/* Tree：内容列（字体/行高与 Raw code-block 完全一致） */
.tree-block {
  padding: 14px 16px;
  flex: 1;
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 1.8;
  overflow: visible;
}
</style>