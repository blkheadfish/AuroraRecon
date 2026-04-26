<template>
  <div class="terminal-wrap">
    <div class="terminal-header">
      <div class="terminal-dots">
        <span class="dot red"></span>
        <span class="dot yellow"></span>
        <span class="dot green"></span>
      </div>
      <span class="terminal-title">task.log</span>
      <div class="terminal-actions">
        <el-tooltip content="自动滚动">
          <el-switch v-model="autoScroll" size="small"/>
        </el-tooltip>
        <el-button
          v-if="hiddenCount > 0 && !showAllRows"
          link
          size="small"
          class="action-btn"
          @click="showAllRows = true"
        >
          <span class="action-label">展开全部 {{ totalRows }} 行</span>
        </el-button>
        <el-button
          v-else-if="showAllRows"
          link
          size="small"
          class="action-btn"
          @click="showAllRows = false"
        >
          <span class="action-label">仅显示最近 {{ MAX_VISIBLE_ROWS }} 行</span>
        </el-button>
        <el-button link size="small" @click="copyLogs" class="action-btn">
          <el-icon>
            <CopyDocument/>
          </el-icon>
        </el-button>
        <el-button link size="small" @click="toggleHidden" class="action-btn">
          <el-icon>
            <component :is="hidden ? 'Monitor' : 'Remove'" />
          </el-icon>
          <span class="action-label">{{ hidden ? '显示日志' : '隐藏日志' }}</span>
        </el-button>
      </div>
    </div>

    <div class="terminal-body" ref="terminalRef">
      <div v-if="keyEvents.length" class="key-events">
        <span class="key-title">关键事件</span>
        <div class="key-list">
          <span v-for="(event, idx) in keyEvents" :key="idx" class="key-chip">{{ event }}</span>
        </div>
      </div>

      <div v-if="!displayLogs.length" class="empty-terminal">
        <span class="cursor-blink">█</span>
        <span class="wait-text">等待任务输出...</span>
      </div>

      <div v-if="hiddenCount > 0 && !showAllRows" class="log-truncate-hint">
        已折叠 {{ hiddenCount }} 行历史日志，仅渲染最近 {{ MAX_VISIBLE_ROWS }} 行避免页面卡顿
      </div>

      <div
          v-for="line in displayLogs"
          :key="line"
          class="log-line"
          :class="getLineClass(line)"
      >
        <span class="line-content" v-html="formatLine(line)"></span>
      </div>

      <!-- Live tool streams -->
      <template v-if="activeToolStreams.length">
        <details v-for="stream in activeToolStreams" :key="stream.id" class="tool-stream-section" open>
          <summary class="stream-header">
            <span class="pulse-dot"></span> {{ stream.id }}
          </summary>
          <div class="stream-lines">
            <div v-for="(line, li) in stream.lines" :key="li" class="log-line line-stream">
              <span class="line-num">{{ String(li + 1).padStart(4, ' ') }}</span>
              <span class="line-content">{{ line }}</span>
            </div>
          </div>
        </details>
      </template>

      <div v-if="running" class="log-line running-indicator">
        <span class="line-num">    </span>
        <span class="cursor-blink">█</span>
      </div>
    </div>

    <div class="terminal-footer">
      <span class="log-count">
        {{ displayLogs.length }} / {{ totalRows }} 行
      </span>
      <span v-if="running" class="running-badge">
        <span class="pulse-dot"></span> 实时接收中
      </span>
      <span v-else class="done-badge">● 已完成</span>
    </div>
  </div>
</template>

<script setup>
import {ref, computed, watch, nextTick, shallowRef} from 'vue'
import {ElMessage} from 'element-plus'

const props = defineProps({
  logs: {type: Array, default: () => []},
  running: Boolean,
  toolStreams: {type: Object, default: () => ({})},
})

// 单帧 DOM 渲染上千行 v-html + 多次正则会把主线程锁死。
// 默认只渲染最近 MAX_VISIBLE_ROWS 行,通过 toolbar 上的「展开全部」按钮
// 让用户在需要时主动放开,完整历史日志走分页接口而不是塞 DOM。
const MAX_VISIBLE_ROWS = 800
const KEY_EVENT_SCAN_TAIL = 600
const TOOL_STREAM_TAIL = 200

const showAllRows = ref(false)

const activeToolStreams = computed(() => {
  const result = []
  for (const [id, lines] of Object.entries(props.toolStreams || {})) {
    if (Array.isArray(lines) && lines.length > 0) {
      result.push({ id, lines: lines.slice(-TOOL_STREAM_TAIL) })
    }
  }
  return result
})

const terminalRef = ref()
const autoScroll = ref(true)
const hidden = ref(false)

const totalRows = computed(() => props.logs.length)

const displayLogs = computed(() => {
  if (hidden.value) return []
  if (showAllRows.value || props.logs.length <= MAX_VISIBLE_ROWS) {
    return props.logs
  }
  return props.logs.slice(-MAX_VISIBLE_ROWS)
})

const hiddenCount = computed(() =>
  Math.max(0, props.logs.length - displayLogs.value.length),
)

const keyEvents = computed(() => {
  const tail = props.logs.length > KEY_EVENT_SCAN_TAIL
    ? props.logs.slice(-KEY_EVENT_SCAN_TAIL)
    : props.logs
  return tail
    .filter(line =>
      /approval|required|authorized|利用成功|利用失败|report|报告生成|done|error|failed/i.test(line),
    )
    .slice(-5)
})

// 滚动批处理:连续日志到达时只在下一帧更新一次,避免每行触发一次同步
// scrollTop 计算(scrollHeight 在大列表下读取很贵,会触发 reflow)。
let scrollFrame = 0
function scheduleScrollToBottom() {
  if (!autoScroll.value) return
  if (scrollFrame) return
  scrollFrame = window.requestAnimationFrame(() => {
    scrollFrame = 0
    if (terminalRef.value) {
      terminalRef.value.scrollTop = terminalRef.value.scrollHeight
    }
  })
}

watch(() => props.logs.length, async () => {
  await nextTick()
  scheduleScrollToBottom()
})

function getLineClass(line) {
  if (line.includes('异常') || line.includes('失败') || line.includes('ERROR') || line.includes('error')) return 'line-error'
  if (line.includes('完成') || line.includes('成功') || line.includes('生成')) return 'line-success'
  if (line.includes('警告') || line.includes('WARNING') || line.includes('warn')) return 'line-warn'
  if (line.includes('[recon]')) return 'line-recon'
  if (line.includes('[vuln')) return 'line-vuln'
  if (line.includes('[exploit')) return 'line-exploit'
  if (line.includes('[post')) return 'line-post'
  if (line.includes('[report]')) return 'line-report'
  return ''
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

// 高亮结果按行内容缓存。同一条日志行在重渲染时不再重复跑 4 次正则替换,
// 切换/滚动 / 重新挂载时尤其有效。Map 大小上限同步 MAX_VISIBLE_ROWS。
const formatCache = shallowRef(new Map())
const FORMAT_CACHE_CAP = MAX_VISIBLE_ROWS * 2

function formatLine(line) {
  const cache = formatCache.value
  const cached = cache.get(line)
  if (cached !== undefined) return cached
  let out = escapeHtml(line)
  out = out.replace(/\[(\d{2}:\d{2}:\d{2})\]/g, '<span class="ts">[$1]</span>')
  out = out.replace(/\[([a-z_]+)\]/g, '<span class="phase-tag">[$1]</span>')
  out = out.replace(
    /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?)/g,
    '<span class="hl-ip">$1</span>',
  )
  out = out.replace(
    /\b(\d+)\s*(个|端口|漏洞|条|ms|s)\b/g,
    '<span class="hl-num">$1</span>$2',
  )
  if (cache.size >= FORMAT_CACHE_CAP) {
    // FIFO 驱逐: Map 维持插入顺序,删第一个就够。
    const firstKey = cache.keys().next().value
    if (firstKey !== undefined) cache.delete(firstKey)
  }
  cache.set(line, out)
  return out
}

function copyLogs() {
  navigator.clipboard.writeText(props.logs.join('\n'))
  ElMessage.success('日志已复制')
}

function toggleHidden() {
  hidden.value = !hidden.value
}
</script>

<style scoped>
.terminal-wrap {
  border-radius: var(--radius-md);
  overflow: hidden;
  border: 1px solid var(--border);
  font-family: var(--font-mono);
  background: var(--hljs-bg);
}

.terminal-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 14px;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border);
}

.terminal-dots {
  display: flex;
  gap: 6px;
}

.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

.dot.red {
  background: #ff5f57;
}

.dot.yellow {
  background: #ffbd2e;
}

.dot.green {
  background: #28c840;
}

.terminal-title {
  flex: 1;
  font-size: 12px;
  color: var(--text-muted);
  text-align: center;
}

.terminal-actions {
  display: flex;
  align-items: center;
  gap: 4px;
}

.action-btn {
  color: var(--text-muted) !important;
  font-size: 13px !important;
  padding: 2px !important;
}

.action-btn:hover {
  color: var(--text-secondary) !important;
}
.action-label {
  font-size: 11px;
  margin-left: 2px;
}

.terminal-body {
  min-height: 380px;
  max-height: 520px;
  overflow-y: auto;
  padding: 12px 0;
  background: var(--hljs-bg);
}

.key-events {
  padding: 0 16px 10px;
}
.key-title {
  display: inline-block;
  font-size: 11px;
  color: var(--text-muted);
  margin-bottom: 6px;
}
.key-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.key-chip {
  font-size: 11px;
  color: var(--accent-blue);
  border: 1px solid rgba(56,139,253,0.35);
  background: rgba(56,139,253,0.08);
  border-radius: 999px;
  padding: 2px 8px;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.empty-terminal {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 24px 16px;
  color: var(--text-muted);
  font-size: 13px;
}

.log-truncate-hint {
  margin: 6px 16px 8px;
  padding: 6px 10px;
  font-size: 11px;
  color: var(--text-muted);
  background: rgba(56, 139, 253, 0.06);
  border: 1px dashed rgba(56, 139, 253, 0.25);
  border-radius: 4px;
}

.wait-text {
  color: var(--text-muted);
}

.log-line {
  display: flex;
  gap: 16px;
  padding: 1px 16px;
  font-size: 12.5px;
  line-height: 1.7;
  color: var(--text-secondary);
  transition: background 0.1s;
}

.log-line:hover {
  background: var(--bg-hover);
}

.line-num {
  color: var(--text-muted);
  user-select: none;
  min-width: 32px;
  text-align: right;
  flex-shrink: 0;
}

.line-content {
  flex: 1;
  word-break: break-all;
  white-space: pre-wrap;
}

/* Line type colors */
.line-error .line-content {
  color: var(--accent-red);
}

.line-success .line-content {
  color: var(--accent-green);
}

.line-warn .line-content {
  color: var(--accent-yellow);
}

.line-recon .line-content {
  color: var(--accent-blue);
}

.line-vuln .line-content {
  color: var(--accent-yellow);
}

.line-exploit .line-content {
  color: var(--accent-red);
}

.line-post .line-content {
  color: var(--accent-purple);
}

.line-report .line-content {
  color: var(--accent-green);
}

.running-indicator {
  color: var(--accent-blue);
  padding-top: 4px;
}

/* Inline highlight classes (used in v-html) */
:deep(.ts) {
  color: var(--text-muted);
}

:deep(.phase-tag) {
  color: var(--accent-blue);
  font-weight: 500;
}

:deep(.hl-ip) {
  color: var(--accent-blue);
}

:deep(.hl-num) {
  color: var(--accent-yellow);
  font-weight: 600;
}

.terminal-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 16px;
  background: var(--bg-elevated);
  border-top: 1px solid var(--border);
  font-size: 11px;
}

.log-count {
  color: var(--text-muted);
}

.running-badge {
  display: flex;
  align-items: center;
  gap: 5px;
  color: var(--accent-blue);
}

.done-badge {
  color: var(--accent-green);
}

.pulse-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent-blue);
  display: inline-block;
  animation: pulse 1.2s infinite;
}

.cursor-blink {
  animation: blink 1s step-end infinite;
  color: var(--accent-blue);
}

@keyframes pulse {
  0%, 100% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.3;
    transform: scale(0.8);
  }
}

@keyframes blink {
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0;
  }
}

.tool-stream-section {
  margin: 8px 16px;
  border: 1px solid rgba(56, 139, 253, 0.2);
  border-radius: 6px;
  overflow: hidden;
}

.stream-header {
  cursor: pointer;
  padding: 4px 10px;
  font-size: 11px;
  color: var(--accent-blue);
  background: rgba(56, 139, 253, 0.06);
  display: flex;
  align-items: center;
  gap: 6px;
}

.stream-lines {
  max-height: 200px;
  overflow-y: auto;
}

.line-stream .line-content {
  color: var(--accent-blue);
  opacity: 0.85;
}
</style>
