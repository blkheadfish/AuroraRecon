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

      <div
          v-for="(line, i) in displayLogs"
          :key="i"
          class="log-line"
          :class="getLineClass(line)"
      >
        <span class="line-num">{{ String(i + 1).padStart(4, ' ') }}</span>
        <span class="line-content" v-html="formatLine(line)"></span>
      </div>

      <div v-if="running" class="log-line running-indicator">
        <span class="line-num">    </span>
        <span class="cursor-blink">█</span>
      </div>
    </div>

    <div class="terminal-footer">
      <span class="log-count">{{ displayLogs.length }} 行</span>
      <span v-if="running" class="running-badge">
        <span class="pulse-dot"></span> 实时接收中
      </span>
      <span v-else class="done-badge">● 已完成</span>
    </div>
  </div>
</template>

<script setup>
import {ref, computed, watch, nextTick} from 'vue'
import {ElMessage} from 'element-plus'

const props = defineProps({
  logs: {type: Array, default: () => []},
  running: Boolean,
})

const terminalRef = ref()
const autoScroll = ref(true)
const hidden = ref(false)

const displayLogs = computed(() => hidden.value ? [] : props.logs)
const keyEvents = computed(() =>
  props.logs
    .filter(line =>
      /approval|required|authorized|利用成功|利用失败|report|报告生成|done|error|failed/i.test(line),
    )
    .slice(-5),
)

watch(() => props.logs.length, async () => {
  if (autoScroll.value) {
    await nextTick()
    if (terminalRef.value) {
      terminalRef.value.scrollTop = terminalRef.value.scrollHeight
    }
  }
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

function formatLine(line) {
  let out = escapeHtml(line)
  out = out.replace(
      /\[(\d{2}:\d{2}:\d{2})\]/g,
      '<span class="ts">[$1]</span>'
  )
  out = out.replace(
      /\[([a-z_]+)\]/g,
      '<span class="phase-tag">[$1]</span>'
  )
  out = out.replace(
      /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?)/g,
      '<span class="hl-ip">$1</span>'
  )
  out = out.replace(
      /\b(\d+)\s*(个|端口|漏洞|条|ms|s)\b/g,
      '<span class="hl-num">$1</span>$2'
  )
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
</style>
