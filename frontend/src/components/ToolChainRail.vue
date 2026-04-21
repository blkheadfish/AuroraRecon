<template>
  <div class="rail-wrap">
    <div class="rail-header">
      <span class="rail-title">工具链</span>
      <span class="rail-count">{{ nodes.length }}</span>
    </div>
    <div class="rail-list" ref="listRef">
      <div
        v-for="(node, i) in nodes"
        :key="node.id"
        class="rail-node"
        :class="{ active: node.id === activeId }"
        @click="$emit('jump', node.id)"
      >
        <div class="node-connector" v-if="i > 0" />
        <div class="node-dot" :class="'dot-' + node.tone" />
        <div class="node-body">
          <span class="node-label">{{ node.label }}</span>
          <span class="node-time">{{ node.time }}</span>
        </div>
      </div>
      <div v-if="!nodes.length" class="rail-empty">暂无事件</div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'

const props = defineProps({
  items: { type: Array, default: () => [] },
  activeId: { type: String, default: '' },
})

defineEmits(['jump'])

const listRef = ref(null)

const TOOL_ACTIONS = new Set([
  'command_exec', 'tool_start', 'tool_result', 'tool_executed',
  'approval_required', 'approval',
])

const nodes = computed(() => {
  const result = []
  for (const item of props.items) {
    const action = item.action || ''
    if (!TOOL_ACTIONS.has(action)) continue
    result.push({
      id: item.id,
      tone: item.tone || 'info',
      label: extractLabel(item),
      time: item.time || '',
    })
  }
  return result
})

function extractToolName(item) {
  if (item.tool) return item.tool
  const title = item.title || ''
  const mCmd = title.match(/命令执行\s*·\s*(.+)/)
  if (mCmd) return mCmd[1]
  const mTool = title.match(/工具调用\s*·\s*(.+)/)
  if (mTool) return mTool[1]
  const mRes = title.match(/调用结果\s*·\s*(.+)/)
  if (mRes) return mRes[1]
  return ''
}

function extractLabel(item) {
  const action = item.action || ''

  if (action === 'command_exec') {
    return (extractToolName(item) || 'shell').slice(0, 22)
  }
  if (action === 'tool_start') {
    const name = extractToolName(item) || 'tool'
    return `▶ ${name}`.slice(0, 22)
  }
  if (action === 'tool_result' || action === 'tool_executed') {
    const name = extractToolName(item) || 'tool'
    return `✓ ${name}`.slice(0, 22)
  }
  if (action === 'approval_required' || action === 'approval') {
    return '审批'
  }
  return (item.title || '事件').slice(0, 22)
}
</script>

<style scoped>
.rail-wrap {
  width: 180px;
  min-width: 180px;
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--border);
  background: var(--bg-elevated);
  overflow: hidden;
}

.rail-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}

.rail-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
}

.rail-count {
  font-size: 10px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  background: var(--bg-hover);
  padding: 1px 6px;
  border-radius: 8px;
}

.rail-list {
  flex: 1;
  overflow-y: auto;
  padding: 8px 0;
}

.rail-node {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 5px 12px;
  cursor: pointer;
  position: relative;
  transition: background 0.15s;
}

.rail-node:hover {
  background: var(--bg-hover);
}

.rail-node.active {
  background: color-mix(in srgb, var(--accent-blue) 10%, transparent);
}

.rail-node.active .node-label {
  color: var(--accent-blue);
  font-weight: 600;
}

.node-connector {
  position: absolute;
  left: 17px;
  top: -4px;
  width: 1px;
  height: 9px;
  background: var(--border);
}

.node-dot {
  width: 8px;
  height: 8px;
  min-width: 8px;
  border-radius: 50%;
  margin-top: 3px;
  border: 1.5px solid var(--border);
  background: var(--bg-base);
  transition: all 0.15s;
}

.dot-primary { border-color: var(--accent-blue); background: color-mix(in srgb, var(--accent-blue) 25%, var(--bg-base)); }
.dot-success { border-color: var(--accent-green); background: color-mix(in srgb, var(--accent-green) 25%, var(--bg-base)); }
.dot-warning { border-color: var(--accent-yellow); background: color-mix(in srgb, var(--accent-yellow) 25%, var(--bg-base)); }
.dot-danger { border-color: var(--accent-red); background: color-mix(in srgb, var(--accent-red) 25%, var(--bg-base)); }
.dot-info { border-color: var(--text-muted); }

.node-body {
  display: flex;
  flex-direction: column;
  min-width: 0;
  flex: 1;
}

.node-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  line-height: 1.3;
}

.node-time {
  font-size: 9px;
  color: var(--text-muted);
  font-family: var(--font-mono);
}

.rail-empty {
  padding: 20px 12px;
  text-align: center;
  font-size: 11px;
  color: var(--text-muted);
}
</style>
