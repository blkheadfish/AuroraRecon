<template>
  <div
    class="bt-node"
    :class="{
      active: isActive,
      [`status-${node.status}`]: true,
    }"
    :style="{ '--depth': depth }"
  >
    <div class="bt-row">
      <span class="bt-rail">
        <span v-if="depth > 0" class="bt-line" />
      </span>
      <span class="bt-status-dot" :title="statusLabel" />
      <span class="bt-label">
        {{ node.label || node.branch_id }}
        <span v-if="node.is_root" class="bt-tag root">root</span>
        <span v-if="isActive" class="bt-tag active">激活</span>
      </span>
      <span class="bt-meta">
        <span v-if="node.fork_phase" class="bt-meta-item">@{{ node.fork_phase }}</span>
        <span v-if="node.fork_round" class="bt-meta-item">round {{ node.fork_round }}</span>
        <span class="bt-meta-item">{{ statusLabel }}</span>
      </span>
      <span class="bt-actions">
        <button v-if="!isActive" class="bt-btn primary" @click="$emit('activate', node.branch_id)">
          切到
        </button>
        <button v-if="node.status === 'paused'" class="bt-btn" @click="$emit('resume', node.branch_id)">
          继续运行
        </button>
        <button v-if="node.status === 'running'" class="bt-btn" @click="$emit('pause', node.branch_id)">
          暂停
        </button>
      </span>
    </div>
    <div v-if="children.length" class="bt-children">
      <BranchTreeNode
        v-for="child in children"
        :key="child.branch_id"
        :node="child"
        :children-by-parent="childrenByParent"
        :active-id="activeId"
        :depth="depth + 1"
        @activate="(id) => $emit('activate', id)"
        @resume="(id) => $emit('resume', id)"
        @pause="(id) => $emit('pause', id)"
      />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  node: { type: Object, required: true },
  childrenByParent: { type: Object, required: true },
  activeId: { type: String, default: '' },
  depth: { type: Number, default: 0 },
})

defineEmits(['activate', 'resume', 'pause'])

const isActive = computed(() => props.node.branch_id === props.activeId)
const children = computed(() => {
  if (!props.childrenByParent || typeof props.childrenByParent.get !== 'function') return []
  return props.childrenByParent.get(props.node.branch_id) || []
})
const statusLabel = computed(() => {
  switch (props.node.status) {
    case 'running': return '运行中'
    case 'paused': return '已暂停'
    case 'completed': return '已完成'
    case 'failed': return '失败'
    default: return props.node.status || ''
  }
})
</script>

<style scoped>
.bt-node {
  display: block;
}
.bt-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px 6px calc(8px + var(--depth, 0) * 16px);
  border-radius: var(--radius-sm);
}
.bt-row:hover {
  background: color-mix(in srgb, var(--text-primary) 6%, transparent);
}
.bt-node.active > .bt-row {
  background: color-mix(in srgb, var(--accent-blue, #58a6ff) 14%, var(--bg-base));
  border: 1px solid color-mix(in srgb, var(--accent-blue, #58a6ff) 50%, transparent);
}
.bt-rail {
  width: 0;
  position: relative;
}
.bt-line {
  position: absolute;
  top: -8px;
  bottom: 50%;
  left: -10px;
  width: 8px;
  border-left: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
  border-bottom-left-radius: 4px;
}
.bt-status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.status-running .bt-status-dot { background: var(--accent-green, #3fb950); box-shadow: 0 0 4px var(--accent-green, #3fb950); }
.status-paused .bt-status-dot { background: var(--accent-yellow, #d29922); }
.status-completed .bt-status-dot { background: var(--accent-blue, #58a6ff); }
.status-failed .bt-status-dot { background: var(--accent-red, #f85149); }

.bt-label {
  flex: 1;
  font-weight: 500;
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.bt-tag {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 999px;
  margin-left: 6px;
  vertical-align: middle;
  font-weight: 600;
}
.bt-tag.root {
  background: color-mix(in srgb, var(--accent-blue, #58a6ff) 15%, transparent);
  color: var(--accent-blue, #58a6ff);
}
.bt-tag.active {
  background: color-mix(in srgb, var(--accent-green, #3fb950) 18%, transparent);
  color: var(--accent-green, #3fb950);
}
.bt-meta {
  display: inline-flex;
  gap: 6px;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: 10px;
}
.bt-meta-item {
  padding: 1px 6px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--text-primary) 5%, transparent);
}
.bt-actions {
  display: inline-flex;
  gap: 4px;
}
.bt-btn {
  font-size: 11px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-secondary);
  padding: 2px 8px;
  border-radius: 999px;
  cursor: pointer;
}
.bt-btn:hover {
  color: var(--text-primary);
  border-color: var(--accent-blue, #58a6ff);
}
.bt-btn.primary {
  color: var(--accent-blue, #58a6ff);
  border-color: var(--accent-blue, #58a6ff);
}
.bt-children {
  position: relative;
}
</style>
