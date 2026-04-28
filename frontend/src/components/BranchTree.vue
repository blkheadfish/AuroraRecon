<template>
  <aside class="branch-tree-panel" :class="{ collapsed: !expanded }">
    <header class="bt-header">
      <button class="bt-toggle" @click="expanded = !expanded" :title="expanded ? '收起' : '展开'">
        <el-icon><Share /></el-icon>
        <span class="bt-title">分支</span>
        <span class="bt-count" v-if="items.length">
          {{ items.length }}/{{ maxBranches }}
        </span>
        <el-icon class="bt-chevron" :class="{ open: expanded }">
          <ArrowDown />
        </el-icon>
      </button>
    </header>

    <section v-if="expanded" class="bt-body">
      <div v-if="!items.length" class="bt-empty">暂无分支记录</div>
      <ul v-else class="bt-tree" role="tree">
        <li
          v-for="node in tree"
          :key="node.branch_id"
          class="bt-node-root"
          role="treeitem"
        >
          <BranchTreeNode
            :node="node"
            :children-by-parent="childrenByParent"
            :active-id="activeBranchId"
            :depth="0"
            @activate="handleActivate"
            @resume="handleResume"
            @pause="handlePause"
          />
        </li>
      </ul>
    </section>
  </aside>
</template>

<script setup>
import { computed, ref } from 'vue'
import { ArrowDown, Share } from '@element-plus/icons-vue'
import BranchTreeNode from '@/components/BranchTreeNode.vue'

const props = defineProps({
  items: { type: Array, required: true },
  activeBranchId: { type: String, default: '' },
  maxBranches: { type: Number, default: 12 },
  defaultExpanded: { type: Boolean, default: true },
})

const emit = defineEmits(['activate', 'resume', 'pause'])

const expanded = ref(props.defaultExpanded)

const childrenByParent = computed(() => {
  const map = new Map()
  for (const it of props.items) {
    const key = it.parent_branch_id || ''
    if (!map.has(key)) map.set(key, [])
    map.get(key).push(it)
  }
  for (const arr of map.values()) {
    arr.sort((a, b) => (a.created_at || '').localeCompare(b.created_at || ''))
  }
  return map
})

const tree = computed(() => {
  // root nodes = parent_branch_id is empty/null
  return childrenByParent.value.get('') || childrenByParent.value.get(null) || []
})

function handleActivate(id) { emit('activate', id) }
function handleResume(id) { emit('resume', id) }
function handlePause(id) { emit('pause', id) }
</script>

<style scoped>
.branch-tree-panel {
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-surface);
  overflow: hidden;
  font-size: 12px;
}
.bt-header {
  border-bottom: 1px solid var(--border);
  background: var(--bg-elevated);
}
.bt-header > .bt-toggle {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 8px 12px;
  border: none;
  background: transparent;
  color: var(--text-primary);
  cursor: pointer;
  font-size: 13px;
  font-weight: 600;
}
.bt-title { flex: 1; text-align: left; }
.bt-count {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
  padding: 1px 8px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--text-primary) 8%, transparent);
}
.bt-chevron {
  transition: transform .15s ease;
}
.bt-chevron.open { transform: rotate(180deg); }

.bt-body {
  max-height: 320px;
  overflow-y: auto;
  padding: 6px 8px;
}
.bt-empty {
  color: var(--text-muted);
  text-align: center;
  padding: 18px 0;
}
.bt-tree { list-style: none; padding: 0; margin: 0; }
.bt-node-root + .bt-node-root { margin-top: 2px; }
.branch-tree-panel.collapsed .bt-body { display: none; }
</style>
