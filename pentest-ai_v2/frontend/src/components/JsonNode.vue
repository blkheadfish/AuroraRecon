<template>
  <div class="json-node" :style="{ paddingLeft: depth > 0 ? '18px' : '0' }">

    <!-- ── 展开状态：key + 开括号独占一行 ── -->
    <div v-if="isExpandable && isOpen" class="node-row" @click="toggle">
      <span class="arrow expanded">▶</span>
      <span v-if="showKey" class="node-key">"{{ name }}"<span class="colon">: </span></span>
      <span class="bracket">{{ openBracket }}</span>
      <el-button link size="small" class="drill-btn" @click.stop="$emit('drill-down', name)" title="在 Raw 模式查看">⤢
      </el-button>
    </div>

    <!-- ── 折叠状态：key + 预览摘要 ── -->
    <div v-else-if="isExpandable && !isOpen" class="node-row" @click="toggle">
      <span class="arrow">▶</span>
      <span v-if="showKey" class="node-key">"{{ name }}"<span class="colon">: </span></span>
      <span class="collapsed-preview">{{ collapsedPreview }}</span>
      <span class="item-count">{{ childCount }} {{ isArray ? 'items' : 'keys' }}</span>
      <el-button link size="small" class="drill-btn" @click.stop="$emit('drill-down', name)" title="在 Raw 模式查看">⤢
      </el-button>
    </div>

    <!-- ── 原始值 ── -->
    <div v-else class="node-row">
      <span class="arrow-placeholder"></span>
      <span v-if="showKey" class="node-key">"{{ name }}"<span class="colon">: </span></span>
      <span class="node-val" :class="valueClass">{{ displayValue }}</span>
    </div>

    <!-- ── 子节点列表 + 闭合括号 ── -->
    <div v-if="isExpandable && isOpen" class="children">
      <template v-if="childCount === 0">
        <div class="close-row">
          <span class="arrow-placeholder"></span>
          <span class="bracket">{{ closeBracket }}</span>
        </div>
      </template>
      <template v-else>
        <JsonNode
            v-for="(child, key) in childEntries"
            :key="key"
            :data="child"
            :name="key"
            :depth="depth + 1"
            :force-expand="forceExpand"
            @drill-down="(k) => $emit('drill-down', k)"
        />
        <div class="close-row">
          <span class="arrow-placeholder"></span>
          <span class="bracket">{{ closeBracket }}</span>
        </div>
      </template>
    </div>

  </div>
</template>

<script setup>
import {ref, computed, watch} from 'vue'

const props = defineProps({
  data: {default: undefined},
  name: {default: undefined},
  depth: {type: Number, default: 0},
  forceExpand: Boolean,
})

defineEmits(['drill-down'])

const isOpen = ref(props.depth < 2)
watch(() => props.forceExpand, (v) => {
  isOpen.value = v
})

const isArray = computed(() => Array.isArray(props.data))
const isExpandable = computed(() => props.data !== null && typeof props.data === 'object')

// depth === 0 时是 root，不显示 key；depth > 0 才显示
const showKey = computed(() =>
    props.name !== undefined && props.name !== null && props.depth > 0
)

const openBracket = computed(() => isArray.value ? '[' : '{')
const closeBracket = computed(() => isArray.value ? ']' : '}')

const childCount = computed(() =>
    isArray.value ? props.data.length : Object.keys(props.data || {}).length
)

const childEntries = computed(() => {
  if (isArray.value) {
    return props.data.reduce((acc, v, i) => {
      acc[i] = v;
      return acc
    }, {})
  }
  return props.data || {}
})

const collapsedPreview = computed(() => {
  if (isArray.value) {
    const preview = props.data.slice(0, 3).map(v => JSON.stringify(v)).join(', ')
    return `[ ${preview}${props.data.length > 3 ? ', …' : ''} ]`
  }
  const keys = Object.keys(props.data || {}).slice(0, 3)
  const preview = keys.map(k => `${k}: …`).join(', ')
  return `{ ${preview}${Object.keys(props.data || {}).length > 3 ? ', …' : ''} }`
})

const displayValue = computed(() => {
  if (props.data === null) return 'null'
  if (props.data === undefined) return 'undefined'
  if (typeof props.data === 'string') return `"${props.data}"`
  return String(props.data)
})

const valueClass = computed(() => {
  if (props.data === null) return 'val-null'
  if (typeof props.data === 'boolean') return 'val-bool'
  if (typeof props.data === 'number') return 'val-num'
  if (typeof props.data === 'string') return 'val-str'
  return ''
})

function toggle() {
  if (isExpandable.value) isOpen.value = !isOpen.value
}
</script>

<style scoped>
.json-node {
  line-height: 1.8;
  font-family: var(--font-mono);
  font-size: 12.5px;
}

.node-row {
  display: flex;
  align-items: baseline;
  gap: 2px;
  cursor: default;
  border-radius: 3px;
  padding: 0 4px 0 0;
  transition: background 0.1s;
  min-height: 1.8em;
}

.node-row:hover {
  background: var(--bg-hover);
}

.arrow {
  display: inline-block;
  font-size: 9px;
  color: var(--text-muted);
  width: 14px;
  cursor: pointer;
  transition: transform 0.15s;
  user-select: none;
  flex-shrink: 0;
}

.arrow.expanded {
  transform: rotate(90deg);
}

.arrow-placeholder {
  display: inline-block;
  width: 14px;
  flex-shrink: 0;
}

.node-key {
  color: var(--hljs-attr);
}

.colon {
  color: var(--text-muted);
}

.bracket {
  color: var(--text-secondary);
}

.node-val {
}

.val-str {
  color: var(--hljs-string);
}

.val-num {
  color: var(--hljs-number);
}

.val-bool {
  color: var(--hljs-keyword);
}

.val-null {
  color: var(--text-muted);
  font-style: italic;
}

.collapsed-preview {
  color: var(--text-muted);
  font-style: italic;
  max-width: 400px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.item-count {
  font-size: 10px;
  color: var(--text-muted);
  background: var(--bg-elevated);
  padding: 1px 6px;
  border-radius: 10px;
  margin-left: 4px;
  white-space: nowrap;
}

.drill-btn {
  font-size: 12px !important;
  color: var(--text-muted) !important;
  padding: 0 4px !important;
  opacity: 0;
  transition: opacity 0.15s;
  line-height: 1 !important;
  margin-left: 2px;
}

.node-row:hover .drill-btn {
  opacity: 1;
}

.drill-btn:hover {
  color: var(--accent-blue) !important;
}

.children {
  border-left: 1px solid var(--border-muted);
  margin-left: 6px;
}

.close-row {
  display: flex;
  align-items: baseline;
  gap: 2px;
  padding: 0 4px 0 0;
  min-height: 1.8em;
}
</style>