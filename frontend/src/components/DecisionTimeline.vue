<template>
  <div class="timeline-wrap" ref="wrapRef" @scroll="onUserScroll">
    <el-timeline>
      <TransitionGroup name="tl-item" tag="div">
        <el-timeline-item
          v-for="item in items"
          :key="item.id"
          :timestamp="item.time"
          :type="item.tone"
          :hollow="item.tone === 'info'"
          :data-item-id="item.id"
        >
          <div class="timeline-item" :class="{ 'thought-item': item.action === 'thought' }" :data-item-id="item.id">
            <div class="top-line">
              <span class="title">{{ item.title }}</span>
              <el-tag size="small" :type="toneTagMap[item.tone]">{{ toneTextMap[item.tone] }}</el-tag>
            </div>
            <p class="desc">{{ item.desc }}</p>

            <template v-if="item.action === 'thought'">
              <div v-if="item.purpose" class="thought-meta">
                <span class="meta-label">目标</span> {{ item.purpose }}
              </div>
              <div v-if="item.expected" class="thought-meta">
                <span class="meta-label">预期</span> {{ item.expected }}
              </div>
              <div v-if="Array.isArray(item.plan) && item.plan.length" class="thought-plan">
                <span class="meta-label">攻击计划</span>
                <ol>
                  <li v-for="(step, si) in item.plan" :key="si">{{ step }}</li>
                </ol>
              </div>
              <details v-if="item.expandable" class="thought-expand">
                <summary>展开完整推理</summary>
                <pre class="thought-full">{{ item.thinking }}</pre>
              </details>
            </template>

            <slot name="card" :item="item" />
            <PayloadCodeBlock
              v-for="(block, index) in payloadBlocks(item)"
              :key="`${item.id}-block-${index}`"
              :title="block.title"
              :language="block.language"
              :code="block.code"
              :truncated="Boolean(block.truncated)"
              :total-len="Number(block.totalLen || 0)"
            />
          </div>
        </el-timeline-item>
      </TransitionGroup>
    </el-timeline>

    <div ref="bottomAnchor" class="bottom-anchor" />

    <transition name="fade">
      <button v-if="showJumpBtn" class="jump-latest" @click="jumpToBottom">
        <el-icon><ArrowDown /></el-icon>
        跳转最新
      </button>
    </transition>
  </div>
</template>

<script setup>
import { ref, watch, nextTick, onMounted, onBeforeUnmount } from 'vue'
import { ArrowDown } from '@element-plus/icons-vue'
import PayloadCodeBlock from '@/components/PayloadCodeBlock.vue'

const props = defineProps({
  items: {
    type: Array,
    default: () => [],
  },
})

const wrapRef = ref(null)
const bottomAnchor = ref(null)
const showJumpBtn = ref(false)
const stickyBottom = ref(true)
let scrollRafId = 0
let userScrolling = false
let scrollTimeout = null

const BOTTOM_THRESHOLD = 150

function isNearBottom() {
  const el = wrapRef.value
  if (!el) return true
  return el.scrollHeight - el.scrollTop - el.clientHeight < BOTTOM_THRESHOLD
}

function onUserScroll() {
  userScrolling = true
  if (scrollTimeout) clearTimeout(scrollTimeout)
  scrollTimeout = setTimeout(() => { userScrolling = false }, 120)

  stickyBottom.value = isNearBottom()
  if (stickyBottom.value) {
    showJumpBtn.value = false
  }
}

function smoothScrollToBottom() {
  if (!wrapRef.value) return
  cancelAnimationFrame(scrollRafId)
  scrollRafId = requestAnimationFrame(() => {
    wrapRef.value?.scrollTo({ top: wrapRef.value.scrollHeight, behavior: 'smooth' })
  })
}

function jumpToBottom() {
  stickyBottom.value = true
  showJumpBtn.value = false
  smoothScrollToBottom()
}

watch(
  () => props.items.length,
  async (newLen, oldLen) => {
    if (newLen <= (oldLen || 0)) return
    await nextTick()

    if (stickyBottom.value && !userScrolling) {
      smoothScrollToBottom()
    } else {
      showJumpBtn.value = true
    }
  },
)

onMounted(() => {
  nextTick(() => {
    if (wrapRef.value) {
      wrapRef.value.scrollTop = wrapRef.value.scrollHeight
    }
  })
})

onBeforeUnmount(() => {
  cancelAnimationFrame(scrollRafId)
  if (scrollTimeout) clearTimeout(scrollTimeout)
})

const toneTextMap = {
  primary: '决策',
  success: '成功',
  warning: '待确认',
  danger: '风险',
  info: '信息',
}

const toneTagMap = {
  primary: 'primary',
  success: 'success',
  warning: 'warning',
  danger: 'danger',
  info: 'info',
}

function payloadBlocks(item) {
  if (Array.isArray(item?.payloads) && item.payloads.length) return item.payloads
  if (item?.payload) return [item.payload]
  return []
}

function scrollToItem(id) {
  if (!wrapRef.value || !id) return
  const el = wrapRef.value.querySelector(`[data-item-id="${id}"]`)
  if (el) {
    stickyBottom.value = false
    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
    el.classList.add('highlight-flash')
    setTimeout(() => el.classList.remove('highlight-flash'), 1500)
  }
}

defineExpose({ scrollToItem })
</script>

<style scoped>
.timeline-wrap {
  position: relative;
  padding: 8px 4px;
  overflow-y: auto;
  scroll-behavior: auto;
  flex: 1;
  min-height: 0;
}

.bottom-anchor {
  height: 1px;
  width: 100%;
}

.timeline-item {
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-base);
  padding: 10px 12px;
}

/* TransitionGroup animations for new items */
.tl-item-enter-active {
  transition: all 0.4s cubic-bezier(0.22, 1, 0.36, 1);
}
.tl-item-enter-from {
  opacity: 0;
  transform: translateY(16px);
}
.tl-item-move {
  transition: transform 0.3s ease;
}

.top-line {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
}

.title {
  color: var(--text-primary);
  font-size: 13px;
  font-weight: 600;
}

.desc {
  color: var(--text-secondary);
  margin: 0 0 8px;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-line;
}

.thought-item {
  border-left: 3px solid var(--el-color-primary);
}

.thought-meta {
  font-size: 12px;
  color: var(--text-secondary);
  margin: 2px 0;
  line-height: 1.5;
}

.meta-label {
  display: inline-block;
  min-width: 3em;
  font-weight: 600;
  color: var(--text-primary);
  margin-right: 4px;
}

.thought-plan {
  font-size: 12px;
  color: var(--text-secondary);
  margin: 4px 0 6px;
}

.thought-plan ol {
  margin: 2px 0 0;
  padding-left: 20px;
}

.thought-plan li {
  line-height: 1.6;
}

.thought-expand {
  margin-top: 6px;
  font-size: 12px;
}

.thought-expand summary {
  cursor: pointer;
  color: var(--accent-blue);
  font-weight: 500;
  user-select: none;
}

.thought-full {
  margin: 6px 0 0;
  padding: 8px 10px;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-secondary);
  background: color-mix(in srgb, var(--bg-base) 80%, var(--el-color-primary) 5%);
  border-radius: var(--radius-md);
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 300px;
  overflow-y: auto;
}

.jump-latest {
  position: sticky;
  bottom: 12px;
  left: 50%;
  transform: translateX(-50%);
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 7px 18px;
  border: 1px solid var(--accent-blue);
  border-radius: 20px;
  background: var(--bg-elevated);
  color: var(--accent-blue);
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
  z-index: 10;
  transition: all 0.2s ease;
}
.jump-latest:hover {
  background: var(--accent-blue);
  color: #fff;
  box-shadow: 0 4px 20px rgba(91, 153, 209, 0.35);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.25s ease, transform 0.25s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  transform: translateX(-50%) translateY(8px);
}

@keyframes highlight-pulse {
  0%   { box-shadow: 0 0 0 0 var(--accent-blue); }
  50%  { box-shadow: 0 0 0 4px color-mix(in srgb, var(--accent-blue) 25%, transparent); }
  100% { box-shadow: 0 0 0 0 transparent; }
}

.highlight-flash {
  animation: highlight-pulse 0.7s ease 2;
  border-color: var(--accent-blue) !important;
}
</style>
