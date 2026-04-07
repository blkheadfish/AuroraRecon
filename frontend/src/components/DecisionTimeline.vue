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
        >
          <div class="timeline-item">
            <div class="top-line">
              <span class="title">{{ item.title }}</span>
              <el-tag size="small" :type="toneTagMap[item.tone]">{{ toneTextMap[item.tone] }}</el-tag>
            </div>
            <p class="desc">{{ item.desc }}</p>
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
</style>
