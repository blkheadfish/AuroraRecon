<template>
  <div class="timeline-wrap" ref="wrapRef" @scroll="onUserScroll">
    <el-timeline>
      <div class="timeline-list">
        <el-timeline-item
          v-for="item in items"
          :key="item.id"
          :timestamp="item.time"
          :type="item.tone"
          :hollow="item.tone === 'info'"
          :data-item-id="item.id"
          class="timeline-fade-in"
        >
          <div class="timeline-item" :class="{ 'thought-item': item.action === 'thought' }" :data-item-id="item.id">
            <div class="top-line">
              <span class="title">{{ item.title }}</span>
              <el-tag size="small" :type="toneTagMap[item.tone]">{{ toneTextMap[item.tone] }}</el-tag>
            </div>
            <p class="desc">{{ item.desc }}</p>

            <component
              v-if="rendererFor(item.action)"
              :is="rendererFor(item.action)"
              :item="item"
            />

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
      </div>
    </el-timeline>

    <!-- Live LLM thinking bubbles -->
    <div v-for="(bubble, sid) in activeBubbles" :key="sid" class="llm-bubble">
      <div class="bubble-header">
        <span class="bubble-phase">{{ bubble.phase }}</span>
        <span class="bubble-indicator">正在思考<span class="dots">...</span></span>
      </div>
      <pre class="bubble-text">{{ bubble.text }}</pre>
    </div>

    <div ref="bottomAnchor" class="bottom-anchor" />

    <transition name="fade">
      <button v-if="showJumpBtn" class="jump-latest" @click="jumpToBottom">
        <el-icon><ArrowDown /></el-icon>
        跳转最新
      </button>
    </transition>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, nextTick, onMounted, onBeforeUnmount, defineComponent, h } from 'vue'
import { ArrowDown } from '@element-plus/icons-vue'
import PayloadCodeBlock from '@/components/PayloadCodeBlock.vue'

const DecisionThoughtRenderer = defineComponent({
  name: 'DecisionThoughtRenderer',
  props: { item: { type: Object, default: () => ({}) } },
  setup(props) {
    return () => [
      props.item.purpose ? h('div', { class: 'thought-meta' }, [h('span', { class: 'meta-label' }, '目标'), ` ${props.item.purpose}`]) : null,
      props.item.expected ? h('div', { class: 'thought-meta' }, [h('span', { class: 'meta-label' }, '预期'), ` ${props.item.expected}`]) : null,
      Array.isArray(props.item.plan) && props.item.plan.length ? h('div', { class: 'thought-plan' }, [
        h('span', { class: 'meta-label' }, '攻击计划'),
        h('ol', props.item.plan.map((step: string, si: number) => h('li', { key: si }, step))),
      ]) : null,
      props.item.expandable ? h('details', { class: 'thought-expand' }, [
        h('summary', '展开完整推理'),
        h('pre', { class: 'thought-full' }, props.item.thinking),
      ]) : null,
      props.item.reasoning ? h('details', { class: 'thought-expand reasoning-expand' }, [
        h('summary', 'LLM Thinking (Chain-of-Thought)'),
        h('pre', { class: 'thought-full reasoning-full' }, props.item.reasoning),
      ]) : null,
    ]
  },
})

const DemoRenderer = defineComponent({
  name: 'DemoRenderer',
  props: { item: { type: Object, default: () => ({}) } },
  setup(props) {
    return () => h('div', {
      style: 'border:1px dashed #58b8e0; border-radius:6px; padding:8px 12px; margin:4px 0; font-size:12px; color:#58b8e0;',
    }, props.item.message || '[demo] 渲染点验证')
  },
})

const TargetSelectedRenderer = defineComponent({
  name: 'TargetSelectedRenderer',
  props: { item: { type: Object, default: () => ({}) } },
  setup(props) {
    const candidates = (props.item.candidates || []) as Array<Record<string, unknown>>
    return () => [
      props.item.chosen ? h('div', { class: 'thought-meta' }, [
        h('span', { class: 'meta-label', style: 'color:#e06979' }, '选中'),
        ` ${props.item.chosen}`,
        props.item.chosen_reason ? h('span', { style: 'color:#9198a9;font-size:11px' }, ` — ${props.item.chosen_reason}`) : null,
      ]) : null,
      candidates.length ? h('div', { class: 'thought-meta', style: 'margin-top:4px' }, [
        h('span', { class: 'meta-label' }, '候选'),
        h('ol', { style: 'margin:2px 0;font-size:11px;color:#9198a9' },
          candidates.map((c: Record<string, unknown>) =>
            h('li', { key: String(c.node_id || '') }, [
              h('span', { style: 'color:#58b8e0' }, String(c.label || '?')),
              ` (${c.severity || '?'}, score=${c.score})`,
              c.leads_to_high_value ? h('span', { style: 'color:#d9a84e' }, ' →高价值') : null,
            ])
          )
        ),
      ]) : null,
    ]
  },
})

const WorldModelReadoutRenderer = defineComponent({
  name: 'WorldModelReadoutRenderer',
  props: { item: { type: Object, default: () => ({}) } },
  setup(props) {
    const frontier = (props.item.frontier || []) as Array<{ id: string; label: string; score: number }>
    const unreached = (props.item.unreached || []) as Array<{ id: string; label: string }>
    return () => [
      h('div', { class: 'thought-meta', style: 'color:#58b8e0' }, props.item.message || ''),
      frontier.length ? h('details', { class: 'thought-expand' }, [
        h('summary', `可利用前沿 (${frontier.length})`),
        ...frontier.map((n) => h('div', { style: 'font-size:11px;padding:1px 0;color:#9198a9' }, `${n.label} (${n.score})`)),
      ]) : null,
      unreached.length ? h('details', { class: 'thought-expand' }, [
        h('summary', `未触达高价值 (${unreached.length})`),
        ...unreached.map((n) => h('div', { style: 'font-size:11px;padding:1px 0;color:#d9a84e' }, n.label)),
      ]) : null,
    ]
  },
})

const ChainSelectedRenderer = defineComponent({
  name: 'ChainSelectedRenderer',
  props: { item: { type: Object, default: () => ({}) } },
  setup(props) {
    const chains = (props.item.chains || []) as Array<{ start: string; via: string; target: string; score: number; reason: string }>
    return () => [
      h('div', { class: 'thought-meta', style: 'color:#58b8e0' }, props.item.message || ''),
      chains.length ? h('details', { class: 'thought-expand' }, [
        h('summary', `候选横向链 (${chains.length})`),
        ...chains.map((c, i) =>
          h('div', { style: 'font-size:11px;padding:2px 0;font-family:monospace', key: i }, [
            h('span', { style: 'color:#d9a84e' }, `${c.score} `),
            h('span', { style: 'color:#9198a9' }, c.reason),
          ])
        ),
      ]) : null,
    ]
  },
})

const decisionRenderers: Record<string, ReturnType<typeof defineComponent>> = {
  thought: DecisionThoughtRenderer,
  __demo_event: DemoRenderer,
  target_selected: TargetSelectedRenderer,
  world_model_readout: WorldModelReadoutRenderer,
  chain_selected: ChainSelectedRenderer,
}

function rendererFor(action: string): ReturnType<typeof defineComponent> | null {
  return decisionRenderers[action] || null
}

const props = defineProps({
  items: {
    type: Array,
    default: () => [],
  },
  llmStreams: {
    type: Object,
    default: () => ({}),
  },
})

import { computed } from 'vue'

const activeBubbles = computed(() => {
  const now = Date.now()
  const result = {}
  for (const [sid, bubble] of Object.entries(props.llmStreams || {})) {
    if (bubble && bubble.text && now - bubble.updatedAt < 60000) {
      result[sid] = bubble
    }
  }
  return result
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

/* Pure CSS fade-in (replaces TransitionGroup to avoid forced reflow) */
@keyframes timelineFadeIn {
  from { opacity: 0; transform: translateY(16px); }
  to { opacity: 1; transform: translateY(0); }
}
.timeline-fade-in {
  animation: timelineFadeIn 0.4s cubic-bezier(0.22, 1, 0.36, 1);
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

.reasoning-expand summary {
  color: var(--accent-purple);
}

.reasoning-full {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
  background: var(--bg-base);
  border: 1px solid var(--border-muted);
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

.llm-bubble {
  border: 1px solid var(--accent-purple, #a371f7);
  border-left: 3px solid var(--accent-purple, #a371f7);
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--bg-base) 92%, var(--accent-purple, #a371f7) 8%);
  padding: 10px 12px;
  margin: 8px 0;
}

.bubble-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
}

.bubble-phase {
  font-size: 12px;
  font-weight: 600;
  color: var(--accent-purple, #a371f7);
}

.bubble-indicator {
  font-size: 11px;
  color: var(--text-muted);
}

@keyframes dot-blink {
  0%, 20% { opacity: 0; }
  50% { opacity: 1; }
  100% { opacity: 0; }
}

.dots { animation: dot-blink 1.4s infinite; }

.bubble-text {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 200px;
  overflow-y: auto;
  margin: 0;
  line-height: 1.6;
}
</style>
