<template>
  <div class="timeline-wrap" ref="wrapRef" @scroll="onUserScroll">
    <!-- ── 此刻在做什么 banner ─────────────────────────── -->
    <div class="now-banner" :class="{ done: currentAction.startsWith('\u2713') }">
      <span class="now-dot" :class="{ done: currentAction.startsWith('\u2713') }" />
      <span class="now-text">{{ currentAction.startsWith('\u2713') ? 'Agent 状态：' : 'Agent 正在：' }}{{ currentAction }}</span>
    </div>

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
      <ThinkingTypewriter :text="bubble.text" class="bubble-text" />
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
import ThinkingTypewriter from '@/components/ThinkingTypewriter.vue'

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

const ReflectionRenderer = defineComponent({
  name: 'ReflectionRenderer',
  props: { item: { type: Object, default: () => ({}) } },
  setup(props) {
    const ref = (props.item.reflection || {}) as Record<string, unknown>
    return () => h('div', { class: 'thought-meta', style: 'padding:4px 0' }, [
      h('span', { style: 'color:#e06979' }, '失败归因: '),
      h('span', { style: 'color:#9198a9' }, `${ref.cause || '?'}`),
      ref.suggested_next ? h('div', { style: 'font-size:11px;color:#58b8e0;margin-top:2px' }, [
        h('span', { style: 'color:#4ec9b0' }, '下一步: '),
        ref.suggested_next,
      ]) : null,
    ])
  },
})

const HypothesisTestRenderer = defineComponent({
  name: 'HypothesisTestRenderer',
  props: { item: { type: Object, default: () => ({}) } },
  setup(props) {
    const hyp = (props.item.hypothesis || {}) as Record<string, unknown>
    const status = String(hyp.status || 'unverified')
    const confidence = Number(hyp.confidence || 0)
    const statusColor = status === 'verified' ? '#3fb980' : status === 'failed' ? '#e06979' : '#d9a84e'
    return () => h('div', { class: 'thought-meta', style: 'padding:4px 0' }, [
      h('span', { style: 'color:#4ec9b0' }, '假设: '),
      h('span', { style: 'color:#58b8e0' }, String(hyp.text || props.item.thinking || '').slice(0, 120)),
      h('div', { style: 'font-size:11px;margin-top:2px' }, [
        h('span', { style: `color:${statusColor}` }, `${status}`),
        h('span', { style: 'color:#9198a9;margin-left:4px' }, `conf=${confidence.toFixed(2)}`),
        hyp.category ? h('span', { style: 'color:#9198a9;margin-left:4px' }, `#${hyp.category}`) : null,
      ]),
    ])
  },
})

const ObjectivePathRenderer = defineComponent({
  name: 'ObjectivePathRenderer',
  props: { item: { type: Object, default: () => ({}) } },
  setup(props) {
    const path = (props.item.path || {}) as { nodes: string[]; gaps: string[] }
    return () => h('div', { class: 'thought-meta', style: 'padding:4px 0' }, [
      h('span', { style: 'color:#2d9d76' }, '目标路径: '),
      h('span', { style: 'color:#9198a9;font-size:11px' }, `${(path.nodes || []).length} 节点`),
      (path.gaps || []).length ? h('details', { class: 'thought-expand', style: 'margin-top:2px' }, [
        h('summary', `缺口 (${path.gaps.length})`),
        ...path.gaps.map((g: string, i: number) =>
          h('div', { style: 'font-size:11px;color:#e06979;padding:1px 0', key: i }, g)
        ),
      ]) : h('span', { style: 'color:#3fb980;font-size:11px;margin-left:4px' }, '完整'),
    ])
  },
})

const SceneClassifiedRenderer = defineComponent({
  name: 'SceneClassifiedRenderer',
  props: { item: { type: Object, default: () => ({}) } },
  setup(props) {
    const scene = String((props.item as any).scene || '')
    const sceneLabel = {
      web: 'Web 应用', intranet: '内网', ad: 'Active Directory', cloud: '云环境',
      container: '容器', network: '网络', host: '主机',
    } as Record<string, string>
    return () => h('div', { class: 'scene-badge' }, [
      h('span', { class: 'scene-dot' }),
      h('span', { class: 'scene-label' }, sceneLabel[scene] || scene || '未知场景'),
      h('span', { class: 'scene-meta' }, scene || ''),
    ])
  },
})

const decisionRenderers: Record<string, ReturnType<typeof defineComponent>> = {
  thought: DecisionThoughtRenderer,
  __demo_event: DemoRenderer,
  target_selected: TargetSelectedRenderer,
  world_model_readout: WorldModelReadoutRenderer,
  chain_selected: ChainSelectedRenderer,
  reflection: ReflectionRenderer,
  hypothesis_test: HypothesisTestRenderer,
  objective_path: ObjectivePathRenderer,
  scene_classified: SceneClassifiedRenderer,
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
  taskStatus: {
    type: String,
    default: '',
  },
})

import { computed } from 'vue'

const activeBubbles = computed(() => {
  const now = Date.now()
  const result: Record<string, any> = {}
  for (const [sid, bubble] of Object.entries(props.llmStreams || {})) {
    if (bubble && bubble.text && now - (bubble as any).updatedAt < 60000) {
      result[sid] = bubble
    }
  }
  return result
})

const actionLabels: Record<string, string> = {
  thought: '推理分析',
  target_selected: '选择攻击目标',
  chain_selected: '规划攻击链',
  reflection: '失败归因分析',
  hypothesis_test: '验证假设',
  objective_path: '计算目标路径',
  scene_classified: '识别运行场景',
  world_model_readout: '读取世界模型状态',
  world_model_update: '更新世界模型',
  llm_delta: 'LLM 推理',
  checkpoint_request: '等待操作员确认',
}

const currentAction = computed(() => {
  if (props.taskStatus === 'completed' || props.taskStatus === 'done') {
    return '\u2713 \u5df2\u5b8c\u6210'
  }
  const items = props.items as any[]
  if (items.length > 0) {
    const latest = items[items.length - 1]
    if (latest?.action && actionLabels[latest.action]) {
      return actionLabels[latest.action]
    }
    if (latest?.title) return latest.title
  }
  const bubbleKeys = Object.keys(activeBubbles.value)
  if (bubbleKeys.length > 0) {
    const b = activeBubbles.value[bubbleKeys[0]]
    return b?.phase ? `${b.phase}` : 'LLM 推理'
  }
  return '监控中'
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

/* ── 此刻在做什么 banner ──────────────────────── */
.now-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  margin-bottom: 10px;
  background: color-mix(in srgb, var(--accent-green) 8%, var(--bg-surface));
  border: 1px solid color-mix(in srgb, var(--accent-green) 28%, var(--border));
  border-radius: var(--radius-md);
  position: sticky;
  top: 0;
  z-index: 10;
  backdrop-filter: blur(6px);
  transition: background var(--t-base) var(--ease-out), border-color var(--t-base) var(--ease-out);
}
.now-banner.done {
  background: color-mix(in srgb, var(--text-muted) 6%, var(--bg-surface));
  border-color: var(--border-muted);
}

.now-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent-green);
  box-shadow: var(--glow-green);
  animation: pulse-dot 1.4s ease-in-out infinite;
}
.now-dot.done {
  background: var(--text-muted);
  box-shadow: none;
  animation: none;
}

@keyframes pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.6; transform: scale(1.3); }
}

.now-text {
  font-size: 12px;
  color: var(--text-primary);
  font-family: var(--font-mono);
}
.now-banner.done .now-text {
  color: var(--text-muted);
}

/* ── 场景识别 badge ──────────────────────────── */
.scene-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  border-radius: 12px;
  background: color-mix(in srgb, var(--accent-green) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--accent-green) 28%, var(--border));
  font-size: 11px;
  font-family: var(--font-mono);
  margin-top: 4px;
}

.scene-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent-green);
}

.scene-label {
  color: var(--text-primary);
  font-weight: 600;
}

.scene-meta {
  color: var(--text-muted);
  font-size: 10px;
}

@media (prefers-reduced-motion: reduce) {
  .now-dot { animation: none; }
  .timeline-fade-in { animation: none; }
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
  border-left: 3px solid var(--accent-purple);
}

/* per-action phase stripe colors */
.timeline-item:has(.scene-badge) { border-left: 3px solid var(--accent-green); }

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
  font-size: 11.5px;
  color: var(--text-secondary);
  line-height: 1.65;
}
</style>
