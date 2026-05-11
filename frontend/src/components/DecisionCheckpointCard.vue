<template>
  <el-card class="checkpoint-card" :class="[`tone-${headerTone}`, { 'is-inline': inline }]" shadow="never">
    <div class="header">
      <div class="header-left">
        <el-icon class="header-icon"><WarningFilled /></el-icon>
        <div>
          <div class="title">
            <span>Plan 模式 · 决策确认</span>
            <el-tag size="small" type="warning" class="phase-tag">
              {{ phaseLabel }}
            </el-tag>
            <el-tag v-if="checkpointTypeLabel" size="small" effect="plain" class="type-tag">
              {{ checkpointTypeLabel }}
            </el-tag>
          </div>
          <div class="subtitle">{{ summary || recommendation || '等待用户确认下一步动作' }}</div>
        </div>
      </div>
      <div class="header-right">
        <el-tag v-if="riskLabel" :type="riskTagType" effect="dark" size="small">
          风险 · {{ riskLabel }}
        </el-tag>
      </div>
    </div>

    <div v-if="thinking" class="block thinking-block">
      <div class="block-head">
        <el-icon><MagicStick /></el-icon>
        <span>Agent 思考</span>
        <el-button
          v-if="thinking.length > THINKING_PREVIEW"
          link
          size="small"
          @click="expanded = !expanded"
        >{{ expanded ? '收起' : '展开全部' }}</el-button>
      </div>
      <pre class="thinking-text">{{ thinkingDisplay }}</pre>
    </div>

    <div v-if="recommendation" class="block reco-block">
      <div class="block-head">
        <el-icon><Promotion /></el-icon>
        <span>Agent 建议</span>
      </div>
      <div class="reco-text">{{ recommendation }}</div>
    </div>

    <div v-if="contextEntries.length" class="block context-block">
      <div class="block-head">
        <el-icon><DataBoard /></el-icon>
        <span>关键上下文</span>
      </div>
      <ul class="context-list">
        <li v-for="(item, i) in contextEntries" :key="i">
          <span class="ctx-key">{{ item.key }}</span>
          <span class="ctx-val">{{ item.value }}</span>
        </li>
      </ul>
    </div>

    <div v-if="commandText" class="block command-block">
      <div class="block-head">
        <el-icon><Operation /></el-icon>
        <span>拟执行命令</span>
      </div>
      <pre class="command-text">{{ commandText }}</pre>
    </div>

    <div v-if="visibleOptions.length" class="block options-block">
      <div class="block-head">
        <el-icon><Operation /></el-icon>
        <span>可选动作</span>
      </div>
      <div class="options-row">
        <el-radio-group v-model="selectedId">
          <el-radio
            v-for="opt in visibleOptions"
            :key="opt.id"
            :label="opt.id"
            class="opt-radio"
          >
            <span class="opt-label" :class="`tone-${opt.tone || 'info'}`">{{ opt.label }}</span>
            <span v-if="opt.hint" class="opt-hint">{{ opt.hint }}</span>
          </el-radio>
        </el-radio-group>
      </div>
    </div>

    <div class="block prompt-block">
      <div class="block-head">
        <el-icon><ChatLineRound /></el-icon>
        <span>追加你的意见</span>
        <span class="block-hint">将作为 user_prompt 软引导给后续节点</span>
      </div>
      <el-input
        v-model="userPrompt"
        type="textarea"
        :rows="3"
        :placeholder="promptPlaceholder"
        resize="none"
      />
    </div>

    <div class="footer">
      <div class="footer-left">
        <span v-if="checkpointId" class="cp-id">id · {{ checkpointId.slice(-12) }}</span>
        <span v-if="createdAtLabel" class="cp-time">{{ createdAtLabel }}</span>
      </div>
      <div class="footer-actions">
        <el-button
          v-if="isPhaseCompleted"
          type="danger"
          plain
          :loading="loading"
          @click="onSubmitFinish"
        >
          <el-icon><CircleClose /></el-icon>
          结束任务，生成报告
        </el-button>
        <el-button
          v-else
          plain
          :loading="loading"
          @click="onSubmit('reject')"
        >
          <el-icon><CircleClose /></el-icon>
          拒绝并跳过
        </el-button>
        <el-button
          v-if="hasModifyOption && !isPhaseCompleted"
          type="warning"
          plain
          :loading="loading"
          @click="onSubmit('modify')"
        >
          <el-icon><Edit /></el-icon>
          采纳意见后继续
        </el-button>
        <el-button
          v-if="checkpointType === 'exploit_step'"
          type="success"
          plain
          :loading="loading"
          @click="onSubmit('auto_all')"
        >
          <el-icon><Check /></el-icon>
          自动批准后续全部
        </el-button>
        <el-button
          type="primary"
          :loading="loading"
          @click="onSubmit('approve')"
        >
          <el-icon><Check /></el-icon>
          {{ isPhaseCompleted ? '继续下一阶段' : '批准并继续' }}
        </el-button>
      </div>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import {
  Check,
  CircleClose,
  ChatLineRound,
  DataBoard,
  Edit,
  MagicStick,
  Operation,
  Promotion,
  WarningFilled,
} from '@element-plus/icons-vue'
import type { CheckpointOption, CheckpointPayload } from '@/types/task'

const props = withDefaults(
  defineProps<{
    checkpoint: CheckpointPayload
    loading?: boolean
    /** 嵌入到 timeline 等其它容器中时,去掉外层卡片的边框/背景,让上层容器控制视觉。 */
    inline?: boolean
  }>(),
  { loading: false, inline: false },
)

const emit = defineEmits<{
  (e: 'submit', payload: {
    action: 'approve' | 'reject' | 'modify' | 'skip' | 'auto_all'
    selected_option: string
    user_prompt: string
    note: string
    next_action: string
  }): void
}>()

const THINKING_PREVIEW = 320

const expanded = ref(false)
const userPrompt = ref('')
const selectedId = ref('')

const checkpointId = computed(() => props.checkpoint?.checkpoint_id || '')
const checkpointType = computed(() => props.checkpoint?.checkpoint_type || 'generic')
const phase = computed(() => props.checkpoint?.phase || '')
const summary = computed(() => props.checkpoint?.summary || '')
const thinking = computed(() => props.checkpoint?.thinking || '')
const recommendation = computed(() => props.checkpoint?.recommendation || '')
const riskRaw = computed(() => props.checkpoint?.risk || '')
const options = computed<CheckpointOption[]>(() => props.checkpoint?.options || [])
const defaultAction = computed(() => props.checkpoint?.default_action || 'approve')

const visibleOptions = computed(() => options.value.filter((o) => o && o.id))
const hasModifyOption = computed(() =>
  visibleOptions.value.some((o) => o.action === 'modify' || o.id === 'modify'),
)

const PHASE_LABELS: Record<string, string> = {
  awaiting_approval: '利用前确认',
  post_foothold_approval: '立足后确认',
  exploit_decision: '利用决策',
  privesc_attempt: '提权决策',
  report: '报告生成前',
}
const phaseLabel = computed(() => PHASE_LABELS[phase.value] || phase.value || 'checkpoint')

const TYPE_LABELS: Record<string, string> = {
  exploit_gate: '利用授权',
  post_foothold_gate: '立足后授权',
  exploit_plan: '利用方案确认',
  exploit_step: '命令逐条审批',
  generic: '',
}
const checkpointTypeLabel = computed(() =>
  TYPE_LABELS[checkpointType.value] ?? checkpointType.value,
)

const headerTone = computed(() => {
  const r = riskRaw.value
  if (/高/.test(r)) return 'danger'
  if (/中/.test(r)) return 'warning'
  return 'primary'
})

const riskLabel = computed(() => riskRaw.value || '')
const riskTagType = computed(() => {
  if (/高/.test(riskRaw.value)) return 'danger'
  if (/中/.test(riskRaw.value)) return 'warning'
  return 'info'
})

const thinkingDisplay = computed(() => {
  const txt = thinking.value
  if (!txt) return ''
  if (expanded.value || txt.length <= THINKING_PREVIEW) return txt
  return `${txt.slice(0, THINKING_PREVIEW)}…`
})

const contextEntries = computed(() => {
  const ctx = props.checkpoint?.context as Record<string, unknown> | undefined
  if (!ctx) return []
  const out: { key: string; value: string }[] = []
  for (const [k, v] of Object.entries(ctx)) {
    if (v == null || v === '') continue
    let val: string
    if (Array.isArray(v)) {
      val = typeof v[0] === 'string' ? v.slice(0, 3).join(', ') : (v.length ? `${v.length} 项` : '')
    } else if (typeof v === 'object') {
      try { val = JSON.stringify(v) } catch { val = String(v) }
    } else {
      val = String(v)
    }
    if (!val) continue
    if (val.length > 80) val = `${val.slice(0, 80)}…`
    out.push({ key: k, value: val })
  }
  return out
})

const commandText = computed(() => {
  return props.checkpoint?.command || ''
})

const createdAtLabel = computed(() => {
  const ts = props.checkpoint?.created_at
  if (!ts) return ''
  try {
    const d = new Date(ts)
    if (Number.isNaN(d.getTime())) return ts
    return d.toLocaleString()
  } catch {
    return ts
  }
})

const promptPlaceholder = computed(() => {
  if (props.checkpoint?.checkpoint_type === 'post_foothold_gate') {
    return '例如:在尝试提权前先收集 SUID 与 sudo -l;只在低噪声窗口执行...'
  }
  return '例如:优先验证可读 /etc/passwd,再尝试 RCE;避免 nc 反弹,使用 webshell...'
})

watch(
  () => props.checkpoint?.checkpoint_id,
  () => {
    expanded.value = false
    userPrompt.value = ''
    const matched = visibleOptions.value.find((o) => o.action === defaultAction.value)
    selectedId.value = matched?.id || visibleOptions.value[0]?.id || ''
  },
  { immediate: true },
)

// phase_completed 类型的 checkpoint —— 交互式流程暂停点
const isPhaseCompleted = computed(() => checkpointType.value === 'phase_completed')

function onSubmit(action: 'approve' | 'reject' | 'modify' | 'skip' | 'auto_all') {
  if (props.loading) return
  let resolved = action
  let nextAction = ''
  let selectedOption = selectedId.value || ''
  // 如果用户选了一个具体选项,以选项里声明的 action 为准
  const opt = visibleOptions.value.find((o) => o.id === selectedOption)
  if (opt?.action) {
    resolved = opt.action as typeof action
    // 如果选项的 action 是 continue/skip/finish，将其作为 next_action
    if (['continue', 'skip', 'finish'].includes(opt.action)) {
      nextAction = opt.action
      resolved = 'approve'  // 对后端来说，phase_checkpoint 的 continue=approve
    }
  }
  if (resolved === 'modify' && !userPrompt.value.trim()) {
    ElMessage.warning('请输入你想要补充的意见,再点击「采纳意见后继续」')
    return
  }
  emit('submit', {
    action: resolved,
    selected_option: selectedOption,
    user_prompt: userPrompt.value.trim(),
    note: '',
    next_action: nextAction,
  })
}

function onSubmitFinish() {
  selectedId.value = 'finish'
  onSubmit('approve')
}
</script>

<style scoped>
.checkpoint-card {
  border-radius: var(--radius-lg);
  border: 1px solid color-mix(in srgb, var(--accent-yellow) 38%, var(--border));
  background: color-mix(in srgb, var(--accent-yellow) 5%, var(--bg-elevated));
}
.checkpoint-card.tone-danger {
  border-color: color-mix(in srgb, var(--accent-red) 50%, var(--border));
  background: color-mix(in srgb, var(--accent-red) 6%, var(--bg-elevated));
}
.checkpoint-card.tone-warning {
  border-color: color-mix(in srgb, var(--accent-yellow) 42%, var(--border));
  background: color-mix(in srgb, var(--accent-yellow) 6%, var(--bg-elevated));
}
.checkpoint-card.tone-primary {
  border-color: color-mix(in srgb, var(--accent-blue) 38%, var(--border));
  background: color-mix(in srgb, var(--accent-blue) 5%, var(--bg-elevated));
}
.checkpoint-card :deep(.el-card__body) {
  padding: 16px 18px !important;
}

/* inline 模式: 卡片融入 timeline / 对话流, 由父容器控制外框 */
.checkpoint-card.is-inline {
  background: transparent;
  border: none;
  border-left: 3px solid color-mix(in srgb, var(--accent-yellow) 80%, var(--text-primary));
  border-radius: 0;
}
.checkpoint-card.is-inline.tone-danger {
  border-left-color: color-mix(in srgb, var(--accent-red) 80%, var(--text-primary));
}
.checkpoint-card.is-inline.tone-primary {
  border-left-color: color-mix(in srgb, var(--accent-blue) 80%, var(--text-primary));
}
.checkpoint-card.is-inline :deep(.el-card__body) {
  padding: 4px 0 4px 12px !important;
}
.checkpoint-card.is-inline .header { margin-bottom: 10px; }

.header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  margin-bottom: 14px;
}
.header-left { display: flex; gap: 10px; align-items: flex-start; }
.header-icon {
  margin-top: 2px;
  font-size: 22px;
  color: color-mix(in srgb, var(--accent-yellow) 80%, var(--text-primary));
}
.tone-danger .header-icon {
  color: color-mix(in srgb, var(--accent-red) 80%, var(--text-primary));
}
.tone-primary .header-icon {
  color: color-mix(in srgb, var(--accent-blue) 80%, var(--text-primary));
}
.title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 700;
  font-size: 14px;
  color: var(--text-primary);
}
.phase-tag, .type-tag { font-weight: 500; }
.subtitle {
  margin-top: 4px;
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.5;
  max-width: 720px;
}

.block {
  margin-top: 12px;
  padding: 10px 12px;
  border-radius: var(--radius-md);
  background: var(--bg-surface);
  border: 1px solid var(--border);
}
.block-head {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 600;
  font-size: 12px;
  color: var(--text-secondary);
  margin-bottom: 6px;
}
.block-hint {
  margin-left: 6px;
  font-weight: 400;
  color: var(--text-muted);
  font-size: 11px;
}
.thinking-text {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  color: var(--text-primary);
  max-height: 240px;
  overflow-y: auto;
}
.reco-text {
  font-size: 13px;
  line-height: 1.55;
  color: var(--text-primary);
}

.command-text {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  color: var(--text-primary);
  background: color-mix(in srgb, var(--bg-base) 50%, transparent);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 8px 10px;
  max-height: 120px;
  overflow-y: auto;
}

.context-list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 6px 14px;
}
.context-list li {
  display: flex;
  gap: 6px;
  font-size: 12px;
}
.ctx-key {
  color: var(--text-muted);
  font-family: var(--font-mono);
}
.ctx-val {
  color: var(--text-primary);
  font-weight: 500;
  word-break: break-all;
}

.options-row :deep(.el-radio-group) {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.opt-radio { margin-right: 0 !important; }
.opt-label { font-weight: 600; font-size: 13px; }
.opt-label.tone-success { color: color-mix(in srgb, var(--accent-green) 88%, var(--text-primary)); }
.opt-label.tone-warning { color: color-mix(in srgb, var(--accent-yellow) 88%, var(--text-primary)); }
.opt-label.tone-danger  { color: color-mix(in srgb, var(--accent-red) 88%, var(--text-primary)); }
.opt-label.tone-primary { color: color-mix(in srgb, var(--accent-blue) 88%, var(--text-primary)); }
.opt-hint {
  margin-left: 8px;
  color: var(--text-muted);
  font-size: 12px;
}

.footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-top: 14px;
}
.footer-left {
  color: var(--text-muted);
  font-size: 11px;
  display: flex;
  gap: 10px;
  font-family: var(--font-mono);
}
.footer-actions { display: flex; gap: 8px; }
</style>
