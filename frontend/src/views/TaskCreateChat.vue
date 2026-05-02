<template>
  <div class="chat-page">
    <header class="chat-header">
      <div class="header-left">
        <el-button text @click="goBack">
          <el-icon><ArrowLeft /></el-icon>
          返回任务列表
        </el-button>
        <div class="title-block">
          <h2>创建渗透测试任务</h2>
          <p class="title-sub">用一句话告诉 Agent 你想测什么,目标会自动从描述中识别。</p>
        </div>
      </div>
    </header>

    <main class="chat-main">
      <section class="message-stream" ref="streamRef">
        <ChatBubble
          v-for="msg in messages"
          :key="msg.id"
          :role="msg.role"
          :text="msg.text"
          :timestamp="msg.timestamp"
          :tone="msg.tone"
        >
          <template v-if="msg.suggestions?.length" #suggestions>
            <div class="suggestion-row">
              <el-button
                v-for="s in msg.suggestions"
                :key="s"
                size="small"
                round
                @click="applySuggestion(s)"
              >{{ s }}</el-button>
            </div>
          </template>
        </ChatBubble>

        <!-- 安全卡口确认卡片 -->
        <div v-if="pendingConfirmationState" class="confirmation-card">
          <div class="confirmation-header">
            <el-icon class="confirmation-icon"><Warning /></el-icon>
            <span>安全风险确认</span>
          </div>
          <p class="confirmation-message">{{ pendingConfirmationState.message }}</p>
          <ul class="confirmation-warnings">
            <li v-for="w in pendingConfirmationState.warnings" :key="w">
              <el-icon><Warning /></el-icon>
              {{ w }}
            </li>
          </ul>
          <div class="confirmation-checks">
            <el-checkbox
              v-for="rid in pendingConfirmationState.required_confirmations"
              :key="rid"
              v-model="confirmedRisks"
              :label="rid"
            >
              {{ confirmationLabel(rid) }}
            </el-checkbox>
          </div>
          <div class="confirmation-actions">
            <el-button @click="cancelConfirmation" :disabled="creating">取消</el-button>
            <el-button
              type="primary"
              :loading="creating"
              :disabled="confirmedRisks.length === 0"
              @click="confirmAndResubmit"
            >
              确认并提交
            </el-button>
          </div>
        </div>

        <!-- Plan Mode: 策略预览卡片 -->
        <div v-if="planPreview" class="plan-preview-card">
          <div class="plan-preview-head">
            <el-icon class="plan-preview-icon"><MagicStick /></el-icon>
            <span>渗透策略预览</span>
            <span class="plan-preview-id">#{{ planPreview.planId }}</span>
          </div>

          <div v-if="planPreview.plan.target_understanding" class="plan-preview-section">
            <span class="plan-preview-label">目标理解</span>
            <p>{{ planPreview.plan.target_understanding }}</p>
          </div>

          <div
            v-for="(phase, pi) in planPreview.plan.phases"
            :key="pi"
            class="plan-preview-phase"
          >
            <div class="plan-preview-phase-head">
              <code class="plan-preview-phase-name">{{ phase.phase }}</code>
              <span v-if="phase.description" class="plan-preview-phase-desc">{{ phase.description }}</span>
            </div>
            <div class="plan-preview-steps">
              <div
                v-for="(step, si) in phase.steps.filter(s => s.enabled)"
                :key="si"
                class="plan-preview-step"
              >
                <span class="plan-preview-step-idx">{{ si + 1 }}</span>
                <span v-if="step.tool" class="plan-preview-step-tool">{{ step.tool }}</span>
                <span v-if="step.skill" class="plan-preview-step-skill">{{ step.skill }}</span>
                <span class="plan-preview-step-purpose">{{ step.purpose }}</span>
              </div>
            </div>
          </div>

          <div v-if="planPreview.plan.risk_notes?.length" class="plan-preview-risks">
            <span class="plan-preview-label">风险提示</span>
            <ul>
              <li v-for="(r, ri) in planPreview.plan.risk_notes" :key="ri">{{ r }}</li>
            </ul>
          </div>

          <div v-if="planPreview.plan.unsupported_hints?.length" class="plan-preview-hints">
            <span class="plan-preview-label">能力限制</span>
            <ul>
              <li v-for="(h, hi) in planPreview.plan.unsupported_hints" :key="hi">{{ h }}</li>
            </ul>
          </div>
        </div>

        <div v-if="advancedDirty" class="advanced-summary">
          <span class="muted">已生效的高级配置:</span>
          <el-tag
            v-for="(tag, i) in advancedSummary"
            :key="i"
            size="small"
            class="adv-tag"
            type="info"
          >{{ tag }}</el-tag>
        </div>
      </section>

      <section class="composer">
        <transition name="intent-fade">
          <div
            v-if="intentVisible"
            class="intent-card"
            :class="{ 'is-loading': intent.loading, 'is-fallback': intent.fallback }"
          >
            <div class="intent-head">
              <span class="intent-badge">
                <el-icon class="intent-icon"><MagicStick /></el-icon>
                <span v-if="intent.loading">AI 正在解读你的描述</span>
                <span v-else-if="intent.fallback">AI 暂不可用 · 已退化为正则提取</span>
                <span v-else>AI 已解读你的描述</span>
              </span>
              <span v-if="!intent.loading && intent.confidence > 0" class="intent-confidence">
                置信度 {{ Math.round(intent.confidence * 100) }}%
              </span>
            </div>

            <p v-if="intent.summary" class="intent-summary">{{ intent.summary }}</p>

            <div class="intent-grid">
              <div v-if="intent.target" class="intent-row">
                <span class="intent-label">目标</span>
                <code class="intent-target">{{ intent.target }}</code>
              </div>
              <div
                v-if="intent.suggestedMode && intent.suggestedMode !== form.workflowMode"
                class="intent-row"
              >
                <span class="intent-label">推荐模式</span>
                <span class="intent-mode-name">{{ modeLabel(intent.suggestedMode) }}</span>
                <el-button
                  size="small"
                  type="primary"
                  text
                  bg
                  @click="applySuggestedMode"
                >采用</el-button>
              </div>
              <div v-if="intent.priorityVulns.length" class="intent-row">
                <span class="intent-label">关注漏洞</span>
                <el-tag
                  v-for="vuln in intent.priorityVulns"
                  :key="vuln"
                  size="small"
                  effect="plain"
                  class="intent-tag"
                >{{ vuln }}</el-tag>
              </div>
              <div v-if="intent.intents.length" class="intent-row">
                <span class="intent-label">行动倾向</span>
                <el-tag
                  v-for="tag in intent.intents"
                  :key="tag"
                  size="small"
                  effect="plain"
                  type="info"
                  class="intent-tag"
                >{{ tag }}</el-tag>
              </div>
              <div
                v-if="intent.scopeNote && intent.scopeNote !== form.scopeNote"
                class="intent-row"
              >
                <span class="intent-label">scope</span>
                <span class="intent-text">{{ intent.scopeNote }}</span>
                <el-button size="small" text bg @click="applyIntentScope">应用</el-button>
              </div>
              <div
                v-if="intent.extraHint && intent.extraHint !== form.extraHint"
                class="intent-row"
              >
                <span class="intent-label">建议</span>
                <span class="intent-text">{{ intent.extraHint }}</span>
                <el-button size="small" text bg @click="applyIntentHint">应用</el-button>
              </div>
            </div>
          </div>
        </transition>

        <div class="composer-toolbar">
          <div class="mode-pills" role="tablist" aria-label="Agent 模式">
            <button
              v-for="m in MODES"
              :key="m.value"
              type="button"
              class="pill"
              :class="{ active: form.workflowMode === m.value }"
              role="tab"
              :aria-selected="form.workflowMode === m.value"
              @click="setMode(m.value)"
            >
              <el-icon class="pill-icon"><component :is="m.icon" /></el-icon>
              <span>{{ m.label }}</span>
            </button>
          </div>

          <el-popover placement="top" trigger="click" :width="380">
            <template #reference>
              <button type="button" class="pill pill-ghost">
                <el-icon class="pill-icon"><Setting /></el-icon>
                <span>高级</span>
              </button>
            </template>
            <div class="adv-panel">
              <div class="adv-row">
                <label>授权说明 (scope_note)</label>
                <el-input v-model="form.scopeNote" size="small" />
              </div>
              <div class="adv-row">
                <label>额外提示 (extra_hint)</label>
                <el-input v-model="form.extraHint" size="small" type="textarea" :rows="2" />
              </div>
              <div class="adv-row">
                <label>证据门槛</label>
                <el-radio-group v-model="form.successGateLevel" size="small">
                  <el-radio-button label="">默认</el-radio-button>
                  <el-radio-button label="strict">严格</el-radio-button>
                  <el-radio-button label="medium">中等</el-radio-button>
                  <el-radio-button label="lenient">宽松</el-radio-button>
                </el-radio-group>
              </div>
              <div class="adv-row two-col">
                <div>
                  <label>风险预算</label>
                  <el-input-number
                    v-model="form.riskBudget"
                    :min="0"
                    :max="50"
                    size="small"
                    controls-position="right"
                  />
                </div>
                <div>
                  <label>ReAct 轮次</label>
                  <el-input-number
                    v-model="form.maxReactRounds"
                    :min="1"
                    :max="200"
                    size="small"
                    controls-position="right"
                  />
                </div>
              </div>
              <div class="adv-row">
                <label>探索最大轮次</label>
                <el-input-number
                  v-model="form.maxExploreRounds"
                  :min="1"
                  :max="200"
                  size="small"
                  controls-position="right"
                />
              </div>
            </div>
          </el-popover>
        </div>

        <div class="input-bar">
          <el-input
            v-model="form.userPrompt"
            type="textarea"
            :rows="4"
            resize="none"
            class="prompt-input"
            placeholder='例如:请对 192.168.1.10 进行渗透测试,优先验证 SQL 注入,拿 flag 优先;或 https://target.example.com 走 web 攻击面'
            @keydown.ctrl.enter.prevent="submit"
            @keydown.meta.enter.prevent="submit"
          />
          <div class="send-row">
            <span class="hint">
              <span class="hint-shortcut">Ctrl/Cmd + Enter 发送</span>
              <span class="hint-divider">·</span>
              <span v-if="intent.loading" class="hint-target hint-target-loading">
                <el-icon class="spin"><Loading /></el-icon>
                AI 正在解析意图...
              </span>
              <span v-else-if="detectedTarget" class="hint-target">
                <el-icon><Aim /></el-icon>
                已识别目标: <code>{{ detectedTarget }}</code>
                <span v-if="targetSource === 'llm'" class="hint-source">via AI</span>
                <span v-else class="hint-source hint-source-fallback">via 正则</span>
              </span>
              <span v-else class="hint-target hint-target-missing">
                <el-icon><Aim /></el-icon>
                可以直接描述测试意图，无明确目标时 AI 会向你确认
              </span>
            </span>
            <el-button
              type="primary"
              :loading="creating || planGenerating"
              :disabled="!canSubmit || planGenerating"
              @click="submit"
            >
              <el-icon><Promotion /></el-icon>
              {{ planGenerating ? '生成策略中...' : planPreview ? '确认并创建' : '创建并开始' }}
            </el-button>
          </div>
        </div>
      </section>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, defineAsyncComponent, nextTick, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  Aim,
  ArrowLeft,
  Cpu,
  Loading,
  MagicStick,
  Promotion,
  Setting,
  Tools,
  Warning,
} from '@element-plus/icons-vue'
import { api } from '@/api'
import { useTaskListStore } from '@/stores/taskList'
import { trackEvent } from '@/metrics/tracker'
import type { PendingConfirmationResponse, WorkflowMode, PentestPlan } from '@/types/task'

const ChatBubble = defineAsyncComponent(() => import('@/components/ChatBubble.vue'))

const router = useRouter()
const listStore = useTaskListStore()

const MODES: Array<{ value: WorkflowMode; label: string; icon: unknown }> = [
  { value: 'pentest_engineer', label: '渗透工程师', icon: Tools },
  { value: 'ctf_expert', label: 'CTF 选手', icon: Cpu },
]

interface ChatMessage {
  id: string
  role: 'agent' | 'user' | 'system'
  text: string
  timestamp: string
  tone?: 'info' | 'warning' | 'primary'
  suggestions?: string[]
}

const form = ref({
  scopeNote: 'CTF/授权靶场测试',
  extraHint: '',
  userPrompt: '',
  workflowMode: 'pentest_engineer' as WorkflowMode,
  successGateLevel: '' as '' | 'strict' | 'medium' | 'lenient',
  riskBudget: null as number | null,
  maxReactRounds: null as number | null,
  maxExploreRounds: null as number | null,
})

const creating = ref(false)
const streamRef = ref<HTMLElement | null>(null)

// pending_confirmation 流程状态
const pendingConfirmationState = ref<PendingConfirmationResponse | null>(null)
const confirmedRisks = ref<string[]>([])

// Plan Mode: 策略预览状态
const planGenerating = ref(false)
const planPreview = ref<{ planId: string; plan: PentestPlan } | null>(null)
const planError = ref('')

const messages = ref<ChatMessage[]>([
  {
    id: 'agent-greeting',
    role: 'agent',
    text:
      '你好,我是渗透测试 Agent。\n直接告诉我你想测试什么,例如:"请对 10.0.0.1 进行渗透测试,优先验证 SQL 注入"。\n关键节点我会暂停并请你确认是否继续,类似 Plan 模式。',
    timestamp: nowTime(),
    tone: 'info',
    suggestions: [
      '请对 192.168.1.10 进行渗透测试,优先低噪声命令',
      '对 https://ctf.example.com 做 web 攻击面侦察并尝试拿 flag',
      '对 10.0.0.5:8080 验证 RCE,避免触发 IDS/IPS',
    ],
  },
])

interface IntentState {
  target: string
  suggestedMode: WorkflowMode | ''
  priorityVulns: string[]
  scopeNote: string
  extraHint: string
  summary: string
  intents: string[]
  confidence: number
  fallback: boolean
  loading: boolean
  loaded: boolean
  source: 'idle' | 'llm' | 'regex'
}

const intent = ref<IntentState>({
  target: '',
  suggestedMode: '',
  priorityVulns: [],
  scopeNote: '',
  extraHint: '',
  summary: '',
  intents: [],
  confidence: 0,
  fallback: false,
  loading: false,
  loaded: false,
  source: 'idle',
})

const intentVisible = computed(() => {
  if (creating.value) return false
  if (planPreview.value) return false
  if (intent.value.loading) return true
  if (!intent.value.loaded) return false
  return Boolean(
    intent.value.summary ||
    intent.value.target ||
    intent.value.priorityVulns.length ||
    intent.value.intents.length ||
    (intent.value.suggestedMode && intent.value.suggestedMode !== form.value.workflowMode) ||
    (intent.value.scopeNote && intent.value.scopeNote !== form.value.scopeNote) ||
    (intent.value.extraHint && intent.value.extraHint !== form.value.extraHint),
  )
})

const detectedTarget = computed(() => intent.value.target || extractTarget(form.value.userPrompt))

const targetSource = computed<'llm' | 'regex' | 'idle'>(() => {
  if (intent.value.target && intent.value.source === 'llm') return 'llm'
  if (detectedTarget.value) return 'regex'
  return 'idle'
})

const canSubmit = computed(
  () => !creating.value && form.value.userPrompt.trim().length > 0,
)

let intentDebounceTimer: ReturnType<typeof setTimeout> | null = null
let intentRequestSeq = 0

function resetIntent() {
  intent.value = {
    target: '',
    suggestedMode: '',
    priorityVulns: [],
    scopeNote: '',
    extraHint: '',
    summary: '',
    intents: [],
    confidence: 0,
    fallback: false,
    loading: false,
    loaded: false,
    source: 'idle',
  }
}

async function runIntentParse(prompt: string, mode: WorkflowMode) {
  const seq = ++intentRequestSeq
  intent.value.loading = true
  try {
    const resp = await api.parseTaskIntent({ userPrompt: prompt, workflowMode: mode })
    if (seq !== intentRequestSeq) return
    intent.value = {
      target: resp.target || '',
      suggestedMode: (resp.suggested_workflow_mode as WorkflowMode | '') || '',
      priorityVulns: Array.isArray(resp.priority_vulns) ? resp.priority_vulns : [],
      scopeNote: resp.scope_note || '',
      extraHint: resp.extra_hint || '',
      summary: resp.summary || '',
      intents: Array.isArray(resp.intents) ? resp.intents : [],
      confidence: Number(resp.confidence) || 0,
      fallback: Boolean(resp.fallback),
      loading: false,
      loaded: true,
      source: resp.fallback ? 'regex' : 'llm',
    }
  } catch (e) {
    if (seq !== intentRequestSeq) return
    // 网络层失败:静默降级到正则提取,避免在用户没意识到时弹错误
    intent.value = {
      ...intent.value,
      target: extractTarget(prompt) || '',
      summary: '',
      suggestedMode: '',
      priorityVulns: [],
      intents: [],
      scopeNote: '',
      extraHint: '',
      confidence: 0,
      fallback: true,
      loading: false,
      loaded: true,
      source: 'regex',
    }
  }
}

function scheduleIntentParse() {
  if (intentDebounceTimer) clearTimeout(intentDebounceTimer)
  const prompt = form.value.userPrompt.trim()
  // 太短就不触发 LLM,直接清空已有解析结果
  if (prompt.length < 6) {
    intentRequestSeq++
    resetIntent()
    return
  }
  intentDebounceTimer = setTimeout(() => {
    runIntentParse(prompt, form.value.workflowMode)
  }, 600)
}

watch(
  () => [form.value.userPrompt, form.value.workflowMode] as const,
  () => {
    scheduleIntentParse()
  },
)

onUnmounted(() => {
  if (intentDebounceTimer) clearTimeout(intentDebounceTimer)
  intentRequestSeq++
})

function modeLabel(value: string): string {
  return MODES.find((m) => m.value === value)?.label || value
}

function applySuggestedMode() {
  if (intent.value.suggestedMode) {
    setMode(intent.value.suggestedMode as WorkflowMode)
    trackEvent('task.intent.apply', { field: 'mode', value: intent.value.suggestedMode })
  }
}

function applyIntentScope() {
  if (intent.value.scopeNote) {
    form.value.scopeNote = intent.value.scopeNote
    trackEvent('task.intent.apply', { field: 'scope_note' })
    ElMessage.success('已采用建议的 scope')
  }
}

function applyIntentHint() {
  if (intent.value.extraHint) {
    form.value.extraHint = intent.value.extraHint
    trackEvent('task.intent.apply', { field: 'extra_hint' })
    ElMessage.success('已采用建议的提示')
  }
}

const advancedSummary = computed(() => {
  const out: string[] = []
  if (form.value.scopeNote && form.value.scopeNote !== 'CTF/授权靶场测试') {
    out.push(`scope=${form.value.scopeNote.slice(0, 16)}`)
  }
  if (form.value.extraHint) out.push(`hint=${form.value.extraHint.slice(0, 16)}`)
  if (form.value.successGateLevel) out.push(`gate=${form.value.successGateLevel}`)
  if (form.value.riskBudget) out.push(`risk=${form.value.riskBudget}`)
  if (form.value.maxReactRounds) out.push(`react=${form.value.maxReactRounds}`)
  if (form.value.maxExploreRounds) out.push(`explore=${form.value.maxExploreRounds}`)
  return out
})

const advancedDirty = computed(() => advancedSummary.value.length > 0)

function nowTime() {
  return new Date().toLocaleTimeString()
}

const CONFIRMATION_LABELS: Record<string, string> = {
  confirm_public_ip_authorization: '我确认拥有对该公网 IP 目标的合法渗透测试授权',
  confirm_third_party_target: '我确认拥有对该第三方目标的合法测试授权',
  confirm_sensitive_port_scan: '我确认对该敏感端口的扫描已获授权',
  confirm_aggressive_exploit: '我确认执行高影响利用操作已获授权',
  confirm_lateral_movement: '我确认横向移动操作已获授权',
  confirm_data_exfiltration: '我确认数据外传测试已获授权',
}

function confirmationLabel(riskId: string): string {
  return CONFIRMATION_LABELS[riskId] || `确认风险项: ${riskId}`
}

function pushAgent(text: string, tone: ChatMessage['tone'] = 'info') {
  messages.value.push({
    id: `agent-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    role: 'agent',
    text,
    timestamp: nowTime(),
    tone,
  })
  scrollToBottom()
}

function scrollToBottom() {
  nextTick(() => {
    const el = streamRef.value
    if (el) el.scrollTop = el.scrollHeight
  })
}

function applySuggestion(text: string) {
  const cur = form.value.userPrompt.trim()
  form.value.userPrompt = cur ? `${cur}\n${text}` : text
}

function setMode(mode: WorkflowMode) {
  form.value.workflowMode = mode
}

function isValidIPv4(host: string): boolean {
  const parts = host.split('.')
  if (parts.length !== 4) return false
  return parts.every((item) => {
    if (!/^\d{1,3}$/.test(item)) return false
    const n = Number(item)
    return n >= 0 && n <= 255
  })
}

function isValidHost(host: string): boolean {
  if (!host) return false
  if (host === 'localhost') return true
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return isValidIPv4(host)
  const label = '[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?'
  const hostnamePattern = new RegExp(`^${label}(\\.${label})*$`)
  return hostnamePattern.test(host)
}

// 从自然语言 prompt 中识别第一个目标 (URL / IP[:port] / 域名[:port])。
function extractTarget(prompt: string): string | null {
  const text = String(prompt || '')
  if (!text.trim()) return null
  const patterns: RegExp[] = [
    /https?:\/\/[^\s,;'"，。、）)]+/i,
    /\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b/,
    /(?<![./@\w])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?::\d{1,5})?(?![\w./])/,
  ]
  for (const p of patterns) {
    const m = text.match(p)
    if (!m) continue
    const candidate = m[0].replace(/[.,;'"，。、)）]+$/, '')
    if (!candidate) continue
    if (/^https?:/i.test(candidate)) {
      try {
        const u = new URL(candidate)
        if (!isValidHost(u.hostname)) continue
        if (u.port) {
          const p2 = Number(u.port)
          if (!Number.isFinite(p2) || p2 < 1 || p2 > 65535) continue
        }
        return candidate
      } catch {
        continue
      }
    }
    const portMatch = candidate.match(/:(\d{1,5})$/)
    let host = candidate
    if (portMatch) {
      host = candidate.slice(0, -portMatch[0].length)
      const p2 = Number(portMatch[1])
      if (!Number.isFinite(p2) || p2 < 1 || p2 > 65535) continue
    }
    if (isValidHost(host) && !host.includes(':')) return candidate
  }
  return null
}

function goBack() {
  router.push('/tasks')
}

async function generatePlanPreview() {
  const userPrompt = form.value.userPrompt.trim()
  if (!userPrompt) return
  // 添加用户消息（仅首次生成时）
  if (!planPreview.value) {
    messages.value.push({
      id: `user-${Date.now()}`,
      role: 'user',
      text: userPrompt,
      timestamp: nowTime(),
    })
    scrollToBottom()
  }
  planGenerating.value = true
  planError.value = ''
  try {
    const resp = await api.generatePlan({ userPrompt })
    planPreview.value = {
      planId: resp.plan_id,
      plan: resp.plan,
    }
    pushAgent(
      `策略预览已生成 (工具 ${resp.available_tools_count} 个, Skill ${resp.available_skills_count} 个)`,
      'primary',
    )
  } catch (e: unknown) {
    const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      || (e as Error)?.message || '策略生成失败'
    planError.value = String(msg)
    pushAgent(`策略生成失败: ${planError.value}`, 'warning')
    // 失败后允许直接创建
    planPreview.value = null
    doCreateTask()
    return
  } finally {
    planGenerating.value = false
  }
}

async function submit() {
  if (!canSubmit.value) {
    if (!form.value.userPrompt.trim()) {
      ElMessage.warning('请先输入任务描述')
    }
    return
  }

  // 未生成策略 → 先生成
  if (!planPreview.value && !planGenerating.value) {
    await generatePlanPreview()
    return
  }

  // 策略已生成 → 确认创建
  doCreateTask()
}

async function doCreateTask() {
  const target = detectedTarget.value || ''
  const userText = form.value.userPrompt.trim()
  creating.value = true
  scrollToBottom()

  try {
    const task = await listStore.createTask({
      target,
      rawPrompt: userText,
      scopeNote: form.value.scopeNote,
      extraHint: form.value.extraHint,
      userPrompt: userText,
      workflowMode: form.value.workflowMode,
      // 始终走手动确认,关键节点会通过 checkpoint 暂停并征求用户意见
      autoApprove: false,
      successGateLevel: form.value.successGateLevel || null,
      riskBudget: form.value.riskBudget,
      maxReactRounds: form.value.maxReactRounds,
      maxExploreRounds: form.value.maxExploreRounds,
      confirmedPlan: planPreview.value?.plan ? (planPreview.value.plan as unknown as Record<string, unknown>) : null,
      parsedIntentExtra: intent.value.loaded ? {
        intents: intent.value.intents,
        extra_hint: intent.value.extraHint,
        scope_note: intent.value.scopeNote,
        priority_vulns: intent.value.priorityVulns,
      } : null,
    })

    // ── 安全卡口待确认 ──
    if (task.status === 'pending_confirmation') {
      pendingConfirmationState.value = task as PendingConfirmationResponse
      confirmedRisks.value = []
      pushAgent(
        task.warnings.map((w) => `⚠️ ${w}`).join('\n') +
          '\n\n请在下方勾选确认项后点击「确认并提交」。',
        'warning',
      )
      creating.value = false
      return
    }

    // ── 正常创建成功 ──
    planPreview.value = null
    trackEvent('task.create', {
      target,
      workflowMode: form.value.workflowMode,
      autoApprove: false,
      taskId: task.task_id,
    })
    pushAgent(
      `任务已创建: ${task.task_id}。即将跳转到任务详情页,关键节点我会在对话流中暂停等待你确认。`,
      'primary',
    )
    ElMessage.success(`任务已创建: ${task.target}`)
    setTimeout(() => router.push(`/tasks/${task.task_id}/chat`), 600)
  } catch (e: unknown) {
    const responseData = (e as { response?: { data?: { detail?: unknown } } })?.response?.data
    const rawDetail = responseData?.detail

    // 后端可能返回结构化对象 detail={status, message, questions, ...}
    // 或者普通字符串 detail="xxx"
    let detail: string
    if (typeof rawDetail === 'object' && rawDetail !== null) {
      const structured = rawDetail as Record<string, unknown>
      detail = (structured.message as string) || (structured.detail as string) || JSON.stringify(rawDetail)
      // 如果有补充问题，在聊天流中展示出来，引导用户补充
      if (structured.status === 'pending_clarification' && Array.isArray(structured.questions) && structured.questions.length) {
        pushAgent(
          `${detail}\n\n${(structured.questions as string[]).map((q) => `• ${q}`).join('\n')}`,
          'warning',
        )
        ElMessage.warning(detail)
        creating.value = false
        return
      }
    } else {
      detail = String(rawDetail || (e as Error)?.message || '创建失败')
    }
    pushAgent(`${detail}`, 'warning')
    ElMessage.error(detail)
  } finally {
    creating.value = false
  }
}

async function confirmAndResubmit() {
  const pending = pendingConfirmationState.value
  if (!pending || confirmedRisks.value.length === 0) {
    ElMessage.warning('请至少勾选一项确认')
    return
  }
  creating.value = true
  try {
    const task = await listStore.createTask({
      target: pending.target,
      rawPrompt: form.value.userPrompt.trim(),
      scopeNote: form.value.scopeNote,
      extraHint: form.value.extraHint,
      userPrompt: form.value.userPrompt.trim(),
      workflowMode: form.value.workflowMode,
      autoApprove: false,
      successGateLevel: form.value.successGateLevel || null,
      riskBudget: form.value.riskBudget,
      maxReactRounds: form.value.maxReactRounds,
      maxExploreRounds: form.value.maxExploreRounds,
      userConfirmedRisks: confirmedRisks.value,
      parsedIntentExtra: intent.value.loaded ? {
        intents: intent.value.intents,
        extra_hint: intent.value.extraHint,
        scope_note: intent.value.scopeNote,
        priority_vulns: intent.value.priorityVulns,
      } : null,
    })

    if (task.status === 'pending_confirmation') {
      // 仍有关卡未通过，更新确认列表
      pendingConfirmationState.value = task as PendingConfirmationResponse
      confirmedRisks.value = []
      pushAgent(
        task.warnings.map((w) => `⚠️ ${w}`).join('\n') +
          '\n\n还有风险项未确认，请继续勾选。',
        'warning',
      )
      creating.value = false
      return
    }

    // 创建成功
    pendingConfirmationState.value = null
    trackEvent('task.create', {
      target: pending.target,
      workflowMode: form.value.workflowMode,
      autoApprove: false,
      taskId: task.task_id,
    })
    pushAgent(
      `✅ 确认通过，任务已创建: ${task.task_id}。即将跳转到任务详情页。`,
      'primary',
    )
    ElMessage.success(`任务已创建: ${task.target}`)
    setTimeout(() => router.push(`/tasks/${task.task_id}/chat`), 600)
  } catch (e: unknown) {
    const responseData = (e as { response?: { data?: { detail?: unknown } } })?.response?.data
    const rawDetail = responseData?.detail
    let detail: string
    if (typeof rawDetail === 'object' && rawDetail !== null) {
      const structured = rawDetail as Record<string, unknown>
      detail = (structured.message as string) || (structured.detail as string) || JSON.stringify(rawDetail)
    } else {
      detail = String(rawDetail || (e as Error)?.message || '提交失败')
    }
    pushAgent(`${detail}`, 'warning')
    ElMessage.error(detail)
  } finally {
    creating.value = false
  }
}

function cancelConfirmation() {
  pendingConfirmationState.value = null
  confirmedRisks.value = []
  pushAgent('已取消安全确认，你可以修改目标后重新提交。', 'info')
}
</script>

<style scoped>
.chat-page {
  display: flex;
  flex-direction: column;
  /* 父级 .main-content 已经是 column flex 且 height = 100vh,顶部还有 ~48px sticky topbar。
     如果这里写 min-height:100vh,整页会比 viewport 高一个 topbar,导致输入框被推出屏幕。
     改成 flex:1 + min-height:0,由父级的 flex 布局自动分配剩余高度。*/
  flex: 1;
  min-height: 0;
  background: var(--bg-base);
}

.chat-header {
  padding: 18px 28px 8px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-surface);
}
.header-left { display: flex; align-items: center; gap: 14px; }
.title-block h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 700;
  color: var(--text-primary);
}
.title-sub { margin: 2px 0 0; color: var(--text-muted); font-size: 12px; }

.chat-main {
  flex: 1;
  display: flex;
  flex-direction: column;
  max-width: 960px;
  width: 100%;
  margin: 0 auto;
  padding: 16px 18px 22px;
  min-height: 0;
}

.message-stream {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 6px 4px 18px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 0;
  scrollbar-width: thin;
  scrollbar-color: color-mix(in srgb, var(--text-primary) 22%, transparent) transparent;
}
.message-stream::-webkit-scrollbar { width: 10px; }
.message-stream::-webkit-scrollbar-track { background: transparent; }
.message-stream::-webkit-scrollbar-thumb {
  background: color-mix(in srgb, var(--text-primary) 18%, transparent);
  border: 2px solid transparent;
  background-clip: content-box;
  border-radius: 999px;
}
.message-stream::-webkit-scrollbar-thumb:hover {
  background: color-mix(in srgb, var(--accent-blue) 55%, var(--text-primary) 30%);
  background-clip: content-box;
}

.suggestion-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}

.advanced-summary {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  padding: 6px 4px 0;
  font-size: 12px;
  color: var(--text-muted);
}
.adv-tag { font-family: var(--font-mono); }

.composer {
  flex-shrink: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--bg-surface);
  padding: 10px 12px 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  box-shadow: 0 6px 24px color-mix(in srgb, #000000 24%, transparent);
}

.composer-toolbar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  padding-bottom: 6px;
  border-bottom: 1px dashed var(--border);
}

/* Cursor 风格的胶囊模式切换 */
.mode-pills {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  padding: 2px;
  background: color-mix(in srgb, var(--text-primary) 6%, transparent);
  border-radius: 999px;
}
.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  font-size: 12px;
  line-height: 1;
  color: var(--text-muted);
  background: transparent;
  border: none;
  border-radius: 999px;
  cursor: pointer;
  transition: background 0.15s ease, color 0.15s ease;
}
.pill:hover {
  color: var(--text-secondary);
  background: color-mix(in srgb, var(--text-primary) 6%, transparent);
}
.pill.active {
  color: var(--text-primary);
  background: var(--bg-elevated);
  box-shadow: 0 1px 2px color-mix(in srgb, #000 30%, transparent);
}
.pill-ghost {
  margin-left: auto;
  background: transparent;
  border: 1px solid transparent;
}
.pill-ghost:hover {
  background: color-mix(in srgb, var(--text-primary) 6%, transparent);
}
.pill-icon {
  font-size: 13px;
}

.input-bar {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.prompt-input :deep(.el-textarea__inner) {
  font-size: 13px;
  line-height: 1.55;
}
.send-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.hint {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  font-size: 12px;
  color: var(--text-muted);
}
.hint-divider { opacity: 0.5; }
.hint-target {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: var(--text-secondary);
}
.hint-target code {
  font-family: var(--font-mono);
  padding: 1px 6px;
  border-radius: var(--radius-sm);
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  color: var(--text-primary);
  font-size: 11px;
}
.hint-target-missing {
  color: var(--text-muted);
}
.hint-target-loading {
  color: var(--accent-blue);
}
.hint-source {
  font-size: 10px;
  font-family: var(--font-mono);
  padding: 1px 6px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--accent-blue) 18%, transparent);
  color: var(--accent-blue);
  margin-left: 4px;
  letter-spacing: 0.04em;
}
.hint-source-fallback {
  background: color-mix(in srgb, var(--text-muted) 22%, transparent);
  color: var(--text-muted);
}
.spin {
  animation: rotate 1.4s linear infinite;
}
@keyframes rotate {
  from { transform: rotate(0); }
  to   { transform: rotate(360deg); }
}

/* ── AI 意图解析卡 ─────────────────────────────── */
.intent-card {
  position: relative;
  padding: 10px 12px;
  border: 1px solid color-mix(in srgb, var(--accent-blue) 35%, var(--border));
  border-left: 3px solid var(--accent-blue);
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--accent-blue) 6%, var(--bg-elevated));
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.intent-card.is-loading {
  border-left-color: color-mix(in srgb, var(--accent-blue) 60%, var(--text-muted));
}
.intent-card.is-fallback {
  border-color: color-mix(in srgb, var(--accent-yellow) 30%, var(--border));
  border-left-color: var(--accent-yellow);
  background: color-mix(in srgb, var(--accent-yellow) 5%, var(--bg-elevated));
}
.intent-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.intent-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 600;
  color: var(--accent-blue);
}
.intent-card.is-fallback .intent-badge {
  color: var(--accent-yellow);
}
.intent-icon { font-size: 14px; }
.intent-confidence {
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  padding: 1px 8px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--text-primary) 6%, transparent);
}
.intent-summary {
  margin: 0;
  font-size: 13px;
  line-height: 1.55;
  color: var(--text-primary);
}
.intent-grid {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.intent-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  font-size: 12px;
  color: var(--text-secondary);
}
.intent-label {
  display: inline-block;
  min-width: 56px;
  font-weight: 600;
  color: var(--text-muted);
  letter-spacing: 0.02em;
}
.intent-target {
  font-family: var(--font-mono);
  padding: 1px 8px;
  border-radius: var(--radius-sm);
  background: var(--bg-base);
  border: 1px solid var(--border);
  color: var(--text-primary);
  font-size: 12px;
}
.intent-mode-name {
  font-weight: 600;
  color: var(--text-primary);
}
.intent-text {
  flex: 1;
  min-width: 0;
  color: var(--text-secondary);
  word-break: break-word;
}
.intent-tag { font-family: var(--font-mono); }

.intent-fade-enter-active,
.intent-fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.intent-fade-enter-from,
.intent-fade-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}

.adv-panel { display: flex; flex-direction: column; gap: 10px; }
.adv-row { display: flex; flex-direction: column; gap: 4px; }
.adv-row label { font-size: 12px; color: var(--text-muted); }
.adv-row.two-col {
  flex-direction: row;
  gap: 12px;
}
.adv-row.two-col > div { flex: 1; display: flex; flex-direction: column; gap: 4px; }

.muted { color: var(--text-muted); }

/* ── 安全卡口确认卡片 ─────────────────────────── */
.confirmation-card {
  margin: 12px 0;
  padding: 16px 20px;
  background: color-mix(in srgb, var(--accent-warning) 8%, var(--bg-surface));
  border: 1px solid color-mix(in srgb, var(--accent-warning) 30%, var(--border));
  border-radius: 10px;
  animation: confirmationIn 0.25s ease-out;
}
@keyframes confirmationIn {
  from { opacity: 0; transform: translateY(-6px); }
  to   { opacity: 1; transform: translateY(0); }
}
.confirmation-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
  font-weight: 600;
  color: var(--accent-warning);
  margin-bottom: 10px;
}
.confirmation-icon { font-size: 20px; }
.confirmation-message {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.5;
}
.confirmation-warnings {
  margin: 0 0 14px;
  padding-left: 0;
  list-style: none;
}
.confirmation-warnings li {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  padding: 6px 8px;
  margin-bottom: 4px;
  font-size: 13px;
  color: var(--accent-warning);
  background: color-mix(in srgb, var(--accent-warning) 12%, transparent);
  border-radius: 6px;
  line-height: 1.45;
}
.confirmation-checks {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 16px;
}
.confirmation-checks :deep(.el-checkbox__label) {
  font-size: 13px;
  color: var(--text-primary);
  white-space: normal;
  line-height: 1.45;
}
.confirmation-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

/* ── Plan Mode: 策略预览卡片 ─────────────────────── */
.plan-preview-card {
  margin: 12px 0;
  padding: 20px 24px;
  background: color-mix(in srgb, var(--accent-blue) 6%, var(--bg-surface));
  border: 1px solid color-mix(in srgb, var(--accent-blue) 30%, var(--border));
  border-left: 3px solid var(--accent-blue);
  border-radius: 10px;
  display: flex;
  flex-direction: column;
  gap: 14px;
  animation: planIn 0.25s ease-out;
}
@keyframes planIn {
  from { opacity: 0; transform: translateY(-6px); }
  to   { opacity: 1; transform: translateY(0); }
}
.plan-preview-head {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: var(--accent-blue);
  padding-bottom: 8px;
  border-bottom: 1px solid color-mix(in srgb, var(--accent-blue) 20%, transparent);
}
.plan-preview-icon { font-size: 18px; }
.plan-preview-id {
  margin-left: auto;
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  font-weight: 400;
}
.plan-preview-section {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.plan-preview-section p {
  margin: 0;
  font-size: 14px;
  line-height: 1.6;
  color: var(--text-primary);
}
.plan-preview-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.plan-preview-phase {
  padding: 14px 0;
  border-top: 1px dashed color-mix(in srgb, var(--text-primary) 10%, transparent);
}
.plan-preview-phase-head {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin-bottom: 8px;
}
.plan-preview-phase-name {
  font-size: 13px;
  font-weight: 600;
  font-family: var(--font-mono);
  color: var(--accent-blue);
  padding: 2px 10px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--accent-blue) 12%, transparent);
}
.plan-preview-phase-desc {
  font-size: 13px;
  color: var(--text-secondary);
}
.plan-preview-steps {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-left: 4px;
}
.plan-preview-step {
  display: flex;
  align-items: baseline;
  gap: 8px;
  font-size: 13px;
  line-height: 1.6;
}
.plan-preview-step-idx {
  flex-shrink: 0;
  width: 22px;
  height: 22px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: color-mix(in srgb, var(--text-primary) 8%, transparent);
  font-size: 11px;
  color: var(--text-muted);
  font-weight: 600;
}
.plan-preview-step-tool {
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, #2ea043 15%, transparent);
  color: color-mix(in srgb, #2ea043 85%, var(--text-primary));
  font-weight: 500;
}
.plan-preview-step-skill {
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--accent-purple) 15%, transparent);
  color: var(--accent-purple);
  font-weight: 500;
}
.plan-preview-step-purpose {
  color: var(--text-secondary);
}
.plan-preview-risks,
.plan-preview-hints {
  padding: 8px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--accent-yellow) 6%, transparent);
}
.plan-preview-risks ul,
.plan-preview-hints ul {
  margin: 4px 0 0;
  padding-left: 18px;
}
.plan-preview-risks li,
.plan-preview-hints li {
  font-size: 12px;
  color: var(--text-secondary);
  line-height: 1.5;
}
</style>
