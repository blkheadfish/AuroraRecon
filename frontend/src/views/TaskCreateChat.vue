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
              <span class="hint-target" v-if="detectedTarget">
                <el-icon><Aim /></el-icon>
                已识别目标: <code>{{ detectedTarget }}</code>
              </span>
              <span class="hint-target hint-target-missing" v-else>
                <el-icon><Warning /></el-icon>
                请在描述中包含目标 IP / 域名 / URL
              </span>
            </span>
            <el-button
              type="primary"
              :loading="creating"
              :disabled="!canSubmit"
              @click="submit"
            >
              <el-icon><Promotion /></el-icon>
              创建并开始
            </el-button>
          </div>
        </div>
      </section>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, defineAsyncComponent, nextTick, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { ArrowLeft, Setting, Promotion, Aim, Warning, Cpu, Tools } from '@element-plus/icons-vue'
import { useTaskListStore } from '@/stores/taskList'
import { trackEvent } from '@/metrics/tracker'
import type { WorkflowMode } from '@/types/task'

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

const detectedTarget = computed(() => extractTarget(form.value.userPrompt))

const canSubmit = computed(
  () => !creating.value && form.value.userPrompt.trim().length > 0 && !!detectedTarget.value,
)

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

async function submit() {
  if (!canSubmit.value) {
    if (!form.value.userPrompt.trim()) {
      ElMessage.warning('请先输入任务描述')
    } else if (!detectedTarget.value) {
      pushAgent('我没有从描述里识别到目标(IP / 域名 / URL),请在句子里写清楚要测试的对象。', 'warning')
    }
    return
  }
  const target = detectedTarget.value as string
  creating.value = true
  const userText = form.value.userPrompt.trim()
  messages.value.push({
    id: `user-${Date.now()}`,
    role: 'user',
    text: userText,
    timestamp: nowTime(),
  })
  scrollToBottom()

  try {
    const task = await listStore.createTask({
      target,
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
    })
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
    const detail =
      (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
      (e as Error)?.message ||
      '创建失败'
    pushAgent(`创建失败: ${detail}`, 'warning')
    ElMessage.error(detail)
  } finally {
    creating.value = false
  }
}
</script>

<style scoped>
.chat-page {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 100vh;
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
  padding: 6px 4px 18px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 280px;
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
  color: var(--accent-yellow);
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
</style>
