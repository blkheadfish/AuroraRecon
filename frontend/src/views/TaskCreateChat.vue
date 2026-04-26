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
          <p class="title-sub">用对话告诉 Agent 你想做什么,Agent mode 在输入框上方切换。</p>
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
          <div class="toolbar-group">
            <span class="toolbar-label">Agent 模式</span>
            <el-radio-group v-model="form.workflowMode" size="small" @change="onWorkflowModeChange">
              <el-radio-button label="pentest_engineer">渗透工程师</el-radio-button>
              <el-radio-button label="ctf_expert">CTF 选手</el-radio-button>
            </el-radio-group>
          </div>

          <div class="toolbar-group">
            <span class="toolbar-label">审批策略</span>
            <el-radio-group v-model="form.autoApprove" size="small">
              <el-radio-button :label="false">手动确认</el-radio-button>
              <el-radio-button :label="true">全自动</el-radio-button>
            </el-radio-group>
          </div>

          <el-popover placement="top" trigger="click" :width="380">
            <template #reference>
              <el-button size="small">
                <el-icon><Setting /></el-icon>
                高级
              </el-button>
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

        <div class="target-line">
          <span class="target-label">目标</span>
          <el-input
            v-model="form.target"
            size="default"
            class="target-input"
            placeholder="IP / 域名 / IP:端口 / URL — 仅在合法授权范围内使用"
            clearable
            @input="targetWasFocused = true"
          />
          <span v-if="targetWasFocused && targetError" class="target-err">{{ targetError }}</span>
        </div>

        <div class="input-bar">
          <el-input
            v-model="form.userPrompt"
            type="textarea"
            :rows="3"
            resize="none"
            placeholder="例如：先验证 SQL 注入再尝试 RCE,优先低噪声命令,拿 flag 优先..."
            @keydown.ctrl.enter.prevent="submit"
            @keydown.meta.enter.prevent="submit"
          />
          <div class="send-row">
            <span class="hint">Ctrl/Cmd + Enter 发送 · 当前 mode: {{ workflowModeLabel }}</span>
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
import { computed, defineAsyncComponent, nextTick, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { ArrowLeft, Setting, Promotion } from '@element-plus/icons-vue'
import { useTaskListStore } from '@/stores/taskList'
import { trackEvent } from '@/metrics/tracker'
import type { WorkflowMode } from '@/types/task'

const ChatBubble = defineAsyncComponent(() => import('@/components/ChatBubble.vue'))

const router = useRouter()
const listStore = useTaskListStore()

const MODE_DEFAULTS: Record<WorkflowMode, { autoApprove: boolean; description: string }> = {
  pentest_engineer: {
    autoApprove: false,
    description: '渗透工程师模式: 严格证据门槛, 利用前需要人工授权。',
  },
  ctf_expert: {
    autoApprove: true,
    description: 'CTF 选手模式: 全自动 + 宽松证据, 优先拿 flag。',
  },
}

interface ChatMessage {
  id: string
  role: 'agent' | 'user' | 'system'
  text: string
  timestamp: string
  tone?: 'info' | 'warning' | 'primary'
  suggestions?: string[]
}

const form = ref({
  target: '',
  scopeNote: 'CTF/授权靶场测试',
  extraHint: '',
  userPrompt: '',
  workflowMode: 'pentest_engineer' as WorkflowMode,
  autoApprove: MODE_DEFAULTS.pentest_engineer.autoApprove,
  successGateLevel: '' as '' | 'strict' | 'medium' | 'lenient',
  riskBudget: null as number | null,
  maxReactRounds: null as number | null,
  maxExploreRounds: null as number | null,
})

const creating = ref(false)
const targetWasFocused = ref(false)
const streamRef = ref<HTMLElement | null>(null)

const messages = ref<ChatMessage[]>([
  {
    id: 'agent-greeting',
    role: 'agent',
    text:
      '你好,我是渗透测试 Agent。\n请告诉我:\n  1) 想攻击的目标(顶部输入框)\n  2) 你的偏好与策略(下方输入框,例如优先验证 PoC、避免长时间暴力等)\n\n在输入框上方可以切换 Agent 模式与审批策略。',
    timestamp: nowTime(),
    tone: 'info',
    suggestions: [
      '先做轻量侦察,确认 web 攻击面后再尝试利用',
      '优先低噪声命令,避免触发 IDS/IPS',
      '尽快验证可利用性并尝试拿 flag',
    ],
  },
])

const workflowModeLabel = computed(() =>
  form.value.workflowMode === 'ctf_expert' ? 'CTF 选手' : '渗透工程师',
)

const targetError = computed(() => {
  const v = form.value.target.trim()
  if (!v) return '请输入目标'
  if (!isValidTarget(v)) return '格式应为 IP / 域名 / IP:端口 / URL'
  return ''
})

const canSubmit = computed(() => !targetError.value && !creating.value)

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

watch(
  () => form.value.workflowMode,
  (mode) => {
    pushAgent(MODE_DEFAULTS[mode].description, 'info')
  },
)

watch(
  () => form.value.autoApprove,
  (val) => {
    pushAgent(
      val
        ? '已切换到全自动: 后续 Agent 决策不会再弹出审批确认。'
        : '已切换到手动确认: 关键节点会暂停并请求你的判断。',
      'info',
    )
  },
)

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

function onWorkflowModeChange(mode: WorkflowMode) {
  form.value.autoApprove = MODE_DEFAULTS[mode].autoApprove
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

function isValidTarget(value: string): boolean {
  const raw = String(value || '').trim()
  if (!raw) return false
  try {
    const u = new URL(raw)
    if (!['http:', 'https:'].includes(u.protocol)) return false
    if (!isValidHost(u.hostname)) return false
    if (u.port) {
      const p = Number(u.port)
      if (!Number.isFinite(p) || p < 1 || p > 65535) return false
    }
    return true
  } catch {
    // fallthrough
  }
  const portMatch = raw.match(/:(\d{1,5})$/)
  let host = raw
  if (portMatch) {
    host = raw.slice(0, -portMatch[0].length)
    const p = Number(portMatch[1])
    if (!Number.isFinite(p) || p < 1 || p > 65535) return false
  }
  return isValidHost(host) && !host.includes(':')
}

function goBack() {
  router.push('/tasks')
}

async function submit() {
  if (!canSubmit.value) {
    targetWasFocused.value = true
    return
  }
  creating.value = true
  const userText = form.value.userPrompt.trim()
  messages.value.push({
    id: `user-${Date.now()}`,
    role: 'user',
    text: userText
      ? `目标: ${form.value.target}\n${userText}`
      : `目标: ${form.value.target}`,
    timestamp: nowTime(),
  })
  scrollToBottom()

  try {
    const task = await listStore.createTask({
      target: form.value.target.trim(),
      scopeNote: form.value.scopeNote,
      extraHint: form.value.extraHint,
      userPrompt: userText,
      workflowMode: form.value.workflowMode,
      autoApprove: form.value.autoApprove,
      successGateLevel: form.value.successGateLevel || null,
      riskBudget: form.value.riskBudget,
      maxReactRounds: form.value.maxReactRounds,
      maxExploreRounds: form.value.maxExploreRounds,
    })
    trackEvent('task.create', {
      target: form.value.target,
      workflowMode: form.value.workflowMode,
      autoApprove: form.value.autoApprove,
      taskId: task.task_id,
    })
    pushAgent(
      `任务已创建: ${task.task_id}。即将跳转到任务详情页,你可以在那里查看实时 thinking 与确认卡片。`,
      'primary',
    )
    ElMessage.success(`任务已创建: ${task.target}`)
    setTimeout(() => router.push(`/tasks/${task.task_id}`), 600)
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
  gap: 14px;
  padding-bottom: 4px;
  border-bottom: 1px dashed var(--border);
}
.toolbar-group { display: flex; align-items: center; gap: 8px; }
.toolbar-label { font-size: 12px; color: var(--text-muted); }

.target-line {
  display: flex;
  align-items: center;
  gap: 10px;
}
.target-label {
  flex: 0 0 auto;
  width: 44px;
  font-size: 12px;
  color: var(--text-muted);
}
.target-input { flex: 1; }
.target-err {
  font-size: 12px;
  color: var(--accent-red);
  white-space: nowrap;
}

.input-bar {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.send-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.hint { font-size: 12px; color: var(--text-muted); }

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
