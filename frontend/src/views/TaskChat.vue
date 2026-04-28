<template>
  <div class="task-chat-page" v-loading="loading" element-loading-background="rgba(13,17,23,0.9)">
    <header class="chat-header">
      <div class="header-left">
        <el-button text @click="goTasks">
          <el-icon><ArrowLeft /></el-icon>
          任务列表
        </el-button>
        <div class="title-block">
          <h2>对话 · {{ task?.target || '...' }}</h2>
          <code class="task-id">{{ taskId }}</code>
        </div>
      </div>
      <div class="header-right" v-if="task">
        <StatusBadge :status="task.status" size="large" />
        <el-button plain @click="goDetail">
          <el-icon><Memo /></el-icon>
          任务详情
        </el-button>
        <el-button
          v-if="task.report_path || task.report_available"
          type="success"
          plain
          @click="goReport"
        >
          <el-icon><Document /></el-icon>
          报告中心
        </el-button>
        <el-button
          v-if="isRunning"
          type="danger"
          plain
          :loading="cancelling"
          @click="doCancel"
        >取消任务</el-button>
      </div>
    </header>

    <main class="chat-main">
      <div class="chat-side">
        <ToolChainRail
          :items="railItems"
          :active-id="activeRailId"
          class="chat-rail"
          @jump="handleRailJump"
        />
        <BranchTree
          v-if="branches.length"
          class="chat-branch-tree"
          :items="branches"
          :active-branch-id="activeBranchId"
          :max-branches="state.maxBranchesPerTask || 12"
          @activate="onBranchActivate"
          @resume="onBranchResume"
          @pause="onBranchPause"
        />
      </div>

      <div class="chat-stream-wrap" ref="streamRef" @scroll="onUserScroll">
        <div class="bubble-stream">
          <template v-for="msg in messages" :key="msg.id">
            <div :data-bubble-id="msg.id" class="bubble-anchor">
          <ChatBubble
            :role="msg.role"
            :text="msg.text"
            :timestamp="msg.timestamp"
            :tone="msg.tone"
          >
            <div v-if="msg.purpose" class="thought-meta">
              <span class="meta-label">目标</span> {{ msg.purpose }}
            </div>
            <div v-if="msg.expected" class="thought-meta">
              <span class="meta-label">预期</span> {{ msg.expected }}
            </div>
            <div v-if="Array.isArray(msg.plan) && msg.plan.length" class="thought-plan">
              <span class="meta-label">攻击计划</span>
              <ol>
                <li v-for="(step, si) in msg.plan" :key="si">{{ step }}</li>
              </ol>
            </div>
            <details v-if="msg.thinking" class="thought-expand">
              <summary>展开完整推理</summary>
              <pre class="thought-full">{{ msg.thinking }}</pre>
            </details>

            <div v-if="msg.action === 'checkpoint_request'" class="checkpoint-slot">
              <DecisionCheckpointCard
                v-if="pendingCheckpoint && pendingCheckpoint.checkpoint_id === msg.checkpointId"
                :checkpoint="pendingCheckpoint"
                :loading="checkpointSubmitting"
                inline
                @submit="onCheckpointSubmit"
              />
              <div v-else class="checkpoint-done">
                <el-icon><Check /></el-icon>
                决策点已处理
              </div>
            </div>

            <div v-if="msg.action === 'approval_required'" class="approval-slot">
              <div v-if="showApprovalActions && msg.isLastApproval" class="inline-approval">
                <span class="inline-approval-text">是否继续执行?</span>
                <div class="inline-approval-actions">
                  <el-button type="primary" size="small" :loading="approving" @click="doApprove(true)">
                    <el-icon><Check /></el-icon>
                    批准并继续
                  </el-button>
                  <el-button size="small" plain :loading="approving" @click="doApprove(false)">
                    拒绝
                  </el-button>
                </div>
              </div>
              <div v-else class="checkpoint-done">
                <el-icon><Check /></el-icon>
                审批已处理
              </div>
            </div>

            <div v-if="Array.isArray(msg.payloads) && msg.payloads.length" class="payload-slot">
              <PayloadCodeBlock
                v-for="(block, idx) in msg.payloads"
                :key="`${msg.id}-pl-${idx}`"
                :title="block.title"
                :language="block.language"
                :code="block.code"
                :truncated="Boolean(block.truncated)"
                :total-len="Number(block.totalLen || 0)"
              />
            </div>

            <div
              v-if="msg.action === 'branch_forked' && msg.branchId && siblingNavFor(msg.branchId)"
              class="branch-navigator"
            >
              <button
                class="nav-btn"
                :disabled="siblingNavFor(msg.branchId).total <= 1"
                @click="gotoSibling(msg.branchId, -1)"
                title="上一个兄弟分支"
              >‹</button>
              <span class="nav-counter">
                &lt;{{ siblingNavFor(msg.branchId).index }}/{{ siblingNavFor(msg.branchId).total }}&gt;
              </span>
              <button
                class="nav-btn"
                :disabled="siblingNavFor(msg.branchId).total <= 1"
                @click="gotoSibling(msg.branchId, 1)"
                title="下一个兄弟分支"
              >›</button>
              <span class="nav-active" v-if="msg.branchId === activeBranchId">当前激活</span>
              <button
                v-else
                class="nav-activate"
                @click="activateBranch(msg.branchId)"
              >切到此分支</button>
            </div>
          </ChatBubble>
            </div>
          </template>

          <div v-for="(bubble, sid) in activeStreamBubbles" :key="sid" class="llm-stream-bubble">
            <div class="bubble-header">
              <span class="bubble-phase">{{ bubble.phase || '推理' }}</span>
              <span class="bubble-indicator">正在思考<span class="dots">...</span></span>
            </div>
            <pre class="bubble-text">{{ bubble.text }}</pre>
          </div>
        </div>

        <transition name="fade">
          <button v-if="showJumpBtn" class="jump-latest" @click="jumpToBottom">
            <el-icon><ArrowDown /></el-icon>
            跳转最新
          </button>
        </transition>
      </div>
    </main>

    <footer class="chat-footer">
      <section class="composer" :class="{ 'composer-flash': composerFlashing }">
        <div v-if="branches.length > 1 || activeBranch" class="branch-status-band">
          <span class="band-icon">
            <el-icon><Promotion /></el-icon>
          </span>
          <span class="band-text">
            <template v-if="activeBranch">
              当前分支
              <strong>{{ activeBranch.label || activeBranch.branch_id }}</strong>
              <span class="band-status" :class="`status-${activeBranch.status}`">
                · {{ branchStatusLabel(activeBranch.status) }}
              </span>
            </template>
            <template v-else>
              <strong>主分支(root)</strong> 进行中
            </template>
            <span v-if="branches.length > 1" class="band-count">
              · 共 {{ branches.length }} 个分支
            </span>
          </span>
          <span v-if="branchAtCap" class="band-cap">已达分支上限, 新输入将被合并到当前分支</span>
        </div>
        <div class="composer-toolbar">
          <span class="composer-tip">
            <el-icon><ChatLineRound /></el-icon>
            你可以追加指令影响后续决策, 或在决策点提出修改意见
          </span>
          <span class="composer-shortcut">Ctrl/Cmd + Enter 发送</span>
        </div>
        <div class="input-bar">
          <el-input
            v-model="chatInput"
            type="textarea"
            :rows="3"
            :autosize="{ minRows: 2, maxRows: 6 }"
            resize="none"
            class="prompt-input"
            placeholder="输入指令或问题，影响 Agent 决策..."
            :disabled="sending"
            @keydown.ctrl.enter.prevent="sendMessage"
            @keydown.meta.enter.prevent="sendMessage"
          />
          <div class="send-row">
            <span class="hint">
              <span v-if="needsApproval" class="hint-warn">
                <el-icon><Warning /></el-icon>
                Agent 已暂停, 等待审批
              </span>
              <span v-else-if="pendingCheckpoint" class="hint-warn">
                <el-icon><Warning /></el-icon>
                有 Plan 决策点等待确认
              </span>
              <span v-else-if="isRunning" class="hint-info">
                <el-icon><Loading class="spin" /></el-icon>
                Agent 正在执行
              </span>
              <span v-else class="hint-info">
                <el-icon><CircleCheck /></el-icon>
                任务已结束
              </span>
            </span>
            <el-button
              type="primary"
              :loading="sending"
              :disabled="!chatInput.trim()"
              @click="sendMessage"
            >
              <el-icon><Promotion /></el-icon>
              发送
            </el-button>
          </div>
        </div>
      </section>
    </footer>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  ArrowDown,
  ArrowLeft,
  ChatLineRound,
  Check,
  CircleCheck,
  Document,
  Loading,
  Memo,
  Promotion,
  Warning,
} from '@element-plus/icons-vue'
import { api } from '@/api'
import { useTaskListStore } from '@/stores/taskList'
import { useTaskLiveStore } from '@/stores/taskLive'
import { trackEvent } from '@/metrics/tracker'
import BranchTree from '@/components/BranchTree.vue'
import ChatBubble from '@/components/ChatBubble.vue'
import DecisionCheckpointCard from '@/components/DecisionCheckpointCard.vue'
import PayloadCodeBlock from '@/components/PayloadCodeBlock.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import ToolChainRail from '@/components/ToolChainRail.vue'

const route = useRoute()
const router = useRouter()
const taskId = String(route.params.id)
const listStore = useTaskListStore()
const liveStore = useTaskLiveStore()

const loading = ref(true)
const chatInput = ref('')
const sending = ref(false)
const cancelling = ref(false)
const streamRef = ref(null)
const showJumpBtn = ref(false)
const stickyBottom = ref(true)
let scrollTimeout = null
let userScrolling = false
let scrollRafId = 0

const state = computed(() => liveStore.getLiveState(taskId))
const task = computed(() => state.value.task || listStore.getTaskById(taskId))

// 后端 timestamp 是 HH:MM:SS 短格式,store 层虽然做了 sort 但 Vue3 reactive
// 对原地 sort 触发依赖更新不一定可靠。这里在 view 层再 sort 一次作为最终防线,
// 确保 rail/messages 的渲染顺序严格按事件先后。
//
// 比较器:
//   1. 主 key = timestamp 字典序 (HH:MM:SS / ISO 都是字典序 = 时间序)
//   2. tie-breaker = id 里的 idx (后端 push 顺序), 解决同秒 / 同 timestamp 时的稳定性
function _eventIdx(id) {
  const m = String(id || '').match(/^de-(\d+)-/)
  return m ? Number(m[1]) : 0
}
function _compareEvents(a, b) {
  const ta = String(a?.timestamp || '')
  const tb = String(b?.timestamp || '')
  const cmp = ta.localeCompare(tb)
  if (cmp !== 0) return cmp
  return _eventIdx(a?.id) - _eventIdx(b?.id)
}

const decisionEvents = computed(() => {
  const raw = state.value?.decisionEvents
  if (!Array.isArray(raw) || !raw.length) return []
  // slice 后再 sort, 不影响 store 内部数组
  return raw.slice().sort(_compareEvents)
})
const llmStreams = computed(() => state.value?.llmStreams || {})
const isRunning = computed(() => ['pending', 'running'].includes(task.value?.status || ''))
const needsApproval = computed(() => task.value?.current_phase === 'awaiting_approval')
const approvalState = computed(() => state.value.approvalState)
const approving = computed(() => approvalState.value === 'submitting')
const showApprovalActions = computed(() => needsApproval.value && approvalState.value === 'idle')
const pendingCheckpoint = computed(() => state.value?.pendingCheckpoint || null)
const checkpointSubmitting = computed(() => state.value?.checkpointState === 'submitting')

const _SHELL_NAMES = new Set(['/bin/bash', '/bin/sh', 'bash', 'sh', '/bin/zsh', 'zsh'])
const _SKIP_RE = /^(set\s|export\s|cd\s|echo\s|#|if\s|then\b|else\b|fi\b|do\b|done\b|while\s|for\s|\[)/
const _VAR_RE = /^\w+=/

function inferToolFromCommand(cmd) {
  if (!cmd) return ''
  for (const seg of cmd.split(/[;\n|]|&&|\|\|/)) {
    const trimmed = seg.trim()
    if (!trimmed) continue
    if (_SKIP_RE.test(trimmed)) continue
    if (_VAR_RE.test(trimmed)) continue
    const token = trimmed.split(/\s/)[0]
    const name = token.split('/').pop()
    if (name && !_SHELL_NAMES.has(name)) return name
  }
  return ''
}

function inferPayloadLang(text) {
  if (/^\s*\{[\s\S]*\}\s*$/.test(text)) return 'json'
  if (/GET\s+\/|POST\s+\/|HTTP\/1\.1/i.test(text)) return 'http'
  if (/^\s*<\?xml|^\s*<\/?[a-zA-Z][\w:-]*[\s>]/.test(String(text || ''))) return 'xml'
  if (/python|def |import /.test(text)) return 'python'
  return 'bash'
}

function inferOutputLang(text) {
  const raw = String(text || '').trim()
  if (!raw) return 'text'
  if (/^\s*[\[{][\s\S]*[\]}]\s*$/.test(raw)) return 'json'
  if (/^(HTTP\/\d\.\d\s+\d{3}|GET\s+\/|POST\s+\/|PUT\s+\/|DELETE\s+\/)/im.test(raw)) return 'http'
  if (/^\s*<\?xml|^\s*<\/?[a-zA-Z][\w:-]*[\s>]/.test(raw)) return 'xml'
  return 'auto'
}

function buildExecPayloads(command, stdout, stderr, meta = {}) {
  const outputMeta = {
    truncated: Boolean(meta?.truncated),
    totalLen: Number(meta?.totalLen || 0),
  }
  const blocks = [{
    title: 'Command',
    language: inferPayloadLang(command || ''),
    code: command || '(empty command)',
  }]
  if (stdout) blocks.push({ title: 'Stdout', language: inferOutputLang(stdout), code: stdout, ...outputMeta })
  if (stderr) blocks.push({ title: 'Stderr', language: inferOutputLang(stderr), code: stderr, ...outputMeta })
  if (!stdout && !stderr) blocks.push({ title: 'Output', language: 'text', code: '(empty)', ...outputMeta })
  return blocks
}

function formatTime(ts) {
  if (!ts) return ''
  try {
    const d = new Date(ts)
    if (Number.isNaN(d.getTime())) return ts
    return d.toLocaleTimeString()
  } catch {
    return ts
  }
}

const messages = computed(() => {
  const out = []
  // 第一条: 用户的原始指令
  const userPrompt = task.value?.user_prompt || ''
  if (userPrompt) {
    out.push({
      id: 'origin-user-prompt',
      role: 'user',
      text: userPrompt,
      timestamp: formatTime(task.value?.created_at),
    })
  }

  const events = decisionEvents.value.slice(-160)
  // 找到最新一个 approval_required event 的 id, 用于决定哪条审批 bubble 可交互
  let lastApprovalId = ''
  for (let i = events.length - 1; i >= 0; i--) {
    if (events[i]?.action === 'approval_required') {
      lastApprovalId = events[i]?.id || ''
      break
    }
  }
  // 处理过的 checkpoint id 集合, 用于决策点已处理标识
  const resolvedCheckpointIds = new Set()
  for (const ev of events) {
    if (ev?.action === 'checkpoint_resolved' && ev.checkpoint_id) {
      resolvedCheckpointIds.add(String(ev.checkpoint_id))
    }
  }

  events.forEach((entry, idx) => {
    const time = formatTime(entry.timestamp)
    const baseId = entry.id || `ev-${idx}`

    if (entry.action === 'thought') {
      const roundLabel = entry.round ? `第 ${entry.round} 轮` : ''
      const vulnLabel = entry.vuln_name ? ` · ${entry.vuln_name}` : ''
      const head = `AI 推理${roundLabel ? ' · ' + roundLabel : ''}${vulnLabel}`
      const summary = (entry.message || entry.thinking || '').slice(0, 240)
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'primary',
        text: summary ? `${head}\n${summary}` : head,
        timestamp: time,
        thinking: entry.thinking || entry.message || '',
        purpose: entry.purpose || '',
        expected: entry.expected || '',
        plan: entry.plan || [],
      })
      return
    }

    if (entry.action === 'agent_reply') {
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'success',
        text: entry.message || '(空回复)',
        timestamp: time,
      })
      return
    }

    if (entry.action === 'user_chat') {
      out.push({
        id: baseId,
        role: 'user',
        tone: 'info',
        text: entry.message || '',
        timestamp: time,
      })
      return
    }

    if (entry.action === 'command_exec') {
      const command = entry.command || '(empty command)'
      const stdout = entry.stdout || ''
      const stderr = entry.stderr || ''
      const toolLabel = (entry.tool && !_SHELL_NAMES.has(entry.tool))
        ? entry.tool
        : inferToolFromCommand(entry.command) || 'shell'
      const head = entry.poc_or_vuln
        ? `命令执行 · ${entry.poc_or_vuln}`
        : `命令执行 · ${toolLabel}`
      const desc = `exit=${entry.exit_code ?? '-'} ｜ elapsed=${entry.elapsed_ms ?? '-'}ms${entry.purpose ? ' ｜ ' + entry.purpose : ''}`
      out.push({
        id: baseId,
        role: 'agent',
        tone: (entry.exit_code ?? -1) === 0 ? 'success' : 'danger',
        text: `${head}\n${desc}`,
        timestamp: time,
        payloads: buildExecPayloads(command, stdout, stderr, {
          runtimeCommand: entry.runtime_command || '',
          truncated: Boolean(entry.truncated),
          totalLen: Number(entry.total_len || 0),
        }),
      })
      return
    }

    if (entry.action === 'tool_start') {
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'primary',
        text: `工具调用 · ${entry.tool || 'unknown'}\n阶段 ${entry.phase || '-'}\n${entry.message || ''}`.trim(),
        timestamp: time,
      })
      return
    }

    if (entry.action === 'tool_result') {
      const exitText = entry.exit_code ?? '-'
      const elapsedText = entry.elapsed_ms ? `${entry.elapsed_ms}ms` : '-'
      out.push({
        id: baseId,
        role: 'agent',
        tone: Number(exitText) === 0 ? 'success' : 'danger',
        text: `调用结果 · ${entry.tool || 'unknown'}\nexit=${exitText} ｜ elapsed=${elapsedText}\n${entry.message || ''}`.trim(),
        timestamp: time,
      })
      return
    }

    if (entry.action === 'checkpoint_request') {
      const cpId = entry.checkpoint_id || ''
      const head = `Plan 决策点 · 等待确认`
      const summary = entry.summary || entry.recommendation || entry.message || '我建议进入下一步, 请确认是否继续。'
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'warning',
        text: `${head}\n${summary}`,
        timestamp: time,
        thinking: entry.thinking || '',
        action: 'checkpoint_request',
        checkpointId: cpId,
      })
      return
    }

    if (entry.action === 'checkpoint_resolved') {
      const resp = entry.response || {}
      const acted = resp.action || 'approve'
      const label = acted === 'approve'
        ? '已批准'
        : (acted === 'reject' ? '已拒绝' : (acted === 'modify' ? '已采纳意见' : '已处理'))
      out.push({
        id: baseId,
        role: 'agent',
        tone: acted === 'reject' ? 'danger' : 'success',
        text: `Plan 决策点 · ${label}${resp.user_prompt ? '\n补充意见: ' + resp.user_prompt : ''}`,
        timestamp: time,
      })
      return
    }

    if (entry.action === 'approval_required') {
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'warning',
        text: `审批请求\n${entry.message || '系统检测到可利用路径,等待人工审批。'}`,
        timestamp: time,
        action: 'approval_required',
        isLastApproval: baseId === lastApprovalId,
      })
      return
    }

    if (entry.action === 'approval') {
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'warning',
        text: `审批节点\n${entry.message || entry.raw || ''}`,
        timestamp: time,
      })
      return
    }

    if (entry.action === 'branch_forked') {
      const branchId = String(entry.branch_id || '')
      out.push({
        id: baseId,
        role: 'system',
        tone: 'primary',
        text: entry.message || '已基于此处分叉新分支',
        timestamp: time,
        action: 'branch_forked',
        branchId,
      })
      return
    }

    if (entry.action === 'log') {
      const msg = entry.message || entry.raw || ''
      if (!msg) return
      const isPhase = /开始|完成|端口|漏洞|侦察|扫描|利用|后渗透|报告|阶段|Phase/i.test(msg)
      if (!isPhase) return
      out.push({
        id: baseId,
        role: 'system',
        tone: 'info',
        text: msg,
        timestamp: time,
      })
    }
  })

  // 兜底: 如果有 pendingCheckpoint 但未在事件流中找到对应 checkpoint_request bubble, 单独追加一条
  if (pendingCheckpoint.value) {
    const cpId = pendingCheckpoint.value.checkpoint_id
    const has = out.some((m) => m.action === 'checkpoint_request' && m.checkpointId === cpId)
    if (!has) {
      out.push({
        id: `cp-pending-${cpId}`,
        role: 'agent',
        tone: 'warning',
        text: `Plan 决策点 · 等待确认\n${pendingCheckpoint.value.summary || pendingCheckpoint.value.recommendation || ''}`,
        timestamp: formatTime(pendingCheckpoint.value.created_at),
        thinking: pendingCheckpoint.value.thinking || '',
        action: 'checkpoint_request',
        checkpointId: cpId,
      })
    }
  }

  return out
})

const activeStreamBubbles = computed(() => {
  const now = Date.now()
  const result = {}
  for (const [sid, bubble] of Object.entries(llmStreams.value || {})) {
    if (bubble && bubble.text && now - bubble.updatedAt < 60000) {
      result[sid] = bubble
    }
  }
  return result
})

// 给侧边工具链用的事件项: 收集 thought / tool / approval / checkpoint 类事件
const railItems = computed(() => {
  const events = decisionEvents.value.slice(-200)
  const items = []
  for (const ev of events) {
    const action = ev?.action || ''
    const id = ev?.id || ''
    if (!id) continue

    if (action === 'thought') {
      items.push({
        id,
        action,
        tone: 'primary',
        title: 'AI 推理',
        round: ev.round || 0,
        purpose: ev.purpose || '',
        thinking: ev.thinking || ev.message || '',
        time: formatTime(ev.timestamp),
      })
    } else if (action === 'command_exec') {
      items.push({
        id,
        action,
        tone: (ev.exit_code ?? -1) === 0 ? 'success' : 'danger',
        title: `命令执行 · ${ev.tool || inferToolFromCommand(ev.command || '') || 'shell'}`,
        tool: ev.tool || '',
        command: ev.command || '',
        time: formatTime(ev.timestamp),
      })
    } else if (action === 'tool_start') {
      items.push({
        id,
        action,
        tone: 'primary',
        title: `工具调用 · ${ev.tool || 'tool'}`,
        tool: ev.tool || '',
        time: formatTime(ev.timestamp),
      })
    } else if (action === 'tool_result' || action === 'tool_executed') {
      items.push({
        id,
        action,
        tone: Number(ev.exit_code ?? -1) === 0 ? 'success' : 'danger',
        title: `调用结果 · ${ev.tool || 'tool'}`,
        tool: ev.tool || '',
        time: formatTime(ev.timestamp),
      })
    } else if (action === 'approval_required' || action === 'approval') {
      items.push({
        id,
        action,
        tone: 'warning',
        title: '审批',
        time: formatTime(ev.timestamp),
      })
    } else if (action === 'checkpoint_request') {
      items.push({
        id,
        action,
        tone: 'warning',
        title: 'Plan 决策点',
        summary: ev.summary || ev.recommendation || '',
        time: formatTime(ev.timestamp),
      })
    } else if (action === 'checkpoint_resolved') {
      items.push({
        id,
        action,
        tone: 'success',
        title: 'Plan 已决策',
        time: formatTime(ev.timestamp),
      })
    }
  }
  return items
})

const activeRailId = ref('')

function handleRailJump(id) {
  if (!id || !streamRef.value) return
  const target = streamRef.value.querySelector(`[data-bubble-id="${CSS.escape(id)}"]`)
  if (!target) return
  activeRailId.value = id
  target.scrollIntoView({ behavior: 'smooth', block: 'center' })
  target.classList.add('bubble-flash')
  setTimeout(() => target.classList.remove('bubble-flash'), 1400)
  // 因为是手动跳转, 不再粘到底部
  stickyBottom.value = false
}

const BOTTOM_THRESHOLD = 150

function isNearBottom() {
  const el = streamRef.value
  if (!el) return true
  return el.scrollHeight - el.scrollTop - el.clientHeight < BOTTOM_THRESHOLD
}

function onUserScroll() {
  userScrolling = true
  if (scrollTimeout) clearTimeout(scrollTimeout)
  scrollTimeout = setTimeout(() => { userScrolling = false }, 120)
  stickyBottom.value = isNearBottom()
  if (stickyBottom.value) showJumpBtn.value = false
}

function smoothScrollToBottom() {
  if (!streamRef.value) return
  cancelAnimationFrame(scrollRafId)
  scrollRafId = requestAnimationFrame(() => {
    streamRef.value?.scrollTo({ top: streamRef.value.scrollHeight, behavior: 'smooth' })
  })
}

function jumpToBottom() {
  stickyBottom.value = true
  showJumpBtn.value = false
  smoothScrollToBottom()
}

watch(
  () => messages.value.length,
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

async function sendMessage() {
  const text = chatInput.value.trim()
  if (!text || sending.value) return
  sending.value = true
  try {
    const res = await api.sendChat(taskId, text)
    chatInput.value = ''
    trackEvent('task.chat.send', {
      taskId,
      forked: Boolean(res?.fork_active),
      branch_id: res?.branch?.branch_id || '',
    })
    if (res?.fork_active) {
      composerFlashAt.value = Date.now()
    }
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '发送失败')
  } finally {
    sending.value = false
  }
}

// ── 分支(branch tree)视图状态 ───────────────────────────

const branches = computed(() => state.value?.branches || [])
const activeBranchId = computed(() => state.value?.activeBranchId || '')
const branchById = computed(() => {
  const map = {}
  for (const b of branches.value) map[b.branch_id] = b
  return map
})
const activeBranch = computed(() => branchById.value[activeBranchId.value] || null)
const branchAtCap = computed(() => {
  const max = state.value?.maxBranchesPerTask || 12
  return branches.value.length >= max
})
const composerFlashAt = ref(0)
const composerFlashing = computed(() => {
  if (!composerFlashAt.value) return false
  return Date.now() - composerFlashAt.value < 2400
})

// 把 branch_forked 事件下方挂的 sibling navigator 用到的元数据集中算一次, 避免
// v-for 内部闭包反复扫描 branches。key = branch_id。
const navigatorBubbleMeta = computed(() => {
  const out = {}
  for (const b of branches.value) {
    const total = Number(b.sibling_total || 1)
    if (total <= 1) continue
    const siblings = branches.value
      .filter((s) => (s.parent_branch_id || '') === (b.parent_branch_id || '')
        && (s.fork_event_id || '') === (b.fork_event_id || ''))
      .sort((a, c) => (a.created_at || '').localeCompare(c.created_at || ''))
    out[b.branch_id] = {
      siblings: siblings.map((s) => ({
        id: s.branch_id,
        label: s.label || s.branch_id,
        status: s.status,
      })),
      index: Math.max(1, Number(b.sibling_index || 1)),
      total,
    }
  }
  return out
})

function siblingNavFor(branchId) {
  return navigatorBubbleMeta.value[branchId] || null
}

async function activateBranch(branchId) {
  if (!branchId || branchId === activeBranchId.value) return
  await liveStore.activateBranch(taskId, branchId)
  trackEvent('task.branch.activate', { taskId, branch_id: branchId })
}

function onBranchActivate(branchId) {
  return activateBranch(branchId)
}

async function onBranchResume(branchId) {
  await liveStore.resumeBranch(taskId, branchId)
  trackEvent('task.branch.resume', { taskId, branch_id: branchId })
}

async function onBranchPause(branchId) {
  await liveStore.pauseBranch(taskId, branchId)
  trackEvent('task.branch.pause', { taskId, branch_id: branchId })
}

async function gotoSibling(currentBranchId, delta) {
  const meta = navigatorBubbleMeta.value[currentBranchId]
  if (!meta) return
  const siblings = meta.siblings
  const cur = siblings.findIndex((s) => s.id === currentBranchId)
  if (cur < 0) return
  const next = (cur + delta + siblings.length) % siblings.length
  const tgt = siblings[next]
  if (tgt) await activateBranch(tgt.id)
}

function branchStatusLabel(status) {
  switch (status) {
    case 'running': return '运行中'
    case 'paused': return '已暂停'
    case 'completed': return '已完成'
    case 'failed': return '失败'
    default: return status || ''
  }
}

function doApprove(approved) {
  trackEvent('task.approval', { taskId, approved })
  liveStore.submitApproval(taskId, approved)
}

function onCheckpointSubmit(payload) {
  trackEvent('task.checkpoint.respond', {
    taskId,
    action: payload.action,
    has_prompt: Boolean(payload.user_prompt),
    selected_option: payload.selected_option || '',
  })
  liveStore.submitCheckpoint(taskId, payload)
}

async function doCancel() {
  if (cancelling.value) return
  cancelling.value = true
  try {
    await api.cancelTask(taskId)
    ElMessage.success('任务已取消')
    await liveStore.refreshTask(taskId)
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '取消失败')
  } finally {
    cancelling.value = false
  }
}

function goTasks() { router.push('/tasks') }
function goDetail() { router.push(`/tasks/${taskId}`) }
function goReport() { router.push(`/reports/${taskId}`) }

onMounted(async () => {
  loading.value = true
  try {
    await liveStore.refreshTask(taskId)
    await liveStore.attach(taskId)
    trackEvent('task.chat.open', { taskId })
  } finally {
    loading.value = false
    await nextTick()
    smoothScrollToBottom()
  }
})

onUnmounted(() => {
  liveStore.detach(taskId)
  if (scrollTimeout) clearTimeout(scrollTimeout)
  cancelAnimationFrame(scrollRafId)
})
</script>

<style scoped>
.task-chat-page {
  display: flex;
  flex-direction: column;
  /* 父级 (.main-content) 已经是 column flex 且 height = 100vh,
     这里用 flex:1 + min-height:0 占满 topbar 之外的剩余高度,
     避免之前 height:100vh 把 topbar 高度也算进来导致整页溢出。*/
  flex: 1;
  min-height: 0;
  background: var(--bg-base);
}

.chat-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 14px 28px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-elevated);
  flex-shrink: 0;
}
.header-left { display: flex; align-items: center; gap: 14px; }
.title-block h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 700;
  color: var(--text-primary);
  font-family: var(--font-mono);
}
.task-id {
  margin-top: 4px;
  display: inline-block;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1px 7px;
  color: var(--text-muted);
  font-size: 11px;
  font-family: var(--font-mono);
}
.header-right { display: flex; gap: 8px; align-items: center; }

.chat-main {
  flex: 1;
  min-height: 0;
  display: flex;
  align-items: stretch;
  overflow: hidden;
}
.chat-side {
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-right: 8px;
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: color-mix(in srgb, var(--text-primary) 22%, transparent) transparent;
}
.chat-side::-webkit-scrollbar { width: 8px; }
.chat-side::-webkit-scrollbar-thumb {
  background: color-mix(in srgb, var(--text-primary) 18%, transparent);
  border-radius: 4px;
}
.chat-rail {
  flex-shrink: 0;
}
.chat-branch-tree {
  flex-shrink: 0;
  width: 280px;
}
.chat-stream-wrap {
  flex: 1;
  min-width: 0;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 20px 28px 28px;
  position: relative;
  /* Firefox 滚动条 */
  scrollbar-width: thin;
  scrollbar-color: color-mix(in srgb, var(--text-primary) 22%, transparent) transparent;
}
/* WebKit 自定义滚动条,在 dark 主题下默认滚动条几乎不可见,做成 cursor 风格 */
.chat-stream-wrap::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}
.chat-stream-wrap::-webkit-scrollbar-track {
  background: transparent;
}
.chat-stream-wrap::-webkit-scrollbar-thumb {
  background: color-mix(in srgb, var(--text-primary) 18%, transparent);
  border: 2px solid transparent;
  background-clip: content-box;
  border-radius: 999px;
  transition: background 0.15s ease;
}
.chat-stream-wrap::-webkit-scrollbar-thumb:hover {
  background: color-mix(in srgb, var(--accent-blue) 55%, var(--text-primary) 30%);
  background-clip: content-box;
}
.chat-stream-wrap::-webkit-scrollbar-corner {
  background: transparent;
}
.bubble-stream {
  max-width: 1080px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.bubble-anchor {
  scroll-margin-top: 40px;
  border-radius: var(--radius-md);
  transition: background 0.4s ease, box-shadow 0.4s ease;
}
.bubble-flash {
  background: color-mix(in srgb, var(--accent-blue) 12%, transparent);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent-blue) 40%, transparent);
}

.thought-meta {
  font-size: 12px;
  color: var(--text-secondary);
  margin: 4px 0 0;
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
  margin: 6px 0 0;
}
.thought-plan ol { margin: 2px 0 0; padding-left: 20px; }
.thought-plan li { line-height: 1.6; }

.thought-expand { margin-top: 6px; font-size: 12px; }
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
  background: color-mix(in srgb, var(--bg-base) 80%, var(--accent-blue) 5%);
  border-radius: var(--radius-md);
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 280px;
  overflow-y: auto;
  font-family: var(--font-mono);
  scrollbar-width: thin;
  scrollbar-color: color-mix(in srgb, var(--text-primary) 22%, transparent) transparent;
}
.thought-full::-webkit-scrollbar { width: 8px; }
.thought-full::-webkit-scrollbar-track { background: transparent; }
.thought-full::-webkit-scrollbar-thumb {
  background: color-mix(in srgb, var(--text-primary) 18%, transparent);
  border: 2px solid transparent;
  background-clip: content-box;
  border-radius: 999px;
}

.checkpoint-slot { margin-top: 8px; }
.checkpoint-done {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-top: 6px;
  font-size: 12px;
  color: var(--text-muted);
}

.approval-slot { margin-top: 8px; }
.inline-approval {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  border-left: 3px solid color-mix(in srgb, var(--accent-yellow) 80%, var(--text-primary));
  background: color-mix(in srgb, var(--accent-yellow) 6%, var(--bg-elevated));
}
.inline-approval-text {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}
.inline-approval-actions { display: flex; gap: 8px; }

.payload-slot { margin-top: 8px; }

.llm-stream-bubble {
  align-self: stretch;
  max-width: min(78%, 720px);
  margin-left: 40px;
  border: 1px solid var(--accent-purple, #a371f7);
  border-left: 3px solid var(--accent-purple, #a371f7);
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--bg-base) 92%, var(--accent-purple, #a371f7) 8%);
  padding: 10px 12px;
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
}
.fade-enter-active, .fade-leave-active {
  transition: opacity 0.25s ease, transform 0.25s ease;
}
.fade-enter-from, .fade-leave-to {
  opacity: 0;
  transform: translateX(-50%) translateY(8px);
}

.chat-footer {
  flex-shrink: 0;
  padding: 14px 28px 18px;
  border-top: 1px solid var(--border);
  background: var(--bg-elevated);
}
.composer {
  max-width: 1080px;
  margin: 0 auto;
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
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
  padding-bottom: 6px;
  border-bottom: 1px dashed var(--border);
}
.composer-tip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text-secondary);
}
.composer-shortcut {
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--text-primary) 6%, transparent);
}
.input-bar {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.prompt-input :deep(.el-textarea__inner) {
  background: var(--bg-base);
  border-color: var(--border);
  border-radius: var(--radius-md);
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
.hint-warn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: var(--accent-yellow);
}
.hint-info {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: var(--text-secondary);
}
.spin {
  animation: rotate 1.4s linear infinite;
}
@keyframes rotate {
  from { transform: rotate(0); }
  to { transform: rotate(360deg); }
}

/* ── 分支(branch tree) UI ─────────────────────────────── */

.branch-navigator {
  margin-top: 8px;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  border-radius: 16px;
  background: color-mix(in srgb, var(--accent-blue, #58a6ff) 10%, var(--bg-base));
  border: 1px dashed color-mix(in srgb, var(--accent-blue, #58a6ff) 40%, transparent);
  font-size: 11px;
  font-family: var(--font-mono);
}
.nav-btn {
  width: 22px;
  height: 22px;
  border-radius: 11px;
  border: 1px solid var(--border);
  background: var(--bg-elevated);
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 14px;
  line-height: 1;
}
.nav-btn[disabled] { cursor: not-allowed; opacity: 0.4; }
.nav-counter {
  font-weight: 600;
  color: var(--accent-blue, #58a6ff);
  letter-spacing: 0.5px;
  min-width: 44px;
  text-align: center;
}
.nav-active {
  font-weight: 600;
  font-size: 11px;
  color: var(--accent-green, #3fb950);
  padding: 2px 8px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--accent-green, #3fb950) 12%, transparent);
}
.nav-activate {
  font-size: 11px;
  border: 1px solid var(--accent-blue, #58a6ff);
  background: transparent;
  color: var(--accent-blue, #58a6ff);
  padding: 2px 10px;
  border-radius: 999px;
  cursor: pointer;
}
.nav-activate:hover {
  background: color-mix(in srgb, var(--accent-blue, #58a6ff) 12%, transparent);
}

.branch-status-band {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  padding: 6px 10px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--accent-blue, #58a6ff) 8%, var(--bg-base));
  border: 1px solid color-mix(in srgb, var(--accent-blue, #58a6ff) 30%, transparent);
  font-size: 12px;
  color: var(--text-secondary);
}
.band-icon { color: var(--accent-blue, #58a6ff); }
.band-text strong { color: var(--text-primary); margin-left: 4px; }
.band-status { font-weight: 600; }
.band-status.status-running  { color: var(--accent-green, #3fb950); }
.band-status.status-paused   { color: var(--accent-yellow, #d29922); }
.band-status.status-completed { color: var(--accent-blue, #58a6ff); }
.band-status.status-failed   { color: var(--accent-red, #f85149); }
.band-count { color: var(--text-muted); margin-left: 4px; }
.band-cap {
  margin-left: auto;
  color: var(--accent-yellow, #d29922);
  font-weight: 600;
}

@keyframes composerFlash {
  0%   { box-shadow: 0 0 0 0 color-mix(in srgb, var(--accent-blue, #58a6ff) 60%, transparent); }
  60%  { box-shadow: 0 0 0 8px color-mix(in srgb, var(--accent-blue, #58a6ff) 0%, transparent); }
  100% { box-shadow: 0 6px 24px color-mix(in srgb, #000000 24%, transparent); }
}
.composer-flash {
  animation: composerFlash 1.6s ease-out;
}
</style>
