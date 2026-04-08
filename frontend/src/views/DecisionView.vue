<template>
  <div class="decision-page" v-loading="loading" element-loading-background="rgba(13,17,23,0.9)">
    <header class="decision-header">
      <el-button link @click="router.push(`/tasks/${taskId}`)" class="back-btn">
        <el-icon><ArrowLeft /></el-icon>
        返回任务详情
      </el-button>
      <div class="header-title-row">
        <div>
          <h2 class="target-title">{{ task?.target || '...' }}</h2>
          <code class="task-id">{{ taskId }}</code>
        </div>
        <StatusBadge v-if="task" :status="task.status" size="large" />
      </div>
    </header>

    <section v-if="attackNextSteps.length" class="chain-hints">
      <div class="chain-hints-title">攻链建议（下一步）</div>
      <ul class="chain-hints-list">
        <li v-for="(s, i) in attackNextSteps" :key="i">
          <span class="ch-stage">{{ s.stage || '—' }}</span>
          {{ s.action || '' }}
        </li>
      </ul>
    </section>

    <section class="timeline-section">
      <DecisionTimeline :items="decisionItems">
        <template #card="{ item }">
          <div v-if="item.action === 'approval_required' && !approvalDone" class="approval-card-slot">
            <ApprovalComposer
              :needs-approval="needsApproval"
              :loading="approving"
              compact
              @approve="doApprove(true)"
              @reject="doApprove(false)"
            />
          </div>
          <div v-else-if="item.action === 'approval_required' && approvalDone" class="approval-card approval-done">
            <p class="approval-msg">审批已完成</p>
          </div>
        </template>
      </DecisionTimeline>
    </section>

    <footer class="chat-footer">
      <el-input
        v-model="chatInput"
        placeholder="输入指令或问题，影响代理决策..."
        :disabled="sending"
        class="chat-input"
        @keyup.enter="sendMessage"
      >
        <template #append>
          <el-button type="primary" :loading="sending" @click="sendMessage">发送</el-button>
        </template>
      </el-input>
    </footer>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { useTaskListStore } from '@/stores/taskList'
import { useTaskLiveStore } from '@/stores/taskLive'
import DecisionTimeline from '@/components/DecisionTimeline.vue'
import ApprovalComposer from '@/components/ApprovalComposer.vue'
import StatusBadge from '@/components/StatusBadge.vue'

const route = useRoute()
const router = useRouter()
const taskId = String(route.params.id)
const listStore = useTaskListStore()
const liveStore = useTaskLiveStore()

const loading = ref(true)
const chatInput = ref('')
const sending = ref(false)

const approvalState = computed(() => liveStore.getLiveState(taskId).approvalState)
const approvalDone = computed(() => approvalState.value === 'submitted')
const approving = computed(() => approvalState.value === 'submitting')

function doApprove(approved) {
  liveStore.submitApproval(taskId, approved)
}

async function sendMessage() {
  const text = chatInput.value.trim()
  if (!text || sending.value) return
  sending.value = true
  try {
    await api.sendChat(taskId, text)
    chatInput.value = ''
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || '发送失败')
  } finally {
    sending.value = false
  }
}

const state = computed(() => liveStore.getLiveState(taskId))
const task = computed(() => state.value.task || listStore.getTaskById(taskId))
const logs = computed(() => state.value.logs || [])
const findings = computed(() => task.value?.findings || [])
const needsApproval = computed(() => task.value?.current_phase === 'awaiting_approval')
const attackNextSteps = computed(() => task.value?.attack_next_steps || [])

function phaseText(phase) {
  return {
    init: '初始化',
    recon: '信息侦察',
    vuln_scan: '漏洞扫描',
    surface_enum: '表面枚举',
    exploit_decision: '利用决策',
    awaiting_approval: '等待审批',
    foothold_attempt: '立足点尝试',
    exploit: '漏洞利用',
    secondary_attack: '二次利用',
    post_foothold_enum: '立足后枚举',
    privesc_attempt: '提权尝试',
    objective_collect: '目标收集',
    post_exploit: '后渗透',
    report: '报告生成',
  }[phase] || phase
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
  const runtimeCommand = String(meta?.runtimeCommand || '').trim()
  const outputMeta = {
    truncated: Boolean(meta?.truncated),
    totalLen: Number(meta?.totalLen || 0),
  }
  const blocks = [{
    title: 'Command',
    language: inferPayloadLang(command || ''),
    code: command || '(empty command)',
  }]
  if (stdout) {
    blocks.push({ title: 'Stdout', language: inferOutputLang(stdout), code: stdout, ...outputMeta })
  }
  if (stderr) {
    blocks.push({ title: 'Stderr', language: inferOutputLang(stderr), code: stderr, ...outputMeta })
  }
  if (!stdout && !stderr) {
    blocks.push({ title: 'Output', language: 'text', code: '(empty)', ...outputMeta })
  }
  return blocks
}

const decisionItems = computed(() => {
  const events = []
  const phase = task.value?.current_phase || 'init'

  events.push({
    id: 'phase',
    time: new Date().toLocaleTimeString(),
    tone: needsApproval.value ? 'warning' : 'primary',
    title: `阶段更新：${phaseText(phase)}`,
    desc: needsApproval.value
      ? '系统检测到可利用路径，等待人工审批。'
      : '系统正在执行当前阶段决策。',
  })

  if (task.value?.extra_hint || task.value?.user_prompt || task.value?.workflow_mode) {
    events.push({
      id: 'task-pref',
      time: new Date().toLocaleTimeString(),
      tone: 'info',
      title: '任务偏好与策略',
      desc: [
        `workflow_mode: ${task.value.workflow_mode || 'standard'}`,
        `extra_hint: ${task.value.extra_hint || '无'}`,
        `user_prompt: ${task.value.user_prompt || '无'}`,
      ].join('\n'),
    })
  }

  const evidenceFinding = findings.value.find((item) => item.evidence)
  if (evidenceFinding?.evidence) {
    events.push({
      id: `finding-${evidenceFinding.vuln_id}`,
      time: new Date().toLocaleTimeString(),
      tone: evidenceFinding.exploitable ? 'danger' : 'info',
      title: `发现：${evidenceFinding.name}`,
      desc: evidenceFinding.description || '命中漏洞证据。',
    })
  }

  const liveDecisionEvents = Array.isArray(state.value?.decisionEvents) ? state.value.decisionEvents : []
  const storedDecisionEvents = Array.isArray(task.value?.decision_events) ? task.value.decision_events : []
  const structuredEvents = liveDecisionEvents.length ? liveDecisionEvents : storedDecisionEvents

  structuredEvents.slice(-120).forEach((entry, idx) => {
    const time = entry.timestamp || new Date().toLocaleTimeString()

    if (entry.action === 'tool_start') {
      events.push({
        id: `tool-start-${idx}`,
        time,
        tone: 'primary',
        title: `工具调用 · ${entry.tool || 'unknown'}`,
        desc: `阶段 ${entry.phase || '-'}\n${entry.message || ''}`.trim(),
      })
      return
    }

    if (entry.action === 'tool_result') {
      const elapsedText = entry.elapsed_ms ? `${entry.elapsed_ms}ms` : '-'
      const exitText = entry.exit_code ?? '-'
      events.push({
        id: `tool-res-${idx}`,
        time,
        tone: Number(exitText) === 0 ? 'success' : 'danger',
        title: `调用结果 · ${entry.tool || 'unknown'}`,
        desc: `exit=${exitText} ｜ elapsed=${elapsedText}\n${entry.message || ''}`.trim(),
      })
      return
    }

    if (entry.action === 'command_exec') {
      const command = entry.command || '(empty command)'
      const runtimeCommand = entry.runtime_command || ''
      const stdout = entry.stdout || ''
      const stderr = entry.stderr || ''
      const purposeText = entry.purpose ? ` ｜ purpose=${entry.purpose}` : ''
      const roundText = entry.round !== undefined && entry.round !== null ? ` ｜ round=${entry.round}` : ''
      const phaseTextInfo = entry.phase ? ` ｜ phase=${entry.phase}` : ''
      const titleText = entry.poc_or_vuln
        ? `命令执行 · ${entry.poc_or_vuln}`
        : `命令执行 · ${entry.tool || 'shell'}`
      events.push({
        id: `cmd-${idx}`,
        time,
        tone: (entry.exit_code ?? -1) === 0 ? 'success' : 'danger',
        title: titleText,
        desc: `exit=${entry.exit_code ?? '-'} ｜ elapsed=${entry.elapsed_ms ?? '-'}ms${phaseTextInfo}${roundText}${purposeText}`,
        payloads: buildExecPayloads(command, stdout, stderr, {
          runtimeCommand,
          truncated: Boolean(entry.truncated),
          totalLen: Number(entry.total_len || 0),
        }),
      })
      return
    }

    if (entry.action === 'approval') {
      events.push({
        id: `approve-${idx}`,
        time,
        tone: 'warning',
        title: '审批节点',
        desc: entry.message || entry.raw || '',
      })
      return
    }

    if (entry.action === 'approval_required') {
      events.push({
        id: entry.id || `approval-req-${idx}`,
        time,
        tone: 'warning',
        title: '审批请求',
        desc: entry.message || '系统检测到可利用路径，等待人工审批。',
        action: 'approval_required',
        exploitable_count: entry.exploitable_count,
        findings_count: entry.findings_count,
      })
      return
    }

    if (entry.action === 'thought') {
      const roundLabel = entry.round ? `第 ${entry.round} 轮` : ''
      const vulnLabel = entry.vuln_name ? ` · ${entry.vuln_name}` : ''
      const purposeLine = entry.purpose ? `\n🎯 目标: ${entry.purpose}` : ''
      const expectedLine = entry.expected ? `\n📋 预期: ${entry.expected}` : ''
      const planLines = Array.isArray(entry.plan) && entry.plan.length
        ? '\n📝 计划:\n' + entry.plan.map((s, i) => `  ${i + 1}. ${s}`).join('\n')
        : ''
      events.push({
        id: entry.id || `thought-${idx}`,
        time,
        tone: 'primary',
        title: `AI 推理${roundLabel ? ' · ' + roundLabel : ''}${vulnLabel}`,
        desc: (entry.message || entry.thinking || '').slice(0, 200),
        thinking: entry.thinking || entry.message || '',
        purpose: entry.purpose || '',
        expected: entry.expected || '',
        plan: entry.plan || [],
        round: entry.round,
        expandable: (entry.thinking || '').length > 200,
        fullDesc: (entry.thinking || '') + purposeLine + expectedLine + planLines,
        action: 'thought',
      })
      return
    }

    if (entry.action === 'user_chat') {
      events.push({
        id: `user-chat-${idx}`,
        time,
        tone: 'warning',
        title: '用户指令',
        desc: entry.message || '',
      })
      return
    }

    if (entry.action === 'agent_reply') {
      events.push({
        id: `agent-reply-${idx}`,
        time,
        tone: 'success',
        title: 'AI 回复',
        desc: entry.message || '',
      })
      return
    }

    if (entry.action === 'log') {
      const msg = entry.message || entry.raw || ''
      if (!msg) return
      const isLlm = /LLM|分析|决策|策略|模型|推理|建议|主动发现|KB|知识库/i.test(msg)
      events.push({
        id: `log-${idx}`,
        time,
        tone: isLlm ? 'primary' : 'info',
        title: isLlm ? 'AI 决策' : '日志',
        desc: msg,
      })
    }
  })

  const hasCommandExec = structuredEvents.some((e) => e?.action === 'command_exec')
  const exploitResults = Array.isArray(task.value?.exploit_results) ? task.value.exploit_results : []
  if (!hasCommandExec) {
    exploitResults.forEach((result, ridx) => {
      const records = result.command_records || result.command_results || []
      records.forEach((record, cidx) => {
        const command = record.command || ''
        events.push({
          id: `exploit-${ridx}-${cidx}`,
          time: new Date().toLocaleTimeString(),
          tone: record.exit_code === 0 ? 'success' : 'danger',
          title: `命令执行 · ${result.vuln_id || 'unknown vuln'}`,
          desc: `purpose=${record.purpose || '-'} ｜ exit=${record.exit_code ?? '-'} ｜ elapsed=${record.elapsed ?? '-'}s`,
          payloads: buildExecPayloads(command, record.stdout || '', record.stderr || '', {
            runtimeCommand: record.runtime_command || '',
            truncated: Boolean(record.truncated),
            totalLen: Number(record.total_len || 0),
          }),
        })
      })
    })
  }

  if (!structuredEvents.length && !hasCommandExec) {
    const payloadLogs = logs.value
      .filter((line) => /payload|poc|webshell|cmd|curl|python|bash|执行|完成|exit=/i.test(line))
      .slice(-12)
    payloadLogs.forEach((line, idx) => {
      events.push({
        id: `fallback-log-${idx}`,
        time: new Date().toLocaleTimeString(),
        tone: /failed|error|denied|401|403|❌/i.test(line) ? 'danger' : 'success',
        title: '执行轨迹',
        desc: line,
        payloads: [{ title: '执行命令片段', language: inferPayloadLang(line), code: line }],
      })
    })
  }

  return events
})

onMounted(async () => {
  loading.value = true
  try {
    await liveStore.refreshTask(taskId)
    await liveStore.attach(taskId)
  } finally {
    loading.value = false
  }
})

onUnmounted(() => {
  liveStore.detach(taskId)
})
</script>

<style scoped>
.decision-page {
  display: flex;
  flex-direction: column;
  height: 100vh;
  padding: 0;
  background: var(--bg-base);
}

.decision-header {
  flex-shrink: 0;
  padding: 16px 28px 12px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-elevated);
}

.back-btn {
  color: var(--text-secondary) !important;
  margin-bottom: 6px;
}

.header-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.target-title {
  color: var(--text-primary);
  font-size: 20px;
  font-weight: 700;
  font-family: var(--font-mono);
  margin: 0;
}

.task-id {
  margin-top: 4px;
  display: inline-block;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 2px 8px;
  color: var(--text-muted);
  font-size: 11px;
  font-family: var(--font-mono);
}

.chain-hints {
  flex-shrink: 0;
  margin: 0 28px 0;
  padding: 10px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-elevated);
  font-size: 12px;
  color: var(--text-secondary);
}

.chain-hints-title {
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 6px;
}

.chain-hints-list {
  margin: 0;
  padding-left: 18px;
}

.ch-stage {
  display: inline-block;
  min-width: 4.5em;
  margin-right: 6px;
  font-family: var(--font-mono);
  color: var(--accent-green);
}

.timeline-section {
  flex: 1;
  min-height: 0;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  padding: 16px 28px;
}

.chat-footer {
  flex-shrink: 0;
  padding: 12px 28px;
  border-top: 1px solid var(--border);
  background: var(--bg-elevated);
}

.chat-input {
  width: 100%;
}

.chat-input :deep(.el-input__wrapper) {
  background: var(--bg-base);
  border-color: var(--border);
  border-radius: var(--radius-lg);
}

.chat-input :deep(.el-input-group__append) {
  background: transparent;
  border-color: var(--border);
  border-radius: 0 var(--radius-lg) var(--radius-lg) 0;
}

.chat-input :deep(.el-input-group__append .el-button) {
  color: var(--accent-green);
}

.approval-card-slot {
  margin-top: 8px;
}
.approval-card {
  margin-top: 8px;
  padding: 12px 14px;
  border: 1px solid color-mix(in srgb, var(--accent-yellow) 50%, var(--border));
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--accent-yellow) 8%, var(--bg-elevated));
}
.approval-card.approval-done {
  opacity: 0.6;
}
.approval-msg {
  margin: 0;
  font-size: 13px;
  color: var(--text-primary);
  line-height: 1.5;
}
</style>
