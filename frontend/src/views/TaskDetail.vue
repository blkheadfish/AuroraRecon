<template>
  <div class="page-wrap" v-loading="loading" element-loading-background="rgba(13,17,23,0.9)">
    <div class="detail-header">
      <el-button link @click="router.push('/tasks')" class="back-btn">
        <el-icon><ArrowLeft /></el-icon>
        返回列表
      </el-button>

      <div class="title-line">
        <div>
          <h2 class="target-title">{{ task?.target || '...' }}</h2>
          <code class="task-id">{{ taskId }}</code>
        </div>
        <div class="title-actions" v-if="task">
          <StatusBadge :status="task.status" size="large" />
          <el-button plain @click="router.push(`/tasks/${taskId}/decision`)">决策视图</el-button>
          <el-button v-if="task.report_path" type="success" plain @click="router.push(`/reports/${taskId}`)">
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
      </div>
    </div>

    <div class="summary-grid" v-if="task">
      <el-card class="summary-card">
        <div class="summary-label">当前阶段</div>
        <div class="summary-value">{{ phaseText(task.current_phase) }}</div>
      </el-card>
      <el-card class="summary-card">
        <div class="summary-label">下一步动作</div>
        <div class="summary-value">{{ nextAction }}</div>
      </el-card>
      <el-card class="summary-card">
        <div class="summary-label">风险提示</div>
        <div class="summary-value risk">{{ riskHint }}</div>
      </el-card>
      <el-card class="summary-card">
        <div class="summary-label">关键证据</div>
        <div class="summary-value evidence">{{ keyEvidence }}</div>
      </el-card>
    </div>

    <TaskProgressMermaid
      v-if="task"
      :current-phase="task.current_phase"
      :status="task.status"
      :findings-count="findings.length"
      :exploitable-count="exploitableCount"
      :got-shell="task.got_shell || false"
      :needs-approval="needsApproval"
      :chain-visited="task.chain_visited || []"
      :secondary-elided="task.secondary_elided || false"
      :foothold-status="task.foothold_status || 'none'"
      :privilege-level="task.privilege_level || ''"
      :privesc-attempt-count="task.privesc_attempt_count || 0"
      class="progress-mermaid"
    />

    <ApprovalComposer
      :needs-approval="showApprovalActions"
      :loading="approving"
      @approve="doApprove(true)"
      @reject="doApprove(false)"
      class="approval-composer"
    />

    <el-card class="main-card">
      <el-tabs v-model="activeTab" class="detail-tabs">
        <el-tab-pane name="decision">
          <template #label>
            <span class="tab-label">
              <el-icon><ChatDotRound /></el-icon>
              决策摘要
            </span>
          </template>
          <div class="decision-summary-header">
            <span class="summary-hint">仅显示关键决策节点，详细工具调用请查看完整视图</span>
            <el-button type="primary" link @click="router.push(`/tasks/${taskId}/decision`)">
              查看完整决策 →
            </el-button>
          </div>
          <DecisionTimeline :items="decisionItems" />
        </el-tab-pane>

        <el-tab-pane name="findings">
          <template #label>
            <span class="tab-label">
              <el-icon><Warning /></el-icon>
              漏洞发现
              <el-badge v-if="findings.length" :value="findings.length" class="tab-badge" />
            </span>
          </template>
          <FindingsPanel :findings="findings" />
        </el-tab-pane>

        <el-tab-pane label="实时日志" name="logs">
          <LogTerminal :logs="logs" :running="isRunning" />
        </el-tab-pane>

        <el-tab-pane label="侦察数据" name="recon">
          <ReconPanel :task="task" />
        </el-tab-pane>

        <el-tab-pane label="原始数据" name="raw">
          <JsonViewer :data="task" title="任务完整状态" />
        </el-tab-pane>

        <el-tab-pane label="报告" name="report" v-if="task?.report_path">
          <ReportPanel :task-id="taskId" />
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { useTaskListStore } from '@/stores/taskList'
import { useTaskLiveStore } from '@/stores/taskLive'
import { trackEvent } from '@/metrics/tracker'
import StatusBadge from '@/components/StatusBadge.vue'
import TaskProgressMermaid from '@/components/TaskProgressMermaid.vue'
import LogTerminal from '@/components/LogTerminal.vue'
import FindingsPanel from '@/components/FindingsPanel.vue'
import ReconPanel from '@/components/ReconPanel.vue'
import JsonViewer from '@/components/JsonViewer.vue'
import ReportPanel from '@/components/ReportPanel.vue'
import DecisionTimeline from '@/components/DecisionTimeline.vue'
import ApprovalComposer from '@/components/ApprovalComposer.vue'

const route = useRoute()
const router = useRouter()
const taskId = String(route.params.id)
const listStore = useTaskListStore()
const liveStore = useTaskLiveStore()

const loading = ref(true)
const activeTab = ref('decision')
const cancelling = ref(false)
const pollTimer = ref(null)

const state = computed(() => liveStore.getLiveState(taskId))
const task = computed(() => state.value.task || listStore.getTaskById(taskId))
const logs = computed(() => state.value.logs || [])
const findings = computed(() => task.value?.findings || [])
const isRunning = computed(() => ['pending', 'running'].includes(task.value?.status || ''))
const needsApproval = computed(() => task.value?.current_phase === 'awaiting_approval')
const approvalState = computed(() => state.value.approvalState)
const approving = computed(() => approvalState.value === 'submitting')
const showApprovalActions = computed(() => needsApproval.value && approvalState.value === 'idle')
const exploitableCount = computed(() => findings.value.filter((item) => item.exploitable).length)

const nextAction = computed(() => {
  if (!task.value) return '-'
  if (task.value.status === 'completed') return '审阅报告并发布'
  if (needsApproval.value) return '确认利用授权范围并执行审批'
  if (task.value.current_phase === 'exploit_decision') return '等待模型生成 PoC/Payload'
  if (task.value.current_phase === 'surface_enum') return '合并 Web 攻击面与目录线索'
  if (task.value.current_phase === 'foothold_attempt') return '战术层尝试建立立足点（CVE/Skill/ReAct）'
  if (task.value.current_phase === 'secondary_attack') return '二次利用：结合对话提示重试失败项'
  if (task.value.current_phase === 'post_foothold_enum') return '立足后枚举：身份、内核、sudo/SUID 线索'
  if (task.value.current_phase === 'privesc_attempt') return '提权验证与假设排序'
  if (task.value.current_phase === 'objective_collect') return '检索 flag/proof 与攻链总结'
  return '持续观察实时状态'
})

const riskHint = computed(() => {
  if (needsApproval.value) return '高风险动作待确认'
  if (exploitableCount.value > 0) return `${exploitableCount.value} 个漏洞可利用`
  return '当前暂无高危利用动作'
})

const keyEvidence = computed(() => {
  const withEvidence = findings.value.find((item) => item.evidence)
  if (!withEvidence) return '等待更多利用证据'
  const text = withEvidence.evidence || ''
  return text.slice(0, 48) + (text.length > 48 ? '...' : '')
})

const decisionItems = computed(() => {
  const events = []
  const phase = task.value?.current_phase || 'init'
  events.push({
    id: 'phase',
    time: new Date().toLocaleTimeString(),
    tone: needsApproval.value ? 'warning' : 'primary',
    title: `阶段更新：${phaseText(phase)}`,
    desc: needsApproval.value ? '系统检测到可利用路径，等待人工审批。' : '系统正在执行当前阶段决策。',
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
      payloads: splitEvidencePayloads(evidenceFinding.evidence),
    })
  }

  const liveDecisionEvents = Array.isArray(state.value?.decisionEvents) ? state.value.decisionEvents : []
  const storedDecisionEvents = Array.isArray(task.value?.decision_events) ? task.value.decision_events : []
  const structuredEvents = liveDecisionEvents.length ? liveDecisionEvents : storedDecisionEvents
  const SKIP_ACTIONS = new Set([
    'command_exec', 'tool_start', 'tool_result',
    'tool_coverage_report', 'tool_executed', 'tool_skipped',
  ])

  structuredEvents.slice(-120).forEach((entry, idx) => {
    if (SKIP_ACTIONS.has(entry.action)) return

    const time = entry.timestamp || new Date().toLocaleTimeString()
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
      })
      return
    }
    if (entry.action === 'thought') {
      const roundLabel = entry.round ? `第 ${entry.round} 轮` : ''
      const vulnLabel = entry.vuln_name ? ` · ${entry.vuln_name}` : ''
      events.push({
        id: entry.id || `thought-${idx}`,
        time,
        tone: 'primary',
        title: `AI 推理${roundLabel ? ' · ' + roundLabel : ''}${vulnLabel}`,
        desc: (entry.message || entry.thinking || entry.raw || '').slice(0, 200),
        thinking: entry.thinking || entry.message || '',
        purpose: entry.purpose || '',
        expected: entry.expected || '',
        plan: entry.plan || [],
        round: entry.round,
        expandable: (entry.thinking || '').length > 200,
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
      const isPhase = /开始|完成|端口|漏洞|侦察|扫描|利用|后渗透|报告|PHP|phuip/i.test(msg)
      if (!isPhase) return
      events.push({
        id: `log-${idx}`,
        time,
        tone: 'info',
        title: '阶段进展',
        desc: msg,
      })
    }
  })

  return events
})

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
  if (/^(HTTP\/\d\.\d\s+\d{3}|GET\s+\/|POST\s+\/|PUT\s+\/|DELETE\s+\/|PATCH\s+\/|HEAD\s+\/|OPTIONS\s+\/)/im.test(raw)) {
    return 'http'
  }
  if (/^\s*<\?xml|^\s*<\/?[a-zA-Z][\w:-]*[\s>]/.test(raw)) return 'xml'
  return 'auto'
}

function splitEvidencePayloads(evidence) {
  const raw = String(evidence || '').trim()
  if (!raw) return []
  const segments = []
  const lines = raw.split(/\r?\n/)
  const sectionHeader = /^\s*(?:#{1,6}\s*|[-*]\s*)?(command|cmd|poc|payload|stdout|stderr|response|output|result|命令|输出|响应|错误|回显)\s*[:：]?\s*$/i
  const inlineHeader = /^\s*(command|cmd|poc|payload|stdout|stderr|response|output|result|命令|输出|响应|错误|回显)\s*[:：]\s*(.*)$/i

  let currentType = ''
  let buffer = []

  const flush = () => {
    const content = buffer.join('\n').trim()
    if (!content) {
      buffer = []
      return
    }
    if (/(command|cmd|poc|payload|命令)/i.test(currentType)) {
      segments.push({
        title: 'PoC / Command',
        language: inferPayloadLang(content),
        code: content,
      })
    } else if (/(stderr|error|错误)/i.test(currentType)) {
      segments.push({
        title: 'Error Output',
        language: inferOutputLang(content),
        code: content,
      })
    } else if (/(stdout|response|output|result|输出|响应|回显)/i.test(currentType)) {
      segments.push({
        title: 'Response / Output',
        language: inferOutputLang(content),
        code: content,
      })
    }
    buffer = []
  }

  lines.forEach((line) => {
    const inline = line.match(inlineHeader)
    if (inline) {
      flush()
      currentType = String(inline[1] || '')
      const tail = String(inline[2] || '').trim()
      if (tail) buffer.push(tail)
      return
    }
    const section = line.match(sectionHeader)
    if (section) {
      flush()
      currentType = String(section[1] || '')
      return
    }
    buffer.push(line)
  })
  flush()

  if (!segments.length) {
    segments.push({
      title: 'PoC / Payload',
      language: inferPayloadLang(raw),
      code: raw,
    })
  }
  return segments
}

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

function doApprove(approved) {
  trackEvent('task.approval', { taskId, approved })
  liveStore.submitApproval(taskId, approved)
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

async function pollTask() {
  if (!isRunning.value) return
  try {
    await liveStore.refreshTask(taskId)
    const logResp = await api.getLogs(taskId)
    const stateRef = liveStore.getLiveState(taskId)
    if (logResp.logs?.length) {
      stateRef.logs = logResp.logs
    }
  } catch {
    // Ignore polling errors.
  }
}

function startPolling() {
  stopPolling()
  pollTimer.value = window.setInterval(pollTask, 3000)
}

function stopPolling() {
  if (pollTimer.value) {
    window.clearInterval(pollTimer.value)
    pollTimer.value = null
  }
}

onMounted(async () => {
  loading.value = true
  try {
    await Promise.all([listStore.fetchTasks(), liveStore.refreshTask(taskId)])
    await liveStore.attach(taskId)
    startPolling()
    trackEvent('task.detail.open', { taskId })
  } finally {
    loading.value = false
  }
})

onUnmounted(() => {
  stopPolling()
  liveStore.detach(taskId)
})
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.detail-header { margin-bottom: 14px; }
.back-btn { color: var(--text-secondary) !important; margin-bottom: 8px; }
.title-line { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.target-title { color: var(--text-primary); font-size: 22px; font-weight: 700; font-family: var(--font-mono); }
.task-id { margin-top: 6px; display: inline-block; border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 2px 8px; color: var(--text-muted); font-size: 11px; font-family: var(--font-mono); }
.title-actions { display: flex; gap: 8px; align-items: center; }

.summary-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 12px; }
.summary-card :deep(.el-card__body) { padding: 12px !important; }
.summary-label { color: var(--text-muted); font-size: 12px; }
.summary-value { margin-top: 6px; font-size: 14px; color: var(--text-primary); font-weight: 600; }
.summary-value.risk { color: var(--accent-yellow); }
.summary-value.evidence { font-family: var(--font-mono); font-size: 12px; }

.progress-mermaid { margin-bottom: 12px; }
.approval-composer { margin-bottom: 12px; }
.main-card { border-radius: var(--radius-lg) !important; }
.tab-label { display: inline-flex; align-items: center; gap: 5px; }
.tab-badge { margin-left: 4px; }

.decision-summary-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 12px;
  margin-bottom: 8px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  font-size: 12px;
}
.summary-hint {
  color: var(--text-muted);
}
</style>
