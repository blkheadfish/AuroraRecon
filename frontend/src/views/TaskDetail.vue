<template>
  <div class="page-wrap" v-loading="loading" element-loading-background="rgba(13,17,23,0.9)">
    <div class="detail-header">
      <el-breadcrumb separator="/" class="page-breadcrumb">
        <el-breadcrumb-item :to="{ path: '/dashboard' }">首页</el-breadcrumb-item>
        <el-breadcrumb-item :to="{ path: '/tasks' }">任务列表</el-breadcrumb-item>
        <el-breadcrumb-item>{{ task?.target || '任务详情' }}</el-breadcrumb-item>
      </el-breadcrumb>

      <div class="title-line">
        <div>
          <h2 class="target-title">{{ task?.target || '...' }}</h2>
          <code class="task-id">{{ taskId }}</code>
        </div>
        <div class="title-actions" v-if="task">
          <StatusBadge :status="task.status" size="large" />
          <span v-if="isRunning && elapsedSeconds > 0" class="elapsed-pill" title="本轮已运行时长">
            <el-icon><Clock /></el-icon>
            已运行 {{ elapsedText }}
          </span>
          <el-button plain @click="router.push(`/tasks/${taskId}/chat`)">
            <el-icon><ChatDotRound /></el-icon>对话视图
          </el-button>
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

    <div
      v-if="pendingCheckpoint || showApprovalActions"
      class="pause-banner"
      role="status"
    >
      <el-icon class="pause-icon"><Warning /></el-icon>
      <div class="pause-text">
        <strong>Plan 模式 · 已暂停</strong>
        <span>Agent 给出了下一步建议,请在下方决策摘要中确认是否继续。</span>
      </div>
      <el-button
        type="primary"
        size="small"
        plain
        @click="router.push(`/tasks/${taskId}/chat`)"
      >查看建议</el-button>
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

    <PhaseTree
      v-if="task"
      :events="state.decisionEvents || task.decision_events || []"
      :current="task.current_phase || ''"
      :status="task.status || ''"
      class="progress-tree"
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
            <el-button type="primary" link @click="router.push(`/tasks/${taskId}/chat`)">
              查看完整决策 →
            </el-button>
          </div>
          <DecisionTimeline :items="decisionItems" :llm-streams="llmStreams">
            <template #card="{ item }">
              <DecisionCheckpointCard
                v-if="item.action === 'checkpoint_request' && pendingCheckpoint && pendingCheckpoint.checkpoint_id === item.id"
                :checkpoint="pendingCheckpoint"
                :loading="checkpointSubmitting"
                inline
                class="inline-checkpoint"
                @submit="onCheckpointSubmit"
              />
              <div
                v-else-if="item.action === 'checkpoint_request'"
                class="inline-checkpoint-done"
              >
                <el-icon><Check /></el-icon>
                决策点已处理
              </div>
              <div
                v-else-if="item.action === 'approval_required' && showApprovalActions"
                class="inline-approval"
              >
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
              <div
                v-else-if="item.action === 'approval_required'"
                class="inline-checkpoint-done"
              >
                <el-icon><Check /></el-icon>
                审批已处理
              </div>
            </template>
          </DecisionTimeline>
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

        <el-tab-pane name="attack_graph" lazy>
          <template #label>
            <span class="tab-label">
              <el-icon><Share /></el-icon>
              攻击图
              <el-badge v-if="attackGraphNodeCount" :value="attackGraphNodeCount" class="tab-badge" />
            </span>
          </template>
          <AttackGraphView :graph="attackGraph" :task="task" @refresh="onAttackGraphRefresh" />
        </el-tab-pane>

        <!-- lazy: 这些 Tab 都是重组件,首屏不挂载,减少首次渲染时间和内存。 -->
        <el-tab-pane label="实时日志" name="logs" lazy>
          <LogTerminal :logs="logs" :running="isRunning" :tool-streams="toolStreams" />
        </el-tab-pane>

        <el-tab-pane label="侦察数据" name="recon" lazy>
          <ReconPanel :task="task" />
        </el-tab-pane>

        <el-tab-pane v-if="priorIntel" name="prior" lazy>
          <template #label>
            <span class="tab-label">
              <el-icon><Clock /></el-icon>
              历史先验
              <el-badge v-if="priorIntel.source_task_count" :value="priorIntel.source_task_count" class="tab-badge" />
            </span>
          </template>
          <PriorIntelPanel :intel="priorIntel" />
        </el-tab-pane>

        <el-tab-pane label="原始数据" name="raw" lazy>
          <div v-if="rawLoading" class="raw-loading">正在加载完整任务状态...</div>
          <JsonViewer
            v-else-if="rawTask"
            :data="rawTask"
            title="任务完整状态"
          />
          <div v-else class="raw-loading">
            <el-button size="small" @click="loadRawTask">加载完整任务状态</el-button>
            <span class="raw-hint">默认页面只展示最近的轻量快照,完整 state 按需拉取</span>
          </div>
        </el-tab-pane>

        <el-tab-pane label="报告" name="report" v-if="task?.report_path || task?.report_available" lazy>
          <ReportPanel :task-id="taskId" />
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { computed, defineAsyncComponent, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { useTaskListStore } from '@/stores/taskList'
import { useTaskLiveStore } from '@/stores/taskLive'
import { trackEvent } from '@/metrics/tracker'
import StatusBadge from '@/components/StatusBadge.vue'
import PhaseTree from '@/components/PhaseTree.vue'
import FindingsPanel from '@/components/FindingsPanel.vue'
import DecisionTimeline from '@/components/DecisionTimeline.vue'
import DecisionCheckpointCard from '@/components/DecisionCheckpointCard.vue'

// 重组件改为按需加载, 首屏不付出解析+实例化 cost。
const LogTerminal = defineAsyncComponent(() => import('@/components/LogTerminal.vue'))
const ReconPanel = defineAsyncComponent(() => import('@/components/ReconPanel.vue'))
const JsonViewer = defineAsyncComponent(() => import('@/components/JsonViewer.vue'))
const ReportPanel = defineAsyncComponent(() => import('@/components/ReportPanel.vue'))
const AttackGraphView = defineAsyncComponent(() => import('@/components/AttackGraphView.vue'))
const PriorIntelPanel = defineAsyncComponent(() => import('@/components/PriorIntelPanel.vue'))

const route = useRoute()
const router = useRouter()
const taskId = String(route.params.id)
const listStore = useTaskListStore()
const liveStore = useTaskLiveStore()

const loading = ref(true)
const activeTab = ref('decision')
const cancelling = ref(false)
const pollTimer = ref(null)
const rawTask = ref(null)
const rawLoading = ref(false)

const state = computed(() => liveStore.getLiveState(taskId))
const llmStreams = computed(() => state.value?.llmStreams || {})
const toolStreams = computed(() => state.value?.toolStreams || {})
const task = computed(() => state.value.task || listStore.getTaskById(taskId))
const logs = computed(() => state.value.logs || [])
const findings = computed(() => task.value?.findings || [])
const isRunning = computed(() => ['pending', 'running'].includes(task.value?.status || ''))
const needsApproval = computed(() => task.value?.current_phase === 'awaiting_approval')

// 「已运行 Xs」：后端 liveness 心跳每 ~1.5s 带来一次 elapsed(秒)，
// 这里用本地 1s 计时器在两次心跳间插值，避免数字跳变/看起来卡死。
const elapsedBaseSec = ref(0)
const elapsedBaseAt = ref(0)
const nowTick = ref(Date.now())
const elapsedTimer = ref(null)
watch(
  () => task.value?.elapsed,
  (val) => {
    if (typeof val === 'number' && val >= 0) {
      elapsedBaseSec.value = val
      elapsedBaseAt.value = Date.now()
    }
  },
  { immediate: true },
)
const elapsedSeconds = computed(() => {
  if (!elapsedBaseAt.value) return task.value?.elapsed ?? 0
  if (!isRunning.value) return elapsedBaseSec.value
  const extra = (nowTick.value - elapsedBaseAt.value) / 1000
  return elapsedBaseSec.value + Math.max(0, extra)
})
const elapsedText = computed(() => {
  const total = Math.floor(elapsedSeconds.value)
  if (total < 60) return `${total}s`
  const m = Math.floor(total / 60)
  const s = total % 60
  if (m < 60) return `${m}m${String(s).padStart(2, '0')}s`
  const h = Math.floor(m / 60)
  return `${h}h${String(m % 60).padStart(2, '0')}m`
})
const approvalState = computed(() => state.value.approvalState)
const approving = computed(() => approvalState.value === 'submitting')
const showApprovalActions = computed(() => needsApproval.value && approvalState.value === 'idle')
const exploitableCount = computed(() => findings.value.filter((item) => item.exploitable).length)

// 攻击图（来自 backend state.attack_graph，反馈/监督模式下会填充节点和边）
const attackGraph = computed(() => task.value?.attack_graph || { nodes: [], edges: [] })
const attackGraphNodeCount = computed(() => attackGraph.value?.nodes?.length || 0)

const priorIntel = computed(() => task.value?.prior_intel || null)

const pendingCheckpoint = computed(() => state.value?.pendingCheckpoint || null)
const checkpointSubmitting = computed(() => state.value?.checkpointState === 'submitting')

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
        `workflow_mode: ${task.value.workflow_mode || 'pentest_engineer'}`,
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

  const structuredEvents = Array.isArray(state.value?.decisionEvents) ? state.value.decisionEvents : []
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
    if (entry.action === 'checkpoint_request') {
      events.push({
        id: entry.id || `cp-req-${idx}`,
        time,
        tone: 'warning',
        title: 'Plan 决策点 · 等待确认',
        desc: entry.summary || entry.message || entry.recommendation || '',
        thinking: entry.thinking || '',
        expandable: (entry.thinking || '').length > 80,
        action: 'checkpoint_request',
      })
      return
    }
    if (entry.action === 'checkpoint_resolved') {
      const resp = entry.response || {}
      const acted = resp.action || 'approve'
      events.push({
        id: entry.id || `cp-res-${idx}`,
        time,
        tone: acted === 'reject' ? 'danger' : (acted === 'approve' ? 'success' : 'info'),
        title: `Plan 决策点 · 已${acted === 'approve' ? '批准' : (acted === 'reject' ? '拒绝' : '处理')}`,
        desc: resp.user_prompt || entry.message || '',
        action: 'checkpoint_resolved',
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
    waiting_user: '等待用户指令',
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

async function onAttackGraphRefresh() {
  try {
    await liveStore.refreshTask(taskId)
    ElMessage.success('攻击图已刷新')
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || '刷新失败')
  }
}

async function pollTask() {
  if (!isRunning.value) return
  // WS 在最近 10s 内已带来过更新就跳过这次兜底刷新, 避免 WS+轮询双轨重复处理。
  if (Date.now() - (state.value.lastWsUpdate || 0) < 10000) return
  try {
    await liveStore.refreshTask(taskId)
  } catch {
    // Ignore polling errors.
  }
}

function startPolling() {
  stopPolling()
  // 兜底轮询拉长到 30s。WS 是数据主通道, 轮询只是断网/丢消息的保底,
  // 没有必要每 15s 全量拉一次轻量快照。
  pollTimer.value = window.setInterval(pollTask, 30000)
}

function stopPolling() {
  if (pollTimer.value) {
    window.clearInterval(pollTimer.value)
    pollTimer.value = null
  }
}

function startElapsedTicker() {
  stopElapsedTicker()
  elapsedTimer.value = window.setInterval(() => {
    if (isRunning.value) nowTick.value = Date.now()
  }, 1000)
}

function stopElapsedTicker() {
  if (elapsedTimer.value) {
    window.clearInterval(elapsedTimer.value)
    elapsedTimer.value = null
  }
}

async function loadRawTask() {
  if (rawLoading.value) return
  rawLoading.value = true
  try {
    rawTask.value = await api.getTaskFull(taskId)
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || '加载完整状态失败')
  } finally {
    rawLoading.value = false
  }
}

// 用户首次切到「原始数据」Tab 时再请求完整 state, 避免首屏白白付费。
watch(activeTab, (val) => {
  if (val === 'raw' && !rawTask.value && !rawLoading.value) {
    loadRawTask()
  }
})

onMounted(async () => {
  loading.value = true
  try {
    // 不再阻塞在全量任务列表上 —— 进入单个详情页和列表无强相关,
    // refreshTask 内部会通过 upsertTask 同步当前条目。
    await liveStore.refreshTask(taskId)
    await liveStore.attach(taskId)
    startPolling()
    startElapsedTicker()
    trackEvent('task.detail.open', { taskId })
  } finally {
    loading.value = false
  }
})

onUnmounted(() => {
  stopPolling()
  stopElapsedTicker()
  liveStore.detach(taskId)
})
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.detail-header { margin-bottom: 14px; }
.page-breadcrumb { margin-bottom: 10px; }
.title-line { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.target-title { color: var(--text-primary); font-size: 22px; font-weight: 700; font-family: var(--font-mono); }
.task-id { margin-top: 6px; display: inline-block; border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 2px 8px; color: var(--text-muted); font-size: 11px; font-family: var(--font-mono); }
.title-actions { display: flex; gap: 8px; align-items: center; }
.elapsed-pill { display: inline-flex; align-items: center; gap: 4px; padding: 3px 10px; border: 1px solid var(--border); border-radius: 999px; color: var(--text-muted); font-size: 12px; font-family: var(--font-mono); font-variant-numeric: tabular-nums; white-space: nowrap; }
.elapsed-pill .el-icon { font-size: 13px; }

.summary-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 12px; }
.summary-card :deep(.el-card__body) { padding: 12px !important; }
.summary-label { color: var(--text-muted); font-size: 12px; }
.summary-value { margin-top: 6px; font-size: 14px; color: var(--text-primary); font-weight: 600; }
.summary-value.risk { color: var(--accent-yellow); }
.summary-value.evidence { font-family: var(--font-mono); font-size: 12px; }

.pause-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  margin-bottom: 12px;
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--accent-yellow) 10%, var(--bg-elevated));
  border: 1px solid color-mix(in srgb, var(--accent-yellow) 32%, var(--border));
}
.pause-icon {
  color: color-mix(in srgb, var(--accent-yellow) 80%, var(--text-primary));
  font-size: 18px;
  flex: 0 0 auto;
}
.pause-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1;
  font-size: 12px;
  color: var(--text-secondary);
}
.pause-text strong {
  font-size: 13px;
  font-weight: 700;
  color: var(--text-primary);
}

.inline-checkpoint {
  margin-top: 8px;
}
.inline-checkpoint-done {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-top: 6px;
  font-size: 12px;
  color: var(--text-muted);
}
.inline-approval {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 8px;
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

.progress-tree { margin-bottom: 12px; }
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

.raw-loading {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 24px;
  color: var(--text-muted);
  font-size: 13px;
}

.raw-hint {
  font-size: 12px;
  color: var(--text-muted);
}
</style>
