<template>
  <div class="page-wrap" v-loading="loading" element-loading-background="rgba(13,17,23,0.9)">
    <div class="detail-header">
      <el-button link @click="router.back()" class="back-btn">
        <el-icon><ArrowLeft /></el-icon>
        返回
      </el-button>

      <div class="title-line">
        <div>
          <h2 class="target-title">{{ task?.target || '...' }}</h2>
          <code class="task-id">{{ taskId }}</code>
        </div>
        <div class="title-actions" v-if="task">
          <StatusBadge :status="task.status" size="large" />
          <el-button plain @click="activeTab = 'decision'">决策视图</el-button>
          <el-button v-if="task.report_path" type="success" plain @click="router.push(`/reports/${taskId}`)">
            报告中心
          </el-button>
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

    <div class="pipeline-card" v-if="task">
      <PipelineFlow
        :current-phase="task.current_phase"
        :status="task.status"
        :findings-count="findings.length"
        :exploitable-count="exploitableCount"
        :got-shell="task.got_shell"
        :needs-approval="false"
        :approving="approving"
      />
    </div>

    <ApprovalComposer
      :needs-approval="showApprovalActions"
      :loading="approving"
      @approve="doApprove(true)"
      @reject="doApprove(false)"
      class="approval-composer"
    />

    <el-card class="main-card">
      <el-tabs v-model="activeTab" class="detail-tabs">
        <el-tab-pane label="Decision Chat" name="decision">
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
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { useTaskListStore } from '@/stores/taskList'
import { useTaskLiveStore } from '@/stores/taskLive'
import { trackEvent } from '@/metrics/tracker'
import StatusBadge from '@/components/StatusBadge.vue'
import PipelineFlow from '@/components/PipelineFlow.vue'
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
const approving = ref(false)
const approvalSubmitted = ref(false)
const pollTimer = ref(null)

const state = computed(() => liveStore.getLiveState(taskId))
const task = computed(() => state.value.task || listStore.getTaskById(taskId))
const logs = computed(() => state.value.logs || [])
const findings = computed(() => task.value?.findings || [])
const isRunning = computed(() => ['pending', 'running'].includes(task.value?.status || ''))
const needsApproval = computed(() => task.value?.current_phase === 'awaiting_approval')
const showApprovalActions = computed(() => needsApproval.value && !approvalSubmitted.value)
const exploitableCount = computed(() => findings.value.filter((item) => item.exploitable).length)

const nextAction = computed(() => {
  if (!task.value) return '-'
  if (task.value.status === 'completed') return '审阅报告并发布'
  if (needsApproval.value) return '确认利用授权范围并执行审批'
  if (task.value.current_phase === 'exploit_decision') return '等待模型生成 PoC/Payload'
  if (task.value.current_phase === 'exploit') return '观察利用结果与回显证据'
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

  const evidenceFinding = findings.value.find((item) => item.evidence)
  if (evidenceFinding?.evidence) {
    events.push({
      id: `finding-${evidenceFinding.vuln_id}`,
      time: new Date().toLocaleTimeString(),
      tone: evidenceFinding.exploitable ? 'danger' : 'info',
      title: `发现：${evidenceFinding.name}`,
      desc: evidenceFinding.description || '命中漏洞证据。',
      payload: {
        title: 'PoC / Payload',
        language: inferPayloadLang(evidenceFinding.evidence),
        code: evidenceFinding.evidence,
      },
    })
  }

  const payloadLogs = logs.value.filter((line) => /payload|poc|webshell|cmd|curl|python|bash/i.test(line)).slice(-4)
  payloadLogs.forEach((line, idx) => {
    events.push({
      id: `log-${idx}`,
      time: new Date().toLocaleTimeString(),
      tone: /failed|error|denied|401|403/i.test(line) ? 'danger' : 'success',
      title: '执行轨迹',
      desc: line,
      payload: {
        title: '执行命令片段',
        language: inferPayloadLang(line),
        code: line,
      },
    })
  })

  return events
})

function inferPayloadLang(text) {
  if (/^\s*\{[\s\S]*\}\s*$/.test(text)) return 'json'
  if (/GET\s+\/|POST\s+\/|HTTP\/1\.1/i.test(text)) return 'http'
  if (/python|def |import /.test(text)) return 'python'
  return 'bash'
}

function phaseText(phase) {
  return {
    init: '初始化',
    recon: '信息侦察',
    vuln_scan: '漏洞扫描',
    exploit_decision: '利用决策',
    awaiting_approval: '等待审批',
    exploit: '漏洞利用',
    post_exploit: '后渗透',
    report: '报告生成',
  }[phase] || phase
}

async function doApprove(approved) {
  if (!showApprovalActions.value || approving.value) return
  approving.value = true
  approvalSubmitted.value = true
  try {
    await api.approveTask(taskId, approved)
    trackEvent('task.approval', { taskId, approved })
    ElMessage.success(approved ? '已批准继续利用' : '已拒绝利用阶段')
  } catch (e) {
    approvalSubmitted.value = false
    ElMessage.error(e?.response?.data?.detail || e.message || '审批失败')
  } finally {
    approving.value = false
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

watch(needsApproval, (value) => {
  if (value) return
  approvalSubmitted.value = false
})

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

.pipeline-card { margin-bottom: 12px; }
.approval-composer { margin-bottom: 12px; }
.main-card { border-radius: var(--radius-lg) !important; }
.tab-label { display: inline-flex; align-items: center; gap: 5px; }
.tab-badge { margin-left: 4px; }
</style>
