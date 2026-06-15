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
      </div>

      <div class="chat-stream-wrap" ref="streamRef" @scroll="scroll.onUserScroll">
        <div class="bubble-stream">
          <div v-if="hasMoreMessages" class="load-earlier-wrap">
            <button class="load-earlier-btn" @click="loadMoreMessages">
              <el-icon><ArrowUp /></el-icon>
              加载更早消息 ({{ messages.length - displayedMessages.length }} 条未显示)
            </button>
          </div>
          <template v-for="msg in displayedMessages" :key="msg.id">
            <div
              :data-bubble-id="msg.id"
              class="bubble-anchor"
              :class="{ 'bubble-fork-anchored': forkAnchor && forkAnchor.id === msg.id }"
            >
            <button
              v-if="enableBranchUI && canForkFromMsg(msg)"
              class="bubble-fork-btn"
            type="button"
            :title="forkAnchor && forkAnchor.id === msg.id
              ? '已锚定此处, 再次点击取消'
              : '在此处分叉一条新分支(基于该消息时刻的上下文)'"
            @click="onClickForkFrom(msg)"
          >
            <el-icon><Share /></el-icon>
            <span class="bubble-fork-text">在此分叉</span>
          </button>
          <ChatBubble
            :role="msg.role"
            :text="msg.text"
            :timestamp="msg.timestamp"
            :tone="msg.tone"
            :use-markdown="msg.role === 'agent'"
          >
            <div v-if="msg.action === 'operator_replan' && msg.operatorPlan" class="replan-card">
              <div class="replan-row" v-if="msg.operatorPlan.intent_summary">
                <span class="replan-label">理解</span>
                <span class="replan-value">{{ msg.operatorPlan.intent_summary }}</span>
              </div>
              <div class="replan-row" v-if="msg.operatorPlan.next_phase || msg.operatorPlan.rerun_current">
                <span class="replan-label">下一步</span>
                <span class="replan-value">
                  <code v-if="msg.operatorPlan.next_phase">{{ msg.operatorPlan.next_phase }}</code>
                  <span v-if="msg.operatorPlan.rerun_current" class="replan-pill">重跑当前阶段</span>
                </span>
              </div>
              <div class="replan-row" v-if="msg.operatorPlan.target_phases && msg.operatorPlan.target_phases.length">
                <span class="replan-label">阶段序列</span>
                <span class="replan-value">{{ msg.operatorPlan.target_phases.join(' → ') }}</span>
              </div>
              <div class="replan-row" v-if="msg.operatorPlan.focus_targets && msg.operatorPlan.focus_targets.length">
                <span class="replan-label">聚焦目标</span>
                <span class="replan-value">
                  <span
                    v-for="(t, ti) in msg.operatorPlan.focus_targets"
                    :key="ti"
                    class="replan-chip"
                  >{{ t.type }}={{ t.value }}</span>
                </span>
              </div>
              <div class="replan-row" v-if="msg.operatorPlan.preferred_tools && msg.operatorPlan.preferred_tools.length">
                <span class="replan-label">工具偏好</span>
                <span class="replan-value">
                  <span v-for="t in msg.operatorPlan.preferred_tools" :key="t" class="replan-chip chip-tool">{{ t }}</span>
                </span>
              </div>
              <div class="replan-row" v-if="msg.operatorPlan.avoided_tools && msg.operatorPlan.avoided_tools.length">
                <span class="replan-label">禁用工具</span>
                <span class="replan-value">
                  <span v-for="t in msg.operatorPlan.avoided_tools" :key="t" class="replan-chip chip-warn">{{ t }}</span>
                </span>
              </div>
              <div class="replan-row" v-if="msg.operatorPlan.keyword_hints && msg.operatorPlan.keyword_hints.length">
                <span class="replan-label">关键词</span>
                <span class="replan-value">
                  <span v-for="k in msg.operatorPlan.keyword_hints.slice(0, 12)" :key="k" class="replan-chip chip-soft">{{ k }}</span>
                </span>
              </div>
              <div class="replan-row" v-if="msg.operatorPlan.skip_phases && msg.operatorPlan.skip_phases.length">
                <span class="replan-label">跳过</span>
                <span class="replan-value">
                  <span v-for="p in msg.operatorPlan.skip_phases" :key="p" class="replan-chip chip-warn">{{ p }}</span>
                </span>
              </div>
              <div class="replan-row" v-if="!msg.operatorPlan.needs_human_approval">
                <span class="replan-label">授权</span>
                <span class="replan-value chip-warn-text">用户授权: 跳过人工审批</span>
              </div>
              <div class="replan-rationale" v-if="msg.operatorPlan.rationale">
                <span class="replan-label">推理</span>
                <p>{{ msg.operatorPlan.rationale }}</p>
              </div>
            </div>

            <div v-if="msg.purpose" class="thought-meta">
              <span class="meta-label">目标</span> {{ msg.purpose }}
            </div>
            <div v-if="msg.expected" class="thought-meta">
              <span class="meta-label">预期</span> {{ msg.expected }}
            </div>
            <div v-if="Array.isArray(msg.plan) && msg.plan.length" class="thought-plan">
              <span class="meta-label">{{ msg.action === 'operator_replan' ? '执行要点' : msg.action === 'initial_plan' ? '初始策略' : '攻击计划' }}</span>
              <ol>
                <li v-for="(step, si) in msg.plan" :key="si">{{ step }}</li>
              </ol>
            </div>
            <!-- 默认展示推理摘要(不再让用户每条都点"展开"); 长文本超过 600
                 字才折叠剩余部分。这样 chat 流里"AI 推理"卡片不再只显示一句
                 头部, 用户能一眼看到当前节点究竟在想什么。 -->
            <div v-if="msg.thinkingPreview" class="thought-preview">
              <span class="meta-label">推理</span>
              <p class="thought-preview-text">{{ msg.thinkingPreview }}</p>
            </div>
            <details v-if="msg.thinkingHasMore" class="thought-expand">
              <summary>展开完整推理 ({{ msg.thinkingFullLen }} 字)</summary>
              <pre class="thought-full">{{ msg.thinking }}</pre>
            </details>
            <details v-if="msg.reasoning" class="thought-expand reasoning-expand">
              <summary>展开 LLM 思考链 (reasoning)</summary>
              <pre class="thought-full reasoning-full">{{ msg.reasoning }}</pre>
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

            <div
              v-if="msg.action === 'approval_required' || msg.action === 'approval'"
              class="approval-slot"
            >
              <div v-if="showApprovalActions && msg.isLastApproval">
                <ApprovalCard :context="approvalCardContext" :loading="approving" @approve="doApprove" />
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
              v-if="enableBranchUI && msg.action === 'branch_forked' && msg.branchId && nav.siblingNavFor(msg.branchId)"
              class="branch-navigator"
            >
              <button
                class="nav-btn"
                :disabled="nav.siblingNavFor(msg.branchId).total <= 1"
                @click="nav.gotoSibling(msg.branchId, -1)"
                title="上一个兄弟分支"
              >‹</button>
              <span class="nav-counter">
                &lt;{{ nav.siblingNavFor(msg.branchId).index }}/{{ nav.siblingNavFor(msg.branchId).total }}&gt;
              </span>
              <button
                class="nav-btn"
                :disabled="nav.siblingNavFor(msg.branchId).total <= 1"
                @click="nav.gotoSibling(msg.branchId, 1)"
                title="下一个兄弟分支"
              >›</button>
              <span class="nav-active" v-if="msg.branchId === activeBranchId">当前激活</span>
              <button
                v-else
                class="nav-activate"
                @click="nav.activateBranch(msg.branchId)"
              >切到此分支</button>
            </div>
          </ChatBubble>
            </div>
          </template>

          <div class="stream-bubbles">
            <div v-for="(bubble, sid) in activeStreamBubbles" :key="sid" class="llm-stream-bubble stream-fade-in">
              <div class="bubble-header">
                <span class="bubble-phase">{{ bubble.phase || '推理' }}</span>
                <span class="bubble-indicator">正在思考<span class="dots">...</span></span>
              </div>
              <pre class="bubble-text">{{ bubble.text }}<span class="stream-cursor">|</span></pre>
            </div>
          </div>

          <div class="stream-bubbles">
            <div
              v-for="bubble in activeToolStreamBubbles"
              :key="`tool-${bubble.sid}`"
              class="tool-stream-bubble stream-fade-in"
            >
              <div class="bubble-header">
                <span class="bubble-phase">{{ bubble.tool }}</span>
                <span class="bubble-indicator">
                  正在执行<span class="dots">...</span>
                  · {{ bubble.total }} 行
                </span>
              </div>
              <pre class="bubble-text">{{ bubble.lines.join('\n') }}</pre>
            </div>
          </div>
        </div>

        <transition name="fade">
          <button v-if="scroll.showJumpBtn" class="jump-latest" @click="scroll.jumpToBottom">
            <el-icon><ArrowDown /></el-icon>
            跳转最新
          </button>
        </transition>
      </div>

      <div v-if="strategyPlan.length > 0" class="strategy-side">
        <StrategyRail
          :title="hasPentestPlan ? '渗透策略' : '攻击链'"
          :items="strategyPlan"
          :collapsed="uiPrefs.strategyPanelCollapsed"
          @toggle="uiPrefs.strategyPanelCollapsed = !uiPrefs.strategyPanelCollapsed"
        />
      </div>
    </main>

      <section class="composer" :class="{ 'composer-flash': composerFlashing }">
        <div v-if="enableBranchUI && (branches.length || nav.activeBranch)" class="branch-status-band">
          <span class="band-icon">
            <el-icon><Share /></el-icon>
          </span>
          <span class="band-text">
            <template v-if="nav.activeBranch">
              当前分支
              <strong>{{ nav.activeBranch.label || nav.activeBranch.branch_id }}</strong>
              <span class="band-status" :class="`status-${nav.activeBranch.status}`">
                · {{ nav.branchStatusLabel(nav.activeBranch.status) }}
              </span>
            </template>
            <template v-else>
              <strong>主分支(root)</strong> 进行中
            </template>
            <span v-if="branches.length > 1" class="band-count">
              · 共 {{ branches.length }} 个分支
            </span>
          </span>
          <span v-if="nav.branchAtCap" class="band-cap">已达分支上限, 新输入将被合并到当前分支</span>
          <el-popover
            v-if="branches.length"
            placement="top-end"
            trigger="click"
            :width="420"
            :teleported="false"
            popper-class="branch-popover"
          >
            <template #reference>
              <button type="button" class="band-switch" :title="`分支总数: ${branches.length}`">
                <el-icon><Share /></el-icon>
                全部分支 ({{ branches.length }}/{{ maxBranchesPerTask }})
              </button>
            </template>
            <div class="branch-popover-body">
              <div class="branch-popover-head">
                <strong>分支</strong>
                <span class="branch-popover-hint">点击「切到」激活, 「继续运行」恢复, 「暂停」挂起当前分支</span>
              </div>
              <div class="branch-popover-tree">
                <BranchTreeNode
                  v-for="node in safeBranchRoots"
                  :key="node.branch_id"
                  :node="node"
                  :children-by-parent="nav.branchChildrenByParent"
                  :active-id="activeBranchId"
                  :depth="0"
                  @activate="onBranchActivate"
                  @resume="onBranchResume"
                  @pause="onBranchPause"
                />
              </div>
            </div>
          </el-popover>
        </div>
        <div class="composer-toolbar">
          <span class="composer-tip">
            <el-icon><ChatLineRound /></el-icon>
            你可以追加指令影响后续决策, 或在决策点提出修改意见
          </span>
          <span class="composer-shortcut">Ctrl/Cmd + Enter 发送</span>
        </div>
        <div v-if="enableBranchUI && forkAnchor" class="fork-anchor-band">
          <el-icon><Share /></el-icon>
          <span class="fork-anchor-text">
            将在 <strong>{{ forkAnchor.label || forkAnchor.id }}</strong> 处分叉新分支
          </span>
          <button type="button" class="fork-anchor-clear" @click="clearForkAnchor">取消</button>
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
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  ArrowDown,
  ArrowLeft,
  ArrowUp,
  ChatLineRound,
  Check,
  CircleCheck,
  Close,
  Document,
  Loading,
  Memo,
  Promotion,
  Share,
  Warning,
} from '@element-plus/icons-vue'
import { api } from '@/api'
import { useTaskListStore } from '@/stores/taskList'
import { useTaskLiveStore } from '@/stores/taskLive'
import { useUiPrefsStore } from '@/stores/uiPrefs'
import { trackEvent } from '@/metrics/tracker'
import BranchTreeNode from '@/components/BranchTreeNode.vue'
import ChatBubble from '@/components/ChatBubble.vue'
import DecisionCheckpointCard from '@/components/DecisionCheckpointCard.vue'
import { resolveToolDisplay } from '@/utils/toolDisplay'
import PayloadCodeBlock from '@/components/PayloadCodeBlock.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import ToolChainRail from '@/components/ToolChainRail.vue'
import ApprovalCard from '@/components/ApprovalCard.vue'
import StrategyRail from '@/components/StrategyRail.vue'
import type { StrategyItem } from '@/components/StrategyRail.vue'
import { useChatMessages, PLAN_PHASE_TO_CHAIN, PLAN_PHASE_LABELS, CHAIN_PHASES, formatTime } from '@/composables/useChatMessages'
import { useBranchNavigator } from '@/composables/useBranchNavigator'
import { useApprovalCard } from '@/composables/useApprovalCard'
import { useScrollController } from '@/composables/useScrollController'

const route = useRoute()
const router = useRouter()
const taskId = String(route.params.id)
const listStore = useTaskListStore()
const liveStore = useTaskLiveStore()
const uiPrefs = useUiPrefsStore()

const loading = ref(true)
const chatInput = ref('')
const sending = ref(false)
const cancelling = ref(false)
const streamRef = ref(null)

const state = computed(() => liveStore.getLiveState(taskId))
const task = computed(() => state.value.task || listStore.getTaskById(taskId))

const decisionEvents = computed(() => {
  const raw = state.value?.decisionEvents
  if (!Array.isArray(raw) || !raw.length) return []
  const activeBid = state.value?.activeBranchId || ''
  const filtered = activeBid
    ? raw.filter((ev) => {
        const bid = String((ev || {}).branch_id || '')
        return !bid || bid === activeBid
      })
    : raw
  // taskLive.ts 已保证 decisionEvents 按 event.id 单调有序，此处不再二次排序
  return filtered
})
const llmStreams = computed(() => state.value?.llmStreams || {})
const isRunning = computed(() => ['pending', 'running'].includes(task.value?.status || ''))
const needsApproval = computed(() => task.value?.current_phase === 'awaiting_approval')
const approvalState = computed(() => state.value.approvalState)
const approving = computed(() => approvalState.value === 'submitting')
const showApprovalActions = computed(() => needsApproval.value && (approvalState.value === 'idle' || approvalState.value === 'submitting'))
const pendingCheckpoint = computed(() => state.value?.pendingCheckpoint || null)
const checkpointSubmitting = computed(() => state.value?.checkpointState === 'submitting')

// ── composables ────────────────────────────────
const toolStreams = computed(() => state.value?.toolStreams || {})

const { messages, displayedMessages, hasMoreMessages, loadMoreMessages, activeStreamBubbles, activeToolStreamBubbles } = useChatMessages(
  decisionEvents,
  task,
  pendingCheckpoint,
  llmStreams,
  toolStreams,
)

const { approvalCardContext } = useApprovalCard(pendingCheckpoint, messages)

const scroll = useScrollController(streamRef, computed(() => messages.value.length))

const hasPentestPlan = computed(() => {
  const plan = task.value?.pentest_plan as Record<string, unknown> | undefined
  return plan && Array.isArray(plan.phases) && plan.phases.length > 0
})

const strategyPlan = computed<StrategyItem[]>(() => {
  const t = task.value
  if (!t) return []

  const visited = (t.chain_visited || []) as string[]
  const visitedSet = new Set(visited)
  const curPhase = t.current_phase || ''

  // ── 有策略时：严格按策略阶段展示 ──
  const plan = t.pentest_plan as Record<string, unknown> | undefined
  if (plan && Array.isArray(plan.phases) && plan.phases.length > 0) {
    const phases = plan.phases as Array<{ phase: string; description: string; steps?: Array<{ tool?: string; skill?: string; purpose?: string; enabled?: boolean }> }>
    const items: StrategyItem[] = []
    for (let i = 0; i < phases.length; i++) {
      const p = phases[i]
      const chainNodes = PLAN_PHASE_TO_CHAIN[p.phase] || [p.phase]
      const isActive = chainNodes.includes(curPhase) || curPhase === p.phase
      const isDone = !isActive && chainNodes.some(n => visitedSet.has(n))
      let status: 'done' | 'active' | 'pending' = 'pending'
      let detail = ''
      if (isActive) {
        status = 'active'
        detail = '进行中'
      } else if (isDone) {
        status = 'done'
        detail = '已完成'
      }
      const steps: StrategyStep[] = (p.steps || [])
        .filter(s => s.enabled !== false)
        .map(s => ({ tool: s.tool, skill: s.skill, purpose: s.purpose }))
      items.push({
        key: p.phase,
        label: PLAN_PHASE_LABELS[p.phase] || p.description || p.phase,
        detail,
        status,
        steps: steps.length > 0 ? steps : undefined,
      })
    }
    return items
  }

  // ── 无策略时：展示通用攻击链 ──
  const items: StrategyItem[] = []
  for (let i = 0; i < CHAIN_PHASES.length; i++) {
    const p = CHAIN_PHASES[i]
    let status: 'done' | 'active' | 'pending' = 'pending'
    let detail = ''
    if (curPhase === p.key) {
      status = 'active'
      detail = '进行中'
    } else if (visitedSet.has(p.key)) {
      status = 'done'
      detail = '已完成'
    }
    items.push({ key: p.key, label: p.label, detail, status })
  }
  return items
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
    } else if (action === 'initial_plan') {
      items.push({
        id,
        action,
        tone: 'primary',
        title: '初始策略',
        purpose: ev.purpose || '',
        summary: ev.message || '',
        time: formatTime(ev.timestamp),
      })
    } else if (action === 'command_exec') {
      const toolLabel = resolveToolDisplay({
        display_tool: ev.display_tool,
        tool: ev.tool,
        command: ev.command,
        purpose: ev.purpose,
      })
      items.push({
        id,
        action,
        tone: (ev.exit_code ?? -1) === 0 ? 'success' : 'danger',
        title: `命令执行 · ${toolLabel}`,
        tool: ev.tool || '',
        display_tool: toolLabel,
        command: ev.command || '',
        time: formatTime(ev.timestamp),
      })
    } else if (action === 'tool_start') {
      const toolLabel = resolveToolDisplay({
        display_tool: ev.display_tool,
        tool: ev.tool,
        command: ev.command,
        purpose: ev.purpose,
      })
      items.push({
        id,
        action,
        tone: 'primary',
        title: `工具调用 · ${toolLabel}`,
        tool: ev.tool || '',
        display_tool: toolLabel,
        time: formatTime(ev.timestamp),
      })
    } else if (action === 'tool_result' || action === 'tool_executed') {
      const toolLabel = resolveToolDisplay({
        display_tool: ev.display_tool,
        tool: ev.tool,
        command: ev.command,
        purpose: ev.purpose,
      })
      items.push({
        id,
        action,
        tone: Number(ev.exit_code ?? -1) === 0 ? 'success' : 'danger',
        title: `调用结果 · ${toolLabel}`,
        tool: ev.tool || '',
        display_tool: toolLabel,
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
  if (!target) {
    // 工具链节点对应的气泡不在当前视图(可能在更早的事件中已被裁剪)
    // 尝试滚动到顶部,让用户看到最早的可见气泡
    streamRef.value.scrollTo({ top: 0, behavior: 'smooth' })
    return
  }
  activeRailId.value = id
  target.scrollIntoView({ behavior: 'smooth', block: 'center' })
  target.classList.add('bubble-flash')
  setTimeout(() => target.classList.remove('bubble-flash'), 1400)
  // 因为是手动跳转, 不再粘到底部
  scroll.stickyBottom.value = false
}

// "在此处分叉"上下文: 当用户右键/点击某条历史 chat bubble 选择"在此分叉"时,
// 把对应 decision_event 的 id + timestamp 暂存到这里, 下一次 sendMessage
// 会把它们作为 ``from_event_id`` / ``from_event_ts`` 一并传给后端,
// 让 BranchManager 走 ``find_checkpoint_at_or_before`` 选定 source checkpoint。
const enableBranchUI = ref(false) // 临时禁用分支 UI
const forkAnchor = ref(null)

function setForkAnchor(eventId, timestamp, label) {
  forkAnchor.value = {
    id: String(eventId || ''),
    ts: String(timestamp || ''),
    label: String(label || '').slice(0, 60),
  }
  ElMessage.info('已锚定分叉位置, 输入新指令后发送即可在此处开新分支')
}
function clearForkAnchor() {
  forkAnchor.value = null
}

// 哪些 chat bubble 可以作为分叉锚点:
// - 必须有原始 event ISO timestamp(从 decision_events 里冒上来的)
// - 系统 / origin-user-prompt / branch_forked / approval / checkpoint
//   等元事件不应作为分叉锚点(分叉它们语义不清)
function canForkFromMsg(msg) {
  if (!msg || !msg.eventTs || !msg.eventId) return false
  if (msg.action === 'branch_forked') return false
  if (msg.action === 'approval_required') return false
  if (msg.action === 'approval') return false
  if (msg.action === 'checkpoint_request') return false
  if (msg.action === 'checkpoint_resolved') return false
  if (msg.role === 'system') return false
  return true
}

function onClickForkFrom(msg) {
  if (!canForkFromMsg(msg)) return
  if (forkAnchor.value && forkAnchor.value.id === msg.eventId) {
    clearForkAnchor()
    return
  }
  const labelSrc = (msg.text || '').split('\n')[0] || msg.eventId
  setForkAnchor(msg.eventId, msg.eventTs, labelSrc)
}

async function sendMessage() {
  const text = chatInput.value.trim()
  if (!text || sending.value) return
  sending.value = true
  try {
    const anchor = forkAnchor.value
    const res = await api.sendChat(taskId, text, anchor ? {
      fromEventId: anchor.id,
      fromEventTs: anchor.ts,
    } : undefined)
    chatInput.value = ''
    forkAnchor.value = null
    trackEvent('task.chat.send', {
      taskId,
      forked: Boolean(res?.fork_active),
      branch_id: res?.branch?.branch_id || '',
      from_event_id: anchor?.id || '',
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
const maxBranchesPerTask = computed(() => state.value?.maxBranchesPerTask || 12)
const composerFlashAt = ref(0)
const composerFlashing = computed(() => {
  if (!composerFlashAt.value) return false
  return Date.now() - composerFlashAt.value < 2400
})

const nav = useBranchNavigator(taskId, branches, activeBranchId, maxBranchesPerTask)
const safeBranchRoots = computed(() => {
  const roots = nav.branchRoots
  const arr = Array.isArray(roots) ? roots : (roots && typeof roots === 'object' && 'value' in roots ? roots.value : [])
  return (arr || []).filter(n => n && n.branch_id)
})
function onBranchActivate(branchId: string) { nav.activateBranch(branchId) }
function onBranchResume(branchId: string) { nav.resumeBranch(branchId) }
function onBranchPause(branchId: string) { nav.pauseBranch(branchId) }

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
    scroll.smoothScrollToBottom()
  }
})

onUnmounted(() => {
  liveStore.detach(taskId)
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
  flex: 1;
  min-height: 0;
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
/* ── 右侧策略面板 ── */
.strategy-side {
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
}

.bubble-stream {
  max-width: 1080px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.load-earlier-wrap {
  display: flex;
  justify-content: center;
  padding: 4px 0 8px;
}
.load-earlier-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 16px;
  font-size: 12px;
  color: var(--accent-blue);
  background: color-mix(in srgb, var(--accent-blue) 8%, transparent);
  border: 1px solid color-mix(in srgb, var(--accent-blue) 25%, transparent);
  border-radius: 20px;
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
}
.load-earlier-btn:hover {
  background: color-mix(in srgb, var(--accent-blue) 16%, transparent);
  border-color: var(--accent-blue);
}
.bubble-anchor {
  position: relative;
  scroll-margin-top: 40px;
  border-radius: var(--radius-md);
  transition: background 0.4s ease, box-shadow 0.4s ease;
  content-visibility: auto;
  contain-intrinsic-size: auto 120px;
}
.bubble-flash {
  background: color-mix(in srgb, var(--accent-blue) 12%, transparent);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent-blue) 40%, transparent);
}
.bubble-fork-anchored {
  background: color-mix(in srgb, var(--accent-blue) 14%, transparent);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent-blue) 55%, transparent);
}
.bubble-fork-btn {
  position: absolute;
  top: 4px;
  right: 4px;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  font-size: 11px;
  line-height: 1.5;
  background: var(--bg-elevated, rgba(0, 0, 0, 0.04));
  color: var(--text-secondary);
  border: 1px solid var(--border-color, rgba(0, 0, 0, 0.12));
  border-radius: 999px;
  cursor: pointer;
  opacity: 0;
  transform: translateY(-2px);
  transition: opacity 0.18s ease, transform 0.18s ease;
}
.bubble-anchor:hover .bubble-fork-btn,
.bubble-fork-anchored .bubble-fork-btn {
  opacity: 1;
  transform: translateY(0);
}
.bubble-fork-btn:hover {
  color: var(--accent-blue);
  border-color: var(--accent-blue);
}
.bubble-fork-text {
  font-weight: 500;
}
.fork-anchor-band {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 6px 0 4px;
  padding: 6px 10px;
  font-size: 12px;
  color: var(--text-secondary);
  background: color-mix(in srgb, var(--accent-blue) 10%, transparent);
  border: 1px dashed color-mix(in srgb, var(--accent-blue) 40%, transparent);
  border-radius: var(--radius-md);
}
.fork-anchor-text strong {
  color: var(--text-primary);
  font-weight: 600;
}
.fork-anchor-clear {
  margin-left: auto;
  background: transparent;
  border: none;
  color: var(--accent-blue);
  font-size: 12px;
  cursor: pointer;
}
.fork-anchor-clear:hover {
  text-decoration: underline;
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
.reasoning-expand summary { color: color-mix(in srgb, var(--accent-blue) 60%, var(--text-secondary)); }
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
.reasoning-full {
  background: color-mix(in srgb, var(--bg-base) 80%, var(--text-secondary) 8%);
  font-style: italic;
}

/* AI 推理"摘要"区: 默认展示 thinking 前 600 字, 不再让用户每条都点
   "展开完整推理"才能看到内容。 */
.thought-preview {
  margin: 6px 0 0;
  font-size: 12.5px;
  line-height: 1.65;
  color: var(--text-primary);
}
.thought-preview-text {
  margin: 4px 0 0;
  padding: 8px 10px;
  background: color-mix(in srgb, var(--bg-base) 70%, var(--accent-blue) 6%);
  border-left: 3px solid color-mix(in srgb, var(--accent-blue) 50%, transparent);
  border-radius: 0 var(--radius-md) var(--radius-md) 0;
  white-space: pre-wrap;
  word-break: break-word;
}

/* operator_replan 卡片: 高亮"agent 听懂了"反馈 */
.replan-card {
  margin: 6px 0 0;
  padding: 10px 12px;
  background: linear-gradient(
    135deg,
    color-mix(in srgb, var(--accent-blue) 14%, transparent),
    color-mix(in srgb, var(--accent-blue) 4%, transparent)
  );
  border: 1px solid color-mix(in srgb, var(--accent-blue) 40%, transparent);
  border-radius: var(--radius-md);
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.replan-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 12.5px;
  line-height: 1.6;
  flex-wrap: wrap;
}
.replan-label {
  flex-shrink: 0;
  min-width: 4.5em;
  font-weight: 600;
  color: var(--accent-blue);
  font-size: 12px;
}
.replan-value {
  flex: 1;
  color: var(--text-primary);
  display: inline-flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}
.replan-value code {
  padding: 1px 6px;
  font-size: 12px;
  font-family: var(--font-mono);
  background: color-mix(in srgb, var(--bg-base) 60%, var(--accent-blue) 12%);
  border: 1px solid color-mix(in srgb, var(--accent-blue) 30%, transparent);
  border-radius: 4px;
}
.replan-pill {
  padding: 1px 8px;
  font-size: 11px;
  background: color-mix(in srgb, var(--accent-blue) 20%, transparent);
  border-radius: 999px;
  color: var(--accent-blue);
}
.replan-chip {
  display: inline-flex;
  padding: 2px 8px;
  font-size: 11.5px;
  background: color-mix(in srgb, var(--bg-base) 70%, var(--accent-blue) 10%);
  border: 1px solid color-mix(in srgb, var(--accent-blue) 25%, transparent);
  border-radius: 999px;
  color: var(--text-primary);
}
.replan-chip.chip-tool {
  background: color-mix(in srgb, var(--bg-base) 70%, #2ea043 12%);
  border-color: color-mix(in srgb, #2ea043 35%, transparent);
  color: color-mix(in srgb, #2ea043 80%, var(--text-primary));
}
.replan-chip.chip-warn {
  background: color-mix(in srgb, var(--bg-base) 70%, #d29922 12%);
  border-color: color-mix(in srgb, #d29922 35%, transparent);
  color: color-mix(in srgb, #d29922 80%, var(--text-primary));
}
.replan-chip.chip-soft {
  background: color-mix(in srgb, var(--bg-base) 80%, transparent);
  color: var(--text-secondary);
  font-family: var(--font-mono);
  font-size: 11px;
}
.chip-warn-text {
  color: color-mix(in srgb, #d29922 90%, var(--text-primary));
  font-weight: 500;
}
.replan-rationale {
  margin-top: 4px;
  padding-top: 6px;
  border-top: 1px dashed color-mix(in srgb, var(--accent-blue) 25%, transparent);
}
.replan-rationale p {
  margin: 4px 0 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-word;
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
  contain: layout style;
}
/* 工具实时输出气泡: 让用户在 tool_result 落位之前就能看到工具在跑什么,
 * 同时把样式与 LLM 推理流区分(蓝色,monospace)。 */
.tool-stream-bubble {
  align-self: stretch;
  max-width: min(78%, 720px);
  margin-left: 40px;
  border: 1px solid color-mix(in srgb, var(--accent-blue, #58a6ff) 50%, transparent);
  border-left: 3px solid var(--accent-blue, #58a6ff);
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--bg-base) 92%, var(--accent-blue, #58a6ff) 6%);
  padding: 10px 12px;
  contain: layout style;
}
.tool-stream-bubble .bubble-phase {
  color: var(--accent-blue, #58a6ff);
  font-family: var(--font-mono);
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
@keyframes cursor-blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0; }
}
.stream-cursor {
  animation: cursor-blink 0.8s infinite;
  color: var(--accent-purple, #a371f7);
  font-weight: 700;
  user-select: none;
}
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

/* Stream bubble pure CSS fade-in (replaces TransitionGroup to avoid layout thrashing) */
@keyframes streamFadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
.stream-fade-in {
  animation: streamFadeIn 0.35s ease-out;
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

.composer {
  flex-shrink: 0;
  max-width: 1080px;
  width: 100%;
  margin: 0 auto;
  margin-bottom: 18px;
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
.band-switch {
  margin-left: auto;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  font-family: var(--font-mono);
  padding: 3px 10px;
  border-radius: 999px;
  border: 1px solid color-mix(in srgb, var(--accent-blue, #58a6ff) 50%, transparent);
  background: color-mix(in srgb, var(--accent-blue, #58a6ff) 6%, transparent);
  color: var(--accent-blue, #58a6ff);
  cursor: pointer;
  transition: background 0.15s ease, border-color 0.15s ease;
}
.band-switch:hover {
  background: color-mix(in srgb, var(--accent-blue, #58a6ff) 16%, transparent);
  border-color: var(--accent-blue, #58a6ff);
}
.band-switch + .band-cap {
  margin-left: 8px;
}

/* 分支选择 popover 内部 */
.branch-popover-body {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.branch-popover-head {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
}
.branch-popover-head strong {
  font-size: 13px;
  color: var(--text-primary);
}
.branch-popover-hint {
  font-size: 11px;
  color: var(--text-muted);
}
.branch-popover-tree {
  max-height: 360px;
  overflow-y: auto;
  padding-right: 4px;
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
