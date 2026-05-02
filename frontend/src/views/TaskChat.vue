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

      <div class="chat-stream-wrap" ref="streamRef" @scroll="onUserScroll">
        <div class="bubble-stream">
          <template v-for="msg in messages" :key="msg.id">
            <div
              :data-bubble-id="msg.id"
              class="bubble-anchor"
              :class="{ 'bubble-fork-anchored': forkAnchor && forkAnchor.id === msg.id }"
            >
          <button
            v-if="canForkFromMsg(msg)"
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
              <div v-if="showApprovalActions && msg.isLastApproval" class="approval-card">
                <!-- Header -->
                <div class="approval-card-header">
                  <div class="approval-card-header-left">
                    <el-icon class="approval-card-icon"><WarningFilled /></el-icon>
                    <div>
                      <div class="approval-card-title">
                        <span>人工审批确认</span>
                        <el-tag v-if="approvalCardContext?.phaseLabel" size="small" type="warning" class="approval-card-phase-tag">
                          {{ approvalCardContext.phaseLabel }}
                        </el-tag>
                      </div>
                      <div class="approval-card-subtitle">
                        {{ approvalCardContext?.summary || 'Agent 已暂停, 等待你审批后续操作。' }}
                      </div>
                    </div>
                  </div>
                  <div class="approval-card-header-right">
                    <el-tag v-if="approvalCardContext?.risk" :type="approvalCardContext.riskType" effect="dark" size="small">
                      风险 · {{ approvalCardContext.risk }}
                    </el-tag>
                  </div>
                </div>

                <!-- Targets list -->
                <div v-if="approvalCardContext?.targets?.length" class="approval-card-targets">
                  <div class="approval-card-section-head">
                    <el-icon><Aim /></el-icon>
                    <span>待利用漏洞 ({{ approvalCardContext.targets.length }})</span>
                  </div>
                  <div class="approval-card-target-list">
                    <div v-for="(t, i) in approvalCardContext.targets.slice(0, 6)" :key="i" class="approval-card-target-item">
                      <span class="approval-card-sev" :class="`sev-${t.severity}`">{{ (t.severity || '?').toUpperCase() }}</span>
                      <span class="approval-card-target-name">{{ t.name }}</span>
                      <code v-if="t.cve" class="approval-card-target-cve">{{ t.cve }}</code>
                      <span v-if="t.port" class="approval-card-target-port">:{{ t.port }}</span>
                    </div>
                  </div>
                </div>

                <!-- Recommendation -->
                <div v-if="approvalCardContext?.recommendation" class="approval-card-recommendation">
                  <div class="approval-card-section-head">
                    <el-icon><Promotion /></el-icon>
                    <span>Agent 建议</span>
                  </div>
                  <p class="approval-card-recommendation-text">{{ approvalCardContext.recommendation }}</p>
                </div>

                <!-- What happens -->
                <div class="approval-card-consequences">
                  <div class="approval-card-consequence approve-consequence">
                    <el-icon><CircleCheck /></el-icon>
                    <span>批准后将进入利用阶段, 尝试对上述漏洞发起攻击获取立足点</span>
                  </div>
                  <div class="approval-card-consequence reject-consequence">
                    <el-icon><CircleCloseFilled /></el-icon>
                    <span>拒绝将跳过利用阶段, 直接生成报告</span>
                  </div>
                </div>

                <!-- Actions -->
                <div class="approval-card-actions">
                  <el-button type="primary" :loading="approving" @click="doApprove(true)">
                    <el-icon><Check /></el-icon>
                    批准并开始利用
                  </el-button>
                  <el-button type="danger" plain :loading="approving" @click="doApprove(false)">
                    <el-icon><Close /></el-icon>
                    拒绝, 直接生成报告
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

          <div
            v-for="bubble in activeToolStreamBubbles"
            :key="`tool-${bubble.sid}`"
            class="tool-stream-bubble"
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

        <transition name="fade">
          <button v-if="showJumpBtn" class="jump-latest" @click="jumpToBottom">
            <el-icon><ArrowDown /></el-icon>
            跳转最新
          </button>
        </transition>
      </div>

      <!-- 右侧策略面板，与左侧工具链对称 -->
      <div v-if="strategyPlan.length > 0" class="strategy-side">
        <div class="strategy-rail">
          <div class="strategy-rail-header">
            <span class="strategy-rail-title">策略状态</span>
            <span class="strategy-rail-count">{{ strategyPlan.length }}</span>
          </div>
          <div class="strategy-rail-list">
            <div
              v-for="(item, i) in strategyPlan"
              :key="item.key"
              class="strategy-node"
            >
              <div class="strategy-connector" v-if="i > 0" />
              <div class="strategy-dot" :class="item.enforced ? 'dot-success' : 'dot-warning'" />
              <div class="strategy-body">
                <div class="strategy-label">{{ item.label }}</div>
                <div class="strategy-detail" v-if="item.detail">{{ item.detail }}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>

    <footer class="chat-footer">
      <section class="composer" :class="{ 'composer-flash': composerFlashing }">
        <div v-if="branches.length || activeBranch" class="branch-status-band">
          <span class="band-icon">
            <el-icon><Share /></el-icon>
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
                全部分支 ({{ branches.length }}/{{ state.maxBranchesPerTask || 12 }})
              </button>
            </template>
            <div class="branch-popover-body">
              <div class="branch-popover-head">
                <strong>分支</strong>
                <span class="branch-popover-hint">点击「切到」激活, 「继续运行」恢复, 「暂停」挂起当前分支</span>
              </div>
              <div class="branch-popover-tree">
                <BranchTreeNode
                  v-for="node in branchRoots"
                  :key="node.branch_id"
                  :node="node"
                  :children-by-parent="branchChildrenByParent"
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
        <div v-if="forkAnchor" class="fork-anchor-band">
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
    </footer>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  Aim,
  ArrowDown,
  ArrowLeft,
  ChatLineRound,
  Check,
  CircleCheck,
  CircleCloseFilled,
  Close,
  Document,
  Loading,
  Memo,
  Promotion,
  Share,
  Warning,
  WarningFilled,
} from '@element-plus/icons-vue'
import { api } from '@/api'
import { useTaskListStore } from '@/stores/taskList'
import { useTaskLiveStore } from '@/stores/taskLive'
import { trackEvent } from '@/metrics/tracker'
import BranchTreeNode from '@/components/BranchTreeNode.vue'
import ChatBubble from '@/components/ChatBubble.vue'
import DecisionCheckpointCard from '@/components/DecisionCheckpointCard.vue'
import { resolveToolDisplay } from '@/utils/toolDisplay'
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
  // 按 activeBranchId 切片: 后端在 ``push_decision`` / WS sink 注入了
  // ``branch_id``, 切到老分支时 chat 流和 ToolChainRail 只显示属于该
  // 分支的事件; 没有 branch_id 的"全局事件"(老快照、approval_required
  // 等系统事件)始终展示, 避免审批气泡因切分支而消失。
  const activeBid = state.value?.activeBranchId || ''
  const filtered = activeBid
    ? raw.filter((ev) => {
        const bid = String((ev || {}).branch_id || '')
        return !bid || bid === activeBid
      })
    : raw
  // slice 后再 sort, 不影响 store 内部数组
  return filtered.slice().sort(_compareEvents)
})
const llmStreams = computed(() => state.value?.llmStreams || {})
const isRunning = computed(() => ['pending', 'running'].includes(task.value?.status || ''))
const needsApproval = computed(() => task.value?.current_phase === 'awaiting_approval')
const approvalState = computed(() => state.value.approvalState)
const approving = computed(() => approvalState.value === 'submitting')
const showApprovalActions = computed(() => needsApproval.value && approvalState.value === 'idle')
const pendingCheckpoint = computed(() => state.value?.pendingCheckpoint || null)
const checkpointSubmitting = computed(() => state.value?.checkpointState === 'submitting')

const strategyPlan = computed(() => {
  const t = task.value
  if (!t) return []

  const parsed: Record<string, unknown> = t.parsed_intent || {}
  if (!parsed || !Object.keys(parsed).length) return []

  const items: Array<{ key: string; label: string; detail: string; enforced: boolean }> = []

  const enforcedActions = new Set(
    (decisionEvents.value || [])
      .filter(e => e.action === 'operator_plan_applied'
                || e.action === 'intent_to_plan_converted'
                || e.action === 'intent_recon_only')
      .map(e => String(e.action))
  )
  const hasEnforcement = enforcedActions.size > 0

  const phases = Array.isArray(parsed.pentest_phase) ? parsed.pentest_phase as string[] : []
  if (phases.length) {
    const EXPLOIT_PHASES = new Set(['exploit', 'full_chain', 'post_exploit'])
    const hasExploit = phases.some(p => EXPLOIT_PHASES.has(p))
    const phaseLabels: Record<string, string> = {
      recon: '侦察', exploit: '利用', post_exploit: '后渗透', full_chain: '完整链',
    }
    const display = phases.map(p => phaseLabels[p] || p).join(' → ')
    items.push({
      key: 'phases',
      label: `执行阶段: ${display}`,
      detail: hasExploit ? '含利用阶段' : '仅侦察/扫描',
      enforced: true,
    })
  }

  const priorityVulns = Array.isArray(parsed.priority_vulns) ? parsed.priority_vulns as string[] : []
  if (priorityVulns.length) {
    items.push({
      key: 'priority_vulns',
      label: `重点漏洞: ${priorityVulns.slice(0, 5).join(', ')}`,
      detail: hasEnforcement ? '已注入扫描约束' : '等待执行',
      enforced: hasEnforcement,
    })
  }

  const intents = Array.isArray(parsed.intents) ? parsed.intents as string[] : []
  if (intents.length) {
    items.push({
      key: 'intents',
      label: `意图标签: ${intents.slice(0, 5).join(', ')}`,
      detail: hasEnforcement ? '已转换为工具约束' : '等待执行',
      enforced: hasEnforcement,
    })
  }

  // 兜底：parsed_intent 存在但没有具体策略项时，至少展示目标信息
  if (!items.length) {
    const targets = Array.isArray(parsed.targets) ? parsed.targets as string[] : []
    if (targets.length) {
      items.push({
        key: 'target_fallback',
        label: `目标: ${targets.slice(0, 3).join(', ')}`,
        detail: '默认策略',
        enforced: true,
      })
    }
  }

  return items
})

// ── 审批卡片上下文: 优先从 pendingCheckpoint 取(最丰富),
//    再回退到 approval_required 事件里的轻量字段 ─────────
interface ApprovalCardContext {
  phase: string
  phaseLabel: string
  risk: string
  riskType: 'danger' | 'warning' | 'info' | ''
  summary: string
  targets: { name: string; severity: string; vuln_id: string; cve?: string; port?: number }[]
  recommendation: string
  exploitableCount: number
}

const approvalCardContext = computed<ApprovalCardContext | null>(() => {
  // Priority 1: pending checkpoint (from node_human_approval)
  const ckpt = pendingCheckpoint.value
  if (ckpt && (ckpt.checkpoint_type === 'exploit_gate' || ckpt.checkpoint_type === 'post_foothold_gate')) {
    const ctx = (ckpt.context || {}) as Record<string, unknown>
    const topTargets = (ctx.top_targets || []) as { name: string; severity: string; vuln_id: string; cve?: string; port?: number }[]
    const count = Number(ctx.exploitable_count ?? topTargets.length)
    return {
      phase: ckpt.phase || 'awaiting_approval',
      phaseLabel: ckpt.phase === 'post_foothold_approval' ? '立足后确认' : '利用前确认',
      risk: ckpt.risk || '',
      riskType: (ckpt.risk === '高风险' ? 'danger' : ckpt.risk === '中等风险' ? 'warning' : 'info') as ApprovalCardContext['riskType'],
      summary: ckpt.summary || `系统已识别 ${count} 个可利用漏洞，等待你的授权再开始利用。`,
      targets: topTargets,
      recommendation: ckpt.recommendation || '批准后将进入利用阶段;拒绝则跳过利用并直接生成报告。',
      exploitableCount: count,
    }
  }

  // Priority 2: last approval message with inline context
  const msgs = messages.value
  for (let i = msgs.length - 1; i >= 0; i--) {
    const m = msgs[i]
    if ((m.action === 'approval_required' || m.action === 'approval') && m.isLastApproval) {
      const targets = (m.topTargets || []) as ApprovalCardContext['targets']
      const count = Number(m.exploitableCount ?? targets.length)
      if (count > 0 || targets.length > 0) {
        return {
          phase: 'awaiting_approval',
          phaseLabel: '利用前确认',
          risk: m.risk || '',
          riskType: (m.risk === '高风险' ? 'danger' : m.risk === '中等风险' ? 'warning' : 'info') as ApprovalCardContext['riskType'],
          summary: m.text?.split('\n').slice(1).join('\n') || `系统已识别 ${count} 个可利用漏洞，等待你的授权。`,
          targets,
          recommendation: '批准后将进入利用阶段;拒绝则跳过利用并直接生成报告。',
          exploitableCount: count,
        }
      }
    }
  }

  // No context available — still show a card, but minimal
  return null
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

  const events = decisionEvents.value.slice(-200)
  // 找到最新一个审批气泡的 id, 用于决定哪条审批 bubble 可交互。
  // 同时认 'approval_required' (后端 WS bus 推) 和 'approval'
  // (phase_log 文本"等待审批"派生) 两种 action: 任何一种事件存在都能让
  // 用户点按钮, 哪怕另一条因为 WS race / 时间戳排序错位丢失了, 兜底通路
  // 始终在线 — 这是用户截图里 "审批节点卡片有但按钮没有" 的根本修复。
  let lastApprovalId = ''
  for (let i = events.length - 1; i >= 0; i--) {
    const a = events[i]?.action
    if (a === 'approval_required' || a === 'approval') {
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

    // 操作员实时重规划: 由后端 ``backend.agents.operator_replanner`` 在
    // chat 触发 fork 时同步生成的 OperatorPlan, 走专用高亮卡片渲染。
    if (entry.action === 'operator_replan') {
      const headBits = ['操作员重规划']
      if (entry.phase) headBits.push(entry.phase)
      const summary = entry.message || entry.operator_plan?.intent_summary || '已重规划'
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'primary',
        action: 'operator_replan',
        text: `${headBits.join(' · ')}\n${summary}`,
        timestamp: time,
        purpose: entry.purpose || '',
        plan: entry.plan || [],
        thinking: '',
        thinkingPreview: '',
        thinkingHasMore: false,
        thinkingFullLen: 0,
        reasoning: '',
        operatorPlan: entry.operator_plan ? (() => {
          const raw = entry.operator_plan
          const normalize = (arr) => {
            if (!Array.isArray(arr)) return []
            return arr.map(x => {
              if (typeof x === 'string') return x
              if (x && typeof x === 'object') return x.name || x.tool || x.value || String(x)
              return String(x)
            }).filter(Boolean)
          }
          return { ...raw, preferred_tools: normalize(raw.preferred_tools), avoided_tools: normalize(raw.avoided_tools), keyword_hints: normalize(raw.keyword_hints) }
        })() : null,
      })
      return
    }

    // 初始策略: 由后端 create_task 在任务创建后立即推送,
    // 让用户在执行开始前就能看到 Agent 对目标的理解和即将遵循的路径。
    if (entry.action === 'initial_plan') {
      const headBits = ['初始策略']
      if (entry.phase) headBits.push(entry.phase)
      const summary = entry.message || '已生成初始渗透策略'
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'primary',
        action: 'initial_plan',
        text: `${headBits.join(' · ')}\n${summary}`,
        timestamp: time,
        purpose: entry.purpose || '',
        plan: entry.plan || [],
        thinking: entry.thinking || '',
        thinkingPreview: (entry.thinking || '').slice(0, 320),
        thinkingHasMore: (entry.thinking || '').length > 320,
        thinkingFullLen: (entry.thinking || '').length,
        reasoning: '',
      })
      return
    }

    // 战术层 (planner / agent.run) 真消费 OperatorPlan 后推送的事件;
    // 与 operator_replan 卡片的区别在于: replan 是"我听懂了你要做什么",
    // plan_applied 是"我把你说的工具偏好真的塞进了本阶段的执行序列",
    // 这两条事件配合可以让用户清楚看到"路由 + 工具选型"两层都改了。
    if (entry.action === 'operator_plan_applied') {
      const headBits = ['战术计划已应用']
      if (entry.phase) headBits.push(entry.phase)
      if (entry.consumer) headBits.push(entry.consumer)
      const headline = entry.message || '已注入工具偏好'
      const text = `${headBits.join(' · ')}\n${headline}`
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'success',
        action: 'operator_plan_applied',
        text,
        timestamp: time,
        purpose: entry.purpose || '',
        plan: entry.plan || [],
        thinking: String(entry.thinking || '').trim(),
        thinkingPreview: String(entry.thinking || '').trim().slice(0, 320),
        thinkingHasMore: String(entry.thinking || '').length > 320,
        thinkingFullLen: String(entry.thinking || '').length,
        reasoning: '',
      })
      return
    }

    if (entry.action === 'thought') {
      const roundLabel = entry.round ? `第 ${entry.round} 轮` : ''
      const vulnLabel = entry.vuln_name ? ` · ${entry.vuln_name}` : ''
      const head = `AI 推理${roundLabel ? ' · ' + roundLabel : ''}${vulnLabel}`
      // 头部展示 message(短句状态), 不放 thinking, 避免 ChatBubble 文本框
      // 把整段推理压成单行、同时还要再"展开完整推理". 推理正文走下面的
      // thinkingPreview / thinking 字段, 默认就在卡片里渲染一段摘要,
      // 解决"AI 决策结果过于精简、只有一行 head" 的问题。
      const headline = String(entry.message || '').trim()
      const thinkingFull = String(entry.thinking || '').trim()
      const reasoningFull = String(entry.reasoning || '').trim()
      const PREVIEW_LIMIT = 600
      const preview = thinkingFull.length > PREVIEW_LIMIT
        ? thinkingFull.slice(0, PREVIEW_LIMIT).replace(/\s+$/, '') + '…'
        : thinkingFull
      const text = headline ? `${head}\n${headline}` : head
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'primary',
        action: 'thought',
        text,
        timestamp: time,
        thinking: thinkingFull,
        thinkingPreview: preview,
        thinkingHasMore: thinkingFull.length > PREVIEW_LIMIT,
        thinkingFullLen: thinkingFull.length,
        reasoning: reasoningFull,
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
      const toolLabel = resolveToolDisplay({
        display_tool: entry.display_tool,
        tool: entry.tool,
        command: entry.command,
        purpose: entry.purpose,
      })
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
      const toolLabel = resolveToolDisplay({
        display_tool: entry.display_tool,
        tool: entry.tool,
        command: entry.command,
        purpose: entry.purpose,
      })
      // tool_start 通常没有 stdout/stderr,只是状态打点;这里给一个最小卡片
      // 让用户至少看到「工具/阶段/目的」三件套,而不是工具链上多了节点但
      // 主聊天区却找不到对应气泡。
      const detailLines = []
      if (entry.phase) detailLines.push(`阶段 ${entry.phase}`)
      if (entry.purpose) detailLines.push(`目的 ${entry.purpose}`)
      if (entry.message) detailLines.push(entry.message)
      out.push({
        id: baseId,
        role: 'agent',
        tone: 'primary',
        text: `工具调用 · ${toolLabel}${detailLines.length ? '\n' + detailLines.join('\n') : ''}`,
        timestamp: time,
        payloads: entry.command
          ? [{ title: 'Command', language: inferPayloadLang(entry.command), code: entry.command }]
          : null,
      })
      return
    }

    if (entry.action === 'tool_result') {
      const exitText = entry.exit_code ?? '-'
      const elapsedText = entry.elapsed_ms ? `${entry.elapsed_ms}ms` : '-'
      const toolLabel = resolveToolDisplay({
        display_tool: entry.display_tool,
        tool: entry.tool,
        command: entry.command,
        purpose: entry.purpose,
      })
      const command = entry.command || ''
      const stdout = entry.stdout || ''
      const stderr = entry.stderr || ''
      // 给 tool_result 也补一组 payload 卡片: 即便没有命令也至少展示
      // 一个 Output 占位,避免「工具链上有节点但聊天区一片空白」。
      const payloads = (command || stdout || stderr)
        ? buildExecPayloads(command, stdout, stderr, {
            runtimeCommand: entry.runtime_command || '',
            truncated: Boolean(entry.truncated),
            totalLen: Number(entry.total_len || 0),
          })
        : [{ title: 'Output', language: 'text', code: '(仅状态事件,无命令输出)' }]
      out.push({
        id: baseId,
        role: 'agent',
        tone: Number(exitText) === 0 ? 'success' : 'danger',
        text: `调用结果 · ${toolLabel}\nexit=${exitText} ｜ elapsed=${elapsedText}${entry.message ? '\n' + entry.message : ''}`.trim(),
        timestamp: time,
        payloads,
      })
      return
    }

    if (entry.action === 'tool_executed') {
      const toolLabel = resolveToolDisplay({
        display_tool: entry.display_tool,
        tool: entry.tool,
        command: entry.command,
        purpose: entry.purpose,
      })
      const statusText = entry.status || entry.message || ''
      const cleanMsg = entry.message
        ? entry.message.replace(/^\s*\w+:\s*/, '').trim()
        : ''
      out.push({
        id: baseId,
        role: 'agent',
        tone: entry.tone === 'warn' ? 'warning' : 'info',
        text: `工具完成 · ${toolLabel}${cleanMsg ? '\n' + cleanMsg : ''}${statusText ? '\n' + statusText : ''}`.trim(),
        timestamp: time,
        payloads: entry.command
          ? [{ title: 'Command', language: 'bash', code: entry.command }]
          : null,
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
        exploitableCount: entry.exploitable_count ?? 0,
        topTargets: entry.top_targets ?? [],
        risk: entry.risk ?? '',
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
        action: 'approval',
        isLastApproval: baseId === lastApprovalId,
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

  // 给每条 message 注入原始事件 id / ISO 时间戳, 供"在此分叉"按钮把
  // ``from_event_id`` / ``from_event_ts`` 透传到后端。message.timestamp
  // 已经经过 formatTime 转成本地时分秒, 不能直接用作分叉锚点。
  const tsByBase = {}
  for (const ev of events) {
    if (ev?.id) tsByBase[ev.id] = ev.timestamp || ''
  }
  for (const m of out) {
    if (m && tsByBase[m.id] && !m.eventTs) {
      m.eventTs = tsByBase[m.id]
      m.eventId = m.id
    }
  }

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

// 工具命令的实时 stdout/stderr 流; 只展示尾部 N 行让用户看见工具正在干活,
// 避免「ToolChainRail 上有节点但聊天区一片空白」的体感。命令完成后对应的
// tool_result 会落到主消息流里, 这块可以淡出。
const TOOL_STREAM_TAIL_VIEW = 12

const activeToolStreamBubbles = computed(() => {
  const streams = state.value?.toolStreams || {}
  const result = []
  // 显示的 stream id 跟 ``stream_id`` 一致 (executor 是 ``{display_tool}-{hash}``),
  // 这里直接拿 stream id 第一段当工具名展示。
  for (const [sid, lines] of Object.entries(streams)) {
    if (!Array.isArray(lines) || !lines.length) continue
    const tail = lines.slice(-TOOL_STREAM_TAIL_VIEW)
    const tool = String(sid).split('-')[0] || 'tool'
    result.push({ sid, tool, lines: tail, total: lines.length })
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

// "在此处分叉"上下文: 当用户右键/点击某条历史 chat bubble 选择"在此分叉"时,
// 把对应 decision_event 的 id + timestamp 暂存到这里, 下一次 sendMessage
// 会把它们作为 ``from_event_id`` / ``from_event_ts`` 一并传给后端,
// 让 BranchManager 走 ``find_checkpoint_at_or_before`` 选定 source checkpoint。
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

// 把分支按 parent_branch_id 聚合成 forest, 给 popover 内嵌 BranchTreeNode 用,
// 同时也复用现有 sibling navigator 的查询逻辑。
const branchChildrenByParent = computed(() => {
  const map = new Map()
  for (const it of branches.value) {
    const key = it.parent_branch_id || ''
    if (!map.has(key)) map.set(key, [])
    map.get(key).push(it)
  }
  for (const arr of map.values()) {
    arr.sort((a, b) => (a.created_at || '').localeCompare(b.created_at || ''))
  }
  return map
})

const branchRoots = computed(() => {
  const map = branchChildrenByParent.value
  return map.get('') || map.get(null) || []
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
.strategy-rail {
  width: 170px;
  min-width: 170px;
  display: flex;
  flex-direction: column;
  border-left: 1px solid var(--border);
  background: var(--bg-elevated);
  overflow: hidden;
  height: 100%;
}
.strategy-rail-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.strategy-rail-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
}
.strategy-rail-count {
  font-size: 10px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  background: var(--bg-hover);
  padding: 1px 6px;
  border-radius: 8px;
}
.strategy-rail-list {
  flex: 1;
  overflow-y: auto;
  padding: 8px 0;
}
.strategy-node {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 6px 12px;
  position: relative;
}
.strategy-connector {
  position: absolute;
  left: 17px;
  top: -4px;
  width: 1px;
  height: 10px;
  background: var(--border);
}
.strategy-dot {
  width: 8px;
  height: 8px;
  min-width: 8px;
  border-radius: 50%;
  margin-top: 3px;
  border: 1.5px solid var(--border);
  background: var(--bg-base);
  transition: all 0.15s;
}
.strategy-body {
  display: flex;
  flex-direction: column;
  min-width: 0;
  flex: 1;
  gap: 2px;
}
.strategy-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-secondary);
  line-height: 1.35;
  word-break: break-word;
}
.strategy-detail {
  font-size: 10px;
  color: var(--text-muted);
  line-height: 1.3;
}

.bubble-stream {
  max-width: 1080px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.bubble-anchor {
  position: relative;
  scroll-margin-top: 40px;
  border-radius: var(--radius-md);
  transition: background 0.4s ease, box-shadow 0.4s ease;
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

/* ── 审批卡片 (取代原来的 inline-approval "是否继续执行?") ── */
.approval-card {
  margin: 6px 0 0;
  border: 1px solid color-mix(in srgb, var(--accent-yellow) 35%, transparent);
  border-left: 4px solid var(--accent-yellow);
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--accent-yellow) 5%, var(--bg-elevated));
  overflow: hidden;
}

.approval-card-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 14px 10px;
  border-bottom: 1px solid color-mix(in srgb, var(--accent-yellow) 15%, transparent);
}

.approval-card-header-left {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  flex: 1;
  min-width: 0;
}

.approval-card-icon {
  margin-top: 2px;
  font-size: 18px;
  color: var(--accent-yellow);
  flex-shrink: 0;
}

.approval-card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 4px;
}

.approval-card-phase-tag {
  font-size: 11px;
}

.approval-card-subtitle {
  font-size: 12.5px;
  color: var(--text-secondary);
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-word;
}

.approval-card-header-right {
  flex-shrink: 0;
}

/* targets */
.approval-card-targets {
  padding: 10px 14px;
  border-bottom: 1px solid color-mix(in srgb, var(--accent-yellow) 10%, transparent);
}

.approval-card-section-head {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 8px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
}

.approval-card-target-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.approval-card-target-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 8px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--bg-base) 80%, var(--accent-yellow) 5%);
  font-size: 12px;
  line-height: 1.5;
}

.approval-card-sev {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 48px;
  padding: 1px 6px;
  font-size: 10px;
  font-weight: 700;
  border-radius: 3px;
  letter-spacing: 0.3px;
  font-family: var(--font-mono);
  flex-shrink: 0;
}

.approval-card-sev.sev-critical {
  background: color-mix(in srgb, #f85149 25%, transparent);
  color: #f85149;
  border: 1px solid color-mix(in srgb, #f85149 45%, transparent);
}

.approval-card-sev.sev-high {
  background: color-mix(in srgb, #d29922 22%, transparent);
  color: #d29922;
  border: 1px solid color-mix(in srgb, #d29922 40%, transparent);
}

.approval-card-sev.sev-medium {
  background: color-mix(in srgb, var(--accent-blue) 18%, transparent);
  color: var(--accent-blue);
  border: 1px solid color-mix(in srgb, var(--accent-blue) 35%, transparent);
}

.approval-card-sev.sev-low,
.approval-card-sev.sev-info {
  background: color-mix(in srgb, var(--text-secondary) 12%, transparent);
  color: var(--text-secondary);
  border: 1px solid color-mix(in srgb, var(--text-secondary) 20%, transparent);
}

.approval-card-target-name {
  color: var(--text-primary);
  font-weight: 500;
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.approval-card-target-cve {
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--accent-blue);
  background: color-mix(in srgb, var(--accent-blue) 8%, transparent);
  padding: 1px 6px;
  border-radius: 3px;
  flex-shrink: 0;
}

.approval-card-target-port {
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  flex-shrink: 0;
}

/* recommendation */
.approval-card-recommendation {
  padding: 10px 14px;
  border-bottom: 1px solid color-mix(in srgb, var(--accent-yellow) 10%, transparent);
}

.approval-card-recommendation-text {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-word;
}

/* consequences */
.approval-card-consequences {
  padding: 8px 14px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  border-bottom: 1px solid color-mix(in srgb, var(--accent-yellow) 10%, transparent);
}

.approval-card-consequence {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11.5px;
  line-height: 1.45;
  color: var(--text-secondary);
}

.approve-consequence .el-icon {
  color: var(--accent-green, #3fb950);
  flex-shrink: 0;
}

.reject-consequence .el-icon {
  color: var(--accent-red, #f85149);
  flex-shrink: 0;
}

/* actions */
.approval-card-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  background: color-mix(in srgb, var(--bg-base) 60%, transparent);
}

.approval-card-actions .el-button {
  font-size: 13px;
}

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
