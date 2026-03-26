<template>
  <div class="chain-wrap">
    <!-- 顶部进度条 -->
    <div class="chain-progress-bar">
      <div
          class="chain-progress-fill"
          :style="{ width: overallProgress + '%' }"
          :class="{ 'fill-failed': hasFailed, 'fill-done': isCompleted }"
      />
    </div>

    <!-- 阶段节点 -->
    <div class="chain-stages">
      <template v-for="(stage, idx) in stages" :key="stage.id">
        <!-- 连接线 -->
        <div v-if="idx > 0" class="chain-connector">
          <div class="connector-line" :class="getConnectorClass(idx)" />
          <!-- 数据流动动画 -->
          <div v-if="isFlowing(idx)" class="connector-pulse" />
        </div>

        <!-- 节点 -->
        <div
            class="stage-node"
            :class="[`node-${getStageStatus(stage.id)}`, { 'node-active': isActive(stage.id) }]"
            @click="onStageClick(stage)"
        >
          <div class="node-icon">
            <component :is="stage.icon" v-if="isCompleted_(stage.id) || hasFailed_(stage.id)" />
            <el-icon v-else-if="isActive(stage.id)" class="spin">
              <Loading />
            </el-icon>
            <component :is="stage.icon" v-else />
          </div>

          <div class="node-label">{{ stage.label }}</div>

          <!-- 阶段统计徽章 -->
          <div v-if="getStageBadge(stage.id)" class="node-badge" :class="getBadgeClass(stage.id)">
            {{ getStageBadge(stage.id) }}
          </div>

          <!-- 时间戳 -->
          <div v-if="getStageTime(stage.id)" class="node-time">
            {{ getStageTime(stage.id) }}
          </div>

          <!-- 人工审批指示 -->
          <div v-if="stage.id === 'exploit' && needsApproval" class="approval-indicator">
            <el-icon><Bell /></el-icon>
            待审批
          </div>
        </div>
      </template>
    </div>

    <!-- 当前阶段详情 -->
    <transition name="fade">
      <div v-if="activeStageDetail" class="stage-detail">
        <div class="detail-header">
          <span class="detail-phase">{{ activeStageDetail.label }}</span>
          <span class="detail-status" :class="`status-${activeStageDetail.status}`">
            {{ statusText(activeStageDetail.status) }}
          </span>
        </div>
        <div class="detail-content">
          <slot :name="`detail-${activeStageDetail.id}`" :stage="activeStageDetail">
            <p class="detail-default">{{ activeStageDetail.desc }}</p>
          </slot>
        </div>
      </div>
    </transition>

    <!-- 审批操作区 -->
    <transition name="fade">
      <div v-if="needsApproval && canApprove" class="approval-bar">
        <div class="approval-info">
          <el-icon class="approval-icon"><WarningFilled /></el-icon>
          <div>
            <div class="approval-title">发现可利用漏洞，等待授权确认</div>
            <div class="approval-sub">
              共 <strong>{{ exploitableCount }}</strong> 个漏洞待利用，请确认授权范围后继续
            </div>
          </div>
        </div>
        <div class="approval-actions">
          <el-button type="danger" plain size="small" @click="$emit('reject')" :loading="approving">
            <el-icon><Close /></el-icon> 跳过利用
          </el-button>
          <el-button type="success" size="small" @click="$emit('approve')" :loading="approving">
            <el-icon><Check /></el-icon> 授权并继续
          </el-button>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import {
  Search, Warning, Aim, Lock, Document,
  Loading, Bell, Check, Close, WarningFilled,
  CircleCheck,
} from '@element-plus/icons-vue'

const props = defineProps({
  // 当前所在阶段 id
  currentPhase: { type: String, default: 'init' },
  // 任务整体状态
  status: { type: String, default: 'pending' },
  // 各阶段开始时间 Map { phase_id: isoString }
  phaseTimes: { type: Object, default: () => ({}) },
  // 漏洞发现数
  findingsCount: { type: Number, default: 0 },
  // 可利用漏洞数
  exploitableCount: { type: Number, default: 0 },
  // 是否已 get shell
  gotShell: { type: Boolean, default: false },
  // 是否需要人工审批
  needsApproval: { type: Boolean, default: false },
  // 审批按钮是否显示（仅 owner/admin 可见）
  canApprove: { type: Boolean, default: true },
  // 审批加载中
  approving: { type: Boolean, default: false },
})

defineEmits(['approve', 'reject', 'stage-click'])

const PHASE_ORDER = ['recon', 'vuln_scan', 'exploit_decision', 'exploit', 'post_exploit', 'report']

const stages = [
  { id: 'recon',            label: '侦察',     icon: Search,       desc: 'Nmap 端口扫描 + Gobuster 路径爆破' },
  { id: 'vuln_scan',        label: '漏洞扫描',  icon: Warning,      desc: 'Nuclei CVE 检测 + Nikto Web 扫描' },
  { id: 'exploit_decision', label: 'AI 决策',  icon: Aim,          desc: 'LLM 分析漏洞优先级，制定利用策略' },
  { id: 'exploit',          label: '漏洞利用',  icon: Aim,          desc: 'Metasploit + PoC 利用' },
  { id: 'post_exploit',     label: '后渗透',   icon: Lock,         desc: '权限提升 · 信息收集 · 横向移动' },
  { id: 'report',           label: '报告生成',  icon: Document,     desc: '汇总发现，生成专业安全报告' },
]

const selectedStage = ref(null)
const currentIdx = computed(() => PHASE_ORDER.indexOf(props.currentPhase))
const isCompleted = computed(() => props.status === 'completed')
const hasFailed   = computed(() => props.status === 'failed')

function getStageStatus(id) {
  const idx = PHASE_ORDER.indexOf(id)
  if (idx < 0) return 'pending'
  if (hasFailed.value && idx === currentIdx.value) return 'failed'
  if (idx < currentIdx.value) return 'done'
  if (idx === currentIdx.value) return isCompleted.value ? 'done' : 'active'
  return 'pending'
}
function isCompleted_(id) { return getStageStatus(id) === 'done' }
function hasFailed_(id)   { return getStageStatus(id) === 'failed' }
function isActive(id)     { return getStageStatus(id) === 'active' && props.status === 'running' }

function isFlowing(idx) {
  // 左侧节点 done，右侧节点 active
  const leftId  = stages[idx - 1]?.id
  const rightId = stages[idx]?.id
  return getStageStatus(leftId) === 'done' && getStageStatus(rightId) === 'active'
}

function getConnectorClass(idx) {
  const leftId = stages[idx - 1]?.id
  const s = getStageStatus(leftId)
  return `conn-${s}`
}

// 各阶段右上角徽章
function getStageBadge(id) {
  if (id === 'vuln_scan' && props.findingsCount > 0)
    return `${props.findingsCount} 漏洞`
  if (id === 'exploit' && props.exploitableCount > 0)
    return `${props.exploitableCount} 可利用`
  if (id === 'post_exploit' && props.gotShell)
    return 'Shell ✓'
  return null
}
function getBadgeClass(id) {
  if (id === 'exploit' || id === 'post_exploit') return 'badge-danger'
  return 'badge-warn'
}

// 阶段时间标注
function getStageTime(id) {
  const t = props.phaseTimes[id]
  if (!t) return null
  return new Date(t).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

// 整体进度（0-100）
const overallProgress = computed(() => {
  if (isCompleted.value) return 100
  if (currentIdx.value < 0) return 0
  return Math.round(((currentIdx.value) / PHASE_ORDER.length) * 100)
})

const activeStageDetail = computed(() => {
  const stage = selectedStage.value
      || stages.find(s => s.id === props.currentPhase)
  if (!stage) return null
  return { ...stage, status: getStageStatus(stage.id) }
})

function onStageClick(stage) {
  selectedStage.value = selectedStage.value?.id === stage.id ? null : stage
}

function statusText(s) {
  return { done: '已完成', active: '进行中', pending: '待执行', failed: '失败' }[s] || s
}
</script>

<style scoped>
.chain-wrap {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

/* ── 进度条 ── */
.chain-progress-bar {
  height: 3px;
  background: var(--bg-hover);
}
.chain-progress-fill {
  height: 100%;
  background: var(--accent-blue);
  transition: width 0.6s ease;
}
.chain-progress-fill.fill-done   { background: var(--accent-green); }
.chain-progress-fill.fill-failed { background: var(--accent-red); }

/* ── 阶段横排 ── */
.chain-stages {
  display: flex;
  align-items: center;
  padding: 20px 24px;
  gap: 0;
  overflow-x: auto;
}

/* ── 连接线 ── */
.chain-connector {
  flex: 1;
  min-width: 20px;
  max-width: 60px;
  position: relative;
  height: 2px;
}
.connector-line {
  width: 100%;
  height: 2px;
  background: var(--border);
  transition: background 0.4s;
}
.conn-done   .connector-line { background: var(--accent-blue); }
.conn-active .connector-line { background: var(--accent-blue); }
.conn-failed .connector-line { background: var(--accent-red); }

.connector-pulse {
  position: absolute;
  top: -3px;
  left: 0;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent-blue);
  animation: flow-pulse 1.4s linear infinite;
}
@keyframes flow-pulse {
  0%   { left: 0%;   opacity: 1; }
  100% { left: 100%; opacity: 0; }
}

/* ── 节点 ── */
.stage-node {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  position: relative;
  cursor: pointer;
  padding: 8px 6px;
  border-radius: var(--radius-md);
  transition: background 0.15s;
  min-width: 72px;
}
.stage-node:hover { background: var(--bg-hover); }

.node-icon {
  width: 42px;
  height: 42px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  border: 2px solid var(--border);
  background: var(--bg-base);
  color: var(--text-muted);
  transition: all 0.3s;
}

/* 状态变体 */
.node-pending .node-icon {
  border-color: var(--border);
  color: var(--text-muted);
}
.node-active .node-icon {
  border-color: var(--accent-blue);
  color: var(--accent-blue);
  box-shadow: 0 0 0 4px rgba(56, 139, 253, 0.15);
}
.node-done .node-icon {
  border-color: var(--accent-green);
  background: rgba(63, 185, 80, 0.1);
  color: var(--accent-green);
}
.node-failed .node-icon {
  border-color: var(--accent-red);
  background: rgba(248, 81, 73, 0.1);
  color: var(--accent-red);
}

.node-label {
  font-size: 12px;
  color: var(--text-muted);
  text-align: center;
  white-space: nowrap;
}
.node-done   .node-label { color: var(--text-secondary); }
.node-active .node-label { color: var(--accent-blue); font-weight: 500; }

.node-badge {
  position: absolute;
  top: 2px;
  right: 0;
  font-size: 10px;
  font-family: var(--font-mono);
  padding: 1px 5px;
  border-radius: 8px;
  white-space: nowrap;
}
.badge-warn   { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }
.badge-danger { background: rgba(248, 81, 73, 0.15);  color: var(--accent-red); }

.node-time {
  font-size: 10px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  white-space: nowrap;
}

.approval-indicator {
  position: absolute;
  bottom: -6px;
  left: 50%;
  transform: translateX(-50%);
  font-size: 10px;
  background: rgba(210, 153, 34, 0.2);
  color: var(--accent-yellow);
  padding: 1px 6px;
  border-radius: 8px;
  white-space: nowrap;
  display: flex;
  align-items: center;
  gap: 3px;
  border: 1px solid rgba(210, 153, 34, 0.3);
}

/* ── 阶段详情区 ── */
.stage-detail {
  border-top: 1px solid var(--border);
  padding: 14px 24px;
  background: var(--bg-base);
}
.detail-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}
.detail-phase {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}
.detail-status {
  font-size: 11px;
  font-family: var(--font-mono);
  padding: 1px 7px;
  border-radius: 8px;
}
.status-active  { background: rgba(56,139,253,.15); color: var(--accent-blue); }
.status-done    { background: rgba(63,185,80,.15);  color: var(--accent-green); }
.status-failed  { background: rgba(248,81,73,.15);  color: var(--accent-red); }
.status-pending { background: var(--bg-hover); color: var(--text-muted); }

.detail-default { font-size: 12px; color: var(--text-muted); margin: 0; }

/* ── 审批栏 ── */
.approval-bar {
  border-top: 1px solid rgba(210, 153, 34, 0.3);
  background: rgba(210, 153, 34, 0.06);
  padding: 14px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.approval-info {
  display: flex;
  align-items: center;
  gap: 12px;
}
.approval-icon {
  font-size: 20px;
  color: var(--accent-yellow);
  flex-shrink: 0;
}
.approval-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}
.approval-sub {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 2px;
}
.approval-sub strong { color: var(--accent-yellow); }
.approval-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

/* ── 动画 ── */
.spin { animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

.fade-enter-active, .fade-leave-active { transition: opacity 0.25s, transform 0.25s; }
.fade-enter-from, .fade-leave-to { opacity: 0; transform: translateY(-6px); }
</style>