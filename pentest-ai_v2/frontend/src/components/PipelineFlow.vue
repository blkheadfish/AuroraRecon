<template>
  <div class="pipeline-wrap">

    <!-- 顶部总进度条 -->
    <div class="progress-bar">
      <div
          class="progress-fill"
          :style="{ width: overallProgress + '%' }"
          :class="{ 'fill-done': status === 'completed', 'fill-fail': status === 'failed' }"
      />
    </div>

    <!-- Kill Chain 节点行 -->
    <div class="pipeline">
      <template v-for="(step, i) in steps" :key="step.key">

        <!-- 连接线 -->
        <div v-if="i > 0" class="connector" :class="getConnectorClass(i)">
          <div class="connector-track" />
          <!-- 数据流动粒子（前一节点已完成且当前节点激活时） -->
          <div v-if="isFlowing(i)" class="flow-particle" />
        </div>

        <!-- 节点 -->
        <div class="step" :class="getStepClass(step.key, i)">
          <!-- 圆形图标节点 -->
          <div class="step-node">
            <!-- 完成状态：对勾 -->
            <svg v-if="getStepClass(step.key,i)==='done'" class="icon-svg" viewBox="0 0 24 24" fill="none">
              <polyline points="20 6 9 17 4 12" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <!-- 失败状态：叉 -->
            <svg v-else-if="getStepClass(step.key,i)==='failed'" class="icon-svg" viewBox="0 0 24 24" fill="none">
              <line x1="18" y1="6" x2="6" y2="18" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
              <line x1="6" y1="6" x2="18" y2="18" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
            </svg>
            <!-- 激活状态：脉冲圆 -->
            <div v-else-if="getStepClass(step.key,i)==='active'" class="pulse-dot" />
            <!-- 等待状态：序号 -->
            <span v-else class="step-num">{{ i + 1 }}</span>

            <!-- 外圈脉冲（active 时） -->
            <div v-if="getStepClass(step.key,i)==='active'" class="pulse-ring" />
          </div>

          <!-- 节点标签 -->
          <div class="step-label">{{ step.label }}</div>

          <!-- 徽章（漏洞数 / Shell / 审批中） -->
          <div v-if="getBadge(step.key)" class="step-badge" :class="getBadgeClass(step.key)">
            {{ getBadge(step.key) }}
          </div>
        </div>

      </template>
    </div>

    <!-- 进度文字 -->
    <div class="progress-text">
      <span class="phase-label">
        <span v-if="status === 'running'" class="dot-running" />
        <span v-else-if="status === 'completed'" class="dot-done" />
        <span v-else-if="status === 'failed'" class="dot-fail" />
        {{ phaseDisplayText }}
      </span>
      <span class="progress-pct">{{ overallProgress }}%</span>
    </div>

    <!-- 审批操作栏 -->
    <transition name="slide-down">
      <div v-if="needsApproval" class="approval-bar">
        <div class="approval-left">
          <svg class="approval-icon" viewBox="0 0 24 24" fill="none">
            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <line x1="12" y1="9" x2="12" y2="13" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            <line x1="12" y1="17" x2="12.01" y2="17" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
          <div>
            <div class="approval-title">发现可利用漏洞，等待授权</div>
            <div class="approval-sub">共 <b>{{ exploitableCount }}</b> 个漏洞待利用，请确认授权范围后操作</div>
          </div>
        </div>
        <div class="approval-actions">
          <button class="btn-reject" @click="$emit('reject')" :disabled="approving">
            跳过利用
          </button>
          <button class="btn-approve" @click="$emit('approve')" :disabled="approving">
            <span v-if="approving" class="btn-loading" />
            授权并继续
          </button>
        </div>
      </div>
    </transition>

  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  currentPhase:    { type: String,  default: 'init' },
  status:          { type: String,  default: 'pending' },
  findingsCount:   { type: Number,  default: 0 },
  exploitableCount:{ type: Number,  default: 0 },
  gotShell:        { type: Boolean, default: false },
  needsApproval:   { type: Boolean, default: false },
  approving:       { type: Boolean, default: false },
})

defineEmits(['approve', 'reject'])

const steps = [
  { key: 'recon',            label: '信息侦察' },
  { key: 'vuln_scan',        label: '漏洞扫描' },
  { key: 'exploit_decision', label: 'AI 决策'  },
  { key: 'exploit',          label: '漏洞利用' },
  { key: 'post_exploit',     label: '后渗透'   },
  { key: 'report',           label: '报告生成' },
]

const phaseOrder = steps.map(s => s.key)

const currentIdx = computed(() => phaseOrder.indexOf(props.currentPhase))

const overallProgress = computed(() => {
  if (props.status === 'completed') return 100
  if (currentIdx.value < 0) return 0
  return Math.round((currentIdx.value / phaseOrder.length) * 100)
})

const phaseDisplayText = computed(() => {
  if (props.status === 'completed') return '测试完成'
  if (props.status === 'failed')    return '执行失败'
  if (props.currentPhase === 'awaiting_approval') return '等待授权确认...'
  const s = steps.find(s => s.key === props.currentPhase)
  return s ? `${s.label}中...` : '准备中...'
})

function getStepClass(key, i) {
  if (props.status === 'completed') return 'done'
  if (props.status === 'failed' && key === props.currentPhase) return 'failed'
  if (key === props.currentPhase) return 'active'
  // awaiting_approval 时 exploit 节点显示为 waiting
  if (props.currentPhase === 'awaiting_approval' && key === 'exploit') return 'waiting'
  if (i < currentIdx.value) return 'done'
  return 'pending'
}

function getConnectorClass(i) {
  const leftKey = steps[i - 1]?.key
  const s = getStepClass(leftKey, i - 1)
  return `conn-${s}`
}

function isFlowing(i) {
  const leftKey  = steps[i - 1]?.key
  const rightKey = steps[i]?.key
  return getStepClass(leftKey, i - 1) === 'done'
      && (getStepClass(rightKey, i) === 'active' || getStepClass(rightKey, i) === 'waiting')
}

function getBadge(key) {
  if (key === 'vuln_scan' && props.findingsCount > 0)
    return `${props.findingsCount} 漏洞`
  if (key === 'exploit' && props.exploitableCount > 0 && props.currentPhase !== 'awaiting_approval')
    return `${props.exploitableCount} 可利用`
  if (key === 'exploit' && props.currentPhase === 'awaiting_approval')
    return '待审批'
  if (key === 'post_exploit' && props.gotShell)
    return 'Shell ✓'
  return null
}

function getBadgeClass(key) {
  if (key === 'exploit') return 'badge-red'
  if (key === 'post_exploit' && props.gotShell) return 'badge-green'
  return 'badge-yellow'
}
</script>

<style scoped>
.pipeline-wrap {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

/* ── 总进度条 ── */
.progress-bar {
  height: 3px;
  background: var(--bg-hover);
}
.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--accent-blue) 0%, #60a5fa 100%);
  transition: width 0.8s cubic-bezier(.4,0,.2,1);
}
.progress-fill.fill-done { background: var(--accent-green); }
.progress-fill.fill-fail { background: var(--accent-red); }

/* ── Kill Chain 节点行 ── */
.pipeline {
  display: flex;
  align-items: center;
  padding: 20px 24px 12px;
  gap: 0;
  overflow-x: auto;
}

/* ── 连接线 ── */
.connector {
  flex: 1;
  min-width: 16px;
  max-width: 56px;
  height: 2px;
  position: relative;
}
.connector-track {
  width: 100%;
  height: 2px;
  background: var(--border);
  transition: background 0.4s;
}
.conn-done   .connector-track { background: var(--accent-blue); }
.conn-active .connector-track { background: var(--accent-blue); }
.conn-waiting .connector-track { background: var(--accent-yellow); }
.conn-failed .connector-track { background: var(--accent-red); }

/* 流动粒子 */
.flow-particle {
  position: absolute;
  top: -3px;
  left: 0;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent-blue);
  box-shadow: 0 0 6px var(--accent-blue);
  animation: flow 1.2s ease-in-out infinite;
}
@keyframes flow {
  0%   { left: 0%;   opacity: 1; transform: scale(1); }
  80%  { opacity: 1; }
  100% { left: 100%; opacity: 0; transform: scale(0.5); }
}

/* ── 节点 ── */
.step {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  position: relative;
  min-width: 64px;
  cursor: default;
}

.step-node {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  border: 2px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-elevated);
  position: relative;
  z-index: 1;
  transition: all 0.3s ease;
}

.icon-svg {
  width: 16px;
  height: 16px;
  color: currentColor;
}

.step-num {
  font-size: 13px;
  font-family: var(--font-mono);
  font-weight: 600;
  color: var(--text-muted);
}

.pulse-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--accent-blue);
}

.pulse-ring {
  position: absolute;
  inset: -4px;
  border-radius: 50%;
  border: 2px solid var(--accent-blue);
  opacity: 0;
  animation: ring-pulse 1.6s ease-out infinite;
}
@keyframes ring-pulse {
  0%   { opacity: 0.8; transform: scale(1); }
  100% { opacity: 0;   transform: scale(1.6); }
}

/* 节点状态 */
.step.pending .step-node  { border-color: var(--border); }
.step.active  .step-node  {
  border-color: var(--accent-blue);
  background: rgba(56,139,253,0.12);
  box-shadow: 0 0 0 3px rgba(56,139,253,0.15);
}
.step.done    .step-node  {
  border-color: var(--accent-blue);
  background: rgba(56,139,253,0.1);
  color: var(--accent-blue);
}
.step.failed  .step-node  {
  border-color: var(--accent-red);
  background: rgba(248,81,73,0.1);
  color: var(--accent-red);
}
.step.waiting .step-node  {
  border-color: var(--accent-yellow);
  background: rgba(210,153,34,0.12);
  box-shadow: 0 0 0 3px rgba(210,153,34,0.15);
  animation: waiting-glow 2s ease-in-out infinite;
}
@keyframes waiting-glow {
  0%,100% { box-shadow: 0 0 0 3px rgba(210,153,34,0.15); }
  50%     { box-shadow: 0 0 0 6px rgba(210,153,34,0.08); }
}

/* 节点标签 */
.step-label {
  font-size: 11px;
  color: var(--text-muted);
  text-align: center;
  white-space: nowrap;
  transition: color 0.3s;
}
.step.active  .step-label { color: var(--accent-blue);   font-weight: 500; }
.step.done    .step-label { color: var(--text-secondary); }
.step.waiting .step-label { color: var(--accent-yellow);  font-weight: 500; }
.step.failed  .step-label { color: var(--accent-red); }

/* 徽章 */
.step-badge {
  position: absolute;
  top: -4px;
  right: -4px;
  font-size: 9px;
  font-family: var(--font-mono);
  padding: 1px 4px;
  border-radius: 6px;
  white-space: nowrap;
  line-height: 1.4;
  z-index: 2;
}
.badge-yellow { background: rgba(210,153,34,.18); color: var(--accent-yellow); border: 1px solid rgba(210,153,34,.3); }
.badge-red    { background: rgba(248,81,73,.18);  color: var(--accent-red);    border: 1px solid rgba(248,81,73,.3); }
.badge-green  { background: rgba(63,185,80,.18);  color: var(--accent-green);  border: 1px solid rgba(63,185,80,.3); }

/* ── 进度文字行 ── */
.progress-text {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px 14px;
  font-size: 11px;
}
.phase-label {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--text-muted);
  font-family: var(--font-mono);
}
.progress-pct {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
}

.dot-running, .dot-done, .dot-fail {
  width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0;
}
.dot-running { background: var(--accent-blue);  animation: blink 1.2s step-end infinite; }
.dot-done    { background: var(--accent-green); }
.dot-fail    { background: var(--accent-red); }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }

/* ── 审批栏 ── */
.approval-bar {
  border-top: 1px solid rgba(210,153,34,0.25);
  background: rgba(210,153,34,0.05);
  padding: 12px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}
.approval-left {
  display: flex;
  align-items: center;
  gap: 12px;
}
.approval-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  color: var(--accent-yellow);
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
.approval-sub b { color: var(--accent-yellow); }
.approval-actions { display: flex; gap: 8px; flex-shrink: 0; }

.btn-reject, .btn-approve {
  padding: 5px 14px;
  border-radius: var(--radius-md);
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid;
  transition: all 0.15s;
  display: flex;
  align-items: center;
  gap: 6px;
}
.btn-reject {
  background: transparent;
  border-color: var(--border);
  color: var(--text-secondary);
}
.btn-reject:hover:not(:disabled) {
  border-color: var(--accent-red);
  color: var(--accent-red);
}
.btn-approve {
  background: rgba(63,185,80,0.12);
  border-color: rgba(63,185,80,0.4);
  color: var(--accent-green);
}
.btn-approve:hover:not(:disabled) {
  background: rgba(63,185,80,0.2);
}
.btn-reject:disabled, .btn-approve:disabled { opacity: 0.5; cursor: not-allowed; }

.btn-loading {
  width: 12px; height: 12px;
  border: 2px solid rgba(63,185,80,0.3);
  border-top-color: var(--accent-green);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* 审批栏动画 */
.slide-down-enter-active, .slide-down-leave-active { transition: all 0.3s ease; }
.slide-down-enter-from, .slide-down-leave-to { opacity: 0; transform: translateY(-8px); }
</style>