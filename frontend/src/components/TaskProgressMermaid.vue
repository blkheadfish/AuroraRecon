<template>
  <div class="mermaid-progress">
    <div class="flow-graph">
      <template v-for="(node, i) in nodes" :key="node.id">
        <div
          class="flow-node"
          :class="[
            nodeState(node.id),
            { 'needs-approval': needsApproval && node.id === 'awaiting_approval' },
          ]"
        >
          <span class="node-icon">{{ nodeIcon(node.id) }}</span>
          <span class="node-label">{{ node.label }}</span>
        </div>
        <div v-if="i < nodes.length - 1" class="flow-arrow" :class="arrowState(i)">
          <span class="arrow-line" />
          <span class="arrow-head">›</span>
        </div>
      </template>
    </div>

    <p class="stats-line">
      发现 {{ findingsCount }} 个漏洞 · {{ exploitableCount }} 个可利用 · Shell:
      {{ gotShell ? '已获取' : '未获取' }}
      · 立足: {{ footholdLabel }} · 权限: {{ privilegeLabel }} · 提权轮次: {{ privescAttemptCount }}
    </p>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  currentPhase: { type: String, default: 'init' },
  status: { type: String, default: 'pending' },
  findingsCount: { type: Number, default: 0 },
  exploitableCount: { type: Number, default: 0 },
  gotShell: { type: Boolean, default: false },
  needsApproval: { type: Boolean, default: false },
  chainVisited: { type: Array, default: () => [] },
  secondaryElided: { type: Boolean, default: false },
  footholdStatus: { type: String, default: 'none' },
  privilegeLevel: { type: String, default: '' },
  privescAttemptCount: { type: Number, default: 0 },
})

const nodes = [
  { id: 'recon', label: '信息侦察' },
  { id: 'surface_enum', label: '表面枚举' },
  { id: 'vuln_scan', label: '漏洞扫描' },
  { id: 'exploit_decision', label: 'AI 决策' },
  { id: 'awaiting_approval', label: '人工审批' },
  { id: 'foothold_attempt', label: '立足点' },
  { id: 'secondary_attack', label: '二次利用' },
  { id: 'post_foothold_enum', label: '立足后枚举' },
  { id: 'privesc_attempt', label: '提权' },
  { id: 'objective_collect', label: '目标收集' },
  { id: 'report', label: '报告生成' },
]

const visitedSet = computed(() => new Set(props.chainVisited || []))

const footholdLabel = computed(() => {
  const m = {
    none: '无',
    web_rce: 'Web RCE',
    shell: 'Shell',
    ssh: 'SSH',
    meterpreter: 'Meterpreter',
  }
  return m[props.footholdStatus] || props.footholdStatus || '—'
})

const privilegeLabel = computed(() => props.privilegeLevel || '—')

function nodeState(id) {
  if (id === 'secondary_attack' && props.secondaryElided && !visitedSet.value.has('secondary_attack')) {
    return 'skipped'
  }

  const legacyIdx = () => {
    const ci = nodes.findIndex((n) => n.id === props.currentPhase)
    const mi = nodes.findIndex((n) => n.id === id)
    if (ci < 0 || mi < 0) return null
    return mi <= ci
  }

  if (props.status === 'completed' && (!props.chainVisited || props.chainVisited.length === 0)) {
    return legacyIdx() ? 'completed' : 'pending'
  }

  if (props.status === 'completed') {
    if (visitedSet.value.has(id) || id === 'report') return 'completed'
    if (id === props.currentPhase) return 'completed'
    return 'pending'
  }

  if (visitedSet.value.has(id) && id !== props.currentPhase) return 'completed'
  if (id === props.currentPhase) return props.status === 'failed' ? 'failed' : 'active'
  return 'pending'
}

function arrowState(i) {
  const left = nodes[i]?.id
  const right = nodes[i + 1]?.id
  if (!left || !right) return 'pending'
  if (props.status === 'completed') return 'completed'
  const ls = nodeState(left)
  const rs = nodeState(right)
  const leftDone = ls === 'completed' || ls === 'skipped'
  const rightReached = rs === 'completed' || rs === 'active' || rs === 'skipped' || rs === 'failed'
  if (leftDone && rightReached) return 'completed'
  return 'pending'
}

function nodeIcon(id) {
  const state = nodeState(id)
  if (state === 'skipped') return '○'
  if (state === 'completed') return '✓'
  if (state === 'failed') return '✕'
  const iconMap = {
    recon: '🔍',
    vuln_scan: '🛡',
    surface_enum: '📂',
    exploit_decision: '🤖',
    awaiting_approval: '⏳',
    foothold_attempt: '⚡',
    secondary_attack: '↻',
    post_foothold_enum: '🧭',
    privesc_attempt: '🔑',
    objective_collect: '🎯',
    report: '📄',
  }
  return iconMap[id] ?? '•'
}
</script>

<style scoped>
.mermaid-progress {
  padding: 14px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-base);
  overflow-x: auto;
}

/* ── Flow graph row ── */
.flow-graph {
  display: flex;
  align-items: center;
  flex-wrap: nowrap;
  gap: 0;
  min-width: min-content;
  padding-bottom: 8px;
}

.flow-node {
  flex: 0 0 auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: var(--bg-elevated);
  min-width: 72px;
  max-width: 100px;
  text-align: center;
  transition:
    border-color 0.15s,
    background 0.15s;
}

.flow-node .node-icon {
  font-size: 1rem;
  line-height: 1;
}

.flow-node .node-label {
  font-size: 11px;
  line-height: 1.25;
  color: var(--text-secondary);
  word-break: break-all;
}

.flow-node.active {
  border-color: var(--accent);
  background: rgba(88, 199, 157, 0.12);
}

.flow-node.active .node-label {
  color: var(--text-primary);
  font-weight: 600;
}

.flow-node.completed {
  border-color: rgba(88, 199, 157, 0.45);
  opacity: 0.95;
}

.flow-node.skipped {
  border-style: dashed;
  opacity: 0.65;
}

.flow-node.failed {
  border-color: var(--danger, #f56c6c);
}

.flow-node.needs-approval {
  animation: pulse-approval 1.6s ease-in-out infinite;
}

@keyframes pulse-approval {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(230, 162, 60, 0.35);
  }
  50% {
    box-shadow: 0 0 0 6px rgba(230, 162, 60, 0);
  }
}

.flow-arrow {
  display: flex;
  align-items: center;
  padding: 0 2px;
  color: var(--text-muted);
}

.flow-arrow .arrow-line {
  width: 12px;
  height: 2px;
  background: currentColor;
  opacity: 0.35;
}

.flow-arrow .arrow-head {
  margin-left: -2px;
  font-size: 14px;
  opacity: 0.5;
}

.flow-arrow.completed {
  color: var(--accent);
}

.flow-arrow.completed .arrow-line {
  opacity: 0.85;
}

.flow-arrow.completed .arrow-head {
  opacity: 1;
}

.stats-line {
  margin: 0;
  font-size: 12px;
  color: var(--text-secondary);
  line-height: 1.5;
}
</style>
