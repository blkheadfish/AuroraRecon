<!-- MissionControl – 任务页顶部指标栏 + kill-chain 进度条 -->
<template>
  <div class="mission-control">
    <!-- 当前阶段大徽章 -->
    <div class="mc-phase-badge">
      <span class="mc-phase-dot" :style="{ background: phaseColor }" />
      <span class="mc-phase-label">{{ phaseText }}</span>
    </div>

    <!-- 指标卡 -->
    <div class="mc-metrics">
      <div v-for="m in metrics" :key="m.key" class="mc-metric-card">
        <span class="mc-metric-icon" :style="{ background: m.color }" />
        <span class="mc-metric-value">{{ formatCount(m.value) }}</span>
        <span class="mc-metric-label">{{ m.label }}</span>
      </div>
    </div>

    <!-- Kill-chain 进度条 -->
    <div class="mc-progress">
      <div
        v-for="step in chainSteps"
        :key="step.key"
        class="mc-progress-seg"
        :class="{ active: step.active, current: step.key === currentChainStep }"
        :style="step.active ? { background: step.color } : {}"
      >
        <span class="mc-progress-label">{{ step.label }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps({
  task: { type: Object, default: null },
  metricsData: { type: Object, default: () => ({}) },
})

const phaseColors: Record<string, string> = {
  recon:        'var(--phase-recon)',
  vuln_scan:    'var(--phase-vuln)',
  exploit:      'var(--phase-exploit)',
  post_exploit: 'var(--phase-post)',
  report:       'var(--phase-report)',
}

const phaseText = computed(() => {
  const p = props.task?.current_phase || ''
  const m: Record<string, string> = {
    recon: '信息侦察', vuln_scan: '漏洞扫描', exploit: '漏洞利用',
    post_exploit: '后渗透', report: '报告生成',
  }
  return m[p] || p || '—'
})

const phaseColor = computed(() => {
  const p = props.task?.current_phase || ''
  const colors: Record<string, string> = {
    recon: '#388bfd', vuln_scan: '#d29922', exploit: '#f85149',
    post_exploit: '#bc8cff', report: '#3fb950',
  }
  return colors[p] || '#8b949e'
})

const chainSteps = computed(() => {
  const p = props.task?.current_phase || ''
  const steps = [
    { key: 'recon',        label: '侦察', color: '#388bfd' },
    { key: 'vuln_scan',    label: '漏洞', color: '#d29922' },
    { key: 'exploit',      label: '利用', color: '#f85149' },
    { key: 'post_exploit', label: '后渗透', color: '#bc8cff' },
    { key: 'report',       label: '报告', color: '#3fb950' },
  ]
  const phaseIdx = steps.findIndex((s) => s.key === p || p.startsWith(s.key))
  return steps.map((s, i) => ({
    ...s,
    active: i <= (phaseIdx >= 0 ? phaseIdx : -1),
  }))
})

const currentChainStep = computed(() => {
  const p = props.task?.current_phase || ''
  if (p.startsWith('recon')) return 'recon'
  if (p.startsWith('vuln')) return 'vuln_scan'
  if (p.startsWith('exploit')) return 'exploit'
  if (p.startsWith('post')) return 'post_exploit'
  if (p.startsWith('report')) return 'report'
  return ''
})

const metrics = computed(() => {
  const d = props.metricsData || {}
  const t = props.task || {}
  return [
    { key: 'hosts',       value: d.hosts      ?? 1,                            label: '主机',   color: '#58b8e0' },
    { key: 'services',    value: d.services   ?? (t.open_ports?.length || 0),   label: '服务',   color: '#56c9a4' },
    { key: 'findings',    value: d.findings   ?? (t.findings?.length || 0),     label: '漏洞',   color: '#e06979' },
    { key: 'exploited',   value: d.exploited  ?? (t.got_shell ? 1 : 0),        label: '已利用', color: '#f85149' },
    { key: 'credentials', value: d.credentials ?? (t.credential_store?.length || 0), label: '凭据', color: '#d9a84e' },
    { key: 'sessions',    value: d.sessions   ?? 0,                              label: '会话',   color: '#56c9a4' },
  ]
})

function formatCount(n: number): string {
  if (n >= 10000) return (n / 1000).toFixed(1) + 'k'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'k'
  return String(n)
}
</script>

<style scoped>
.mission-control {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px 16px;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  flex-wrap: wrap;
}

/* ── Phase 徽章 ──────────────────────────── */
.mc-phase-badge {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 18px;
  border-radius: 24px;
  background: color-mix(in srgb, var(--phase-recon) 12%, var(--bg-elevated));
  border: 1px solid color-mix(in srgb, var(--phase-recon) 30%, var(--border));
  flex-shrink: 0;
}

.mc-phase-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  box-shadow: 0 0 8px currentColor;
}

.mc-phase-label {
  font-family: var(--font-orbitron);
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
  letter-spacing: 0.04em;
}

/* ── 指标卡 ──────────────────────────────── */
.mc-metrics {
  display: flex;
  gap: 4px;
  flex: 1;
  flex-wrap: wrap;
}

.mc-metric-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 6px 12px;
  border-radius: var(--radius-md);
  background: var(--bg-elevated);
  border: 1px solid var(--border-muted);
  min-width: 64px;
  transition: border-color var(--t-fast) var(--ease-out);
}
.mc-metric-card:hover {
  border-color: var(--text-muted);
}

.mc-metric-icon {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}

.mc-metric-value {
  font-family: var(--font-orbitron);
  font-size: 16px;
  font-weight: 700;
  color: var(--text-primary);
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
}

.mc-metric-label {
  font-size: 10px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

/* ── Kill-chain 进度 ─────────────────────── */
.mc-progress {
  display: flex;
  gap: 2px;
  flex-shrink: 0;
}

.mc-progress-seg {
  padding: 4px 10px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-muted);
  font-size: 10px;
  color: var(--text-muted);
  font-family: var(--font-mono);
  transition: background var(--t-base) var(--ease-out), color var(--t-base) var(--ease-out);
}
.mc-progress-seg:first-child { border-radius: var(--radius-sm) 0 0 var(--radius-sm); }
.mc-progress-seg:last-child { border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }

.mc-progress-seg.active {
  color: #fff;
  border-color: transparent;
}

.mc-progress-seg.current {
  box-shadow: var(--glow-blue);
  transform: scale(1.08);
  z-index: 1;
}

.mc-progress-label {
  white-space: nowrap;
}

@media (prefers-reduced-motion: reduce) {
  .mc-progress-seg {
    transition: none;
  }
  .mc-progress-seg.current {
    transform: none;
    box-shadow: none;
  }
}
</style>
