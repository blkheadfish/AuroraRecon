<template>
  <span class="phase-badge" :class="`phase-${phase}`">{{ labelMap[phase] || phase }}</span>
</template>

<script setup>
defineProps({ phase: String })
const labelMap = {
  init: '初始化',
  recon: '侦察',
  surface_enum: '表面枚举',
  intel_harvest: '情报采集',
  vuln_scan: '漏洞扫描',
  exploit_decision: '决策分析',
  awaiting_approval: '人工审批',
  foothold_attempt: '立足点',
  exploit: '漏洞利用',
  secondary_attack: '二次利用',
  post_foothold_enum: '立足后枚举',
  privesc_attempt: '提权',
  objective_collect: '目标收集',
  post_exploit: '后渗透',
  report: '生成报告',
}
</script>

<style scoped>
.phase-badge {
  font-family: var(--font-mono);
  font-size: 11px;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  border: 1px solid currentColor;
  opacity: 0.85;
}
.phase-init          { color: var(--text-muted); }
.phase-recon         { color: var(--phase-recon); }
.phase-surface_enum  { color: var(--phase-recon); }
.phase-intel_harvest { color: var(--phase-recon); }
.phase-vuln_scan     { color: var(--phase-vuln); }
.phase-exploit_decision   { color: var(--accent-orange); }
.phase-awaiting_approval  { color: var(--accent-yellow); }
.phase-foothold_attempt   { color: var(--phase-exploit); }
.phase-exploit       { color: var(--phase-exploit); }
.phase-secondary_attack   { color: var(--phase-exploit); }
.phase-post_foothold_enum { color: var(--phase-post); }
.phase-privesc_attempt    { color: var(--phase-post); }
.phase-objective_collect  { color: var(--phase-post); }
.phase-post_exploit  { color: var(--phase-post); }
.phase-report        { color: var(--phase-report); }
</style>
