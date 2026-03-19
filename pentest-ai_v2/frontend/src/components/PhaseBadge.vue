<template>
  <span class="phase-badge" :class="`phase-${phase}`">{{ labelMap[phase] || phase }}</span>
</template>

<script setup>
defineProps({ phase: String })
const labelMap = {
  init: '初始化',
  recon: '侦察',
  vuln_scan: '漏洞扫描',
  exploit_decision: '决策分析',
  exploit: '漏洞利用',
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
.phase-vuln_scan     { color: var(--phase-vuln); }
.phase-exploit_decision { color: var(--accent-orange); }
.phase-exploit       { color: var(--phase-exploit); }
.phase-post_exploit  { color: var(--phase-post); }
.phase-report        { color: var(--phase-report); }
</style>
