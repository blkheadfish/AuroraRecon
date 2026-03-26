<template>
  <span class="status-badge" :class="[`status-${status}`, size]">
    <span class="dot" v-if="status === 'running'"></span>
    <el-icon v-else-if="status === 'completed'"><CircleCheckFilled /></el-icon>
    <el-icon v-else-if="status === 'failed'"><CircleCloseFilled /></el-icon>
    <el-icon v-else><Clock /></el-icon>
    {{ labelMap[status] || status }}
  </span>
</template>

<script setup>
defineProps({
  status: String,
  size: { type: String, default: '' }
})

const labelMap = {
  pending: '等待中',
  running: '运行中',
  completed: '已完成',
  failed: '失败',
}
</script>

<style scoped>
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 10px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 500;
  border: 1px solid;
}

.status-badge.large {
  font-size: 13px;
  padding: 5px 14px;
}

.status-pending {
  color: var(--status-pending);
  background: rgba(139,148,158,0.1);
  border-color: rgba(139,148,158,0.3);
}
.status-running {
  color: var(--status-running);
  background: rgba(56,139,253,0.1);
  border-color: rgba(56,139,253,0.3);
}
.status-completed {
  color: var(--status-completed);
  background: rgba(63,185,80,0.1);
  border-color: rgba(63,185,80,0.3);
}
.status-failed {
  color: var(--status-failed);
  background: rgba(248,81,73,0.1);
  border-color: rgba(248,81,73,0.3);
}

.dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  animation: blink 1.2s infinite;
}

@keyframes blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.2; }
}
</style>
