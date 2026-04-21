<template>
  <span class="status-badge" :class="[`status-${status}`, size]">
    <span class="dot" v-if="status === 'running'"></span>
    <el-icon v-else-if="status === 'completed'"><CircleCheckFilled /></el-icon>
    <el-icon v-else-if="status === 'failed'"><CircleCloseFilled /></el-icon>
    <el-icon v-else-if="status === 'cancelled'"><RemoveFilled /></el-icon>
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
  cancelled: '已取消',
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
  background: color-mix(in srgb, var(--status-pending) 8%, transparent);
  border-color: color-mix(in srgb, var(--status-pending) 22%, transparent);
}
.status-running {
  color: var(--status-running);
  background: color-mix(in srgb, var(--status-running) 8%, transparent);
  border-color: color-mix(in srgb, var(--status-running) 22%, transparent);
}
.status-completed {
  color: var(--status-completed);
  background: color-mix(in srgb, var(--status-completed) 8%, transparent);
  border-color: color-mix(in srgb, var(--status-completed) 22%, transparent);
}
.status-failed {
  color: var(--status-failed);
  background: color-mix(in srgb, var(--status-failed) 8%, transparent);
  border-color: color-mix(in srgb, var(--status-failed) 22%, transparent);
}
.status-cancelled {
  color: var(--status-cancelled, #8b8fa3);
  background: color-mix(in srgb, var(--status-cancelled, #8b8fa3) 8%, transparent);
  border-color: color-mix(in srgb, var(--status-cancelled, #8b8fa3) 22%, transparent);
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
