<template>
  <div class="empty-state">
    <div class="es-icon-wrap">
      <el-icon class="es-icon"><component :is="icon" /></el-icon>
    </div>
    <p class="es-text">{{ text }}</p>
    <p v-if="hint" class="es-hint">{{ hint }}</p>
    <slot />
  </div>
</template>

<script setup lang="ts">
import { Share } from '@element-plus/icons-vue'

defineProps({
  text: { type: String, default: '暂无数据' },
  hint: { type: String, default: '' },
  icon: { type: Object, default: () => Share },
})
</script>

<style scoped>
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 48px 24px;
  min-height: 240px;
}

.es-icon-wrap {
  width: 72px;
  height: 72px;
  border-radius: 50%;
  background: color-mix(in srgb, var(--text-muted) 8%, transparent);
  display: flex;
  align-items: center;
  justify-content: center;
}

.es-icon {
  font-size: 32px;
  color: var(--text-muted);
  opacity: 0.4;
}

.es-text {
  color: var(--text-secondary);
  font-size: 13px;
  margin: 0;
  font-family: var(--font-mono);
}

.es-hint {
  color: var(--text-muted);
  font-size: 11px;
  margin: 0;
}
</style>
