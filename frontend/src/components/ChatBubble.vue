<template>
  <div class="bubble-row" :class="`role-${role}`">
    <div class="avatar" :class="`avatar-${role}`">
      <span v-if="role === 'agent'">AI</span>
      <span v-else-if="role === 'user'">你</span>
      <span v-else>·</span>
    </div>
    <div class="bubble" :class="[`tone-${tone || 'info'}`]">
      <div class="bubble-meta">
        <span class="role">{{ roleLabel }}</span>
        <span class="time" v-if="timestamp">{{ timestamp }}</span>
      </div>
      <div class="text">{{ text }}</div>
      <slot name="suggestions" />
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    role: 'agent' | 'user' | 'system'
    text: string
    timestamp?: string
    tone?: 'info' | 'primary' | 'warning' | 'success' | 'danger'
  }>(),
  { tone: 'info', timestamp: '' },
)

const roleLabel = computed(() => {
  if (props.role === 'agent') return 'Agent'
  if (props.role === 'user') return '我'
  return 'System'
})
</script>

<style scoped>
.bubble-row {
  display: flex;
  gap: 10px;
  align-items: flex-start;
}
.role-user { flex-direction: row-reverse; }

.avatar {
  flex: 0 0 auto;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 700;
  background: var(--bg-elevated);
  color: var(--text-primary);
  border: 1px solid var(--border);
}
.avatar-agent { color: color-mix(in srgb, var(--accent-blue) 90%, white); }
.avatar-user { color: color-mix(in srgb, var(--accent-green) 90%, white); }
.avatar-system { color: var(--text-muted); }

.bubble {
  max-width: min(78%, 720px);
  padding: 10px 12px;
  border-radius: var(--radius-md);
  background: var(--bg-surface);
  border: 1px solid var(--border);
  color: var(--text-primary);
}
.role-user .bubble {
  background: color-mix(in srgb, var(--accent-blue) 12%, var(--bg-elevated));
  border-color: color-mix(in srgb, var(--accent-blue) 35%, var(--border));
}

.tone-warning {
  background: color-mix(in srgb, var(--accent-yellow) 8%, var(--bg-surface));
  border-color: color-mix(in srgb, var(--accent-yellow) 36%, var(--border));
}
.tone-primary {
  background: color-mix(in srgb, var(--accent-blue) 8%, var(--bg-surface));
  border-color: color-mix(in srgb, var(--accent-blue) 32%, var(--border));
}
.tone-success {
  background: color-mix(in srgb, var(--accent-green) 8%, var(--bg-surface));
  border-color: color-mix(in srgb, var(--accent-green) 32%, var(--border));
}
.tone-danger {
  background: color-mix(in srgb, var(--accent-red) 8%, var(--bg-surface));
  border-color: color-mix(in srgb, var(--accent-red) 32%, var(--border));
}

.bubble-meta {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  font-size: 11px;
  color: var(--text-muted);
  margin-bottom: 4px;
}
.role { font-weight: 600; color: var(--text-secondary); }
.time { font-family: var(--font-mono); }

.text {
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.6;
  font-size: 13px;
  color: var(--text-primary);
}
</style>
