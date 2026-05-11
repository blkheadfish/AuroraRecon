<template>
  <div class="bubble-row" :class="`role-${role}`">
    <div class="avatar" :class="`avatar-${role}`">
      <img v-if="role === 'agent'" :src="robotIcon" class="avatar-img" alt="Agent" />
      <span v-else-if="role === 'user'">你</span>
      <span v-else>·</span>
    </div>
    <div class="bubble" :class="[`tone-${tone || 'info'}`, { 'bubble-markdown': useMarkdown }]">
      <div class="bubble-meta">
        <span class="role">{{ roleLabel }}</span>
        <span class="time" v-if="timestamp">{{ timestamp }}</span>
      </div>
      <div v-if="useMarkdown" class="text md-body" v-html="renderedText"></div>
      <div v-else class="text">{{ text }}</div>
      <slot name="suggestions" />
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { marked } from 'marked'
import robotIcon from '@/assets/robot.png'

// 配置 marked 安全选项
marked.setOptions({
  breaks: true,
  gfm: true,
})

const props = withDefaults(
  defineProps<{
    role: 'agent' | 'user' | 'system'
    text: string
    timestamp?: string
    tone?: 'info' | 'primary' | 'warning' | 'success' | 'danger'
    useMarkdown?: boolean
  }>(),
  { tone: 'info', timestamp: '', useMarkdown: false },
)

const roleLabel = computed(() => {
  if (props.role === 'agent') return 'Agent'
  if (props.role === 'user') return '我'
  return 'System'
})

const renderedText = computed(() => {
  try {
    return marked.parse(props.text) as string
  } catch {
    return props.text
  }
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
  overflow: hidden;
}
.avatar-agent {
  color: color-mix(in srgb, var(--accent-blue) 90%, white);
  background: color-mix(in srgb, var(--accent-blue) 12%, var(--bg-elevated));
  border-color: color-mix(in srgb, var(--accent-blue) 35%, var(--border));
}
.avatar-user { color: color-mix(in srgb, var(--accent-green) 90%, white); }
.avatar-system { color: var(--text-muted); }
.avatar-img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
}

.bubble {
  /* 短消息也吃满 max-width,保证一栏 agent/system 卡片宽度一致更整齐;
     user 卡片保留 fit-content 行为(见下方覆盖),贴右贴合聊天习惯。*/
  max-width: min(78%, 720px);
  padding: 10px 12px;
  border-radius: var(--radius-md);
  background: var(--bg-surface);
  border: 1px solid var(--border);
  color: var(--text-primary);
  box-sizing: border-box;
}
.role-agent .bubble,
.role-system .bubble {
  flex: 1 1 auto;
  min-width: 0;
  width: 100%;
}
.role-user .bubble {
  /* 用户气泡贴右,按内容自适应宽度,但不要过窄(避免一两个字时塌成方块)*/
  min-width: 80px;
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
.md-body {
  white-space: normal;
}
.md-body :deep(p) { margin: 0 0 8px; }
.md-body :deep(p:last-child) { margin-bottom: 0; }
.md-body :deep(ul), .md-body :deep(ol) { margin: 4px 0; padding-left: 20px; }
.md-body :deep(li) { margin: 2px 0; line-height: 1.6; }
.md-body :deep(code) {
  font-family: var(--font-mono);
  font-size: 11px;
  background: color-mix(in srgb, var(--text-primary) 10%, transparent);
  padding: 1px 5px;
  border-radius: 3px;
}
.md-body :deep(pre) {
  font-family: var(--font-mono);
  font-size: 11px;
  background: color-mix(in srgb, var(--bg-base) 60%, black);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 8px 10px;
  overflow-x: auto;
  margin: 6px 0;
}
.md-body :deep(pre code) {
  background: none;
  padding: 0;
  font-size: 11px;
}
.md-body :deep(strong) { font-weight: 600; }
.md-body :deep(em) { font-style: italic; }
.md-body :deep(h1), .md-body :deep(h2), .md-body :deep(h3), .md-body :deep(h4) {
  margin: 10px 0 6px;
  font-weight: 600;
  line-height: 1.4;
}
.md-body :deep(h1) { font-size: 16px; }
.md-body :deep(h2) { font-size: 15px; }
.md-body :deep(h3) { font-size: 14px; }
.md-body :deep(h4) { font-size: 13px; }
.md-body :deep(blockquote) {
  margin: 6px 0;
  padding: 4px 10px;
  border-left: 3px solid var(--accent-blue);
  color: var(--text-secondary);
}
.md-body :deep(table) {
  border-collapse: collapse;
  margin: 6px 0;
  font-size: 12px;
  width: 100%;
}
.md-body :deep(th), .md-body :deep(td) {
  border: 1px solid var(--border);
  padding: 4px 8px;
  text-align: left;
}
.md-body :deep(th) { background: color-mix(in srgb, var(--bg-elevated) 50%, transparent); font-weight: 600; }
.md-body :deep(a) {
  color: var(--accent-blue);
  text-decoration: underline;
}
</style>
