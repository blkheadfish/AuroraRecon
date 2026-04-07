<template>
  <div class="approval-wrap" :class="{ compact }">
    <div class="left" v-if="!compact">
      <div class="title">执行模式</div>
      <el-radio-group v-model="mode" @change="onModeChange">
        <el-radio-button label="manual">手动审核</el-radio-button>
        <el-radio-button label="auto">全自动</el-radio-button>
      </el-radio-group>
      <p class="hint" v-if="needsApproval">当前任务等待人工审批，确认后将进入利用阶段。</p>
    </div>

    <p class="compact-hint" v-if="compact && needsApproval">
      系统检测到可利用路径，等待人工审批确认。
    </p>

    <div class="right" v-if="needsApproval">
      <el-button class="btn-reject" type="danger" plain @click="$emit('reject')" :loading="loading">拒绝执行</el-button>
      <el-button class="btn-approve" @click="$emit('approve')" :loading="loading">批准并继续</el-button>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useUiPrefsStore } from '@/stores/uiPrefs'
import { trackEvent } from '@/metrics/tracker'

const props = defineProps({
  needsApproval: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
  compact: { type: Boolean, default: false },
})

defineEmits(['approve', 'reject'])

const uiPrefs = useUiPrefsStore()
const mode = computed({
  get: () => uiPrefs.executionMode,
  set: (value) => {
    uiPrefs.executionMode = value
  },
})

function onModeChange(value) {
  trackEvent('execution.mode.change', { value })
}
</script>

<style scoped>
.approval-wrap { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 12px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-surface); }
.approval-wrap.compact { flex-direction: column; align-items: stretch; padding: 12px 14px; border-color: color-mix(in srgb, var(--accent-yellow) 50%, var(--border)); background: color-mix(in srgb, var(--accent-yellow) 8%, var(--bg-elevated)); }
.approval-wrap.compact .right { justify-content: flex-end; }
.compact-hint { color: var(--text-primary); font-size: 13px; line-height: 1.5; margin: 0 0 10px; }
.title { color: var(--text-primary); font-size: 13px; font-weight: 600; margin-bottom: 8px; }
.hint { color: var(--text-muted); font-size: 12px; margin: 8px 0 0; }
.right { display: flex; gap: 8px; }
:deep(.right .btn-reject.el-button) {
  border-color: color-mix(in srgb, var(--accent-red) 52%, var(--border)) !important;
  color: color-mix(in srgb, var(--accent-red) 84%, var(--text-primary)) !important;
  background: color-mix(in srgb, var(--accent-red) 20%, var(--bg-elevated)) !important;
}
:deep(.right .btn-reject.el-button:hover),
:deep(.right .btn-reject.el-button:focus-visible),
:deep(.right .btn-reject.el-button:active) {
  border-color: color-mix(in srgb, var(--accent-red) 70%, var(--border)) !important;
  color: color-mix(in srgb, var(--accent-red) 92%, var(--text-primary)) !important;
  background: color-mix(in srgb, var(--accent-red) 28%, var(--bg-hover)) !important;
}
:deep(.approval-wrap .right .btn-approve.el-button:not(.el-button--primary):not(.el-button--danger):not(.is-text):not(.is-link)) {
  border-color: color-mix(in srgb, var(--accent-green) 52%, var(--border)) !important;
  color: color-mix(in srgb, var(--accent-green) 84%, var(--text-primary)) !important;
  font-weight: 600;
  background: color-mix(in srgb, var(--accent-green) 18%, var(--bg-elevated)) !important;
}
:deep(.approval-wrap .right .btn-approve.el-button:not(.el-button--primary):not(.el-button--danger):not(.is-text):not(.is-link):hover),
:deep(.approval-wrap .right .btn-approve.el-button:not(.el-button--primary):not(.el-button--danger):not(.is-text):not(.is-link):focus-visible),
:deep(.approval-wrap .right .btn-approve.el-button:not(.el-button--primary):not(.el-button--danger):not(.is-text):not(.is-link):active) {
  border-color: color-mix(in srgb, var(--accent-green) 70%, var(--border)) !important;
  color: color-mix(in srgb, var(--accent-green) 92%, var(--text-primary)) !important;
  background: color-mix(in srgb, var(--accent-green) 28%, var(--bg-hover)) !important;
}
:deep(.right .btn-reject.el-button.is-disabled),
:deep(.right .btn-reject.el-button.is-loading) {
  border-color: color-mix(in srgb, var(--accent-red) 40%, var(--border)) !important;
  color: color-mix(in srgb, var(--accent-red) 64%, var(--text-muted)) !important;
  background: color-mix(in srgb, var(--accent-red) 12%, var(--bg-elevated)) !important;
}
:deep(.approval-wrap .right .btn-approve.el-button:not(.el-button--primary):not(.el-button--danger):not(.is-text):not(.is-link).is-disabled),
:deep(.approval-wrap .right .btn-approve.el-button:not(.el-button--primary):not(.el-button--danger):not(.is-text):not(.is-link).is-loading) {
  border-color: color-mix(in srgb, var(--accent-green) 40%, var(--border)) !important;
  color: color-mix(in srgb, var(--accent-green) 64%, var(--text-muted)) !important;
  background: color-mix(in srgb, var(--accent-green) 12%, var(--bg-elevated)) !important;
  opacity: 0.9;
}
</style>
