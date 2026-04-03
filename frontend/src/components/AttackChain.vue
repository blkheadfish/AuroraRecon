<template>
  <PipelineFlow
    :current-phase="currentPhase"
    :status="status"
    :findings-count="findingsCount"
    :exploitable-count="exploitableCount"
    :got-shell="gotShell"
    :needs-approval="needsApproval"
    :approving="approving"
    @approve="$emit('approve')"
    @reject="$emit('reject')"
  />
</template>

<script setup>
import PipelineFlow from '@/components/PipelineFlow.vue'

defineProps({
  currentPhase: { type: String, default: 'init' },
  status: { type: String, default: 'pending' },
  findingsCount: { type: Number, default: 0 },
  exploitableCount: { type: Number, default: 0 },
  gotShell: { type: Boolean, default: false },
  needsApproval: { type: Boolean, default: false },
  approving: { type: Boolean, default: false },
})

defineEmits(['approve', 'reject'])
</script>