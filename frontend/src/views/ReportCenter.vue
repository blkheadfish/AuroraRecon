<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">报告中心</h1>
        <p class="page-sub" v-if="task">目标：{{ task.target }}</p>
      </div>
      <div class="header-actions">
        <el-button @click="router.push(`/tasks/${taskId}`)">返回任务详情</el-button>
      </div>
    </div>

    <ReportPanel :task-id="taskId" :task="task" />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '@/api'
import ReportPanel from '@/components/ReportPanel.vue'

const route = useRoute()
const router = useRouter()
const taskId = computed(() => String(route.params.id || ''))
const task = ref(null)

onMounted(async () => {
  try { task.value = await api.getTask(taskId.value) } catch { /* ignore */ }
})
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.page-title { font-size: 22px; color: var(--text-primary); font-weight: 700; }
.page-sub { color: var(--text-secondary); font-size: 13px; margin-top: 4px; }
</style>
