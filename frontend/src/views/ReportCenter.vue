<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">报告中心</h1>
        <p class="page-sub">在线编辑 AI 生成报告并实时渲染预览</p>
      </div>
      <div class="header-actions">
        <el-button @click="router.push(`/tasks/${taskId}`)">返回任务详情</el-button>
      </div>
    </div>

    <ReportPanel :task-id="taskId" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import ReportPanel from '@/components/ReportPanel.vue'

const route = useRoute()
const router = useRouter()
const taskId = computed(() => String(route.params.id || ''))
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.page-title { font-size: 22px; color: var(--text-primary); font-weight: 700; }
.page-sub { color: var(--text-secondary); font-size: 13px; margin-top: 4px; }
</style>
